package analyzer

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

//go:embed data/npm_iocs.json
var npmIOCsJSON []byte

var urlPattern = regexp.MustCompile(`https?://[^\s"'()<>]+`)

type npmIOCEntry struct {
	Ecosystem       string `json:"ecosystem"`
	IOCType         string `json:"ioc_type,omitempty"`
	Name            string `json:"name"`
	Value           string `json:"value,omitempty"`
	Match           string `json:"match,omitempty"`
	Reason          string `json:"reason"`
	Confidence      string `json:"confidence,omitempty"`
	Source          string `json:"source,omitempty"`
	FirstSeen       string `json:"first_seen,omitempty"`
	SuggestedAction string `json:"suggested_action,omitempty"`
}

type npmIOCIndex struct {
	packageNames map[string]npmIOCEntry
	indicators   []npmIOCEntry
}

func buildNPMIOCIndex(data []byte) (npmIOCIndex, error) {
	var entries []npmIOCEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return npmIOCIndex{}, fmt.Errorf("npm_ioc: unmarshal: %w", err)
	}
	idx := npmIOCIndex{
		packageNames: make(map[string]npmIOCEntry, len(entries)),
		indicators:   make([]npmIOCEntry, 0, len(entries)),
	}
	for i := range entries {
		entry := entries[i]
		if !strings.EqualFold(entry.Ecosystem, "npm") {
			continue
		}

		if strings.TrimSpace(entry.IOCType) == "" {
			entry.IOCType = "package_name"
		}
		if strings.TrimSpace(entry.Match) == "" {
			switch entry.IOCType {
			case "package_name", "dependency_name":
				entry.Match = "exact"
			default:
				entry.Match = "contains"
			}
		}
		if strings.TrimSpace(entry.Value) == "" {
			entry.Value = entry.Name
		}

		switch entry.IOCType {
		case "package_name", "dependency_name":
			if strings.TrimSpace(entry.Value) == "" {
				continue
			}
			idx.packageNames[strings.ToLower(entry.Value)] = entry
		case "script_pattern", "domain", "url":
			if strings.TrimSpace(entry.Value) == "" {
				continue
			}
			idx.indicators = append(idx.indicators, entry)
		}
	}
	return idx, nil
}

// NPMIOCChecker flags npm package versions whose published registry metadata
// references known malicious IOC package names. This is intentionally narrower
// than a full tarball signature scan, but it helps catch compromised releases
// even when the top-level package name changes or the IOC appears transitively.
type NPMIOCChecker struct {
	client npmRegistryClient
	index  npmIOCIndex
}

func NewNPMIOCChecker() *NPMIOCChecker {
	idx, err := buildNPMIOCIndex(npmIOCsJSON)
	if err != nil {
		idx = npmIOCIndex{packageNames: map[string]npmIOCEntry{}}
	}
	return &NPMIOCChecker{client: newHTTPNPMRegistryClient(), index: idx}
}

func NewNPMIOCCheckerWithMock(packages map[string]npmVersionResponse, queryErr error) *NPMIOCChecker {
	idx, err := buildNPMIOCIndex(npmIOCsJSON)
	if err != nil {
		idx = npmIOCIndex{packageNames: map[string]npmIOCEntry{}}
	}
	return &NPMIOCChecker{
		client: &mockNPMRegistryClient{packages: packages, err: queryErr},
		index:  idx,
	}
}

func (c *NPMIOCChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-016",
		Title:       "Suspicious NPM IOC Dependency",
		Description: "Flags npm dependency versions whose published metadata or install scripts reference known malicious IOC package names, domains, URLs, or script patterns.",
	}
}

func (c *NPMIOCChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	deps, err := collectDependencies(tool)
	if err != nil || len(deps) == 0 {
		return nil, nil
	}

	var issues []model.Issue
	for _, dep := range deps {
		if !strings.EqualFold(dep.Ecosystem, "npm") {
			continue
		}
		queryCtx, cancel := context.WithTimeout(context.Background(), npmQueryTimeout)
		meta, err := c.client.FetchVersion(queryCtx, dep.Name, dep.Version)
		cancel()
		if err != nil {
			continue
		}

		if issue, ok := buildNPMIOCIssue(tool.Name, dep, meta, c.index); ok {
			issues = append(issues, issue)
		}
	}
	return issues, nil
}

func buildNPMIOCIssue(toolName string, dep dependencyEvidence, meta npmVersionResponse, index npmIOCIndex) (model.Issue, bool) {
	type iocHit struct {
		name   string
		source string
		entry  npmIOCEntry
	}

	var hit iocHit
	for name := range meta.Dependencies {
		if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
			hit = iocHit{name: name, source: "dependencies", entry: entry}
			break
		}
	}
	if hit.name == "" {
		for name := range meta.OptionalDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "optionalDependencies", entry: entry}
				break
			}
		}
	}
	if hit.name == "" {
		for _, name := range meta.BundleDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "bundleDependencies", entry: entry}
				break
			}
		}
	}
	if hit.name == "" {
		for _, name := range meta.BundledDependencies {
			if entry, ok := index.packageNames[strings.ToLower(name)]; ok {
				hit = iocHit{name: name, source: "bundledDependencies", entry: entry}
				break
			}
		}
	}

	if hit.name != "" {
		return model.Issue{
			RuleID:      "AS-016",
			ToolName:    toolName,
			Severity:    model.SeverityCritical,
			Code:        "NPM_IOC_DEPENDENCY",
			Description: fmt.Sprintf("npm package %s@%s references suspicious IOC package %s via %s. This IOC is %s.", dep.Name, dep.Version, hit.name, hit.source, hit.entry.Reason),
			Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
			Evidence: []model.Evidence{
				{Kind: "package", Value: dep.Name},
				{Kind: "version", Value: dep.Version},
				{Kind: "ecosystem", Value: dep.Ecosystem},
				{Kind: "dependency_source", Value: dep.Source},
				{Kind: "ioc_type", Value: hit.entry.IOCType},
				{Kind: "ioc_value", Value: hit.name},
				{Kind: "ioc_source", Value: hit.source},
				{Kind: "ioc_confidence", Value: hit.entry.Confidence},
			},
		}, true
	}

	for scriptKey, scriptCmd := range meta.Scripts {
		if matched, ok := matchNPMIOCIndicator(scriptCmd, index.indicators); ok {
			return model.Issue{
				RuleID:      "AS-016",
				ToolName:    toolName,
				Severity:    model.SeverityCritical,
				Code:        "NPM_IOC_INDICATOR",
				Description: fmt.Sprintf("npm package %s@%s publishes a %s script containing suspicious IOC %q (%s). This IOC is %s.", dep.Name, dep.Version, scriptKey, matched.Value, matched.IOCType, matched.Reason),
				Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
				Evidence: []model.Evidence{
					{Kind: "package", Value: dep.Name},
					{Kind: "version", Value: dep.Version},
					{Kind: "ecosystem", Value: dep.Ecosystem},
					{Kind: "dependency_source", Value: dep.Source},
					{Kind: "lifecycle_script", Value: scriptKey},
					{Kind: "ioc_type", Value: matched.IOCType},
					{Kind: "ioc_value", Value: matched.Value},
					{Kind: "ioc_confidence", Value: matched.Confidence},
				},
			}, true
		}
	}

	return model.Issue{}, false
}

func matchNPMIOCIndicator(script string, indicators []npmIOCEntry) (npmIOCEntry, bool) {
	normalizedScript := strings.ToLower(strings.Join(strings.Fields(script), " "))
	urls := extractURLs(normalizedScript)
	domains := extractDomains(urls)
	for i := range indicators {
		entry := indicators[i]
		value := strings.ToLower(strings.TrimSpace(entry.Value))
		if value == "" {
			continue
		}
		match := strings.ToLower(strings.TrimSpace(entry.Match))
		switch strings.ToLower(strings.TrimSpace(entry.IOCType)) {
		case "domain":
			if matchesDomainIOC(value, match, domains) {
				return entry, true
			}
		case "url":
			if matchesURLOC(value, match, urls) {
				return entry, true
			}
		default:
			if matchesStringIOC(value, match, normalizedScript) {
				return entry, true
			}
		}
	}
	return npmIOCEntry{}, false
}

func matchesStringIOC(value, match, haystack string) bool {
	switch match {
	case "exact":
		return haystack == value
	default:
		return strings.Contains(haystack, value)
	}
}

func matchesURLOC(value, match string, urls []string) bool {
	for i := range urls {
		switch match {
		case "exact":
			if urls[i] == value {
				return true
			}
		default:
			if strings.Contains(urls[i], value) {
				return true
			}
		}
	}
	return false
}

func matchesDomainIOC(value, match string, domains []string) bool {
	for i := range domains {
		switch match {
		case "exact":
			if domains[i] == value {
				return true
			}
		default:
			if domains[i] == value || strings.HasSuffix(domains[i], "."+value) || strings.Contains(domains[i], value) {
				return true
			}
		}
	}
	return false
}

func extractURLs(script string) []string {
	matches := urlPattern.FindAllString(script, -1)
	urls := make([]string, 0, len(matches))
	seen := map[string]bool{}
	for i := range matches {
		token := strings.Trim(matches[i], `"'()[]{}<>.,;`)
		parsed, err := url.Parse(token)
		if err != nil || parsed.Host == "" {
			continue
		}
		normalized := strings.ToLower(token)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		urls = append(urls, normalized)
	}
	return urls
}

func extractDomains(urls []string) []string {
	domains := make([]string, 0, len(urls))
	seen := map[string]bool{}
	for i := range urls {
		parsed, err := url.Parse(urls[i])
		if err != nil || parsed.Hostname() == "" {
			continue
		}
		host := strings.ToLower(parsed.Hostname())
		if seen[host] {
			continue
		}
		seen[host] = true
		domains = append(domains, host)
	}
	return domains
}
