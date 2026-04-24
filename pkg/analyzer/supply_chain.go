package analyzer

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

const (
	osvAPIURL          = "https://api.osv.dev/v1/query"
	lockfileFetchLimit = 5 << 20 // 5 MB per lockfile
	maxOSVConcurrency  = 5
)

var osvQueryTimeout = 10 * time.Second

// ── Data types ────────────────────────────────────────────────────────────────

// Dependency describes a package that a tool depends on.
// Adapters should populate UnifiedTool.Metadata["dependencies"] with
// []Dependency when the source protocol exposes package information.
// The supply chain checker also auto-discovers deps by fetching lockfiles from
// UnifiedTool.Metadata["repo_url"] (a GitHub repository URL).
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // e.g. "npm", "Go", "PyPI"
	Source    string `json:"source,omitempty"`
}

type dependencyEvidence struct {
	Dependency
	Source string
}

type osvQueryBody struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
	Affected []osvAffected `json:"affected"` // carries fix-version info
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// osvAffected / osvRange / osvEvent carry the fix-version chain from the OSV
// response: affected[].ranges[].events[].fixed
type osvAffected struct {
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

// ── OSV client interface ──────────────────────────────────────────────────────

// osvClient is an interface for querying the OSV API, enabling test mocking.
type osvClient interface {
	Query(ctx context.Context, dep Dependency) ([]osvVuln, error)
}

// httpOSVClient is the real HTTP implementation of osvClient.
type httpOSVClient struct {
	http    *http.Client
	baseURL string
}

func newHTTPOSVClient() *httpOSVClient {
	return &httpOSVClient{
		http:    &http.Client{Timeout: osvQueryTimeout},
		baseURL: osvAPIURL,
	}
}

func (c *httpOSVClient) Query(ctx context.Context, dep Dependency) ([]osvVuln, error) {
	body, err := json.Marshal(osvQueryBody{
		Package: osvPackage{Name: dep.Name, Ecosystem: dep.Ecosystem},
		Version: dep.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: http request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv: read body: %w", err)
	}

	var result osvResponse
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("osv: unmarshal response: %w", err)
	}
	return result.Vulns, nil
}

// ── Mock client (for tests) ───────────────────────────────────────────────────

// MockVuln describes a fake vulnerability returned by the mock OSV client.
type MockVuln struct {
	ID         string
	Summary    string
	CVSSScore  string // CVSS v3 base score string, e.g. "9.8". Empty = no severity.
	FixVersion string // populated into affected[].ranges[].events[].fixed
}

type mockOSVClient struct {
	vulns []MockVuln
	err   error
}

func (m *mockOSVClient) Query(_ context.Context, _ Dependency) ([]osvVuln, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]osvVuln, len(m.vulns))
	for i, v := range m.vulns {
		ov := osvVuln{ID: v.ID, Summary: v.Summary}
		if v.CVSSScore != "" {
			ov.Severity = []osvSeverity{{Type: "CVSS_V3", Score: v.CVSSScore}}
		}
		if v.FixVersion != "" {
			ov.Affected = []osvAffected{{
				Ranges: []osvRange{{
					Events: []osvEvent{{Fixed: v.FixVersion}},
				}},
			}}
		}
		out[i] = ov
	}
	return out, nil
}

// NewSupplyChainCheckerWithMock returns a SupplyChainChecker backed by an
// in-memory mock OSV client.  Intended for unit tests only.
func NewSupplyChainCheckerWithMock(vulns []MockVuln, queryErr error) *SupplyChainChecker {
	return newSupplyChainCheckerWithClient(&mockOSVClient{vulns: vulns, err: queryErr})
}

// ── Lockfile parsers ──────────────────────────────────────────────────────────

// lockfileSpecs maps well-known lockfile paths to their parsers.
var lockfileSpecs = []struct {
	path  string
	parse func([]byte) ([]Dependency, error)
}{
	{"package-lock.json", parsePackageLockJSON},
	{"pnpm-lock.yaml", parsePNPMLockYAML},
	{"yarn.lock", parseYarnLock},
	{"go.sum", parseGoSum},
	{"requirements.txt", parseRequirementsTxt},
}

var lockfileDepsFetcher = fetchLockfileDeps

type packageLockJSON struct {
	Packages     map[string]packageLockEntry `json:"packages"`     // npm v2/v3
	Dependencies map[string]packageLockEntry `json:"dependencies"` // npm v1
}

type packageLockEntry struct {
	Version string `json:"version"`
}

func parsePackageLockJSON(data []byte) ([]Dependency, error) {
	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse package-lock.json: %w", err)
	}
	seen := make(map[string]bool)
	var deps []Dependency

	if len(lock.Packages) > 0 {
		// npm v2/v3: keys are "node_modules/pkg" or nested "node_modules/a/node_modules/b"
		for key, entry := range lock.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			name := key
			if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
				name = key[idx+len("node_modules/"):]
			}
			k := name + "@" + entry.Version
			if name == "" || seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, Dependency{Name: name, Version: entry.Version, Ecosystem: "npm"})
		}
	} else {
		// npm v1: flat "dependencies" map
		for name, entry := range lock.Dependencies {
			k := name + "@" + entry.Version
			if entry.Version == "" || seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, Dependency{Name: name, Version: entry.Version, Ecosystem: "npm"})
		}
	}
	return deps, nil
}

func parseGoSum(data []byte) ([]Dependency, error) {
	seen := make(map[string]bool)
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		module, version := parts[0], parts[1]
		if strings.HasSuffix(version, "/go.mod") {
			continue // skip go.mod-only hash entries
		}
		version = strings.TrimSuffix(version, "+incompatible")
		k := module + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, Dependency{Name: module, Version: version, Ecosystem: "Go"})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse go.sum: %w", err)
	}
	return deps, nil
}

func parseRequirementsTxt(data []byte) ([]Dependency, error) {
	var deps []Dependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Strip inline comments and environment markers
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		// Only exact pins (==) are meaningful for CVE lookup
		if idx := strings.Index(line, "=="); idx > 0 {
			name := strings.TrimSpace(line[:idx])
			version := strings.TrimSpace(line[idx+2:])
			if name != "" && version != "" {
				deps = append(deps, Dependency{Name: name, Version: version, Ecosystem: "PyPI"})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse requirements.txt: %w", err)
	}
	return deps, nil
}

type pnpmLockfile struct {
	Packages map[string]any `yaml:"packages"`
}

func parsePNPMLockYAML(data []byte) ([]Dependency, error) {
	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse pnpm-lock.yaml: %w", err)
	}

	seen := make(map[string]bool)
	var deps []Dependency
	for key := range lock.Packages {
		name, version, ok := parsePNPMPackageKey(key)
		if !ok {
			continue
		}
		k := name + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, Dependency{Name: name, Version: version, Ecosystem: "npm"})
	}
	return deps, nil
}

func parsePNPMPackageKey(key string) (name, version string, ok bool) {
	trimmed := strings.TrimSpace(strings.TrimPrefix(key, "/"))
	trimmed = strings.Trim(trimmed, "'\"")
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.Index(trimmed, "("); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	trimmed = strings.TrimSuffix(trimmed, ":")
	idx := strings.LastIndex(trimmed, "@")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	return trimmed[:idx], trimmed[idx+1:], true
}

func parseYarnLock(data []byte) ([]Dependency, error) {
	lines := strings.Split(string(data), "\n")
	seen := make(map[string]bool)
	var deps []Dependency

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasSuffix(line, ":") {
			continue
		}
		header := strings.TrimSuffix(line, ":")
		if header == "__metadata" || strings.Contains(line, " version ") {
			continue
		}
		version := ""

		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(lines[j], " ") && !strings.HasPrefix(lines[j], "\t") {
				break
			}
			next := strings.TrimSpace(lines[j])
			if next == "" {
				break
			}
			switch {
			case strings.HasPrefix(next, "version "):
				version = strings.Trim(strings.TrimSpace(next[len("version "):]), "\"'")
			case strings.HasPrefix(next, "version:"):
				version = strings.Trim(strings.TrimSpace(next[len("version:"):]), "\"'")
			}
			if version != "" {
				break
			}
		}
		if version == "" {
			continue
		}
		specs := strings.Split(header, ",")
		for _, spec := range specs {
			spec = strings.Trim(strings.TrimSpace(spec), "\"'")
			if spec == "" {
				continue
			}
			name, ok := parseYarnPackageName(spec)
			if !ok {
				continue
			}
			k := name + "@" + version
			if seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, Dependency{Name: name, Version: version, Ecosystem: "npm"})
		}
	}

	return deps, nil
}

func parseYarnPackageName(spec string) (string, bool) {
	spec = strings.TrimSpace(strings.Trim(spec, "\"'"))
	if spec == "" {
		return "", false
	}
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return "", false
		}
		rest := spec[slash+1:]
		at := strings.Index(rest, "@")
		if at < 0 {
			return "", false
		}
		return spec[:slash+1+at], true
	}
	at := strings.Index(spec, "@")
	if at <= 0 {
		return "", false
	}
	return spec[:at], true
}

// fetchLockfileDeps fetches and parses lockfiles from a GitHub repository URL.
// repoURL must be a https://github.com/owner/repo URL.  Non-GitHub URLs and
// network errors are silently ignored — this is a best-effort enrichment.
func fetchLockfileDeps(repoURL string) []Dependency {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 8 * time.Second}
	var all []Dependency

	for _, spec := range lockfileSpecs {
		for _, branch := range []string{"main", "master"} {
			rawURL, ok := rawGitHubURL(repoURL, branch, spec.path)
			if !ok {
				break // not a GitHub URL — skip all remaining specs too
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
			if err != nil {
				break
			}
			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				if resp != nil {
					if closeErr := resp.Body.Close(); closeErr != nil {
						_ = closeErr
					}
				}
				continue // try next branch
			}
			data, err := io.ReadAll(io.LimitReader(resp.Body, lockfileFetchLimit))
			if closeErr := resp.Body.Close(); closeErr != nil {
				_ = closeErr
			}
			if err != nil {
				continue
			}
			deps, err := spec.parse(data)
			if err != nil || len(deps) == 0 {
				continue
			}
			all = append(all, deps...)
			break // found this lockfile; move to next spec
		}
	}
	return all
}

// rawGitHubURL converts a github.com URL to raw.githubusercontent.com for
// the given branch and file path.  Returns ("", false) for non-GitHub URLs.
func rawGitHubURL(repoURL, branch, filePath string) (string, bool) {
	clean := strings.TrimPrefix(strings.TrimSpace(repoURL), "git+")
	parsed, err := url.Parse(clean)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", false
	}
	host := strings.ToLower(parsed.Hostname())
	if host != "github.com" && host != "www.github.com" {
		return "", false
	}

	repoPath := strings.Trim(parsed.Path, "/")
	repoPath = strings.TrimSuffix(repoPath, ".git")
	parts := strings.Split(repoPath, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", false
	}

	branch = strings.Trim(branch, "/")
	filePath = strings.TrimPrefix(strings.ReplaceAll(filePath, "\\", "/"), "/")
	if branch == "" || filePath == "" {
		return "", false
	}
	return fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", parts[0], parts[1], branch, filePath), true
}

// mergeDependencies merges two dep slices, deduplicating by ecosystem+name+version.
func mergeDependencies(a, b []Dependency) []Dependency {
	seen := make(map[string]bool, len(a)+len(b))
	result := make([]Dependency, 0, len(a)+len(b))
	for _, dep := range append(a, b...) {
		k := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if !seen[k] {
			seen[k] = true
			result = append(result, dep)
		}
	}
	return result
}

// ── SupplyChainChecker ────────────────────────────────────────────────────────

// SupplyChainChecker queries the OSV API for known CVEs in a tool's declared
// dependencies.
//
//   - Dependencies from UnifiedTool.Metadata["dependencies"] are always checked.
//   - If UnifiedTool.Metadata["repo_url"] is a GitHub URL, lockfiles are fetched
//     (package-lock.json, go.sum, requirements.txt) and all transitive deps are
//     also checked — turning AS-004 from decorative to functional.
//   - MAL-* advisories (malicious packages) are always emitted as Critical.
//   - OSV fix versions are appended to the finding description ("upgrade to X.Y.Z").
//
// Rule ID: AS-004.
type SupplyChainChecker struct {
	client osvClient
}

func (c *SupplyChainChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-004",
		Title:       "Supply Chain CVE",
		Description: "Queries the OSV database for known vulnerabilities in a tool's declared package dependencies.",
	}
}

// NewSupplyChainChecker returns a SupplyChainChecker using the live OSV API.
func NewSupplyChainChecker() *SupplyChainChecker {
	return &SupplyChainChecker{client: newHTTPOSVClient()}
}

func newSupplyChainCheckerWithClient(c osvClient) *SupplyChainChecker {
	return &SupplyChainChecker{client: c}
}

// Check queries OSV for all known dependencies and emits AS-004 findings.
func (c *SupplyChainChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	deps, err := collectDependencies(tool)
	if err != nil {
		return nil, nil
	}
	if len(deps) == 0 {
		return nil, nil
	}

	// Query OSV in parallel (capped at maxOSVConcurrency goroutines).
	ch := make(chan []model.Issue, len(deps))
	sem := make(chan struct{}, maxOSVConcurrency)
	var wg sync.WaitGroup

	for _, dep := range deps {
		dep := dep
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			queryCtx, cancel := context.WithTimeout(context.Background(), osvQueryTimeout)
			defer cancel()

			vulns, qErr := c.client.Query(queryCtx, dep.Dependency)
			if qErr != nil {
				ch <- nil
				return
			}
			var issues []model.Issue
			for _, v := range vulns {
				issues = append(issues, buildSupplyChainIssue(v, dep, tool.Name))
			}
			ch <- issues
		}()
	}

	go func() {
		wg.Wait()
		close(ch)
	}()

	var allIssues []model.Issue
	for batch := range ch {
		allIssues = append(allIssues, batch...)
	}
	return allIssues, nil
}

// buildSupplyChainIssue constructs a single AS-004 finding.
//   - MAL-* advisories get Critical severity and code MALICIOUS_PACKAGE.
//   - Fix version from OSV is appended when available.
func buildSupplyChainIssue(v osvVuln, dep dependencyEvidence, toolName string) model.Issue {
	sev := osvSeverityToModel(v)
	code := "SUPPLY_CHAIN_CVE"

	if strings.HasPrefix(v.ID, "MAL-") {
		sev = model.SeverityCritical
		code = "MALICIOUS_PACKAGE"
	}

	desc := fmt.Sprintf("%s in %s@%s: %s", v.ID, dep.Name, dep.Version, v.Summary)
	if fix := extractFixVersion(v); fix != "" {
		desc += fmt.Sprintf(" (upgrade to %s)", fix)
	}

	return model.Issue{
		RuleID:      "AS-004",
		ToolName:    toolName,
		Severity:    sev,
		Code:        code,
		Description: desc,
		Location:    fmt.Sprintf("dependency:%s", dep.Name),
		Evidence: []model.Evidence{
			{Kind: "package", Value: dep.Name},
			{Kind: "version", Value: dep.Version},
			{Kind: "ecosystem", Value: dep.Ecosystem},
			{Kind: "dependency_source", Value: dep.Source},
		},
	}
}

// extractFixVersion returns the first fixed version from the OSV
// affected[].ranges[].events[].fixed chain, or "" if none is present.
func extractFixVersion(v osvVuln) string {
	for _, a := range v.Affected {
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

// extractDependencies deserialises UnifiedTool.Metadata["dependencies"].
func extractDependencies(tool model.UnifiedTool) ([]Dependency, error) {
	raw, ok := tool.Metadata["dependencies"]
	if !ok {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("supply_chain: marshal deps metadata: %w", err)
	}
	var deps []Dependency
	if err = json.Unmarshal(b, &deps); err != nil {
		return nil, fmt.Errorf("supply_chain: unmarshal deps: %w", err)
	}
	return deps, nil
}

func collectDependencies(tool model.UnifiedTool) ([]dependencyEvidence, error) {
	metaDeps, err := extractDependencies(tool)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]bool, len(metaDeps))
	result := make([]dependencyEvidence, 0, len(metaDeps))
	for _, dep := range metaDeps {
		k := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		source := dep.Source
		if source == "" {
			source = "metadata"
		}
		result = append(result, dependencyEvidence{
			Dependency: dep,
			Source:     source,
		})
	}

	if tool.Metadata == nil {
		return result, nil
	}
	repoURL, ok := tool.Metadata["repo_url"].(string)
	if !ok || repoURL == "" {
		return result, nil
	}

	for _, dep := range lockfileDepsFetcher(repoURL) {
		k := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		result = append(result, dependencyEvidence{
			Dependency: dep,
			Source:     "lockfile",
		})
	}
	return result, nil
}

// ── Severity helpers ──────────────────────────────────────────────────────────

func osvSeverityToModel(v osvVuln) model.Severity {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return cvssScoreToSeverity(s.Score)
		}
	}
	return model.SeverityHigh // conservative default
}

func cvssScoreToSeverity(score string) model.Severity {
	f, ok := parseCVSSScore(score)
	if !ok {
		return model.SeverityHigh
	}
	switch {
	case f >= 9.0:
		return model.SeverityCritical
	case f >= 7.0:
		return model.SeverityHigh
	case f >= 4.0:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func parseCVSSScore(score string) (float64, bool) {
	score = strings.TrimSpace(score)
	if score == "" {
		return 0, false
	}
	if f, err := strconv.ParseFloat(score, 64); err == nil {
		return f, true
	}
	if strings.HasPrefix(score, "CVSS:3.") {
		return cvssV3BaseScore(score)
	}
	return 0, false
}

func cvssV3BaseScore(vector string) (float64, bool) {
	metrics := parseCVSSVector(vector)
	scope := metrics["S"]
	av, ok := mapMetric(metrics["AV"], map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	if !ok {
		return 0, false
	}
	ac, ok := mapMetric(metrics["AC"], map[string]float64{"L": 0.77, "H": 0.44})
	if !ok {
		return 0, false
	}
	pr, ok := cvssPrivilegeRequired(metrics["PR"], scope)
	if !ok {
		return 0, false
	}
	ui, ok := mapMetric(metrics["UI"], map[string]float64{"N": 0.85, "R": 0.62})
	if !ok {
		return 0, false
	}
	conf, ok := mapMetric(metrics["C"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}
	integrity, ok := mapMetric(metrics["I"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}
	avail, ok := mapMetric(metrics["A"], map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	if !ok {
		return 0, false
	}

	impactSubScore := 1 - ((1 - conf) * (1 - integrity) * (1 - avail))
	var impact float64
	switch scope {
	case "U":
		impact = 6.42 * impactSubScore
	case "C":
		impact = 7.52*(impactSubScore-0.029) - 3.25*math.Pow(impactSubScore-0.02, 15)
	default:
		return 0, false
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	if scope == "C" {
		return roundUp1(math.Min(1.08*(impact+exploitability), 10)), true
	}
	return roundUp1(math.Min(impact+exploitability, 10)), true
}

func parseCVSSVector(vector string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		key, value, ok := strings.Cut(part, ":")
		if !ok || key == "CVSS" {
			continue
		}
		out[key] = value
	}
	return out
}

func mapMetric(value string, weights map[string]float64) (float64, bool) {
	f, ok := weights[value]
	return f, ok
}

func cvssPrivilegeRequired(value, scope string) (float64, bool) {
	switch value {
	case "N":
		return 0.85, true
	case "L":
		if scope == "C" {
			return 0.68, true
		}
		return 0.62, scope == "U"
	case "H":
		if scope == "C" {
			return 0.5, true
		}
		return 0.27, scope == "U"
	default:
		return 0, false
	}
}

func roundUp1(f float64) float64 {
	return math.Ceil(f*10) / 10
}
