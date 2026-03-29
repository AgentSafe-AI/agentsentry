package analyzer

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

//go:embed data/blacklist.json
var blacklistJSON []byte

// blacklistEntry describes a single known-compromised package version entry.
type blacklistEntry struct {
	ID               string   `json:"id"`
	Component        string   `json:"component"`
	Ecosystem        string   `json:"ecosystem"`
	AffectedVersions []string `json:"affected_versions"`
	Action           string   `json:"action"`   // "BLOCK" | "WARN"
	Severity         string   `json:"severity"` // "CRITICAL" | "HIGH" | ...
	Reason           string   `json:"reason"`
	Link             string   `json:"link"`
}

// blacklistIndex maps "ecosystem:name" → []blacklistEntry for O(1) lookup.
type blacklistIndex map[string][]blacklistEntry

// buildBlacklistIndex parses the embedded JSON and returns a lookup index.
func buildBlacklistIndex(data []byte) (blacklistIndex, error) {
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("blacklist: unmarshal: %w", err)
	}
	idx := make(blacklistIndex, len(entries))
	for i := range entries {
		e := &entries[i]
		key := strings.ToLower(e.Ecosystem) + ":" + strings.ToLower(e.Component)
		idx[key] = append(idx[key], *e)
	}
	return idx, nil
}

// matchesVersion reports whether version satisfies the constraint expr.
//
// Supported constraint forms:
//   - Exact:      "1.82.8"         → version == "1.82.8"
//   - Less-than:  "< 1.9.0"        → semver(version) < semver(bound)
//   - Less-equal: "<= 1.9.0"       → semver(version) <= semver(bound)
func matchesVersion(version, expr string) bool {
	expr = strings.TrimSpace(expr)

	// Wildcard: matches any version.
	if expr == "*" {
		return true
	}

	// Range: "< X" or "<= X"
	if strings.HasPrefix(expr, "<=") {
		bound := strings.TrimSpace(expr[2:])
		return semverLE(version, bound)
	}
	if strings.HasPrefix(expr, "<") {
		bound := strings.TrimSpace(expr[1:])
		return semverLT(version, bound)
	}

	// Exact match (case-insensitive, strip surrounding "v" for consistency).
	return strings.EqualFold(normaliseVersion(version), normaliseVersion(expr))
}

// normaliseVersion strips a leading "v" so "v1.9.0" and "1.9.0" compare equal.
func normaliseVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}

// ensureV prepends "v" if missing, because golang.org/x/mod/semver requires it.
func ensureV(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func semverLT(version, bound string) bool {
	v, b := ensureV(version), ensureV(bound)
	if !semver.IsValid(v) || !semver.IsValid(b) {
		// Fall back to string comparison for non-semver (e.g. PyPI date versions)
		return normaliseVersion(version) < normaliseVersion(bound)
	}
	return semver.Compare(v, b) < 0
}

func semverLE(version, bound string) bool {
	v, b := ensureV(version), ensureV(bound)
	if !semver.IsValid(v) || !semver.IsValid(b) {
		return normaliseVersion(version) <= normaliseVersion(bound)
	}
	return semver.Compare(v, b) <= 0
}

// ── BlacklistChecker ──────────────────────────────────────────────────────────

// BlacklistChecker detects known-compromised package versions using an embedded
// offline blacklist. It runs before any network-based checks, providing instant
// zero-latency detection even in air-gapped environments.
//
// Rule ID: AS-008.
type BlacklistChecker struct {
	index blacklistIndex
}

// NewBlacklistChecker returns a BlacklistChecker with the embedded blacklist.
func NewBlacklistChecker() *BlacklistChecker {
	idx, err := buildBlacklistIndex(blacklistJSON)
	if err != nil {
		// The JSON is embedded at compile time and cannot be corrupt in production;
		// return an empty checker so the scanner still starts cleanly.
		return &BlacklistChecker{index: blacklistIndex{}}
	}
	return &BlacklistChecker{index: idx}
}

// newBlacklistCheckerWithData constructs a BlacklistChecker from a custom JSON
// payload — for unit tests only.
func newBlacklistCheckerWithData(data []byte) (*BlacklistChecker, error) {
	idx, err := buildBlacklistIndex(data)
	if err != nil {
		return nil, err
	}
	return &BlacklistChecker{index: idx}, nil
}

func (c *BlacklistChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-008",
		Title:       "Known Compromised Package Version",
		Description: "Matches tool dependencies against an embedded offline blacklist of confirmed supply-chain attacks and malicious package versions.",
	}
}

// Check examines each dependency declared in tool.Metadata["dependencies"]
// against the offline blacklist and emits a CRITICAL AS-008 finding on any hit.
func (c *BlacklistChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	deps, err := extractDependencies(tool)
	if err != nil || len(deps) == 0 {
		return nil, nil
	}

	var issues []model.Issue
	for _, dep := range deps {
		key := strings.ToLower(dep.Ecosystem) + ":" + strings.ToLower(dep.Name)
		entries, ok := c.index[key]
		if !ok {
			continue
		}
		for i := range entries {
			entry := &entries[i]
			for _, expr := range entry.AffectedVersions {
				if matchesVersion(dep.Version, expr) {
					issues = append(issues, buildBlacklistIssue(*entry, dep, tool.Name))
					break
				}
			}
		}
	}
	return issues, nil
}

// buildBlacklistIssue constructs an AS-008 finding from a blacklist entry.
// BLOCK entries get code SUPPLY_CHAIN_BLOCK; WARN entries get SUPPLY_CHAIN_WARN.
func buildBlacklistIssue(entry blacklistEntry, dep Dependency, toolName string) model.Issue {
	sev := blacklistSeverity(entry.Severity)

	code := "SUPPLY_CHAIN_WARN"
	if strings.EqualFold(entry.Action, "BLOCK") {
		code = "SUPPLY_CHAIN_BLOCK"
	}

	desc := fmt.Sprintf(
		"%s [%s]: %s@%s is a known-compromised version. %s See: %s",
		entry.ID, entry.Action, dep.Name, dep.Version, entry.Reason, entry.Link,
	)
	return model.Issue{
		RuleID:      "AS-008",
		ToolName:    toolName,
		Severity:    sev,
		Code:        code,
		Description: desc,
		Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
		Evidence: []model.Evidence{
			{Kind: "package", Value: dep.Name},
			{Kind: "version", Value: dep.Version},
			{Kind: "ecosystem", Value: dep.Ecosystem},
			{Kind: "blacklist_entry", Value: entry.ID},
			{Kind: "blacklist_action", Value: entry.Action},
		},
	}
}

func blacklistSeverity(s string) model.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityHigh // conservative default
	}
}
