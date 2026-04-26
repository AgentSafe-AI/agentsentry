package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSince       = 24 * time.Hour
	defaultMinSeverity = "HIGH"
	defaultEcosystems  = "npm,PyPI,Go"
	defaultOut         = "candidates.json"
	defaultExisting    = "pkg/analyzer/data/blacklist.json"
	defaultFeedBaseURL = "https://osv-vulnerabilities.storage.googleapis.com"
)

type config struct {
	Since       time.Duration
	MinSeverity string
	Ecosystems  []string
	OutPath     string
	Existing    string
	FeedBaseURL string
	Now         time.Time
}

type blacklistEntry struct {
	ID               string   `json:"id"`
	Component        string   `json:"component"`
	Ecosystem        string   `json:"ecosystem"`
	AffectedVersions []string `json:"affected_versions"`
	Action           string   `json:"action"`
	Severity         string   `json:"severity"`
	Reason           string   `json:"reason"`
	Link             string   `json:"link"`
}

type osvVulnerability struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	Details          string `json:"details"`
	Published        string `json:"published"`
	Modified         string `json:"modified"`
	Aliases          []string
	Severity         []osvSeverity `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []osvAffected `json:"affected"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Versions []string `json:"versions"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}
	entries, warnings, err := fetchCandidates(context.Background(), cfg)
	if err != nil {
		return err
	}
	for _, warning := range warnings {
		if _, writeErr := fmt.Fprintf(stderr, "warning: %s\n", warning); writeErr != nil {
			return fmt.Errorf("write warning output: %w", writeErr)
		}
	}
	out, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal candidates: %w", err)
	}
	out = append(out, '\n')
	if err := os.WriteFile(cfg.OutPath, out, 0o644); err != nil {
		return fmt.Errorf("write candidates file: %w", err)
	}
	if _, writeErr := fmt.Fprintf(stdout, "Wrote %d IOC blacklist candidate(s) to %s\n", len(entries), cfg.OutPath); writeErr != nil {
		return fmt.Errorf("write completion output: %w", writeErr)
	}
	return nil
}

func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("ioc-candidates", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var cfg config
	var ecosystems string
	var minSeverity string
	var outPath string
	var existing string
	var feedBaseURL string
	var since time.Duration

	fs.DurationVar(&since, "since", defaultSince, "only include advisories published within this duration")
	fs.StringVar(&minSeverity, "min-severity", defaultMinSeverity, "minimum severity: CRITICAL | HIGH | MEDIUM | LOW")
	fs.StringVar(&ecosystems, "ecosystems", defaultEcosystems, "comma-separated OSV ecosystems")
	fs.StringVar(&outPath, "out", defaultOut, "output JSON path")
	fs.StringVar(&existing, "existing", defaultExisting, "existing blacklist JSON to de-duplicate against")
	fs.StringVar(&feedBaseURL, "feed-base-url", defaultFeedBaseURL, "base URL for OSV ecosystem zip feeds")

	if err := fs.Parse(args); err != nil {
		return cfg, fmt.Errorf("parse flags: %w", err)
	}

	cfg = config{
		Since:       since,
		MinSeverity: strings.ToUpper(strings.TrimSpace(minSeverity)),
		Ecosystems:  splitCSV(ecosystems),
		OutPath:     outPath,
		Existing:    existing,
		FeedBaseURL: strings.TrimRight(feedBaseURL, "/"),
		Now:         time.Now().UTC(),
	}

	if severityRank(cfg.MinSeverity) == 0 {
		return cfg, fmt.Errorf("invalid -min-severity %q", cfg.MinSeverity)
	}
	if len(cfg.Ecosystems) == 0 {
		return cfg, errors.New("at least one ecosystem is required")
	}
	return cfg, nil
}

func fetchCandidates(ctx context.Context, cfg config) ([]blacklistEntry, []string, error) {
	existing, err := readExistingBlacklist(cfg.Existing)
	if err != nil {
		return nil, nil, err
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return fetchCandidatesWithClient(ctx, cfg, client, existing)
}

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

func fetchCandidatesWithClient(ctx context.Context, cfg config, client httpDoer, existing map[string]struct{}) ([]blacklistEntry, []string, error) {
	var (
		allCandidates []blacklistEntry
		warnings      []string
	)

	for _, ecosystem := range cfg.Ecosystems {
		vulns, warning, err := fetchEcosystemFeed(ctx, client, cfg.FeedBaseURL, ecosystem)
		if warning != "" {
			warnings = append(warnings, warning)
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("skip %s feed: %v", ecosystem, err))
			continue
		}
		allCandidates = append(allCandidates, buildCandidates(vulns, ecosystem, existing, cfg.Now, cfg.Since, cfg.MinSeverity)...)
	}

	sort.Slice(allCandidates, func(i, j int) bool {
		if strings.EqualFold(allCandidates[i].Ecosystem, allCandidates[j].Ecosystem) {
			return strings.ToLower(allCandidates[i].Component) < strings.ToLower(allCandidates[j].Component)
		}
		return strings.ToLower(allCandidates[i].Ecosystem) < strings.ToLower(allCandidates[j].Ecosystem)
	})
	return dedupeCandidates(allCandidates), warnings, nil
}

func fetchEcosystemFeed(ctx context.Context, client httpDoer, baseURL, ecosystem string) ([]osvVulnerability, string, error) {
	feedURL := fmt.Sprintf("%s/%s/all.zip", strings.TrimRight(baseURL, "/"), url.PathEscape(ecosystem))
	var lastErr error
	backoff := time.Second
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, http.NoBody)
		if err != nil {
			return nil, "", fmt.Errorf("build request for %s: %w", ecosystem, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
		} else {
			body, readErr := io.ReadAll(resp.Body)
			closeErr := resp.Body.Close()
			switch {
			case readErr != nil:
				lastErr = readErr
			case closeErr != nil:
				lastErr = closeErr
			case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			case resp.StatusCode != http.StatusOK:
				return nil, "", fmt.Errorf("unexpected status %d from %s", resp.StatusCode, feedURL)
			default:
				vulns, err := parseFeedZip(body)
				if err != nil {
					return nil, "", fmt.Errorf("parse %s feed: %w", ecosystem, err)
				}
				return vulns, "", nil
			}
		}

		select {
		case <-ctx.Done():
			return nil, "", fmt.Errorf("fetch %s feed: %w", ecosystem, ctx.Err())
		case <-time.After(backoff):
			backoff *= 2
		}
	}
	return nil, fmt.Sprintf("OSV feed unavailable for %s after retries (%v)", ecosystem, lastErr), nil
}

func parseFeedZip(data []byte) ([]osvVulnerability, error) {
	readerAt := bytes.NewReader(data)
	zr, err := zip.NewReader(readerAt, int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("open zip: %w", err)
	}
	var vulns []osvVulnerability
	for _, file := range zr.File {
		if file.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(file.Name), ".json") {
			continue
		}
		rc, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", file.Name, err)
		}
		payload, readErr := io.ReadAll(rc)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", file.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", file.Name, closeErr)
		}
		var vuln osvVulnerability
		if err := json.Unmarshal(payload, &vuln); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file.Name, err)
		}
		if strings.TrimSpace(vuln.ID) == "" {
			continue
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func buildCandidates(vulns []osvVulnerability, ecosystem string, existing map[string]struct{}, now time.Time, since time.Duration, minSeverity string) []blacklistEntry {
	var out []blacklistEntry
	seen := map[string]struct{}{}
	for i := range vulns {
		vuln := &vulns[i]
		published, ok := parseTime(vuln.Published)
		if !ok || published.Before(now.Add(-since)) {
			continue
		}

		severity, ok := classifySeverity(*vuln)
		if !ok || severityRank(severity) < severityRank(minSeverity) {
			continue
		}

		for _, affected := range vuln.Affected {
			if !strings.EqualFold(strings.TrimSpace(affected.Package.Ecosystem), ecosystem) {
				continue
			}
			component := strings.TrimSpace(affected.Package.Name)
			if component == "" {
				continue
			}
			versions := uniqueSorted(affected.Versions)
			if len(versions) == 0 {
				continue
			}

			var filtered []string
			for _, version := range versions {
				key := strings.ToLower(ecosystem) + ":" + strings.ToLower(component) + "@" + version
				if _, exists := existing[key]; exists {
					continue
				}
				filtered = append(filtered, version)
			}
			if len(filtered) == 0 {
				continue
			}

			entry := blacklistEntry{
				ID:               preferredID(*vuln),
				Component:        component,
				Ecosystem:        ecosystem,
				AffectedVersions: filtered,
				Action:           "BLOCK",
				Severity:         severity,
				Reason:           truncateReason(firstNonEmpty(strings.TrimSpace(vuln.Summary), strings.TrimSpace(vuln.Details)), 200),
				Link:             fmt.Sprintf("https://osv.dev/vulnerability/%s", vuln.ID),
			}
			seenKey := candidateKey(entry)
			if _, exists := seen[seenKey]; exists {
				continue
			}
			seen[seenKey] = struct{}{}
			out = append(out, entry)
		}
	}
	return out
}

func readExistingBlacklist(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read existing blacklist: %w", err)
	}
	var entries []blacklistEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parse existing blacklist: %w", err)
	}
	seen := make(map[string]struct{}, len(entries))
	for i := range entries {
		entry := entries[i]
		for _, version := range entry.AffectedVersions {
			key := strings.ToLower(entry.Ecosystem) + ":" + strings.ToLower(entry.Component) + "@" + version
			seen[key] = struct{}{}
		}
	}
	return seen, nil
}

func parseTime(value string) (time.Time, bool) {
	if strings.TrimSpace(value) == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

func classifySeverity(vuln osvVulnerability) (string, bool) {
	maxScore := -1.0
	for _, sev := range vuln.Severity {
		score, ok := parseSeverityScore(sev.Score)
		if ok && score > maxScore {
			maxScore = score
		}
	}
	if maxScore >= 0 {
		switch {
		case maxScore >= 9.0:
			return "CRITICAL", true
		case maxScore >= 7.0:
			return "HIGH", true
		case maxScore >= 4.0:
			return "MEDIUM", true
		default:
			return "LOW", true
		}
	}

	severity := strings.ToUpper(strings.TrimSpace(vuln.DatabaseSpecific.Severity))
	if severityRank(severity) > 0 {
		return severity, true
	}
	return "", false
}

func parseSeverityScore(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	score, err := strconv.ParseFloat(raw, 64)
	if err == nil {
		return score, true
	}
	return 0, false
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func preferredID(vuln osvVulnerability) string {
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "GHSA-") {
			return alias
		}
	}
	for _, alias := range vuln.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	if len(vuln.Aliases) > 0 {
		return vuln.Aliases[0]
	}
	return vuln.ID
}

func truncateReason(reason string, maxLen int) string {
	reason = strings.TrimSpace(strings.Join(strings.Fields(reason), " "))
	if len(reason) <= maxLen {
		return reason
	}
	if maxLen <= 1 {
		return reason[:maxLen]
	}
	return reason[:maxLen-1] + "…"
}

func splitCSV(input string) []string {
	var out []string
	for _, part := range strings.Split(input, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func candidateKey(entry blacklistEntry) string {
	return strings.ToLower(entry.Ecosystem) + "|" + strings.ToLower(entry.Component) + "|" + strings.Join(entry.AffectedVersions, ",")
}

func dedupeCandidates(entries []blacklistEntry) []blacklistEntry {
	seen := map[string]struct{}{}
	var out []blacklistEntry
	for i := range entries {
		entry := entries[i]
		key := candidateKey(entry)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entry)
	}
	return out
}
