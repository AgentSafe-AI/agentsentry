package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

const (
	npmRegistryVersionURL = "https://registry.npmjs.org"
)

var npmQueryTimeout = 8 * time.Second

var suspiciousNPMScriptKeys = []string{
	"preinstall",
	"install",
	"postinstall",
	"prepare",
}

var highRiskNPMScriptPatterns = []string{
	"curl ",
	"wget ",
	"powershell",
	"invoke-webrequest",
	"bash -c",
	"sh -c",
	"node -e",
	"python -c",
	"certutil",
}

type npmVersionResponse struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]string `json:"scripts"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	BundleDependencies   []string          `json:"bundleDependencies"`
	BundledDependencies  []string          `json:"bundledDependencies"`
}

func (r *npmVersionResponse) UnmarshalJSON(data []byte) error {
	var wire struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Scripts              map[string]string `json:"scripts"`
		Dependencies         map[string]string `json:"dependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		BundleDependencies   json.RawMessage   `json:"bundleDependencies"`
		BundledDependencies  json.RawMessage   `json:"bundledDependencies"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}

	bundleDeps, err := decodeNPMStringList(wire.BundleDependencies, "bundleDependencies")
	if err != nil {
		return err
	}
	bundledDeps, err := decodeNPMStringList(wire.BundledDependencies, "bundledDependencies")
	if err != nil {
		return err
	}

	*r = npmVersionResponse{
		Name:                 wire.Name,
		Version:              wire.Version,
		Scripts:              wire.Scripts,
		Dependencies:         wire.Dependencies,
		OptionalDependencies: wire.OptionalDependencies,
		BundleDependencies:   bundleDeps,
		BundledDependencies:  bundledDeps,
	}
	return nil
}

func decodeNPMStringList(raw json.RawMessage, field string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	switch trimmed[0] {
	case '[':
		var out []string
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("npm: decode %s: %w", field, err)
		}
		return out, nil
	case '"':
		var one string
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, fmt.Errorf("npm: decode %s: %w", field, err)
		}
		if strings.TrimSpace(one) == "" {
			return nil, nil
		}
		return []string{one}, nil
	case 't', 'f':
		var enabled bool
		if err := json.Unmarshal(raw, &enabled); err != nil {
			return nil, fmt.Errorf("npm: decode %s: %w", field, err)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("npm: decode %s: unsupported JSON value %s", field, trimmed)
	}
}

type npmRegistryClient interface {
	FetchVersion(ctx context.Context, pkg, version string) (npmVersionResponse, error)
}

type httpNPMRegistryClient struct {
	http    *http.Client
	baseURL string
}

func newHTTPNPMRegistryClient() *httpNPMRegistryClient {
	return &httpNPMRegistryClient{
		http:    &http.Client{Timeout: npmQueryTimeout},
		baseURL: npmRegistryVersionURL,
	}
}

func (c *httpNPMRegistryClient) FetchVersion(ctx context.Context, pkg, version string) (npmVersionResponse, error) {
	escapedPkg := url.PathEscape(pkg)
	escapedVersion := url.PathEscape(version)
	endpoint := fmt.Sprintf("%s/%s/%s", c.baseURL, escapedPkg, escapedVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return npmVersionResponse{}, fmt.Errorf("npm: build request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return npmVersionResponse{}, fmt.Errorf("npm: request: %w", err)
	}
	defer func() {
		//nolint:errcheck // best-effort close on a short-lived registry lookup
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return npmVersionResponse{}, fmt.Errorf("npm: unexpected status %d", resp.StatusCode)
	}

	var out npmVersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return npmVersionResponse{}, fmt.Errorf("npm: decode response: %w", err)
	}
	return out, nil
}

type mockNPMRegistryClient struct {
	packages map[string]npmVersionResponse
	err      error
}

func (m *mockNPMRegistryClient) FetchVersion(_ context.Context, pkg, version string) (npmVersionResponse, error) {
	if m.err != nil {
		return npmVersionResponse{}, m.err
	}
	key := strings.ToLower(pkg) + "@" + strings.ToLower(version)
	resp, ok := m.packages[key]
	if !ok {
		return npmVersionResponse{}, nil
	}
	return resp, nil
}

// NPMLifecycleScriptChecker flags npm package versions whose registry metadata
// declares install-time lifecycle scripts. These scripts frequently appear in
// supply-chain compromises because they execute automatically on install.
type NPMLifecycleScriptChecker struct {
	client npmRegistryClient
}

func NewNPMLifecycleScriptChecker() *NPMLifecycleScriptChecker {
	return &NPMLifecycleScriptChecker{client: newHTTPNPMRegistryClient()}
}

func NewNPMLifecycleScriptCheckerWithMock(packages map[string]npmVersionResponse, queryErr error) *NPMLifecycleScriptChecker {
	return &NPMLifecycleScriptChecker{
		client: &mockNPMRegistryClient{packages: packages, err: queryErr},
	}
}

func (c *NPMLifecycleScriptChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-015",
		Title:       "Suspicious NPM Lifecycle Script",
		Description: "Flags npm dependency versions that publish install-time lifecycle scripts. Severity increases when the script contains remote-fetch or inline-execution patterns.",
	}
}

func (c *NPMLifecycleScriptChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
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
		if len(meta.Scripts) == 0 {
			continue
		}
		for _, scriptKey := range suspiciousNPMScriptKeys {
			scriptCmd, ok := meta.Scripts[scriptKey]
			if !ok || strings.TrimSpace(scriptCmd) == "" {
				continue
			}
			sev, rationale := classifyNPMScript(scriptCmd)
			issues = append(issues, model.Issue{
				RuleID:      "AS-015",
				ToolName:    tool.Name,
				Severity:    sev,
				Code:        "NPM_LIFECYCLE_SCRIPT",
				Description: fmt.Sprintf("npm package %s@%s publishes a %s lifecycle script (%s). Review whether this install-time execution is expected%s.", dep.Name, dep.Version, scriptKey, compactScript(scriptCmd), rationale),
				Location:    fmt.Sprintf("dependency:%s@%s", dep.Name, dep.Version),
				Evidence: []model.Evidence{
					{Kind: "package", Value: dep.Name},
					{Kind: "version", Value: dep.Version},
					{Kind: "ecosystem", Value: dep.Ecosystem},
					{Kind: "dependency_source", Value: dep.Source},
					{Kind: "lifecycle_script", Value: scriptKey},
					{Kind: "script_severity", Value: string(sev)},
				},
			})
			break
		}
	}

	return issues, nil
}

func compactScript(script string) string {
	script = strings.Join(strings.Fields(script), " ")
	if len(script) > 80 {
		return script[:77] + "..."
	}
	return script
}

func classifyNPMScript(script string) (severity model.Severity, rationale string) {
	normalized := " " + strings.ToLower(strings.Join(strings.Fields(script), " ")) + " "
	for _, pattern := range highRiskNPMScriptPatterns {
		if strings.Contains(normalized, strings.ToLower(pattern)) {
			return model.SeverityHigh, fmt.Sprintf("; detected higher-risk command pattern %q", strings.TrimSpace(pattern))
		}
	}
	return model.SeverityMedium, ""
}
