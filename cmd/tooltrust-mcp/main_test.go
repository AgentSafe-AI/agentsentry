package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ── tooltrust_scanner_scan tests ────────────────────────────────────────────

func TestHandleScanJSON_ValidInput(t *testing.T) {
	toolsJSON := `{"tools":[{"name":"read_file","description":"Reads a file from disk","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}]}`
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": toolsJSON}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.IsError)

	require.Len(t, result.Content, 1)

	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "Tool Grades:")
	assert.Contains(t, text, "Findings by Severity:")
	assert.Contains(t, text, "MEDIUM×1")
	assert.Contains(t, text, "2 total")
	assert.NotContains(t, text, "Flagged Tools:")
	assert.Contains(t, text, "All tools are ✅ GRADE A and allowed.")
	assert.Contains(t, text, "1 tools")
}

func TestHandleScanJSON_EmptyToolsJSON(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": ""}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_InvalidJSON(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": "not valid json"}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanJSON_UnsupportedProtocol(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"tools_json": `{"tools":[]}`,
		"protocol":   "openapi",
	}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "unsupported protocol")
}

func TestHandleScanJSON_EmptyToolsList(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"tools_json": `{"tools":[]}`}

	result, err := handleScanJSON(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	require.Len(t, result.Content, 1)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Scan Summary:")
	assert.Contains(t, text, "0 tools")
	assert.Contains(t, text, "Tool Grades: None")
	assert.Contains(t, text, "Findings by Severity: None (0 total)")
	assert.Contains(t, text, "All tools are ✅ GRADE A")
}

func TestRenderTextReport_IncludesEvidenceForFlaggedTools(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:    1,
			Allowed:  0,
			Approval: 1,
			Blocked:  0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName: "send_env",
				Action:   model.ActionRequireApproval,
				Score: model.RiskScore{
					Grade: model.GradeC,
					Issues: []model.Issue{
						{
							RuleID:      "AS-002",
							Severity:    model.SeverityHigh,
							Description: "tool declares network permission",
							Evidence: []model.Evidence{
								{Kind: "permission", Value: "network"},
								{Kind: "schema_property_count", Value: "12"},
							},
						},
					},
				},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "Flagged Tools:")
	assert.Contains(t, text, "Evidence: permission=network")
	assert.Contains(t, text, "Evidence: … 1 more item(s)")
	assert.NotContains(t, text, "schema_property_count=12")
}

func TestRenderTextReport_IncludesBehaviorAndDestinationContext(t *testing.T) {
	result := &ScanResult{
		Summary: ScanSummary{
			Total:    1,
			Allowed:  0,
			Approval: 1,
			Blocked:  0,
		},
		Policies: []model.GatewayPolicy{
			{
				ToolName:     "send_email",
				Action:       model.ActionRequireApproval,
				Behavior:     []string{"reads_env", "uses_network"},
				Destinations: []string{"dynamic email recipient (bcc)", "hardcoded domain: api.postmarkapp.com"},
				Score:        model.RiskScore{Grade: model.GradeC},
			},
		},
	}

	text := renderTextReport(result)
	assert.Contains(t, text, "Behavior: reads_env, uses_network")
	assert.Contains(t, text, "Destination: dynamic email recipient (bcc); hardcoded domain: api.postmarkapp.com")
}

func TestProcessToolsRaw_PopulatesBehaviorAndDestinationContext(t *testing.T) {
	tools := []model.UnifiedTool{
		{
			Name:        "fetch_url",
			Description: "Fetch a remote resource over HTTPS.",
			Permissions: []model.Permission{model.PermissionNetwork},
			InputSchema: jsonschema.Schema{
				Properties: map[string]jsonschema.Property{
					"url": {Type: "string"},
				},
			},
		},
	}

	result, err := processToolsRaw(context.Background(), tools)
	require.NoError(t, err)
	require.Len(t, result.Policies, 1)
	assert.Equal(t, []string{"uses_network"}, result.Policies[0].Behavior)
	assert.Equal(t, []string{"dynamic URL input (url)"}, result.Policies[0].Destinations)
}

// ── tooltrust_scan_server tests ─────────────────────────────────────────────

func TestHandleScanServer_EmptyCommand(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": ""}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanServer_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleScanServer_InvalidCommand(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"command": "/nonexistent/command/that/does/not/exist"}

	result, err := handleScanServer(context.Background(), req)
	require.NoError(t, err)
	// Should return error text (not crash), because the command can't be found.
	assert.False(t, result.IsError) // returned as text, not error
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "Failed to scan live server")
}

// ── tooltrust_lookup tests ──────────────────────────────────────────────────

func TestHandleLookup_MissingArgument(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

func TestHandleLookup_EmptyName(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{"server_name": ""}

	result, err := handleLookup(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

// ── tooltrust_list_rules tests ──────────────────────────────────────────────

func TestHandleListRules_ReturnsAllRules(t *testing.T) {
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleListRules(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)

	var rules []map[string]string
	text := result.Content[0].(mcplib.TextContent).Text
	require.NoError(t, json.Unmarshal([]byte(text), &rules))
	assert.Len(t, rules, 16, "should return all 16 built-in rules")

	// Verify expected rule IDs.
	ids := make(map[string]bool)
	for _, r := range rules {
		ids[r["id"]] = true
		assert.NotEmpty(t, r["title"], "rule %s should have a title", r["id"])
		assert.NotEmpty(t, r["description"], "rule %s should have a description", r["id"])
	}
	expectedIDs := []string{"AS-001", "AS-002", "AS-003", "AS-004", "AS-005", "AS-006", "AS-007", "AS-008", "AS-009", "AS-010", "AS-011", "AS-013", "AS-014", "AS-015", "AS-016", "AS-017"}
	for _, id := range expectedIDs {
		assert.True(t, ids[id], "missing rule %s", id)
	}
}

// ── tooltrust_scan_config tests ─────────────────────────────────────────────

func TestLoadMCPConfig_DotMCPJSON(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{"test-server":{"command":"echo","args":["hello"]}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	path, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Equal(t, ".mcp.json", path)
	assert.Len(t, cfg.MCPServers, 1)
	assert.Equal(t, "echo", cfg.MCPServers["test-server"].Command)
}

func TestLoadMCPConfig_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte("not json"), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, _, err := loadMCPConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse .mcp.json")
}

func TestLoadMCPConfig_NoConfigFound(t *testing.T) {
	dir := t.TempDir()

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	// Override HOME to prevent finding real ~/.claude.json.
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	defer os.Setenv("HOME", origHome)

	_, _, err := loadMCPConfig()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no MCP config found")
}

func TestLoadMCPConfig_WithEnvVars(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{"api-server":{"command":"node","args":["server.js"],"env":{"API_KEY":"test123","PORT":"3000"}}}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Equal(t, "test123", cfg.MCPServers["api-server"].Env["API_KEY"])
	assert.Equal(t, "3000", cfg.MCPServers["api-server"].Env["PORT"])
}

func TestLoadMCPConfig_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	_, cfg, err := loadMCPConfig()
	require.NoError(t, err)
	assert.Empty(t, cfg.MCPServers)
}

func TestHandleScanConfig_EmptyServers(t *testing.T) {
	dir := t.TempDir()
	configData := `{"mcpServers":{}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".mcp.json"), []byte(configData), 0o644))

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanConfig(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)
	text := result.Content[0].(mcplib.TextContent).Text
	assert.Contains(t, text, "No MCP servers configured")
}

func TestHandleScanConfig_NoConfigFile(t *testing.T) {
	dir := t.TempDir()

	origDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	defer os.Chdir(origDir) //nolint:errcheck // best-effort restore in test cleanup

	origHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	defer os.Setenv("HOME", origHome)

	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{}

	result, err := handleScanConfig(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
}

// ── Self-scan skip tests ────────────────────────────────────────────────────

func TestIsSelfEntry_ByName(t *testing.T) {
	assert.True(t, isSelfEntry("tooltrust", mcpServerEntry{Command: "node", Args: []string{"server.js"}}))
	assert.True(t, isSelfEntry("ToolTrust-Scanner", mcpServerEntry{Command: "node"}))
}

func TestIsSelfEntry_ByCommand(t *testing.T) {
	assert.True(t, isSelfEntry("my-scanner", mcpServerEntry{Command: "npx", Args: []string{"-y", "tooltrust-mcp"}}))
	assert.True(t, isSelfEntry("scanner", mcpServerEntry{Command: "tooltrust-mcp"}))
}

func TestIsSelfEntry_NotSelf(t *testing.T) {
	assert.False(t, isSelfEntry("filesystem", mcpServerEntry{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem"}}))
	assert.False(t, isSelfEntry("memory", mcpServerEntry{Command: "node", Args: []string{"server.js"}}))
}

// ── scanLiveServer tests ────────────────────────────────────────────────────

func TestScanLiveServer_EmptyArgs(t *testing.T) {
	_, err := scanLiveServer(context.Background(), []string{}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty server command")
}

func TestScanLiveServer_NonexistentCommand(t *testing.T) {
	_, err := scanLiveServer(context.Background(), []string{"/nonexistent/binary"}, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start transport")
}

func TestScanLiveServer_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := scanLiveServer(ctx, []string{"echo"}, nil)
	require.Error(t, err)
}

func TestScanLiveServer_WithExtraEnv(t *testing.T) {
	// This tests that extra env doesn't cause a panic.
	// The command will fail (echo is not an MCP server), but we're testing
	// that env merging works without crashing.
	_, err := scanLiveServer(context.Background(), []string{"/nonexistent/binary"}, []string{"TEST_KEY=test_value"})
	require.Error(t, err)
}

// ── processToolsRaw tests ───────────────────────────────────────────────────

func TestProcessToolsRaw_EmptySlice(t *testing.T) {
	result, err := processToolsRaw(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Summary.Total)
}

func TestProcessToolsRaw_SingleCleanTool(t *testing.T) {
	tools := []model.UnifiedTool{
		{
			Name:        "read_file",
			Description: "Reads a file from disk and returns its contents.",
			InputSchema: jsonschema.Schema{
				Type: "object",
				Properties: map[string]jsonschema.Property{
					"path": {Type: "string"},
				},
			},
		},
	}
	result, err := processToolsRaw(context.Background(), tools)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Summary.Total)
}
