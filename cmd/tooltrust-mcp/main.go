// Package main provides the ToolTrust Scanner MCP Server — the meta-scanner.
// It exposes the scanning capability as an MCP tool so that any AI agent can
// call it to self-inspect other tool definitions.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/kballard/go-shellquote"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	localmcp "github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/gateway"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// version is set at build time via -ldflags.
var version = "dev"

func main() {
	srv := server.NewMCPServer(
		"tooltrust-scanner",
		version,
	)

	srv.AddTool(buildScanJSONTool(), handleScanJSON)
	srv.AddTool(buildScanServerTool(), handleScanServer)
	srv.AddTool(buildLookupTool(), handleLookup)

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintf(os.Stderr, "tooltrust-scanner mcp server error: %v\n", err)
		os.Exit(1)
	}
}

// ── tooltrust_scanner_scan (Legacy / JSON input) ─────────────────────────────

func buildScanJSONTool() mcplib.Tool {
	return mcplib.NewTool(
		"tooltrust_scanner_scan",
		mcplib.WithDescription(
			"Scan a list of AI agent tool definitions for security risks. "+
				"Accepts an MCP tools/list JSON payload and returns a risk report "+
				"with gateway policies (ALLOW, REQUIRE_APPROVAL, or BLOCK) for each tool.",
		),
		mcplib.WithString(
			"tools_json",
			mcplib.Required(),
			mcplib.Description(`JSON string containing an MCP tools/list response, e.g. {"tools":[{"name":"...","description":"...","inputSchema":{...}}]}`),
		),
		mcplib.WithString(
			"protocol",
			mcplib.Description("Protocol format of the tool list. Currently supported: mcp (default)."),
		),
	)
}

func handleScanJSON(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	toolsJSON, ok := req.GetArguments()["tools_json"].(string)
	if !ok || toolsJSON == "" {
		return mcplib.NewToolResultError("tools_json argument is required and must be a non-empty string"), nil
	}

	protocol := "mcp"
	if p, ok := req.GetArguments()["protocol"].(string); ok && p != "" {
		protocol = p
	}

	var tools []model.UnifiedTool
	var parseErr error

	switch protocol {
	case "mcp":
		a := localmcp.NewAdapter()
		tools, parseErr = a.Parse(ctx, []byte(toolsJSON))
	default:
		return mcplib.NewToolResultError(fmt.Sprintf("unsupported protocol %q — supported: mcp", protocol)), nil
	}

	if parseErr != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to parse tool definitions: %v", parseErr)), nil
	}

	return processTools(ctx, tools)
}

// ── tooltrust_scan_server (Live Server Scan) ─────────────────────────────────

func buildScanServerTool() mcplib.Tool {
	return mcplib.NewTool(
		"tooltrust_scan_server",
		mcplib.WithDescription(
			"Connects to a live MCP server via standard input/output (stdio), parses its tools, "+
				"and scans them for prompt injection, data exfiltration, and privilege escalation risks. "+
				"Returns a risk report with gateway policies (ALLOW, REQUIRE_APPROVAL, or BLOCK) for each tool.",
		),
		mcplib.WithString(
			"command",
			mcplib.Required(),
			mcplib.Description(`The exact command used to start the MCP server via stdio. Example: "npx -y @modelcontextprotocol/server-memory"`),
		),
	)
}

func handleScanServer(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	command, ok := req.GetArguments()["command"].(string)
	if !ok || command == "" {
		return mcplib.NewToolResultError("command argument is required and must be a non-empty string"), nil
	}

	tools, err := scanLiveServer(ctx, command)
	if err != nil {
		// Return failure as text rather than crashing the calling agent,
		// so the agent can see the connection/parsing failed.
		return mcplib.NewToolResultText(fmt.Sprintf("Failed to scan live server: %v", err)), nil
	}

	if len(tools) == 0 {
		return mcplib.NewToolResultText("Server connected successfully, but no tools were exported by this server."), nil
	}

	return processTools(ctx, tools)
}

func scanLiveServer(ctx context.Context, serverCmd string) ([]model.UnifiedTool, error) {
	args, err := shellquote.Split(serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server command: %w", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}

	// Create a cancelable context to forcefully kill the sub-process on exit.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stdioTransport := transport.NewStdioWithOptions(args[0], nil, args[1:])
	if startErr := stdioTransport.Start(execCtx); startErr != nil {
		return nil, fmt.Errorf("failed to start transport: %w", startErr)
	}

	c := client.NewClient(stdioTransport)
	defer c.Close() //nolint:errcheck // closing client on exit

	initReq := mcplib.InitializeRequest{}
	initReq.Params.ProtocolVersion = "2024-11-05"
	initReq.Params.ClientInfo = mcplib.Implementation{
		Name:    "tooltrust-scanner-mcp",
		Version: "1.0.0",
	}

	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	listReq := mcplib.ListToolsRequest{}
	resp, err := c.ListTools(ctx, listReq)
	if err != nil {
		return nil, fmt.Errorf("tools/list map failed: %w", err)
	}

	// We serialize the response back to JSON so we can use our existing adapter,
	// which also runs the inference rules for permissions.
	type dummyResponse struct {
		Tools []mcplib.Tool `json:"tools"`
	}
	payload := dummyResponse{Tools: resp.Tools}
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tools: %w", err)
	}

	adapter := localmcp.NewAdapter()
	tools, err := adapter.Parse(ctx, data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse tools: %w", err)
	}
	return tools, nil
}

// ── tooltrust_lookup (Directory API Lookup) ─────────────────────────────────

func buildLookupTool() mcplib.Tool {
	return mcplib.NewTool(
		"tooltrust_lookup",
		mcplib.WithDescription(
			"Look up historical security risk grades for an MCP server from the public ToolTrust Directory. "+
				"Accepts the kebab-case name of the server and returns its full JSON scan report, or 404 if not found.",
		),
		mcplib.WithString(
			"server_name",
			mcplib.Required(),
			mcplib.Description(`The kebab-case identifier of the server (e.g., "mcp-server-filesystem", "n8n", "browser-tools-mcp").`),
		),
	)
}

func handleLookup(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	serverName, ok := req.GetArguments()["server_name"].(string)
	if !ok || serverName == "" {
		return mcplib.NewToolResultError("server_name argument is required"), nil
	}

	url := fmt.Sprintf("https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-directory/main/data/reports/%s.json", serverName)
	reqHTTP, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to create request: %v", err)), nil
	}

	resp, err := http.DefaultClient.Do(reqHTTP)
	if err != nil {
		return mcplib.NewToolResultText(fmt.Sprintf("Failed to query ToolTrust Directory: %v", err)), nil
	}
	defer resp.Body.Close() //nolint:errcheck // defer close on read-only request

	if resp.StatusCode == http.StatusNotFound {
		return mcplib.NewToolResultText(fmt.Sprintf("No historical scan report found for '%s' in the ToolTrust Directory (HTTP 404).", serverName)), nil
	}

	if resp.StatusCode != http.StatusOK {
		return mcplib.NewToolResultText(fmt.Sprintf("Unexpected status code %d from ToolTrust Directory.", resp.StatusCode)), nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to read response: %v", err)), nil
	}

	return mcplib.NewToolResultText(string(bodyBytes)), nil
}

// ── Common Scanner Processing Logic ─────────────────────────────────────────

// ScanResult is the JSON shape returned by the scan tools.
type ScanResult struct {
	Policies []model.GatewayPolicy `json:"policies"`
	Summary  ScanSummary           `json:"summary"`
}

// ScanSummary gives a high-level count of the enforcement decisions.
type ScanSummary struct {
	Total    int `json:"total"`
	Allowed  int `json:"allowed"`
	Approval int `json:"requireApproval"`
	Blocked  int `json:"blocked"`
}

func processTools(ctx context.Context, tools []model.UnifiedTool) (*mcplib.CallToolResult, error) {
	scanner, err := analyzer.NewScanner(false, "")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to initialize scanner: %v", err)), nil
	}
	var policies []model.GatewayPolicy
	summary := ScanSummary{Total: len(tools)}

	for i := range tools {
		score, scanErr := scanner.Scan(ctx, tools[i])
		if scanErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("scan failed for tool %q: %v", tools[i].Name, scanErr)), nil
		}
		policy, evalErr := gateway.Evaluate(tools[i].Name, score)
		if evalErr != nil {
			return mcplib.NewToolResultError(fmt.Sprintf("policy evaluation failed for tool %q: %v", tools[i].Name, evalErr)), nil
		}
		policies = append(policies, policy)

		switch policy.Action {
		case model.ActionAllow:
			summary.Allowed++
		case model.ActionRequireApproval:
			summary.Approval++
		case model.ActionBlock:
			summary.Blocked++
		}
	}

	result := ScanResult{Policies: policies, Summary: summary}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to serialize result: %v", err)), nil
	}

	return mcplib.NewToolResultText(string(encoded)), nil
}
