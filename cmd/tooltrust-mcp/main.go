// Package main provides the ToolTrust Scanner MCP Server — the meta-scanner.
// It exposes the scanning capability as an MCP tool so that any AI agent can
// call it to self-inspect other tool definitions.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kballard/go-shellquote"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/userhome"
	localmcp "github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/gateway"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// version is set at build time via -ldflags.
var version = "dev"

// scanTimeout is the maximum time allowed for a single server scan.
const scanTimeout = 60 * time.Second

const allowUnsafeLiveScanArg = "allow_unsafe_live_scan"

func main() {
	help := flag.Bool("help", false, "Show usage information")
	flag.BoolVar(help, "h", false, "Show usage information")
	ver := flag.Bool("version", false, "Show version information")
	flag.BoolVar(ver, "v", false, "Show version information")
	rules := flag.Bool("rules", false, "List all supported security rules (catalog)")
	flag.BoolVar(rules, "r", false, "List all supported security rules (catalog)")
	flag.Usage = func() {
		fmt.Printf("ToolTrust MCP Server (%s)\n\n", version)
		fmt.Printf("Starts ToolTrust Scanner as an MCP stdio server so your AI agent\n")
		fmt.Printf("can scan other MCP servers for prompt injection, data exfiltration,\n")
		fmt.Printf("privilege escalation, and supply-chain attacks.\n\n")
		fmt.Printf("Options:\n")
		fmt.Printf("  -h, --help     Show this help message\n")
		fmt.Printf("  -v, --version  Show version information\n")
		fmt.Printf("  -r, --rules    List all supported security rules (catalog)\n\n")
		fmt.Printf("Add to your .mcp.json:\n")
		fmt.Printf("  {\"command\": \"npx\", \"args\": [\"-y\", \"tooltrust-mcp\"]}\n\n")
		fmt.Printf("Then ask your agent: \"Run tooltrust_scan_config\"\n")
		fmt.Printf("Learn more: https://github.com/AgentSafe-AI/tooltrust-scanner\n")
	}
	flag.Parse()

	if *ver {
		fmt.Printf("%s\n", version)
		os.Exit(0)
	}
	if *help {
		flag.Usage()
		os.Exit(0)
	}
	if *rules {
		printRulesCatalog()
		os.Exit(0)
	}

	srv := server.NewMCPServer(
		"tooltrust-scanner",
		version,
	)

	srv.AddTool(buildScanJSONTool(), handleScanJSON)
	srv.AddTool(buildScanServerTool(), handleScanServer)
	srv.AddTool(buildLookupTool(), handleLookup)
	srv.AddTool(buildListRulesTool(), handleListRules)
	srv.AddTool(buildScanConfigTool(), handleScanConfig)

	if err := server.ServeStdio(srv); err != nil {
		fmt.Fprintf(os.Stderr, "tooltrust-scanner mcp server error: %v\n", err)
		os.Exit(1)
	}
}

// printRulesCatalog dynamically enumerates all registered checkers.
func printRulesCatalog() {
	scanner, err := analyzer.NewScanner(false, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize scanner: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Supported Security Rules (Catalog):\n")
	for _, r := range scanner.Rules() {
		fmt.Printf("  %-6s  %s (%s)\n", r.ID, r.Title, r.Description)
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
		mcplib.WithBoolean(
			allowUnsafeLiveScanArg,
			mcplib.Description("Set to true to acknowledge that this launches the target process on the host before ToolTrust can score it."),
		),
	)
}

func handleScanServer(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	command, ok := req.GetArguments()["command"].(string)
	if !ok || command == "" {
		return mcplib.NewToolResultError("command argument is required and must be a non-empty string"), nil
	}
	if !allowUnsafeLiveScan(req) {
		return mcplib.NewToolResultError(unsafeLiveScanOptInMessage("tooltrust_scan_server")), nil
	}

	args, err := shellquote.Split(command)
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to parse server command: %v", err)), nil
	}

	tools, err := scanLiveServer(ctx, args, nil)
	if err != nil {
		return mcplib.NewToolResultText(fmt.Sprintf("Failed to scan live server: %v", err)), nil
	}

	if len(tools) == 0 {
		return mcplib.NewToolResultText("Server connected successfully, but no tools were exported by this server."), nil
	}

	return processTools(ctx, tools)
}

func allowUnsafeLiveScan(req mcplib.CallToolRequest) bool {
	value, ok := req.GetArguments()[allowUnsafeLiveScanArg].(bool)
	return ok && value
}

func unsafeLiveScanOptInMessage(toolName string) string {
	return fmt.Sprintf("%s refuses to launch MCP servers without %s=true because the target process runs on the host before ToolTrust can score it", toolName, allowUnsafeLiveScanArg)
}

// scanLiveServer spawns an MCP server, connects via stdio, lists its tools,
// and returns parsed UnifiedTools. The extraEnv parameter allows injecting
// additional environment variables into the child process.
func scanLiveServer(ctx context.Context, args, extraEnv []string) ([]model.UnifiedTool, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}

	// Enforce a 60s timeout to prevent hung servers from blocking indefinitely.
	// 60s accommodates npx cold cache (~15-20s for package install).
	execCtx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	var envSlice []string
	if len(extraEnv) > 0 {
		envSlice = append(os.Environ(), extraEnv...)
	}

	stdioTransport := transport.NewStdioWithOptions(args[0], envSlice, args[1:])
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

	_, err := c.Initialize(execCtx, initReq)
	if err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	listReq := mcplib.ListToolsRequest{}
	resp, err := c.ListTools(execCtx, listReq)
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
	tools, err := adapter.Parse(execCtx, data)
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

// ── tooltrust_list_rules (Rule Catalog) ──────────────────────────────────────

func buildListRulesTool() mcplib.Tool {
	return mcplib.NewTool(
		"tooltrust_list_rules",
		mcplib.WithDescription(
			"Returns the full catalog of security rules used by the ToolTrust scanner, "+
				"including rule IDs, titles, and descriptions. Useful for understanding what the scanner checks for.",
		),
	)
}

func handleListRules(_ context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	scanner, err := analyzer.NewScanner(false, "")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to initialize scanner: %v", err)), nil
	}
	rules := scanner.Rules()
	encoded, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to serialize rules: %v", err)), nil
	}
	return mcplib.NewToolResultText(string(encoded)), nil
}

// ── tooltrust_scan_config (Scan All Configured Servers) ─────────────────────

// mcpConfig represents the structure of .mcp.json or ~/.claude.json.
type mcpConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// serverScanResult holds the result of scanning one server.
type serverScanResult struct {
	Server  string      `json:"server"`
	Status  string      `json:"status"` // "ok", "error", "skipped"
	Error   string      `json:"error,omitempty"`
	Result  *ScanResult `json:"result,omitempty"`
	Skipped string      `json:"skipped,omitempty"`
}

// configScanResult is the full response from tooltrust_scan_config.
type configScanResult struct {
	ConfigFile string             `json:"config_file"`
	Servers    []serverScanResult `json:"servers"`
	Summary    configScanSummary  `json:"summary"`
}

type configScanSummary struct {
	Total   int `json:"total"`
	Scanned int `json:"scanned"`
	Errors  int `json:"errors"`
	Skipped int `json:"skipped"`
}

func buildScanConfigTool() mcplib.Tool {
	return mcplib.NewTool(
		"tooltrust_scan_config",
		mcplib.WithDescription(
			"Reads the user's Claude Code MCP configuration and scans all configured servers in parallel. "+
				"Searches for .mcp.json in the current directory, then ~/.claude.json as fallback. "+
				"Returns a summary report with scan results for each server. Servers that fail to start "+
				"are reported with an error note; scanning continues for remaining servers.",
		),
		mcplib.WithBoolean(
			allowUnsafeLiveScanArg,
			mcplib.Description("Set to true to acknowledge that configured MCP servers are launched on the host before ToolTrust can score them."),
		),
	)
}

func handleScanConfig(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	configPath, cfg, err := loadMCPConfig()
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}

	if len(cfg.MCPServers) == 0 {
		return mcplib.NewToolResultText(fmt.Sprintf("No MCP servers configured in %s.", configPath)), nil
	}
	if !allowUnsafeLiveScan(req) {
		return mcplib.NewToolResultError(unsafeLiveScanOptInMessage("tooltrust_scan_config")), nil
	}

	// Scan all servers in parallel.
	type indexedResult struct {
		index  int
		result serverScanResult
	}

	serverNames := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		serverNames = append(serverNames, name)
	}

	results := make([]serverScanResult, len(serverNames))
	var wg sync.WaitGroup
	ch := make(chan indexedResult, len(serverNames))

	for i, name := range serverNames {
		entry := cfg.MCPServers[name]
		wg.Add(1)
		go func(idx int, serverName string, e mcpServerEntry) {
			defer wg.Done()
			ch <- indexedResult{
				index:  idx,
				result: scanOneServer(ctx, serverName, e),
			}
		}(i, name, entry)
	}

	// Close channel when all goroutines complete.
	go func() {
		wg.Wait()
		close(ch)
	}()

	for ir := range ch {
		results[ir.index] = ir.result
	}

	summary := configScanSummary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case "ok":
			summary.Scanned++
		case "error":
			summary.Errors++
		case "skipped":
			summary.Skipped++
		}
	}

	out := configScanResult{
		ConfigFile: configPath,
		Servers:    results,
		Summary:    summary,
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return mcplib.NewToolResultError(fmt.Sprintf("failed to serialize result: %v", err)), nil
	}
	return mcplib.NewToolResultText(string(encoded)), nil
}

// scanOneServer scans a single MCP server from config.
func scanOneServer(ctx context.Context, name string, entry mcpServerEntry) serverScanResult {
	// Skip self-scan.
	if isSelfEntry(name, entry) {
		return serverScanResult{
			Server:  name,
			Status:  "skipped",
			Skipped: "tooltrust-mcp (self)",
		}
	}

	args := append([]string{entry.Command}, entry.Args...)

	// Build extra env from config entry.
	var extraEnv []string
	for k, v := range entry.Env {
		extraEnv = append(extraEnv, k+"="+v)
	}

	tools, err := scanLiveServer(ctx, args, extraEnv)
	if err != nil {
		return serverScanResult{
			Server: name,
			Status: "error",
			Error:  err.Error(),
		}
	}

	if len(tools) == 0 {
		return serverScanResult{
			Server: name,
			Status: "ok",
			Result: &ScanResult{Summary: ScanSummary{Total: 0}},
		}
	}

	scanResult, err := processToolsRaw(ctx, tools)
	if err != nil {
		return serverScanResult{
			Server: name,
			Status: "error",
			Error:  err.Error(),
		}
	}

	return serverScanResult{
		Server: name,
		Status: "ok",
		Result: scanResult,
	}
}

// isSelfEntry returns true if the config entry refers to tooltrust-mcp itself.
func isSelfEntry(name string, entry mcpServerEntry) bool {
	if strings.Contains(strings.ToLower(name), "tooltrust") {
		return true
	}
	cmdStr := entry.Command + " " + strings.Join(entry.Args, " ")
	return strings.Contains(cmdStr, "tooltrust-mcp")
}

// loadMCPConfig searches for the MCP config file and parses it.
func loadMCPConfig() (string, mcpConfig, error) {
	// 1. Check .mcp.json in current directory.
	if data, err := os.ReadFile(".mcp.json"); err == nil {
		var cfg mcpConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			return ".mcp.json", mcpConfig{}, fmt.Errorf("failed to parse .mcp.json: %w", err)
		}
		return ".mcp.json", cfg, nil
	}

	// 2. Check ~/.claude.json.
	home, err := userhome.Resolve()
	if err == nil {
		claudePath := filepath.Join(home, ".claude.json")
		if data, err := os.ReadFile(claudePath); err == nil { // #nosec G304 -- path is ~/.claude.json, not user-controlled
			var cfg mcpConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				return claudePath, mcpConfig{}, fmt.Errorf("failed to parse %s: %w", claudePath, err)
			}
			return claudePath, cfg, nil
		}
	}

	return "", mcpConfig{}, fmt.Errorf(
		"no MCP config found; searched " +
			".mcp.json (current directory) and ~/.claude.json (global Claude Code config)",
	)
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
	result, err := processToolsRaw(ctx, tools)
	if err != nil {
		return mcplib.NewToolResultError(err.Error()), nil
	}
	report := renderTextReport(result)

	return &mcplib.CallToolResult{
		Content: []mcplib.Content{
			mcplib.TextContent{
				Annotated: mcplib.Annotated{},
				Type:      "text",
				Text:      report,
			},
		},
	}, nil
}

// severityWeight mirrors the CLI scanner weights for display.
var severityWeight = map[model.Severity]int{
	model.SeverityCritical: 25,
	model.SeverityHigh:     15,
	model.SeverityMedium:   8,
	model.SeverityLow:      2,
	model.SeverityInfo:     0,
}

// gradeEmoji returns the emoji prefix for a tool's final grade.
func gradeEmoji(g model.Grade) string {
	switch g {
	case model.GradeA:
		return "✅"
	case model.GradeB:
		return "🟢"
	case model.GradeC:
		return "🟡"
	case model.GradeD:
		return "🟠"
	case model.GradeF:
		return "🔴"
	default:
		return "•"
	}
}

// renderTextReport builds a single plain-text report for MCP clients.
// This avoids duplicate summary + JSON blocks in clients that collapse text.
func renderTextReport(result *ScanResult) string {
	var lines []string

	severityCounts := map[model.Severity]int{}
	for i := range result.Policies {
		p := result.Policies[i]
		for _, issue := range p.Score.Issues {
			severityCounts[issue.Severity]++
		}
	}
	sevOrder := []model.Severity{model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo}
	var sevParts []string
	for _, s := range sevOrder {
		if n := severityCounts[s]; n > 0 {
			sevParts = append(sevParts, fmt.Sprintf("%s×%d", s, n))
		}
	}
	counts := map[model.Grade]int{}
	for i := range result.Policies {
		p := result.Policies[i]
		counts[p.Score.Grade]++
	}
	grades := []model.Grade{model.GradeA, model.GradeB, model.GradeC, model.GradeD, model.GradeF}
	var gradeParts []string
	for _, g := range grades {
		if n := counts[g]; n > 0 {
			gradeParts = append(gradeParts, fmt.Sprintf("%s×%d", g, n))
		}
	}

	totalFindings := 0
	for _, n := range severityCounts {
		totalFindings += n
	}

	lines = append(lines,
		fmt.Sprintf("Scan Summary: %d tools scanned | %d allowed | %d need approval | %d blocked",
			result.Summary.Total, result.Summary.Allowed, result.Summary.Approval, result.Summary.Blocked),
		fmt.Sprintf("Tool Grades: %s", joinOrNone(gradeParts)),
		fmt.Sprintf("Findings by Severity: %s (%d total)", joinOrNone(sevParts), totalFindings),
	)

	flaggedCount := 0
	for i := range result.Policies {
		p := result.Policies[i]
		if p.Action == model.ActionAllow {
			continue
		}
		if flaggedCount == 0 {
			lines = append(lines, "", "Flagged Tools:")
		}
		flaggedCount++

		var actionLabel string
		switch p.Action {
		case model.ActionAllow:
			actionLabel = "allowed"
		case model.ActionRequireApproval:
			actionLabel = "needs approval"
		case model.ActionBlock:
			actionLabel = "blocked"
		}
		lines = append(lines, fmt.Sprintf("• %s  %s GRADE %s  %s",
			p.ToolName, gradeEmoji(p.Score.Grade), p.Score.Grade, actionLabel))
		if len(p.Behavior) > 0 {
			lines = append(lines, fmt.Sprintf("  Behavior: %s", strings.Join(p.Behavior, ", ")))
		}
		if len(p.Destinations) > 0 {
			lines = append(lines, fmt.Sprintf("  Destination: %s", strings.Join(p.Destinations, "; ")))
		}
		for _, issue := range p.Score.Issues {
			lines = append(lines, fmt.Sprintf("  [%s] %s: %s",
				issue.RuleID, issue.Severity, humanizeIssue(issue)))
			for _, detail := range renderIssueEvidence(issue) {
				lines = append(lines, "    "+detail)
			}
		}
		if actionNow, saferConfig := recommendationForPolicy(p); actionNow != "" || saferConfig != "" {
			if actionNow != "" {
				lines = append(lines, fmt.Sprintf("  Action now: %s", actionNow))
			}
			if saferConfig != "" {
				lines = append(lines, fmt.Sprintf("  Safer configuration: %s", saferConfig))
			}
		}
	}

	if flaggedCount == 0 {
		lines = append(lines, "", "All tools are ✅ GRADE A and allowed.")
	} else if result.Summary.Allowed > 0 {
		lines = append(lines, "", fmt.Sprintf("%d allowed tools are omitted for brevity.", result.Summary.Allowed))
	}

	return strings.Join(lines, "\n")
}

func joinOrNone(parts []string) string {
	if len(parts) == 0 {
		return "None"
	}
	return strings.Join(parts, "  ")
}

func humanizeIssue(issue model.Issue) string {
	switch {
	case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "network permission"):
		return "Network access declared"
	case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "fs permission"):
		return "Filesystem access declared"
	case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "db permission"):
		return "Database access declared"
	case issue.RuleID == "AS-011" && strings.Contains(issue.Description, "no rate-limit"):
		return "Missing rate-limit or timeout"
	default:
		return issue.Description
	}
}

func renderIssueEvidence(issue model.Issue) []string {
	if len(issue.Evidence) == 0 {
		return nil
	}

	maxEvidence := 1
	details := make([]string, 0, maxEvidence+1)
	for i, evidence := range issue.Evidence {
		if i >= maxEvidence {
			remaining := len(issue.Evidence) - maxEvidence
			details = append(details, fmt.Sprintf("Evidence: … %d more item(s)", remaining))
			break
		}
		details = append(details, fmt.Sprintf("Evidence: %s=%s", evidence.Kind, evidence.Value))
	}
	return details
}

func recommendationForPolicy(policy model.GatewayPolicy) (actionNow, saferConfig string) {
	hasNetwork := false
	hasFS := false
	hasDB := false
	hasRateLimitGap := false

	for _, issue := range policy.Score.Issues {
		switch {
		case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "network permission"):
			hasNetwork = true
		case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "fs permission"):
			hasFS = true
		case issue.RuleID == "AS-002" && strings.Contains(issue.Description, "db permission"):
			hasDB = true
		case issue.RuleID == "AS-011":
			hasRateLimitGap = true
		}
	}

	switch policy.Action {
	case model.ActionBlock:
		actionNow = "Do not allow this tool by default."
	case model.ActionRequireApproval:
		actionNow = "Keep this tool on manual approval until the risky capabilities are reviewed."
	case model.ActionAllow:
		if len(policy.Score.Issues) > 0 {
			actionNow = "Allowable as-is, but review the declared capabilities before broad deployment."
		}
	}

	var safer []string
	if hasNetwork {
		safer = append(safer, "confirm the tool truly needs network access; remove it if local-only operation is enough")
	}
	if hasFS {
		safer = append(safer, "limit filesystem access to the intended directories only")
	}
	if hasDB {
		safer = append(safer, "limit database access to the intended operations and credentials")
	}
	if hasRateLimitGap {
		safer = append(safer, "add explicit rate-limit, timeout, or retry settings")
	}
	if len(safer) > 0 {
		saferConfig = strings.Join(safer, "; ") + "."
	}

	return actionNow, saferConfig
}

// processToolsRaw runs the scanner and returns raw results (used by both
// processTools and scanOneServer to avoid double-serialization).
func processToolsRaw(ctx context.Context, tools []model.UnifiedTool) (*ScanResult, error) {
	scanner, err := analyzer.NewScanner(false, "")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scanner: %v", err)
	}
	var policies []model.GatewayPolicy
	summary := ScanSummary{Total: len(tools)}

	for i := range tools {
		score, scanErr := scanner.Scan(ctx, tools[i])
		if scanErr != nil {
			return nil, fmt.Errorf("scan failed for tool %q: %v", tools[i].Name, scanErr)
		}
		policy, evalErr := gateway.Evaluate(tools[i].Name, score)
		if evalErr != nil {
			return nil, fmt.Errorf("policy evaluation failed for tool %q: %v", tools[i].Name, evalErr)
		}
		policy.Behavior, policy.Destinations = analyzer.SummarizeToolContext(tools[i])
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

	return &ScanResult{Policies: policies, Summary: summary}, nil
}
