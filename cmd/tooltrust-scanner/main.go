package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/deepscan"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/gateway"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/storage"
)

var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "tooltrust-scanner",
		Short: "Scan MCP servers for security risks before your AI agent trusts them",
		Long: "ToolTrust Scanner checks MCP tool definitions for prompt injection, " +
			"data exfiltration, privilege escalation, and supply-chain attacks. " +
			"Each tool gets a trust grade (A–F) and a gateway policy (ALLOW / REQUIRE_APPROVAL / BLOCK).\n\n" +
			"Quick start:\n" +
			"  tooltrust-scanner scan --server \"npx -y @modelcontextprotocol/server-filesystem /tmp\"\n\n" +
			"Learn more: https://github.com/AgentSafe-AI/tooltrust-scanner",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newGateCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the ToolTrust Scanner version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("tooltrust-scanner", version)
		},
	}
}

// ScanReport is the JSON output conforming to ToolTrust Directory schema v1.0.
type ScanReport struct {
	SchemaVersion string                `json:"schema_version"`
	Policies      []model.GatewayPolicy `json:"policies"`
	Summary       ScanSummary           `json:"summary"`
}

// ScanSummary provides aggregate scan counts.
type ScanSummary struct {
	Total           int       `json:"total"`
	Allowed         int       `json:"allowed"`
	RequireApproval int       `json:"require_approval"`
	Blocked         int       `json:"blocked"`
	AvgScore        int       `json:"avg_score"`
	AvgGrade        string    `json:"avg_grade"`
	ScannedAt       time.Time `json:"scanned_at"`
}

// severityWeight for risk score calculation (matches analyzer).
var severityWeight = map[model.Severity]int{
	model.SeverityCritical: 25,
	model.SeverityHigh:     15,
	model.SeverityMedium:   8,
	model.SeverityLow:      2,
	model.SeverityInfo:     0,
}

func newScanCmd() *cobra.Command {
	var (
		inputFile  string
		serverCmd  string
		protocol   string
		output     string
		outputFile string
		failOn     string
		dbPath     string
		verbose    bool
		deepScan   bool
		rulesDir   string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan an MCP server or tool definition file for security risks",
		Example: `  tooltrust-scanner scan --input tools.json
  tooltrust-scanner scan --input tools.json --output json
  tooltrust-scanner scan --input tools.json --output json --file report.json
  tooltrust-scanner scan --input tools.json --fail-on block
  tooltrust-scanner scan --input tools.json --db scans.db`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), scanOpts{
				inputFile:  inputFile,
				serverCmd:  serverCmd,
				protocol:   protocol,
				output:     output,
				outputFile: outputFile,
				failOn:     failOn,
				dbPath:     dbPath,
				verbose:    verbose,
				deepScan:   deepScan,
				rulesDir:   rulesDir,
			})
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "path to tool definition file")
	cmd.Flags().StringVarP(&serverCmd, "server", "s", "", "live MCP server to scan (e.g. 'npx @modelcontextprotocol/server-filesystem /tmp')")
	cmd.Flags().StringVarP(&protocol, "protocol", "p", "mcp", "protocol format: mcp | openai | skills")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text (default) | json")
	cmd.Flags().StringVar(&outputFile, "file", "", "write output to file instead of stdout")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any tool reaches this action: allow | approval | block")
	cmd.Flags().StringVar(&dbPath, "db", "", "persist scan results to SQLite database at this path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print per-tool scan process tree to stderr during scan")
	cmd.Flags().BoolVar(&deepScan, "deep-scan", false, "Enable AI-based semantic analysis for deep prompt injection detection (downloads a ~22MB quantized ONNX model on first run)")
	cmd.Flags().StringVar(&rulesDir, "rules-dir", "", "path to directory containing custom YAML rules")
	// Mutual exclusivity checked in runScan

	return cmd
}

type scanOpts struct {
	inputFile  string
	serverCmd  string
	protocol   string
	output     string
	outputFile string
	failOn     string
	dbPath     string
	verbose    bool
	deepScan   bool
	rulesDir   string
}

func runScan(ctx context.Context, opts scanOpts) error {
	// Validate --output flag early.
	switch opts.output {
	case "text", "json", "sarif":
	default:
		return fmt.Errorf("invalid --output value %q (use: text | json | sarif)", opts.output)
	}

	if opts.output == "json" || opts.output == "sarif" {
		pterm.DisableOutput()
	}

	if (opts.inputFile == "") == (opts.serverCmd == "") {
		return fmt.Errorf("exactly one of --input or --server must be provided")
	}

	if opts.deepScan {
		if err := deepscan.Init(ctx); err != nil {
			pterm.Warning.Printf("Deep scan initialization failed: %v\n", err)
			pterm.Info.Println("Falling back to standard regex-based scanning.")
			opts.deepScan = false
		}
	}

	var tools []model.UnifiedTool
	var err error

	if opts.serverCmd != "" {
		if opts.protocol != "mcp" {
			return fmt.Errorf("--server only supports the 'mcp' protocol")
		}

		liveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		tools, err = scanLiveServer(liveCtx, opts.serverCmd)
		if err != nil {
			return fmt.Errorf("live server scan failed (or timed out): %w", err)
		}
	} else {
		defData, readErr := os.ReadFile(opts.inputFile)
		if readErr != nil {
			return fmt.Errorf("failed to read input file: %w", readErr)
		}

		switch opts.protocol {
		case "mcp":
			a := mcp.NewAdapter()
			tools, err = a.Parse(ctx, defData)
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}
		default:
			return fmt.Errorf("unsupported protocol %q (supported: mcp)", opts.protocol)
		}
	}

	scanner, err := analyzer.NewScanner(opts.deepScan, opts.rulesDir)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}
	var policies []model.GatewayPolicy
	summary := ScanSummary{Total: len(tools), ScannedAt: time.Now().UTC()}

	for i := range tools {
		score, scanErr := scanner.Scan(ctx, tools[i])
		if scanErr != nil {
			return fmt.Errorf("scan failed for tool %q: %w", tools[i].Name, scanErr)
		}
		policy, evalErr := gateway.Evaluate(tools[i].Name, score)
		if evalErr != nil {
			return fmt.Errorf("gateway evaluation failed for tool %q: %w", tools[i].Name, evalErr)
		}
		policy.Behavior, policy.Destinations = analyzer.SummarizeToolContext(tools[i])
		policy.DependencyVisibility, policy.DependencyNote = dependencyVisibilityForTool(tools[i])
		policies = append(policies, policy)

		if opts.verbose {
			printScanPtree(os.Stderr, tools[i], score, policy)
		}

		switch policy.Action {
		case model.ActionAllow:
			summary.Allowed++
		case model.ActionRequireApproval:
			summary.RequireApproval++
		case model.ActionBlock:
			summary.Blocked++
		}
	}

	score, grade := avgRiskScore(policies)
	summary.AvgScore = score
	summary.AvgGrade = string(grade)

	report := ScanReport{
		SchemaVersion: "1.0",
		Policies:      policies,
		Summary:       summary,
	}

	if opts.dbPath != "" {
		if persistErr := persistResults(ctx, opts.dbPath, tools, policies); persistErr != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to persist results: %v\n", persistErr)
		}
	}

	if err := writeOutput(opts, report); err != nil {
		return err
	}

	return checkFailOn(opts.failOn, summary)
}

// writeOutput dispatches to the correct renderer based on opts.output.
func writeOutput(opts scanOpts, report ScanReport) error {
	if opts.output == "json" {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to encode report: %w", err)
		}
		if opts.outputFile != "" {
			if writeErr := os.WriteFile(opts.outputFile, encoded, 0o644); writeErr != nil {
				return fmt.Errorf("failed to write output file: %w", writeErr)
			}
			fmt.Fprintf(os.Stderr, "report written to %s\n", opts.outputFile)
		} else {
			fmt.Println(string(encoded))
		}
		return nil
	}

	if opts.output == "sarif" {
		return writeSarifOutput(opts, report)
	}

	// Default: text mode — render with pterm.
	if err := printPtermUI(report); err != nil {
		return err
	}
	printStarPrompt()
	return nil
}

// printPtermUI renders the scan report as a pterm tree + summary box.
func printPtermUI(report ScanReport) error {
	// ── Emergency alert for AS-008 BLOCK findings ─────────────────────────────
	printSupplyChainAlert(report.Policies)

	// ── Build the tree ────────────────────────────────────────────────────────
	var rootChildren []pterm.TreeNode

	for i := range report.Policies {
		policy := report.Policies[i]
		// Tool header label, coloured by action.
		toolLabel := formatToolLabel(policy)

		// Children: one per finding, or a green ✅ Pass.
		var children []pterm.TreeNode
		if len(policy.Score.Issues) == 0 {
			if line, note := dependencyVisibilityLines(policy); line != "" {
				children = append(children, pterm.TreeNode{
					Text: pterm.FgGray.Sprint(line),
				})
				if note != "" {
					children = append(children, pterm.TreeNode{
						Text: pterm.FgGray.Sprint(note),
					})
				}
			}
			children = append(children, pterm.TreeNode{
				Text: pterm.FgGreen.Sprint("✅ Pass"),
			})
		} else {
			if reason := summarizeToolReason(policy); reason != "" {
				children = append(children, pterm.TreeNode{
					Text: pterm.FgGray.Sprint(toolReasonLabel(policy) + reason),
				})
			}
			for _, line := range toolContextLines(policy) {
				children = append(children, pterm.TreeNode{
					Text: pterm.FgGray.Sprint(line),
				})
			}
			if line, note := dependencyVisibilityLines(policy); line != "" {
				children = append(children, pterm.TreeNode{
					Text: pterm.FgGray.Sprint(line),
				})
				if note != "" {
					children = append(children, pterm.TreeNode{
						Text: pterm.FgGray.Sprint(note),
					})
				}
			}
			shownHints := map[string]bool{}
			for _, issue := range policy.Score.Issues {
				label := formatIssueLabel(issue, policy, !shownHints[issue.RuleID])
				if label == "" {
					continue
				}
				children = append(children, pterm.TreeNode{
					Text: label,
				})
				shownHints[issue.RuleID] = true
			}
		}

		rootChildren = append(rootChildren, pterm.TreeNode{
			Text:     toolLabel,
			Children: children,
		})
	}

	pterm.Println() // blank line before tree
	if err := pterm.DefaultTree.WithRoot(pterm.TreeNode{
		Text:     pterm.Bold.Sprint("Scan Results"),
		Children: rootChildren,
	}).Render(); err != nil {
		return fmt.Errorf("render tree: %w", err)
	}

	// ── Summary box ───────────────────────────────────────────────────────────
	s := report.Summary
	riskLine := buildRiskLine(report.Policies)
	avgScore, avgGrade := avgRiskScore(report.Policies)
	summaryContent := fmt.Sprintf(
		"Total Scanned    : %d\n"+
			"  ✅ Allowed       : %d\n"+
			"  ⚠️  Req Approval : %d\n"+
			"  🚫 Blocked       : %d\n"+
			"Avg Risk Score   : %d (grade %s)\n"+
			"Grade Breakdown  : %s\n"+
			"Scanned At       : %s",
		s.Total,
		s.Allowed,
		s.RequireApproval,
		s.Blocked,
		avgScore, avgGrade,
		riskLine,
		s.ScannedAt.Format("2006-01-02 15:04:05 UTC"),
	)
	pterm.DefaultBox.
		WithTitle(pterm.Bold.Sprint("Scan Summary")).
		WithTitleTopCenter().
		Println(summaryContent)

	// ── Per-grade action guide ─────────────────────────────────────────────
	printGradeGuide(worstGrade(report.Policies))

	return nil
}

func printStarPrompt() {
	pterm.Println()
	pterm.Info.Println("If ToolTrust helped, star us: github.com/AgentSafe-AI/tooltrust-scanner")
}

func dependencyVisibilityLines(policy model.GatewayPolicy) (line, note string) {
	if policy.DependencyVisibility == "" {
		return "", ""
	}
	if policy.Action == model.ActionAllow && policy.Score.Grade == model.GradeA && policy.DependencyVisibility == "No dependency data" {
		return "", ""
	}
	return "Dependency visibility: " + policy.DependencyVisibility, policy.DependencyNote
}

func toolContextLines(policy model.GatewayPolicy) []string {
	if policy.Action == model.ActionAllow && policy.Score.Grade == model.GradeA {
		return nil
	}

	var lines []string
	if len(policy.Behavior) > 0 {
		lines = append(lines, "Behavior: "+strings.Join(policy.Behavior, ", "))
	}
	if len(policy.Destinations) > 0 {
		lines = append(lines, "Destination: "+strings.Join(policy.Destinations, "; "))
	}
	return lines
}

// printSupplyChainAlert scans all findings for AS-008 BLOCK issues and prints a
// high-visibility ANSI red emergency banner when confirmed malware is detected.
// This runs BEFORE the main scan tree to ensure it is never scrolled past.
func printSupplyChainAlert(policies []model.GatewayPolicy) {
	type alert struct {
		pkg  string
		desc string
	}
	var alerts []alert

	for i := range policies {
		policy := policies[i]
		for _, issue := range policy.Score.Issues {
			if issue.RuleID == "AS-008" && issue.Code == "SUPPLY_CHAIN_BLOCK" {
				alerts = append(alerts, alert{pkg: issue.Location, desc: issue.Description})
			}
		}
	}
	if len(alerts) == 0 {
		return
	}

	redBold := pterm.NewStyle(pterm.FgRed, pterm.Bold)
	red := pterm.NewStyle(pterm.FgRed)

	pterm.Println()
	redBold.Println("╔══════════════════════════════════════════════════════════════╗")
	redBold.Println("║  🚨  SUPPLY CHAIN ATTACK DETECTED — IMMEDIATE ACTION NEEDED  ║")
	redBold.Println("╚══════════════════════════════════════════════════════════════╝")
	pterm.Println()

	for _, a := range alerts {
		redBold.Printf("  ✗  %s\n", a.pkg)
		red.Printf("     %s\n", a.desc)
		pterm.Println()
	}

	redBold.Println("  WHAT TO DO NOW:")
	red.Println("  1. Remove the package from your environment immediately.")
	red.Println("  2. Rotate ALL credentials (SSH keys, AWS/GCP tokens, API keys, .env).")
	red.Println("  3. Check for persistence: ~/.config/sysmon/ and systemd user services.")
	red.Println("  4. Audit recent agent actions — your environment may be compromised.")
	pterm.Println()
}

// worstGrade returns the highest-risk grade across all policies.
func worstGrade(policies []model.GatewayPolicy) model.Grade {
	order := map[model.Grade]int{
		model.GradeA: 0,
		model.GradeB: 1,
		model.GradeC: 2,
		model.GradeD: 3,
		model.GradeF: 4,
	}
	worst := model.GradeA
	for i := range policies {
		p := policies[i]
		if order[p.Score.Grade] > order[worst] {
			worst = p.Score.Grade
		}
	}
	return worst
}

// printGradeGuide prints a concise, actionable next-step box keyed to the worst grade.
func printGradeGuide(grade model.Grade) {
	type guide struct {
		title string
		icon  string
		steps []string
		color pterm.Color
	}

	guides := map[model.Grade]guide{
		model.GradeA: {
			title: "All tools passed",
			icon:  "✅",
			steps: []string{
				"No action required — all tools are within safe thresholds.",
				"Re-run after updates: tooltrust-scanner scan --server \"...\"",
			},
			color: pterm.FgGreen,
		},
		model.GradeB: {
			title: "Low-risk findings detected",
			icon:  "ℹ️ ",
			steps: []string{
				"1. Review the flagged tools above — Grade B is allowed but monitored.",
				"2. Check whether the declared permissions match actual usage.",
				"3. Re-scan after each upstream release to catch regressions.",
				"4. Consider reporting findings to the tool author (see GitHub Issues).",
			},
			color: pterm.FgCyan,
		},
		model.GradeC: {
			title: "Some tools need human approval",
			icon:  "⚠️ ",
			steps: []string{
				"1. Review every APPROVAL tool listed above.",
				"2. In your MCP config set  approval_required: true  for those tools.",
				"3. Ask: do you actually need these tools? Remove unused ones.",
				"4. Report findings to the tool author:",
				"   https://github.com/AgentSafe-AI/tooltrust-directory/issues/new?template=SCAN_REQUEST.md",
			},
			color: pterm.FgYellow,
		},
		model.GradeD: {
			title: "High-risk tools — action required",
			icon:  "🔴",
			steps: []string{
				"1. Do NOT run APPROVAL or BLOCK tools unattended.",
				"2. Remove any BLOCK tools from your MCP config immediately.",
				"3. For APPROVAL tools: run in a sandboxed environment only.",
				"4. File a security report with the tool author.",
				"5. Consider switching to a safer alternative from the ToolTrust Directory:",
				"   https://github.com/AgentSafe-AI/tooltrust-directory",
			},
			color: pterm.FgLightRed,
		},
		model.GradeF: {
			title: "Critical risk — remove these tools",
			icon:  "🚨",
			steps: []string{
				"1. Remove ALL BLOCK tools from your agent config NOW.",
				"2. Do not use these tools even with approval_required.",
				"3. Audit your agent's recent actions — it may have already been compromised.",
				"4. Report to the tool author and the ToolTrust Directory:",
				"   https://github.com/AgentSafe-AI/tooltrust-directory/issues/new?template=SCAN_REQUEST.md",
				"5. Find safer alternatives: https://github.com/AgentSafe-AI/tooltrust-directory",
			},
			color: pterm.FgRed,
		},
	}

	g, ok := guides[grade]
	if !ok || grade == model.GradeA {
		if ok {
			pterm.Println()
			pterm.FgGreen.Printfln("%s  %s", g.icon, g.steps[0])
		}
		return
	}

	content := ""
	for _, step := range g.steps {
		content += step + "\n"
	}
	content = strings.TrimRight(content, "\n")

	pterm.Println()
	pterm.DefaultBox.
		WithTitle(pterm.NewStyle(g.color, pterm.Bold).Sprintf("%s  What to do with Grade %s", g.icon, grade)).
		WithTitleTopLeft().
		Println(pterm.NewStyle(g.color).Sprint(content))
}

func summarizeToolReason(policy model.GatewayPolicy) string {
	if policy.Action == model.ActionAllow {
		return ""
	}

	parts := make([]string, 0, 3)
	seen := map[string]bool{}
	for _, issue := range policy.Score.Issues {
		part := summarizeIssueReason(issue)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		parts = append(parts, part)
		if len(parts) == 3 {
			break
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " + ")
}

func toolReasonLabel(policy model.GatewayPolicy) string {
	switch policy.Action {
	case model.ActionRequireApproval:
		return "Why approval: "
	case model.ActionBlock:
		return "Why blocked: "
	default:
		return "Why flagged: "
	}
}

func summarizeIssueReason(issue model.Issue) string {
	switch issue.RuleID {
	case "AS-002":
		for _, evidence := range issue.Evidence {
			if evidence.Kind == "permission" {
				return evidence.Value + " permission"
			}
		}
	case "AS-011":
		return "missing rate-limit/timeout"
	case "AS-001":
		return "prompt-injection wording"
	case "AS-006":
		return "code execution signal"
	case "AS-008":
		return "known compromised package"
	case "AS-014":
		return ""
	}

	desc := strings.TrimSpace(issue.Description)
	if desc == "" {
		return ""
	}
	return desc
}

func dependencyVisibilityForTool(tool model.UnifiedTool) (visibility, note string) {
	if tool.Metadata == nil {
		return "No dependency data", "No metadata.dependencies or repo_url were exposed by this MCP server."
	}

	sources := dependencySourcesFromMetadata(tool.Metadata)
	if len(sources) == 0 {
		note = metadataString(tool.Metadata, "dependency_visibility_note")
		if note == "" {
			note = "No metadata.dependencies or repo_url were exposed by this MCP server."
		}
		return "No dependency data", note
	}
	return formatDependencyVisibility(sources), visibilityNote(tool.Metadata, sources)
}

func dependencySourcesFromMetadata(meta map[string]any) []string {
	seen := map[string]bool{}
	var sources []string

	if raw, ok := meta["dependencies"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			var deps []struct {
				Source string `json:"source"`
			}
			if err := json.Unmarshal(b, &deps); err == nil {
				for _, dep := range deps {
					source := dep.Source
					if source == "" {
						source = "metadata"
					}
					if !seen[source] {
						seen[source] = true
						sources = append(sources, source)
					}
				}
			}
		}
	}

	if repoURL, ok := meta["repo_url"].(string); ok && strings.TrimSpace(repoURL) != "" {
		if !seen["repo_url"] {
			sources = append(sources, "repo_url")
		}
	}

	return sources
}

func visibilityNote(meta map[string]any, sources []string) string {
	if note := metadataString(meta, "dependency_visibility_note"); note != "" {
		return note
	}
	if len(sources) == 1 && sources[0] == "repo_url" {
		return "repo_url is available, so ToolTrust can try to inspect remote lockfiles for dependency evidence."
	}
	return ""
}

func formatDependencyVisibility(sources []string) string {
	labels := make([]string, 0, len(sources))
	for _, source := range sources {
		switch source {
		case "metadata":
			labels = append(labels, "Declared by MCP metadata")
		case "local_lockfile":
			labels = append(labels, "Verified from local lockfile")
		case "lockfile":
			labels = append(labels, "Verified from remote lockfile")
		case "repo_url":
			labels = append(labels, "Repo URL available")
		default:
			labels = append(labels, source)
		}
	}
	return strings.Join(labels, " + ")
}

// formatToolLabel returns a coloured "Tool: <name>  [ACTION]" label.
func formatToolLabel(policy model.GatewayPolicy) string {
	name := fmt.Sprintf("Tool: %s", policy.ToolName)
	var badge string
	switch policy.Action {
	case model.ActionAllow:
		badge = pterm.FgGreen.Sprint("[ALLOW]")
	case model.ActionRequireApproval:
		badge = pterm.FgYellow.Sprint("[APPROVAL]")
	case model.ActionBlock:
		badge = pterm.FgRed.Sprint("[BLOCK]")
	}
	if policy.Action == model.ActionAllow && policy.Score.Grade == model.GradeA {
		return fmt.Sprintf("%s  %s", pterm.Bold.Sprint(name), badge)
	}
	gradeStr := fmt.Sprintf("grade=%s", policy.Score.Grade)
	return fmt.Sprintf("%s  %s  %s", pterm.Bold.Sprint(name), badge, pterm.FgGray.Sprint(gradeStr))
}

// ruleHint returns a short, specific fix hint for each rule ID.
var ruleHint = map[string]string{
	"AS-001": "→ Remove adversarial instructions from the tool description before registering it.",
	"AS-002": "→ Tool requests broad permissions (exec/fs/network). Validate input parameters using Enums where possible, and restrict file system operations to explicit allowed directories.",
	"AS-003": "→ Rename the tool or fix its permission declarations so name and capabilities match.",
	"AS-004": "→ Upgrade or replace the vulnerable dependency. Enable Dependabot on the repo.",
	"AS-005": "→ Narrow OAuth scopes. Remove admin/:write wildcards and sudo-style escalation.",
	"AS-006": "→ This tool can execute arbitrary code. If not strictly needed, remove it. If required, you MUST set approval_required: true in your MCP client config to ensure human-in-the-loop confirmation.",
	"AS-007": "→ Ask the tool author to add a description and input schema to this tool.",
	"AS-008": "→ REMOVE THIS PACKAGE IMMEDIATELY. This version is confirmed malware/compromised. Rotate all credentials on affected machines.",
	"AS-009": "→ Rename the tool to a unique name. Typosquatting suggests impersonation of a well-known MCP tool.",
	"AS-010": "→ Never pass raw credentials as tool inputs. Use a secret manager instead.",
	"AS-011": "→ Add explicit timeout and rate-limit config to the tool before use in production.",
	"AS-013": "→ Use a unique namespace prefix per server (e.g. github__search_repos) to prevent tool name collisions.",
	"AS-015": "→ Review the install-time script before use. Prefer a version without lifecycle scripts, or install with --ignore-scripts in CI/sandboxed environments.",
	"AS-016": "→ Treat this package version as a likely compromise. Remove it, rotate exposed credentials, and inspect the dependency tree for the IOC package before reinstalling.",
	"AS-017": "→ Review whether the tool description is instructing external data forwarding. If intentional, require approval and narrow the destination scope.",
}

// formatIssueLabel returns a coloured finding line with optional evidence and fix hint.
func formatIssueLabel(issue model.Issue, policy model.GatewayPolicy, showHint bool) string {
	if issue.RuleID == "AS-014" && policy.Action == model.ActionAllow && policy.Score.Grade == model.GradeA {
		return ""
	}

	main := fmt.Sprintf("• [%s] %s: %s", issue.RuleID, issue.Severity, issue.Description)
	hint := ""
	if showHint {
		hint = ruleHint[issue.RuleID]
	}
	mainLine := pterm.Sprint(main)
	hintLine := pterm.FgGray.Sprint(hint)

	evidenceLines := []string(nil)
	if shouldShowIssueEvidence(issue, policy) {
		evidenceLines = issueEvidenceLines(issue)
	}
	if shouldSuppressIssueDetail(issue, policy) {
		evidenceLines = nil
		hint = ""
	}

	if hint == "" {
		return joinIssueDetailLines(mainLine, evidenceLines)
	}
	return joinIssueDetailLines(mainLine, evidenceLines, []string{hintLine})
}

func issueEvidenceLines(issue model.Issue) []string {
	if len(issue.Evidence) == 0 {
		return nil
	}

	maxEvidence := 1
	lines := make([]string, 0, maxEvidence+1)
	for i, evidence := range issue.Evidence {
		if i >= maxEvidence {
			remaining := len(issue.Evidence) - maxEvidence
			lines = append(lines, pterm.FgGray.Sprint(fmt.Sprintf("… %d more evidence item(s)", remaining)))
			break
		}
		lines = append(lines, pterm.FgGray.Sprint(fmt.Sprintf("Evidence: %s=%s", evidence.Kind, evidence.Value)))
	}
	return lines
}

func shouldSuppressIssueDetail(issue model.Issue, policy model.GatewayPolicy) bool {
	if policy.Action == model.ActionAllow && policy.Score.Grade == model.GradeA {
		return true
	}
	return false
}

func shouldShowIssueEvidence(issue model.Issue, policy model.GatewayPolicy) bool {
	if policy.Action != model.ActionAllow || policy.Score.Grade != model.GradeA {
		return !isRedundantPermissionEvidence(issue)
	}
	return false
}

func isRedundantPermissionEvidence(issue model.Issue) bool {
	if issue.RuleID != "AS-002" || len(issue.Evidence) != 1 {
		return false
	}
	evidence := issue.Evidence[0]
	if evidence.Kind != "permission" {
		return false
	}
	switch evidence.Value {
	case "fs", "network", "db", "exec":
		return strings.Contains(issue.Description, evidence.Value+" permission")
	default:
		return false
	}
}

func joinIssueDetailLines(main string, groups ...[]string) string {
	lines := []string{main}
	for _, group := range groups {
		for _, line := range group {
			lines = append(lines, "       "+line)
		}
	}
	return strings.Join(lines, "\n")
}

// buildRiskLine builds a compact risk summary string e.g. "A×3  B×1  F×1".
func buildRiskLine(policies []model.GatewayPolicy) string {
	counts := map[model.Grade]int{}
	for i := range policies {
		p := policies[i]
		counts[p.Score.Grade]++
	}
	grades := []model.Grade{model.GradeA, model.GradeB, model.GradeC, model.GradeD, model.GradeF}
	var parts []string
	for _, g := range grades {
		if n := counts[g]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s×%d", g, n))
		}
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "  ")
}

// avgRiskScore returns the mean risk score and its derived grade across all policies.
func avgRiskScore(policies []model.GatewayPolicy) (int, model.Grade) {
	if len(policies) == 0 {
		return 0, model.GradeA
	}
	total := 0
	for i := range policies {
		p := policies[i]
		total += p.Score.Score
	}
	avg := total / len(policies)
	return avg, model.GradeFromScore(avg)
}

func metadataString(meta map[string]any, key string) string {
	if value, ok := meta[key].(string); ok {
		return value
	}
	return ""
}

// printScanPtree writes a tree view of the scan process to w (stderr) during verbose scan.
func printScanPtree(w *os.File, tool model.UnifiedTool, score model.RiskScore, policy model.GatewayPolicy) {
	const tree, branch, last = "│  ", "├─ ", "└─ "
	fmt.Fprintf(w, "\n┌─ %s\n", tool.Name) //nolint:errcheck // stderr write in verbose debug path
	var lines []string
	if len(tool.Permissions) > 0 {
		lines = append(lines, fmt.Sprintf("Permissions: %v", tool.Permissions))
	}
	if len(score.Issues) == 0 && len(lines) == 0 {
		lines = append(lines, "(no findings)")
	}
	for _, iss := range score.Issues {
		wt := severityWeight[iss.Severity]
		lines = append(lines, fmt.Sprintf("%s %s (+%d): %s [%s]", iss.RuleID, iss.Severity, wt, iss.Description, iss.Location))
	}
	lines = append(lines, fmt.Sprintf("Score: %d → Grade %s → %s", score.Score, score.Grade, policy.Action))
	for i, ln := range lines {
		sep := branch
		if i == len(lines)-1 {
			sep = last
		}
		fmt.Fprintf(w, "%s%s%s\n", tree, sep, ln) //nolint:errcheck // stderr write in verbose debug path
	}
	fmt.Fprintf(w, "└─\n") //nolint:errcheck // stderr write in verbose debug path
}

func checkFailOn(failOn string, summary ScanSummary) error {
	if failOn == "" {
		return nil
	}
	switch failOn {
	case "block":
		if summary.Blocked > 0 {
			return fmt.Errorf("scan failed: %d tool(s) BLOCKED", summary.Blocked)
		}
	case "approval":
		if summary.RequireApproval > 0 || summary.Blocked > 0 {
			return fmt.Errorf("scan failed: %d tool(s) require approval, %d blocked", summary.RequireApproval, summary.Blocked)
		}
	case "allow":
		if summary.RequireApproval > 0 || summary.Blocked > 0 {
			return fmt.Errorf("scan failed: only %d of %d tool(s) are fully allowed", summary.Allowed, summary.Total)
		}
	default:
		return fmt.Errorf("invalid --fail-on value %q (use: allow | approval | block)", failOn)
	}
	return nil
}

func persistResults(ctx context.Context, dbPath string, tools []model.UnifiedTool, policies []model.GatewayPolicy) error {
	store, err := storage.OpenContext(ctx, dbPath)
	if err != nil {
		return fmt.Errorf("persist: %w", err)
	}
	defer func() {
		if closeErr := store.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: db close: %v\n", closeErr)
		}
	}()

	for i := range policies {
		policy := policies[i]
		rec := storage.ScanRecord{
			ID:        fmt.Sprintf("%s-%d", tools[i].Name, time.Now().UnixNano()),
			ToolName:  policy.ToolName,
			Protocol:  tools[i].Protocol,
			RiskScore: policy.Score.Score,
			Grade:     policy.Score.Grade,
			Findings:  policy.Score.Issues,
			ScannedAt: time.Now().UTC(),
		}
		if saveErr := store.Save(ctx, rec); saveErr != nil {
			return fmt.Errorf("persist: save %q: %w", rec.ToolName, saveErr)
		}
	}
	fmt.Fprintf(os.Stderr, "persisted %d scan result(s) to %s\n", len(policies), dbPath)
	return nil
}
