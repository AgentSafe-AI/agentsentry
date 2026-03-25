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
		Short: "Security scanner for AI agent tool definitions",
		Long:  "ToolTrust Scanner analyses AI agent tool definitions for security risks and produces gateway enforcement policies.",
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
		Short: "Scan tool definitions and generate gateway policies",
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
	return printPtermUI(report)
}

// printPtermUI renders the scan report as a pterm tree + summary box.
func printPtermUI(report ScanReport) error {
	// ── Emergency alert for AS-008 BLOCK findings ─────────────────────────────
	printSupplyChainAlert(report.Policies)

	// ── Build the tree ────────────────────────────────────────────────────────
	var rootChildren []pterm.TreeNode

	for _, policy := range report.Policies {
		// Tool header label, coloured by action.
		toolLabel := formatToolLabel(policy)

		// Children: one per finding, or a green ✅ Pass.
		var children []pterm.TreeNode
		if len(policy.Score.Issues) == 0 {
			children = append(children, pterm.TreeNode{
				Text: pterm.FgGreen.Sprint("✅ Pass"),
			})
		} else {
			for _, issue := range policy.Score.Issues {
				children = append(children, pterm.TreeNode{
					Text: formatIssueLabel(issue),
				})
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

// printSupplyChainAlert scans all findings for AS-008 BLOCK issues and prints a
// high-visibility ANSI red emergency banner when confirmed malware is detected.
// This runs BEFORE the main scan tree to ensure it is never scrolled past.
func printSupplyChainAlert(policies []model.GatewayPolicy) {
	type alert struct {
		pkg  string
		desc string
	}
	var alerts []alert

	for _, policy := range policies {
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
	for _, p := range policies {
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
	scoreStr := fmt.Sprintf("score=%d grade=%s", policy.Score.Score, policy.Score.Grade)
	return fmt.Sprintf("%s  %s  %s", pterm.Bold.Sprint(name), badge, pterm.FgGray.Sprint(scoreStr))
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
}

// formatIssueLabel returns a coloured finding line with an actionable fix hint.
func formatIssueLabel(issue model.Issue) string {
	wt := severityWeight[issue.Severity]
	main := fmt.Sprintf("[%s] %s (+%d): %s", issue.RuleID, issue.Severity, wt, issue.Description)
	hint := ruleHint[issue.RuleID]

	var coloredMain, coloredHint string
	switch issue.Severity {
	case model.SeverityCritical:
		coloredMain = "🚨 " + pterm.FgRed.Sprint(main)
		coloredHint = pterm.FgRed.Sprint(hint)
	case model.SeverityHigh:
		coloredMain = "🔴 " + pterm.FgLightRed.Sprint(main)
		coloredHint = pterm.FgLightRed.Sprint(hint)
	case model.SeverityMedium:
		coloredMain = "⚠️  " + pterm.FgYellow.Sprint(main)
		coloredHint = pterm.FgYellow.Sprint(hint)
	case model.SeverityLow:
		coloredMain = "🔵 " + pterm.FgBlue.Sprint(main)
		coloredHint = pterm.FgBlue.Sprint(hint)
	default:
		coloredMain = "ℹ️  " + pterm.FgGray.Sprint(main)
		coloredHint = pterm.FgGray.Sprint(hint)
	}

	if hint == "" {
		return coloredMain
	}
	return coloredMain + "\n       " + coloredHint
}

// buildRiskLine builds a compact risk summary string e.g. "A×3  B×1  F×1".
func buildRiskLine(policies []model.GatewayPolicy) string {
	counts := map[model.Grade]int{}
	for _, p := range policies {
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
	for _, p := range policies {
		total += p.Score.Score
	}
	avg := total / len(policies)
	return avg, model.GradeFromScore(avg)
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

	for i, policy := range policies {
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
