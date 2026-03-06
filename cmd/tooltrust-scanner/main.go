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
		Short: "AI Agent Tool Security Scanner",
		Long:  "ToolTrust Scanner scans AI agent tool definitions for security risks and generates gateway policies.",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
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
		protocol   string
		output     string
		outputFile string
		failOn     string
		dbPath     string
		verbose    bool
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
				protocol:   protocol,
				output:     output,
				outputFile: outputFile,
				failOn:     failOn,
				dbPath:     dbPath,
				verbose:    verbose,
			})
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "path to tool definition file (required)")
	cmd.Flags().StringVarP(&protocol, "protocol", "p", "mcp", "protocol format: mcp | openai | skills")
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text (default) | json")
	cmd.Flags().StringVar(&outputFile, "file", "", "write output to file instead of stdout")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any tool reaches this action: allow | approval | block")
	cmd.Flags().StringVar(&dbPath, "db", "", "persist scan results to SQLite database at this path")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "print per-tool scan process tree to stderr during scan")
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(err)
	}

	return cmd
}

type scanOpts struct {
	inputFile  string
	protocol   string
	output     string
	outputFile string
	failOn     string
	dbPath     string
	verbose    bool
}

func runScan(ctx context.Context, opts scanOpts) error {
	// Validate --output flag early.
	switch opts.output {
	case "text", "json":
	default:
		return fmt.Errorf("invalid --output value %q (use: text | json)", opts.output)
	}

	data, err := os.ReadFile(opts.inputFile)
	if err != nil {
		return fmt.Errorf("cannot read input file: %w", err)
	}

	var tools []model.UnifiedTool

	switch opts.protocol {
	case "mcp":
		a := mcp.NewAdapter()
		tools, err = a.Parse(ctx, data)
		if err != nil {
			return fmt.Errorf("parse error: %w", err)
		}
	default:
		return fmt.Errorf("unsupported protocol %q (supported: mcp)", opts.protocol)
	}

	scanner := analyzer.NewScanner()
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

	// Default: text mode — render with pterm.
	return printPtermUI(report)
}

// printPtermUI renders the scan report as a pterm tree + summary box.
func printPtermUI(report ScanReport) error {
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
	summaryContent := fmt.Sprintf(
		"Total Scanned : %d\n"+
			"  ✅ Allowed       : %d\n"+
			"  ⚠️  Require Approval: %d\n"+
			"  🚫 Blocked       : %d\n"+
			"Risk Overview : %s\n"+
			"Scanned At    : %s",
		s.Total,
		s.Allowed,
		s.RequireApproval,
		s.Blocked,
		riskLine,
		s.ScannedAt.Format("2006-01-02 15:04:05 UTC"),
	)
	pterm.DefaultBox.
		WithTitle(pterm.Bold.Sprint("Scan Summary")).
		WithTitleTopCenter().
		Println(summaryContent)

	return nil
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

// formatIssueLabel returns a coloured finding line.
func formatIssueLabel(issue model.Issue) string {
	wt := severityWeight[issue.Severity]
	raw := fmt.Sprintf("[%s] %s (+%d): %s", issue.RuleID, issue.Severity, wt, issue.Description)
	switch issue.Severity {
	case model.SeverityCritical:
		return "🚨 " + pterm.FgRed.Sprint(raw)
	case model.SeverityHigh:
		return "🔴 " + pterm.FgLightRed.Sprint(raw)
	case model.SeverityMedium:
		return "⚠️  " + pterm.FgYellow.Sprint(raw)
	case model.SeverityLow:
		return "🔵 " + pterm.FgBlue.Sprint(raw)
	default:
		return "ℹ️  " + pterm.FgGray.Sprint(raw)
	}
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
