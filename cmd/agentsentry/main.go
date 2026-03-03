package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/AgentSafe-AI/agentsentry/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/agentsentry/pkg/analyzer"
	"github.com/AgentSafe-AI/agentsentry/pkg/gateway"
	"github.com/AgentSafe-AI/agentsentry/pkg/model"
	"github.com/AgentSafe-AI/agentsentry/pkg/storage"
)

var version = "dev"

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "agentsentry",
		Short: "AI Agent Tool Security Scanner",
		Long:  "AgentSentry scans AI agent tool definitions for security risks and generates gateway policies.",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the AgentSentry version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("agentsentry", version)
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

func newScanCmd() *cobra.Command {
	var (
		inputFile  string
		protocol   string
		outputFile string
		failOn     string
		dbPath     string
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan tool definitions and generate gateway policies",
		Example: `  agentsentry scan --protocol mcp --input tools.json
  agentsentry scan --protocol mcp --input tools.json --output report.json
  agentsentry scan --protocol mcp --input tools.json --fail-on block
  agentsentry scan --protocol mcp --input tools.json --db scans.db`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), scanOpts{
				inputFile:  inputFile,
				protocol:   protocol,
				outputFile: outputFile,
				failOn:     failOn,
				dbPath:     dbPath,
			})
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "path to tool definition file (required)")
	cmd.Flags().StringVarP(&protocol, "protocol", "p", "mcp", "protocol format: mcp | openai | skills")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "write JSON report to file (default: stdout)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit non-zero if any tool reaches this action: allow | approval | block")
	cmd.Flags().StringVar(&dbPath, "db", "", "persist scan results to SQLite database at this path")
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(err)
	}

	return cmd
}

type scanOpts struct {
	inputFile  string
	protocol   string
	outputFile string
	failOn     string
	dbPath     string
}

func runScan(ctx context.Context, opts scanOpts) error {
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

	return checkFailOn(opts.failOn, summary)
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
