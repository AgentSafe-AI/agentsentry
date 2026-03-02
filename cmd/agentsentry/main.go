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
)

// version is set at build time via -ldflags.
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
		Long:  "AgentSafe scans AI agent tool definitions for security risks and generates gateway policies.",
	}
	root.AddCommand(newVersionCmd())
	root.AddCommand(newScanCmd())
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the AgentSafe version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println("agentsentry", version)
		},
	}
}

// ScanReport is the JSON output of the scan command.
// The schema is stable and versioned for ToolTrust Directory compatibility.
type ScanReport struct {
	SchemaVersion string                `json:"schema_version"`
	Policies      []model.GatewayPolicy `json:"policies"`
	Summary       ScanSummary           `json:"summary"`
}

// ScanSummary gives a high-level overview of the scan result.
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
	)

	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan tool definitions and generate gateway policies",
		Example: `  agentsentry scan --protocol mcp --input tools.json
  agentsentry scan --protocol mcp --input tools.json --output report.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd.Context(), inputFile, protocol, outputFile)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "path to tool definition file (required)")
	cmd.Flags().StringVarP(&protocol, "protocol", "p", "mcp", "protocol format: mcp | openai | skills")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "write JSON report to file (default: stdout)")
	if err := cmd.MarkFlagRequired("input"); err != nil {
		// Only fails when the flag name is wrong — this is a programming error.
		panic(err)
	}

	return cmd
}

func runScan(ctx context.Context, inputFile, protocol, outputFile string) error {
	data, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("cannot read input file: %w", err)
	}

	var tools []model.UnifiedTool

	switch protocol {
	case "mcp":
		a := mcp.NewAdapter()
		tools, err = a.Parse(ctx, data)
		if err != nil {
			return fmt.Errorf("parse error: %w", err)
		}
	default:
		return fmt.Errorf("unsupported protocol %q (supported: mcp)", protocol)
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
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode report: %w", err)
	}

	if outputFile != "" {
		if err := os.WriteFile(outputFile, encoded, 0o644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", outputFile)
		return nil
	}

	fmt.Println(string(encoded))
	return nil
}
