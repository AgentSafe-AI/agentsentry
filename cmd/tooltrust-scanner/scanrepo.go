package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/sourcedetect"
)

type scanRepoOpts struct {
	repoDir    string
	output     string
	outputFile string
}

func newScanRepoCmd() *cobra.Command {
	var opts scanRepoOpts
	cmd := &cobra.Command{
		Use:   "scan-repo",
		Short: "Detect embedded MCP server usage directly from source code",
		Example: `  tooltrust-scanner scan-repo --repo /path/to/repo
  tooltrust-scanner scan-repo --repo /path/to/repo --output json
  tooltrust-scanner scan-repo --repo /path/to/repo --output json --file embedded.json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScanRepo(cmd.Context(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.repoDir, "repo", "", "path to the repository root to inspect")
	cmd.Flags().StringVarP(&opts.output, "output", "o", "text", "output format: text | json")
	cmd.Flags().StringVar(&opts.outputFile, "file", "", "write output to file instead of stdout")
	return cmd
}

func runScanRepo(ctx context.Context, opts scanRepoOpts) error {
	if opts.repoDir == "" {
		return fmt.Errorf("--repo is required")
	}
	if opts.output != "text" && opts.output != "json" {
		return fmt.Errorf("invalid --output value %q (use: text | json)", opts.output)
	}

	result, err := sourcedetect.DetectEmbeddedMCP(opts.repoDir, sourcedetect.Options{})
	if err != nil {
		return fmt.Errorf("source detection failed: %w", err)
	}

	var out []byte
	if opts.output == "json" {
		out, err = json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal source-detect output: %w", err)
		}
		out = append(out, '\n')
	} else {
		status := "no embedded MCP detected"
		if result.HasEmbeddedMCP {
			status = "embedded MCP detected"
		}
		out = []byte(fmt.Sprintf("Source detection: %s\nFiles scanned: %d\nMatches: %d\n", status, result.Detection.FilesScanned, len(result.Detection.Matches)))
	}

	if opts.outputFile != "" {
		if writeErr := os.WriteFile(opts.outputFile, out, 0o644); writeErr != nil {
			return fmt.Errorf("write output file %s: %w", opts.outputFile, writeErr)
		}
		return nil
	}
	_, err = os.Stdout.Write(out)
	if err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}
