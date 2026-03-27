package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pterm/pterm"
	"github.com/spf13/cobra"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/gateway"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

type gateOpts struct {
	packageName string
	extraArgs   []string
	name        string
	force       bool
	dryRun      bool
	blockOn     string
	scope       string
	deepScan    bool
	rulesDir    string
}

// blockedError signals that installation was blocked by grade policy (exit 1).
type blockedError struct {
	grade model.Grade
}

func (e *blockedError) Error() string {
	return fmt.Sprintf("installation blocked: server received grade %s", e.grade)
}

func newGateCmd() *cobra.Command {
	var opts gateOpts

	cmd := &cobra.Command{
		Use:   "gate <package> [-- extra-args...]",
		Short: "Scan an MCP server and install it if it passes security checks",
		Long: `Scan an MCP server package before installing it. The server is started
via npx, scanned for security risks, and only installed if it passes
the grade threshold.

  Grade A/B → auto-install
  Grade C/D → prompt for confirmation
  Grade F   → block installation`,
		Example: `  tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp
  tooltrust-scanner gate --dry-run @modelcontextprotocol/server-filesystem -- /tmp
  tooltrust-scanner gate --name my-server @some/package
  tooltrust-scanner gate --block-on D @some/package
  tooltrust-scanner gate --scope user @some/package`,
		Args:               cobra.MinimumNArgs(1),
		DisableFlagParsing: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.packageName = args[0]
			// Cobra puts everything after "--" in cmd.ArgsLenAtDash
			if dashIdx := cmd.ArgsLenAtDash(); dashIdx >= 0 {
				opts.extraArgs = args[dashIdx:]
			}

			err := runGate(cmd.Context(), opts)
			if err != nil {
				if _, ok := err.(*blockedError); ok {
					// Exit 1 for policy block
					fmt.Fprintln(os.Stderr, err.Error())
					os.Exit(1)
				}
				// Exit 2 for errors
				fmt.Fprintln(os.Stderr, "error:", err)
				os.Exit(2)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&opts.name, "name", "", "override server name in config (default: derived from package)")
	cmd.Flags().BoolVar(&opts.force, "force", false, "bypass grade check, install regardless")
	cmd.Flags().BoolVar(&opts.dryRun, "dry-run", false, "scan only, don't install")
	cmd.Flags().StringVar(&opts.blockOn, "block-on", "F", "minimum grade that blocks installation: F (default), D, C, B")
	cmd.Flags().StringVar(&opts.scope, "scope", "project", "config scope: project (writes .mcp.json) or user (writes ~/.claude.json)")
	cmd.Flags().BoolVar(&opts.deepScan, "deep-scan", false, "enable AI-based semantic analysis (pass-through to scanner)")
	cmd.Flags().StringVar(&opts.rulesDir, "rules-dir", "", "custom YAML rules directory (pass-through to scanner)")

	return cmd
}

func runGate(ctx context.Context, opts gateOpts) error {
	// Derive server name.
	serverName := opts.name
	if serverName == "" {
		serverName = deriveServerName(opts.packageName)
	}

	// Build the npx command string for scanning.
	serverCmd := buildServerCommand(opts.packageName, opts.extraArgs)

	pterm.Info.Printfln("Scanning server: %s", serverCmd)
	pterm.Info.Printfln("Server name: %s", serverName)
	pterm.Println()

	// Scan the live server.
	liveCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	tools, err := scanLiveServer(liveCtx, serverCmd)
	if err != nil {
		return fmt.Errorf("live server scan failed: %w", err)
	}

	// Initialize scanner.
	scanner, err := analyzer.NewScanner(opts.deepScan, opts.rulesDir)
	if err != nil {
		return fmt.Errorf("failed to initialize scanner: %w", err)
	}

	// Scan and evaluate each tool.
	var policies []model.GatewayPolicy
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
	}

	// Build and display the report.
	summary := ScanSummary{Total: len(tools), ScannedAt: time.Now().UTC()}
	for _, p := range policies {
		switch p.Action {
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

	if printErr := printPtermUI(report); printErr != nil {
		return fmt.Errorf("render report: %w", printErr)
	}

	// Dry-run: just show results.
	if opts.dryRun {
		pterm.Info.Println("Dry run — skipping installation.")
		return nil
	}

	// Gate decision.
	worst := worstGrade(policies)
	blockOnGrade, err := parseGrade(opts.blockOn)
	if err != nil {
		return err
	}

	proceed := gateDecision(worst, blockOnGrade, opts.force)
	if !proceed {
		return &blockedError{grade: worst}
	}

	// Install.
	pterm.Println()
	pterm.Info.Printfln("Installing %s as %q (scope: %s)...", opts.packageName, serverName, opts.scope)
	if err := installServer(ctx, opts, serverName, serverCmd); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	pterm.Success.Printfln("Server %q installed successfully!", serverName)
	printStarPrompt()
	return nil
}

// deriveServerName extracts a short name from a package identifier.
// "@modelcontextprotocol/server-memory" → "server-memory"
// "some-package" → "some-package".
func deriveServerName(packageName string) string {
	if idx := strings.LastIndex(packageName, "/"); idx >= 0 {
		return packageName[idx+1:]
	}
	return packageName
}

// buildServerCommand builds the npx command string for running the server.
func buildServerCommand(packageName string, extraArgs []string) string {
	parts := []string{"npx", "-y", packageName}
	parts = append(parts, extraArgs...)
	return strings.Join(parts, " ")
}

// parseGrade converts a grade string to a model.Grade.
func parseGrade(s string) (model.Grade, error) {
	switch strings.ToUpper(s) {
	case "A":
		return model.GradeA, nil
	case "B":
		return model.GradeB, nil
	case "C":
		return model.GradeC, nil
	case "D":
		return model.GradeD, nil
	case "F":
		return model.GradeF, nil
	default:
		return "", fmt.Errorf("invalid --block-on grade %q (use: A, B, C, D, or F)", s)
	}
}

// gradeOrder returns a numeric ordering for grades (higher = worse).
func gradeOrder(g model.Grade) int {
	switch g {
	case model.GradeA:
		return 0
	case model.GradeB:
		return 1
	case model.GradeC:
		return 2
	case model.GradeD:
		return 3
	case model.GradeF:
		return 4
	default:
		return 5
	}
}

// gateDecision determines whether installation should proceed.
func gateDecision(worst, blockOn model.Grade, force bool) bool {
	if force {
		pterm.Warning.Println("--force flag set — bypassing grade check.")
		return true
	}

	// If the worst grade is at or beyond the block threshold, block.
	if gradeOrder(worst) >= gradeOrder(blockOn) {
		pterm.Println()
		pterm.Error.Printfln("Installation blocked — server grade %s meets or exceeds block threshold %s.", worst, blockOn)
		return false
	}

	// Grade A/B: auto-proceed.
	if worst == model.GradeA || worst == model.GradeB {
		pterm.Println()
		pterm.Success.Printfln("Security check passed (grade %s) — proceeding with installation.", worst)
		return true
	}

	// Grade C/D (below block threshold): prompt for confirmation.
	pterm.Println()
	pterm.Warning.Printfln("Server received grade %s — some tools have elevated risk.", worst)
	result, err := pterm.DefaultInteractiveConfirm.
		WithDefaultText("Do you want to proceed with installation?").
		WithDefaultValue(false).
		Show()
	if err != nil {
		return false
	}
	return result
}

// mcpConfig represents the .mcp.json / ~/.claude.json config structure.
type mcpConfig struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

// mcpServerEntry represents a single MCP server entry in the config.
type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env,omitempty"`
}

// installServer installs the MCP server, trying the claude CLI first, then falling back to config file.
func installServer(ctx context.Context, opts gateOpts, serverName, serverCmd string) error {
	// Try claude CLI first.
	claudePath, err := exec.LookPath("claude")
	if err == nil {
		return installViaCLI(ctx, claudePath, serverName, opts)
	}

	// Fallback: write config file directly.
	return installViaConfig(serverName, opts)
}

// installViaCLI uses the claude CLI to add the server.
func installViaCLI(ctx context.Context, claudePath, serverName string, opts gateOpts) error {
	args := []string{"mcp", "add", serverName}
	if opts.scope == "user" {
		args = append(args, "-s", "user")
	}
	args = append(args, "--", "npx", "-y", opts.packageName)
	args = append(args, opts.extraArgs...)

	cmd := exec.CommandContext(ctx, claudePath, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmdErr := cmd.Run(); cmdErr != nil {
		return fmt.Errorf("claude command failed: %w", cmdErr)
	}
	return nil
}

// installViaConfig writes the server entry directly to the config file.
func installViaConfig(serverName string, opts gateOpts) error {
	configPath, err := resolveConfigPath(opts.scope)
	if err != nil {
		return err
	}

	cfg := mcpConfig{MCPServers: make(map[string]mcpServerEntry)}

	// Read existing config if present.
	data, readErr := os.ReadFile(configPath)
	if readErr == nil {
		if uErr := json.Unmarshal(data, &cfg); uErr != nil {
			return fmt.Errorf("failed to parse existing config %s: %w", configPath, uErr)
		}
		if cfg.MCPServers == nil {
			cfg.MCPServers = make(map[string]mcpServerEntry)
		}
	}

	// Build the server entry.
	serverArgs := []string{"-y", opts.packageName}
	serverArgs = append(serverArgs, opts.extraArgs...)

	cfg.MCPServers[serverName] = mcpServerEntry{
		Command: "npx",
		Args:    serverArgs,
	}

	// Write config.
	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(configPath); dir != "." {
		if mkErr := os.MkdirAll(dir, 0o755); mkErr != nil {
			return fmt.Errorf("failed to create config directory: %w", mkErr)
		}
	}

	if err := os.WriteFile(configPath, encoded, 0o644); err != nil {
		return fmt.Errorf("failed to write config %s: %w", configPath, err)
	}

	pterm.Info.Printfln("Config written to %s", configPath)
	return nil
}

// resolveConfigPath returns the path to the appropriate config file.
func resolveConfigPath(scope string) (string, error) {
	switch scope {
	case "project":
		return ".mcp.json", nil
	case "user":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to determine home directory: %w", err)
		}
		return filepath.Join(home, ".claude.json"), nil
	default:
		return "", fmt.Errorf("invalid --scope %q (use: project or user)", scope)
	}
}
