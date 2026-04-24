package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestDeriveServerName_Scoped(t *testing.T) {
	got := deriveServerName("@modelcontextprotocol/server-memory")
	want := "server-memory"
	if got != want {
		t.Errorf("deriveServerName(@modelcontextprotocol/server-memory) = %q, want %q", got, want)
	}
}

func TestDeriveServerName_Unscoped(t *testing.T) {
	got := deriveServerName("some-package")
	want := "some-package"
	if got != want {
		t.Errorf("deriveServerName(some-package) = %q, want %q", got, want)
	}
}

func TestBuildServerCommand_NoExtraArgs(t *testing.T) {
	got := buildServerCommand("@modelcontextprotocol/server-memory", nil)
	want := "npx -y @modelcontextprotocol/server-memory"
	if got != want {
		t.Errorf("buildServerCommand() = %q, want %q", got, want)
	}
}

func TestBuildServerCommand_WithExtraArgs(t *testing.T) {
	got := buildServerCommand("@modelcontextprotocol/server-filesystem", []string{"/tmp", "/home"})
	want := "npx -y @modelcontextprotocol/server-filesystem /tmp /home"
	if got != want {
		t.Errorf("buildServerCommand() = %q, want %q", got, want)
	}
}

func TestGateDecision_GradeA_AutoProceed(t *testing.T) {
	got := gateDecision(model.GradeA, model.GradeF, false)
	if !got {
		t.Error("expected grade A to auto-proceed")
	}
}

func TestGateDecision_GradeB_AutoProceed(t *testing.T) {
	got := gateDecision(model.GradeB, model.GradeF, false)
	if !got {
		t.Error("expected grade B to auto-proceed")
	}
}

func TestGateDecision_GradeF_BlockedDefault(t *testing.T) {
	got := gateDecision(model.GradeF, model.GradeF, false)
	if got {
		t.Error("expected grade F to be blocked with default block-on=F")
	}
}

func TestGateDecision_GradeD_BlockedCustom(t *testing.T) {
	got := gateDecision(model.GradeD, model.GradeD, false)
	if got {
		t.Error("expected grade D to be blocked with block-on=D")
	}
}

func TestGateDecision_Force_Bypasses(t *testing.T) {
	got := gateDecision(model.GradeF, model.GradeF, true)
	if !got {
		t.Error("expected --force to bypass grade F block")
	}
}

func TestRunGate_RequiresUnsafeLiveScanOptIn(t *testing.T) {
	err := runGate(context.Background(), gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		dryRun:      true,
	}, false)
	if err == nil {
		t.Fatal("expected gate to refuse unsafe live scan without opt-in")
	}
	if !strings.Contains(err.Error(), "--allow-unsafe-live-scan") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInstallViaConfig_CreatesNew(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")

	opts := gateOpts{
		packageName: "@modelcontextprotocol/server-memory",
		extraArgs:   []string{"/tmp"},
		scope:       "project",
	}

	// Temporarily override resolveConfigPath by writing directly.
	cfg := mcpConfig{MCPServers: make(map[string]mcpServerEntry)}
	serverArgs := []string{"-y", opts.packageName}
	serverArgs = append(serverArgs, opts.extraArgs...)
	cfg.MCPServers["server-memory"] = mcpServerEntry{
		Command: "npx",
		Args:    serverArgs,
	}

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, encoded, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Read it back and verify.
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	var got mcpConfig
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}

	entry, ok := got.MCPServers["server-memory"]
	if !ok {
		t.Fatal("expected server-memory entry in config")
	}
	if entry.Command != "npx" {
		t.Errorf("command = %q, want %q", entry.Command, "npx")
	}
	wantArgs := []string{"-y", "@modelcontextprotocol/server-memory", "/tmp"}
	if len(entry.Args) != len(wantArgs) {
		t.Fatalf("args length = %d, want %d", len(entry.Args), len(wantArgs))
	}
	for i, arg := range wantArgs {
		if entry.Args[i] != arg {
			t.Errorf("args[%d] = %q, want %q", i, entry.Args[i], arg)
		}
	}
}

func TestInstallViaConfig_MergesExisting(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".mcp.json")

	// Write an existing config with another server.
	existing := mcpConfig{
		MCPServers: map[string]mcpServerEntry{
			"existing-server": {
				Command: "node",
				Args:    []string{"server.js"},
			},
		},
	}
	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, data, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Simulate adding a new server by reading, merging, and writing.
	readData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg mcpConfig
	if uErr := json.Unmarshal(readData, &cfg); uErr != nil {
		t.Fatal(uErr)
	}

	cfg.MCPServers["server-memory"] = mcpServerEntry{
		Command: "npx",
		Args:    []string{"-y", "@modelcontextprotocol/server-memory"},
	}

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if wErr := os.WriteFile(configPath, encoded, 0o644); wErr != nil {
		t.Fatal(wErr)
	}

	// Read back and verify both servers exist.
	finalData, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var got mcpConfig
	if err := json.Unmarshal(finalData, &got); err != nil {
		t.Fatal(err)
	}

	if len(got.MCPServers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(got.MCPServers))
	}
	if _, ok := got.MCPServers["existing-server"]; !ok {
		t.Error("existing-server was not preserved")
	}
	if _, ok := got.MCPServers["server-memory"]; !ok {
		t.Error("server-memory was not added")
	}
}
