package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kballard/go-shellquote"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/pterm/pterm"

	localmcp "github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func scanLiveServer(ctx context.Context, serverCmd string) ([]model.UnifiedTool, error) {
	args, err := parseServerCommand(serverCmd)
	if err != nil {
		return nil, err
	}
	return scanLiveServerArgs(ctx, args, serverCmd)
}

func parseServerCommand(serverCmd string) ([]string, error) {
	args, err := shellquote.Split(serverCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server command: %w", err)
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}
	return args, nil
}

func formatCommand(args []string) string {
	return shellquote.Join(args...)
}

func scanLiveServerArgs(ctx context.Context, args []string, displayCmd string) ([]model.UnifiedTool, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("empty server command")
	}
	if strings.TrimSpace(displayCmd) == "" {
		displayCmd = formatCommand(args)
	}

	spinner, err := pterm.DefaultSpinner.Start("🔌 Connecting to live MCP server: " + displayCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to start spinner: %w", err)
	}

	// Create a cancelable context to forcefully kill the sub-process on exit.
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	stdioTransport := transport.NewStdioWithOptions(args[0], nil, args[1:])
	if startErr := stdioTransport.Start(execCtx); startErr != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("connection to MCP server timed out: %w", startErr)
		}
		spinner.Fail("Failed to start transport")
		return nil, fmt.Errorf("failed to start transport: %w", startErr)
	}

	c := client.NewClient(stdioTransport)
	defer c.Close() //nolint:errcheck // closing client on exit, error is acceptable

	initReq := mcpgo.InitializeRequest{}
	initReq.Params.ProtocolVersion = "2024-11-05"
	initReq.Params.ClientInfo = mcpgo.Implementation{
		Name:    "tooltrust-scanner",
		Version: "1.0.0",
	}

	_, err = c.Initialize(ctx, initReq)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("initialization timed out: %w", err)
		}
		spinner.Fail("Initialization failed")
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	listReq := mcpgo.ListToolsRequest{}
	resp, err := c.ListTools(ctx, listReq)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			spinner.Fail("Connection to MCP server timed out after 30 seconds.")
			pterm.Error.Println("❌ Error: Connection to MCP server timed out after 30 seconds.")
			return nil, fmt.Errorf("tools/list map timed out: %w", err)
		}
		spinner.Fail("Failed to fetch tools")
		return nil, fmt.Errorf("tools/list map failed: %w", err)
	}

	spinner.Success("Connected and tools fetched!")

	// We serialize the response back to JSON so we can use our existing adapter,
	// which also runs the inference rules for permissions.
	// Since mcp-go uses `mcpgo.Tool` and we expect `mcp.Tool`, we wrap it.
	type dummyResponse struct {
		Tools []mcpgo.Tool `json:"tools"`
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
	tools = enrichLiveToolsWithLocalNodeDependencies(args, tools)
	return tools, nil
}

func enrichLiveToolsWithLocalNodeDependencies(args []string, tools []model.UnifiedTool) []model.UnifiedTool {
	root := detectLocalProjectRoot(args)
	if root == "" {
		for i := range tools {
			ensureMetadata(&tools[i])
			tools[i].Metadata["dependency_visibility_note"] = "No metadata.dependencies or repo_url were exposed by this MCP server, and no local project manifest could be inferred from the launch command."
		}
		return tools
	}

	artifacts := findLocalDependencyArtifacts(root)
	if len(artifacts) == 0 {
		for i := range tools {
			ensureMetadata(&tools[i])
			if !hasDependencyMetadata(tools[i].Metadata) && !hasRepoURL(tools[i].Metadata) {
				tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local project detected at %s, but no supported dependency artifact was found.", root)
			}
		}
		return tools
	}

	var merged []nodeDependency
	var scanned []string
	for _, artifact := range artifacts {
		deps, err := parseDependencyArtifact(artifact)
		if err != nil || len(deps) == 0 {
			continue
		}
		merged = append(merged, deps...)
		scanned = append(scanned, artifact.path)
	}
	if len(merged) == 0 {
		for i := range tools {
			ensureMetadata(&tools[i])
			if !hasDependencyMetadata(tools[i].Metadata) && !hasRepoURL(tools[i].Metadata) {
				tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local dependency artifacts were found under %s, but ToolTrust could not extract usable dependencies.", root)
			}
		}
		return tools
	}

	for i := range tools {
		ensureMetadata(&tools[i])
		mergeDependencies(&tools[i], merged)
		tools[i].Metadata["dependency_visibility_note"] = fmt.Sprintf("Local dependency artifacts scanned from %s.", strings.Join(scanned, ", "))
	}
	return tools
}

func ensureMetadata(tool *model.UnifiedTool) {
	if tool.Metadata == nil {
		tool.Metadata = map[string]any{}
	}
}

func hasDependencyMetadata(meta map[string]any) bool {
	raw, ok := meta["dependencies"]
	if !ok {
		return false
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return false
	}
	var deps []map[string]any
	if err := json.Unmarshal(b, &deps); err != nil {
		return false
	}
	return len(deps) > 0
}

func hasRepoURL(meta map[string]any) bool {
	repoURL, ok := meta["repo_url"].(string)
	return ok && strings.TrimSpace(repoURL) != ""
}

func mergeDependencies(tool *model.UnifiedTool, deps []nodeDependency) {
	var existing []map[string]any
	if raw, ok := tool.Metadata["dependencies"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			if err := json.Unmarshal(b, &existing); err != nil {
				existing = nil
			}
		}
	}

	seen := map[string]bool{}
	for _, dep := range existing {
		name := stringMapValue(dep, "name")
		version := stringMapValue(dep, "version")
		ecosystem := stringMapValue(dep, "ecosystem")
		seen[ecosystem+":"+name+"@"+version] = true
		if dep["source"] == nil || dep["source"] == "" {
			dep["source"] = "metadata"
		}
	}

	for _, dep := range deps {
		key := dep.Ecosystem + ":" + dep.Name + "@" + dep.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		existing = append(existing, map[string]any{
			"name":      dep.Name,
			"version":   dep.Version,
			"ecosystem": dep.Ecosystem,
			"source":    dep.Source,
		})
	}

	if len(existing) > 0 {
		tool.Metadata["dependencies"] = existing
	}
}

type nodeLockfile struct {
	Packages     map[string]nodeLockEntry `json:"packages"`
	Dependencies map[string]nodeLockEntry `json:"dependencies"`
}

type nodeLockEntry struct {
	Version string `json:"version"`
}

type nodeDependency struct {
	Name      string
	Version   string
	Ecosystem string
	Source    string
}

type dependencyArtifact struct {
	path string
	kind string
}

func parseDependencyArtifact(artifact dependencyArtifact) ([]nodeDependency, error) {
	switch artifact.kind {
	case "npm-lock":
		return parseNodeLockfile(artifact.path)
	case "go-sum":
		return parseGoSumFile(artifact.path)
	case "requirements":
		return parseRequirementsFile(artifact.path)
	case "pnpm-lock":
		return parsePNPMLockfile(artifact.path)
	case "yarn-lock":
		return parseYarnLockfile(artifact.path)
	default:
		return nil, fmt.Errorf("unsupported dependency artifact kind %q", artifact.kind)
	}
}

func parseNodeLockfile(path string) ([]nodeDependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read node lockfile %s: %w", path, err)
	}
	var lock nodeLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("parse node lockfile %s: %w", path, err)
	}

	seen := map[string]bool{}
	var deps []nodeDependency
	if len(lock.Packages) > 0 {
		for key, entry := range lock.Packages {
			if key == "" || entry.Version == "" {
				continue
			}
			name := key
			if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
				name = key[idx+len("node_modules/"):]
			}
			if name == "" {
				continue
			}
			k := name + "@" + entry.Version
			if seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, nodeDependency{Name: name, Version: entry.Version, Ecosystem: "npm", Source: "local_lockfile"})
		}
		return deps, nil
	}

	for name, entry := range lock.Dependencies {
		if name == "" || entry.Version == "" {
			continue
		}
		k := name + "@" + entry.Version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, nodeDependency{Name: name, Version: entry.Version, Ecosystem: "npm", Source: "local_lockfile"})
	}
	return deps, nil
}

func detectLocalProjectRoot(args []string) string {
	candidates := []string{}
	for _, arg := range args {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.Contains(arg, string(os.PathSeparator)) || strings.HasPrefix(arg, ".") {
			candidates = append(candidates, arg)
		}
		if strings.HasSuffix(arg, ".js") || strings.HasSuffix(arg, ".mjs") || strings.HasSuffix(arg, ".cjs") || strings.HasSuffix(arg, ".ts") {
			candidates = append(candidates, arg)
		}
	}

	seen := map[string]bool{}
	for _, candidate := range candidates {
		resolved := candidate
		if !filepath.IsAbs(resolved) {
			if cwd, err := os.Getwd(); err == nil {
				resolved = filepath.Join(cwd, resolved)
			}
		}
		info, err := os.Stat(resolved)
		if err != nil {
			continue
		}
		dir := resolved
		if !info.IsDir() {
			dir = filepath.Dir(resolved)
		}
		for current := dir; current != "" && current != filepath.Dir(current); current = filepath.Dir(current) {
			if seen[current] {
				break
			}
			seen[current] = true
			if fileExists(filepath.Join(current, "package.json")) || fileExists(filepath.Join(current, "go.mod")) || fileExists(filepath.Join(current, "requirements.txt")) || fileExists(filepath.Join(current, "pyproject.toml")) {
				return current
			}
		}
	}
	return ""
}

func findLocalDependencyArtifacts(root string) []dependencyArtifact {
	specs := []dependencyArtifact{
		{path: filepath.Join(root, "package-lock.json"), kind: "npm-lock"},
		{path: filepath.Join(root, "npm-shrinkwrap.json"), kind: "npm-lock"},
		{path: filepath.Join(root, "pnpm-lock.yaml"), kind: "pnpm-lock"},
		{path: filepath.Join(root, "yarn.lock"), kind: "yarn-lock"},
		{path: filepath.Join(root, "go.sum"), kind: "go-sum"},
		{path: filepath.Join(root, "requirements.txt"), kind: "requirements"},
	}
	var found []dependencyArtifact
	for _, spec := range specs {
		if fileExists(spec.path) {
			found = append(found, spec)
		}
	}
	return found
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func stringMapValue(m map[string]any, key string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return ""
}

func parseGoSumFile(path string) ([]nodeDependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read go.sum %s: %w", path, err)
	}
	seen := map[string]bool{}
	var deps []nodeDependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		module, version := parts[0], strings.TrimSuffix(parts[1], "+incompatible")
		if strings.HasSuffix(version, "/go.mod") {
			continue
		}
		k := module + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, nodeDependency{Name: module, Version: version, Ecosystem: "Go", Source: "local_lockfile"})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan go.sum %s: %w", path, err)
	}
	return deps, nil
}

func parseRequirementsFile(path string) ([]nodeDependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read requirements.txt %s: %w", path, err)
	}
	var deps []nodeDependency
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, "=="); i > 0 {
			name := strings.TrimSpace(line[:i])
			version := strings.TrimSpace(line[i+2:])
			if name != "" && version != "" {
				deps = append(deps, nodeDependency{Name: name, Version: version, Ecosystem: "PyPI", Source: "local_lockfile"})
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan requirements.txt %s: %w", path, err)
	}
	return deps, nil
}

func parsePNPMLockfile(path string) ([]nodeDependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pnpm lockfile %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	var deps []nodeDependency
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "/") && !strings.HasPrefix(trimmed, "'/") && !strings.HasPrefix(trimmed, "\"/") {
			continue
		}
		name, version, ok := parsePNPMLockKey(trimmed)
		if !ok {
			continue
		}
		k := name + "@" + version
		if seen[k] {
			continue
		}
		seen[k] = true
		deps = append(deps, nodeDependency{Name: name, Version: version, Ecosystem: "npm", Source: "local_lockfile"})
	}
	return deps, nil
}

func parsePNPMLockKey(key string) (name, version string, ok bool) {
	trimmed := strings.TrimSpace(key)
	trimmed = strings.Trim(trimmed, "'\"")
	trimmed = strings.TrimSuffix(trimmed, ":")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return "", "", false
	}
	if idx := strings.Index(trimmed, "("); idx >= 0 {
		trimmed = trimmed[:idx]
	}
	idx := strings.LastIndex(trimmed, "@")
	if idx <= 0 || idx == len(trimmed)-1 {
		return "", "", false
	}
	return trimmed[:idx], trimmed[idx+1:], true
}

func parseYarnLockfile(path string) ([]nodeDependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read yarn.lock %s: %w", path, err)
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	var deps []nodeDependency
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") || !strings.HasSuffix(line, ":") {
			continue
		}
		header := strings.TrimSuffix(line, ":")
		if header == "__metadata" || strings.Contains(line, " version ") {
			continue
		}
		version := ""
		for j := i + 1; j < len(lines); j++ {
			if !strings.HasPrefix(lines[j], " ") && !strings.HasPrefix(lines[j], "\t") {
				break
			}
			next := strings.TrimSpace(lines[j])
			if next == "" {
				break
			}
			switch {
			case strings.HasPrefix(next, "version "):
				version = strings.Trim(strings.TrimSpace(next[len("version "):]), "\"'")
			case strings.HasPrefix(next, "version:"):
				version = strings.Trim(strings.TrimSpace(next[len("version:"):]), "\"'")
			}
			if version != "" {
				break
			}
		}
		if version == "" {
			continue
		}
		specs := strings.Split(header, ",")
		for _, spec := range specs {
			spec = strings.Trim(strings.TrimSpace(spec), "\"'")
			if spec == "" {
				continue
			}
			name, ok := parseYarnPackageName(spec)
			if !ok {
				continue
			}
			k := name + "@" + version
			if seen[k] {
				continue
			}
			seen[k] = true
			deps = append(deps, nodeDependency{Name: name, Version: version, Ecosystem: "npm", Source: "local_lockfile"})
		}
	}
	return deps, nil
}

func parseYarnPackageName(spec string) (string, bool) {
	spec = strings.TrimSpace(strings.Trim(spec, "\"'"))
	if spec == "" {
		return "", false
	}
	if strings.HasPrefix(spec, "@") {
		slash := strings.Index(spec, "/")
		if slash < 0 {
			return "", false
		}
		rest := spec[slash+1:]
		at := strings.Index(rest, "@")
		if at < 0 {
			return "", false
		}
		return spec[:slash+1+at], true
	}
	at := strings.Index(spec, "@")
	if at <= 0 {
		return "", false
	}
	return spec[:at], true
}
