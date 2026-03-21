package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// Adapter converts MCP tools/list payloads into []model.UnifiedTool.
type Adapter struct{}

// NewAdapter returns a new MCP Adapter.
func NewAdapter() *Adapter { return &Adapter{} }

// Protocol implements adapter.Adapter.
func (a *Adapter) Protocol() model.ProtocolType { return model.ProtocolMCP }

// Parse implements adapter.Adapter for the MCP tools/list response format.
func (a *Adapter) Parse(_ context.Context, data []byte) ([]model.UnifiedTool, error) {
	var resp ListToolsResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("mcp adapter: failed to parse tools/list response: %w", err)
	}

	tools := make([]model.UnifiedTool, 0, len(resp.Tools))
	for _, t := range resp.Tools {
		raw, err := json.Marshal(t)
		if err != nil {
			// Marshalling a plain struct with only string fields should never fail.
			return nil, fmt.Errorf("mcp adapter: failed to marshal tool %q: %w", t.Name, err)
		}
		unified := model.UnifiedTool{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: convertSchema(t.InputSchema),
			Protocol:    model.ProtocolMCP,
			RawSource:   raw,
		}
		unified.Permissions = inferPermissions(t)
		tools = append(tools, unified)
	}
	return tools, nil
}

// convertSchema maps an MCP InputSchema to the internal jsonschema.Schema.
func convertSchema(s InputSchema) jsonschema.Schema {
	props := make(map[string]jsonschema.Property, len(s.Properties))
	for k, v := range s.Properties {
		props[k] = jsonschema.Property{
			Type:        string(v.Type),
			Description: v.Description,
		}
	}
	return jsonschema.Schema{
		Type:        string(s.Type),
		Description: s.Description,
		Properties:  props,
		Required:    s.Required,
	}
}

// permissionRule maps keyword signals to a Permission.
type permissionRule struct {
	propKeys     []string // property names that imply this permission
	descKeywords []string // description substrings (lowercased) that imply it
	nameKeywords []string // tool name substrings (lowercased) that imply it
}

var permissionRules = []struct {
	permission model.Permission
	rule       permissionRule
}{
	{
		model.PermissionFS,
		permissionRule{
			propKeys:     []string{"path", "filepath", "filename", "file", "dir", "directory"},
			descKeywords: []string{"file", "filesystem", "directory", "folder", "read file", "write file"},
			nameKeywords: []string{"create", "delete", "update", "push", "fork", "write", "upload", "remove"},
		},
	},
	{
		model.PermissionNetwork,
		permissionRule{
			propKeys:     []string{"url", "uri", "endpoint", "host"},
			descKeywords: []string{"url", "network", "http", "https", "fetch", "remote", "download"},
			nameKeywords: []string{"fetch", "scrape", "crawl", "download", "search", "query", "api", "request"},
		},
	},
	{
		model.PermissionExec,
		permissionRule{
			propKeys: []string{"command", "cmd", "shell", "script"},
			descKeywords: []string{"execute", "run command", "shell", "subprocess", "exec", "terminal",
				"evaluate_script", "execute javascript", "eval", "run script", "execute script", "browser injection"},
			nameKeywords: []string{"evaluate_script", "execute_javascript", "evaluatescript", "executejavascript",
				"eval", "run_script", "runscript", "execute_script", "executescript", "browser_injection", "browserinjection"},
		},
	},
	{
		model.PermissionDB,
		permissionRule{
			propKeys:     []string{"sql", "database"},
			descKeywords: []string{"database", "sql", "query"},
		},
	},
	{
		model.PermissionEnv,
		permissionRule{
			propKeys:     []string{"env", "environment", "envvar"},
			descKeywords: []string{"environment variable", "env var", "process env"},
		},
	},
	{
		model.PermissionHTTP,
		permissionRule{
			propKeys:     []string{"headers", "method", "body", "payload"},
			descKeywords: []string{"http request", "api call", "rest", "webhook"},
		},
	},
}

// inferPermissions inspects a tool's schema properties, description, and name to
// derive a best-effort list of Permissions.
func inferPermissions(t Tool) []model.Permission {
	descLower := strings.ToLower(t.Description)
	nameLower := strings.ToLower(t.Name)

	seen := map[model.Permission]bool{}
	var perms []model.Permission

	add := func(p model.Permission) {
		if !seen[p] {
			seen[p] = true
			perms = append(perms, p)
		}
	}

	for _, entry := range permissionRules {
		// Check schema property names
		for propKey := range t.InputSchema.Properties {
			propLower := strings.ToLower(propKey)
			for _, ruleKey := range entry.rule.propKeys {
				if propLower == ruleKey || strings.Contains(propLower, ruleKey) {
					add(entry.permission)
				}
			}
		}
		// Check description keywords
		for _, kw := range entry.rule.descKeywords {
			if strings.Contains(descLower, kw) {
				add(entry.permission)
			}
		}
		// Check tool name keywords
		for _, kw := range entry.rule.nameKeywords {
			if strings.Contains(nameLower, kw) {
				add(entry.permission)
			}
		}
	}
	return perms
}
