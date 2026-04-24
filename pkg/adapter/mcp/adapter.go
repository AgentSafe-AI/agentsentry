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
	var resp listToolsEnvelope
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("mcp adapter: failed to parse tools/list response: %w", err)
	}
	toolList := resp.Tools
	if toolList == nil && resp.Result != nil {
		toolList = resp.Result.Tools
	}

	tools := make([]model.UnifiedTool, 0, len(toolList))
	for i := range toolList {
		t := toolList[i]
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
			Metadata:    buildMetadata(t),
		}
		unified.Permissions = inferPermissions(t)
		tools = append(tools, unified)
	}
	return tools, nil
}

func buildMetadata(t Tool) map[string]any {
	meta := map[string]any{}

	mergeToolMeta(meta, t.Meta)
	mergeToolMeta(meta, t.Metadata)

	if _, ok := meta["repo_url"]; !ok {
		repoURL := strings.TrimSpace(t.RepoURL)
		if repoURL != "" {
			meta["repo_url"] = repoURL
		}
	}

	if len(meta) == 0 {
		return nil
	}
	return meta
}

func mergeToolMeta(meta map[string]any, toolMeta ToolMeta) {
	for key, value := range toolMeta.Extra {
		meta[key] = value
	}

	repoURL := strings.TrimSpace(toolMeta.RepoURL)
	if repoURL != "" {
		meta["repo_url"] = repoURL
	}

	if len(toolMeta.OAuthScopes) > 0 {
		scopes := make([]string, len(toolMeta.OAuthScopes))
		copy(scopes, toolMeta.OAuthScopes)
		meta["oauth_scopes"] = scopes
	}

	if len(toolMeta.Dependencies) > 0 {
		deps := make([]map[string]any, 0, len(toolMeta.Dependencies))
		for _, dep := range toolMeta.Dependencies {
			if dep.Name == "" || dep.Version == "" || dep.Ecosystem == "" {
				continue
			}
			entry := map[string]any{
				"name":      dep.Name,
				"version":   dep.Version,
				"ecosystem": dep.Ecosystem,
			}
			if dep.Source != "" {
				entry["source"] = dep.Source
			}
			deps = append(deps, entry)
		}
		if len(deps) > 0 {
			meta["dependencies"] = deps
		}
	}
}

// convertSchema maps an MCP InputSchema to the internal jsonschema.Schema.
func convertSchema(s InputSchema) jsonschema.Schema {
	props := make(map[string]jsonschema.Property, len(s.Properties))
	for k, v := range s.Properties {
		props[k] = convertProperty(v)
	}
	return jsonschema.Schema{
		Type:        string(s.Type),
		Description: s.Description,
		Properties:  props,
		Required:    s.Required,
		Items:       convertPropertyPtr(s.Items),
	}
}

func convertProperty(p SchemaProperty) jsonschema.Property {
	props := make(map[string]jsonschema.Property, len(p.Properties))
	for k, v := range p.Properties {
		props[k] = convertProperty(v)
	}
	return jsonschema.Property{
		Type:        string(p.Type),
		Description: p.Description,
		Enum:        p.Enum,
		Properties:  props,
		Required:    p.Required,
		Items:       convertPropertyPtr(p.Items),
	}
}

func convertPropertyPtr(p *SchemaProperty) *jsonschema.Property {
	if p == nil {
		return nil
	}
	prop := convertProperty(*p)
	return &prop
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
		walkInputSchemaProperties(t.InputSchema, func(propPath string, _ SchemaProperty) {
			propLower := strings.ToLower(propPath)
			for _, ruleKey := range entry.rule.propKeys {
				if propLower == ruleKey || strings.Contains(propLower, ruleKey) {
					add(entry.permission)
				}
			}
		})
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

func walkInputSchemaProperties(schema InputSchema, fn func(path string, prop SchemaProperty)) {
	for name, prop := range schema.Properties {
		walkSchemaProperty(name, prop, fn)
	}
	if schema.Items != nil {
		walkSchemaProperty("[]", *schema.Items, fn)
	}
}

func walkSchemaProperty(prefix string, prop SchemaProperty, fn func(path string, prop SchemaProperty)) {
	if fn != nil {
		fn(prefix, prop)
	}
	for name, child := range prop.Properties {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		walkSchemaProperty(path, child, fn)
	}
	if prop.Items != nil {
		itemPath := prefix + "[]"
		walkSchemaProperty(itemPath, *prop.Items, fn)
	}
}
