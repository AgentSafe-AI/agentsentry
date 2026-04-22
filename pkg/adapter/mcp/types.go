// Package mcp provides an Adapter that parses MCP tools/list responses.
package mcp

import (
	"encoding/json"
	"fmt"
)

// FlexType is a JSON Schema "type" value that accepts either a plain string
// ("string") or an array of strings (["string", "null"]).
// When an array is encountered the first non-"null" element is used; if all
// elements are "null" the value is set to "null".
type FlexType string

// UnmarshalJSON implements json.Unmarshaler for FlexType.
func (ft *FlexType) UnmarshalJSON(b []byte) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("FlexType: %w", err)
		}
		*ft = FlexType(s)
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return fmt.Errorf("FlexType: %w", err)
		}
		for _, v := range arr {
			if v != "null" {
				*ft = FlexType(v)
				return nil
			}
		}
		*ft = "null"
		return nil
	}
	return nil
}

// ListToolsResponse is the top-level MCP tools/list wire format.
type ListToolsResponse struct {
	Tools []Tool `json:"tools"`
}

// Tool is a single tool entry in the MCP tools/list response.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
	RepoURL     string      `json:"repo_url,omitempty"`
	Metadata    ToolMeta    `json:"metadata,omitempty"`
}

// ToolMeta carries optional metadata used by downstream analyzers.
type ToolMeta struct {
	RepoURL      string               `json:"repo_url,omitempty"`
	Dependencies []DependencyMetadata `json:"dependencies,omitempty"`
	OAuthScopes  []string             `json:"oauth_scopes,omitempty"`
	Extra        map[string]any       `json:"-"`
}

// UnmarshalJSON preserves unknown metadata fields so downstream analyzers can inspect them.
func (m *ToolMeta) UnmarshalJSON(data []byte) error {
	type alias ToolMeta
	var parsed alias
	if err := json.Unmarshal(data, &parsed); err != nil {
		return fmt.Errorf("ToolMeta: unmarshal known fields: %w", err)
	}

	var extra map[string]any
	if err := json.Unmarshal(data, &extra); err != nil {
		return fmt.Errorf("ToolMeta: unmarshal extra fields: %w", err)
	}
	delete(extra, "repo_url")
	delete(extra, "dependencies")
	delete(extra, "oauth_scopes")

	*m = ToolMeta(parsed)
	if len(extra) > 0 {
		m.Extra = extra
	}
	return nil
}

// MarshalJSON keeps the preserved metadata keys when fixtures/tests re-encode ToolMeta.
func (m ToolMeta) MarshalJSON() ([]byte, error) {
	out := map[string]any{}
	for key, value := range m.Extra {
		out[key] = value
	}
	if m.RepoURL != "" {
		out["repo_url"] = m.RepoURL
	}
	if len(m.Dependencies) > 0 {
		out["dependencies"] = m.Dependencies
	}
	if len(m.OAuthScopes) > 0 {
		out["oauth_scopes"] = m.OAuthScopes
	}
	data, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("ToolMeta: marshal: %w", err)
	}
	return data, nil
}

// DependencyMetadata is the MCP-side representation of a package dependency.
type DependencyMetadata struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// InputSchema is the JSON Schema fragment embedded in an MCP Tool.
type InputSchema struct {
	Type        FlexType                  `json:"type,omitempty"`
	Properties  map[string]SchemaProperty `json:"properties,omitempty"`
	Required    []string                  `json:"required,omitempty"`
	Description string                    `json:"description,omitempty"`
	Items       *SchemaProperty           `json:"items,omitempty"`
}

// SchemaProperty describes a single property within an InputSchema.
type SchemaProperty struct {
	Type        FlexType                  `json:"type,omitempty"`
	Description string                    `json:"description,omitempty"`
	Enum        []any                     `json:"enum,omitempty"`
	Properties  map[string]SchemaProperty `json:"properties,omitempty"`
	Required    []string                  `json:"required,omitempty"`
	Items       *SchemaProperty           `json:"items,omitempty"`
}
