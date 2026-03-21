package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestAdapter_Protocol(t *testing.T) {
	a := mcp.NewAdapter()
	assert.Equal(t, model.ProtocolMCP, a.Protocol())
}

func TestAdapter_Parse_BasicTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "read_file",
				Description: "Read the contents of a file from the filesystem",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"path": {Type: "string", Description: "absolute file path"},
					},
					Required: []string{"path"},
				},
			},
		},
	})

	a := mcp.NewAdapter()
	tools, err := a.Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	tool := tools[0]
	assert.Equal(t, "read_file", tool.Name)
	assert.Equal(t, model.ProtocolMCP, tool.Protocol)
	assert.True(t, tool.InputSchema.HasProperty("path"))
	assert.Contains(t, tool.Permissions, model.PermissionFS)
}

func TestAdapter_Parse_NetworkTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "fetch_url",
				Description: "Fetch content from a remote URL over the network",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"url": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionNetwork)
}

func TestAdapter_Parse_ExecTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "run_command",
				Description: "Execute a shell command",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"command": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec)
}

func TestAdapter_Parse_MultipleTools(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "tool_a", Description: "first tool"},
			{Name: "tool_b", Description: "second tool"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Len(t, tools, 2)
}

func TestAdapter_Parse_EmptyList(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{Tools: []mcp.Tool{}})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Empty(t, tools)
}

func TestAdapter_Parse_InvalidJSON(t *testing.T) {
	_, err := mcp.NewAdapter().Parse(context.Background(), []byte("not json"))
	assert.Error(t, err)
}

func TestAdapter_Parse_PreservesRawSource(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{Name: "some_tool", Description: "desc"},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.NotEmpty(t, tools[0].RawSource)
}

func TestAdapter_Parse_EvaluateScriptInfersExec(t *testing.T) {
	// evaluate_script / execute javascript etc. must infer PermissionExec (AS-002)
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "evaluate_script",
				Description: "Evaluates JavaScript in the browser context.",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"expression": {Type: "string"},
					},
				},
			},
		},
	})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec, "evaluate_script must infer exec permission")
}

func TestAdapter_Parse_ExecuteJavascriptInDescInfersExec(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "run_in_page",
				Description: "Execute JavaScript in the page to extract data.",
			},
		},
	})
	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionExec)
}

func TestAdapter_Parse_DBTool(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "query_db",
				Description: "Run a SQL query against the database",
				InputSchema: mcp.InputSchema{
					Type: "object",
					Properties: map[string]mcp.SchemaProperty{
						"query": {Type: "string"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	assert.Contains(t, tools[0].Permissions, model.PermissionDB)
}

// TestAdapter_Parse_ArrayTypeField verifies that a JSON Schema "type" value
// encoded as an array (e.g. ["string","null"]) is accepted without error and
// that the first non-null element is used as the property type.
func TestAdapter_Parse_ArrayTypeField(t *testing.T) {
	payload := []byte(`{
		"tools": [{
			"name": "GOOGLESHEETS_ADD_SHEET",
			"description": "Add a new sheet to a spreadsheet",
			"inputSchema": {
				"type": "object",
				"properties": {
					"title":  {"type": ["string", "null"], "description": "Sheet title"},
					"hidden": {"type": ["boolean", "null"], "description": "Hide the sheet"}
				}
			}
		}]
	}`)

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "GOOGLESHEETS_ADD_SHEET", tools[0].Name)
	assert.Equal(t, "string", tools[0].InputSchema.Properties["title"].Type)
	assert.Equal(t, "boolean", tools[0].InputSchema.Properties["hidden"].Type)
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
