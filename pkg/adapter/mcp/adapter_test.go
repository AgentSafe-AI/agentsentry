package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/adapter/mcp"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
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

func TestAdapter_Parse_JSONRPCListToolsResponse(t *testing.T) {
	payload := []byte(`{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"tools": [{
				"name": "read_file",
				"description": "Read a file from disk",
				"inputSchema": {
					"type": "object",
					"properties": {
						"path": {"type": "string"}
					}
				}
			}]
		}
	}`)

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	assert.Equal(t, "read_file", tools[0].Name)
	assert.Contains(t, tools[0].Permissions, model.PermissionFS)
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

func TestAdapter_Parse_PopulatesSupplyChainMetadata(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				RepoURL:     "https://github.com/example/site",
				Metadata: mcp.ToolMeta{
					Dependencies: []mcp.DependencyMetadata{
						{Name: "axios", Version: "1.14.1", Ecosystem: "npm"},
						{Name: "litellm", Version: "1.82.8", Ecosystem: "PyPI"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	meta := tools[0].Metadata
	require.NotNil(t, meta)
	assert.Equal(t, "https://github.com/example/site", meta["repo_url"])

	deps, ok := meta["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, deps, 2)
	assert.Equal(t, "axios", deps[0]["name"])
	assert.Equal(t, "1.14.1", deps[0]["version"])
	assert.Equal(t, "npm", deps[0]["ecosystem"])
}

func TestAdapter_Parse_PreservesDependencySource(t *testing.T) {
	payload := []byte(`{
		"tools": [{
			"name": "deploy_site",
			"description": "Deploy the site",
			"metadata": {
				"dependencies": [{
					"name": "axios",
					"version": "1.14.1",
					"ecosystem": "npm",
					"source": "local_lockfile"
				}]
			}
		}]
	}`)

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	deps, ok := tools[0].Metadata["dependencies"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, deps, 1)
	assert.Equal(t, "local_lockfile", deps[0]["source"])

	visibility, _ := analyzer.DependencyVisibilityForTool(tools[0])
	assert.Equal(t, "Verified from local lockfile", visibility)
}

func TestAdapter_Parse_PrefersMetadataRepoURL(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				RepoURL:     "https://github.com/example/old",
				Metadata: mcp.ToolMeta{
					RepoURL: "https://github.com/example/new",
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	require.NotNil(t, tools[0].Metadata)
	assert.Equal(t, "https://github.com/example/new", tools[0].Metadata["repo_url"])
}

func TestAdapter_Parse_EngineDetectsBlacklistedDependency(t *testing.T) {
	payload := mustMarshal(mcp.ListToolsResponse{
		Tools: []mcp.Tool{
			{
				Name:        "deploy_site",
				Description: "Deploy the site",
				Metadata: mcp.ToolMeta{
					Dependencies: []mcp.DependencyMetadata{
						{Name: "axios", Version: "1.14.1", Ecosystem: "npm"},
					},
				},
			},
		},
	})

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	engine, err := analyzer.NewEngine(false, "")
	require.NoError(t, err)

	report := engine.Scan(tools[0])
	assert.True(t, report.HasFinding("AS-008"))
	require.NotEmpty(t, report.Findings)
	assert.Contains(t, report.Findings[0].Description, "axios@1.14.1")
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

func TestAdapter_Parse_PreservesNestedSchemaAndMetadata(t *testing.T) {
	payload := []byte(`{
		"tools": [{
			"name": "deploy",
			"description": "Deploy to a remote endpoint",
			"metadata": {
				"oauth_scopes": ["repo"],
				"timeout_ms": 5000
			},
			"inputSchema": {
				"type": "object",
				"properties": {
					"auth": {
						"type": "object",
						"properties": {
							"client_secret": {"type": "string"}
						}
					},
					"request": {
						"type": "object",
						"properties": {
							"url": {"type": "string"},
							"timeout": {"type": "integer"}
						}
					}
				}
			}
		}]
	}`)

	tools, err := mcp.NewAdapter().Parse(context.Background(), payload)
	require.NoError(t, err)
	require.Len(t, tools, 1)

	tool := tools[0]
	require.NotNil(t, tool.Metadata)
	assert.Equal(t, []string{"repo"}, tool.Metadata["oauth_scopes"])
	assert.Equal(t, float64(5000), tool.Metadata["timeout_ms"])
	assert.Equal(t, 5, tool.InputSchema.PropertyCount())
	assert.Equal(t, "string", tool.InputSchema.Properties["auth"].Properties["client_secret"].Type)
	assert.Equal(t, "string", tool.InputSchema.Properties["request"].Properties["url"].Type)

	scanner, err := analyzer.NewScanner(false, "")
	require.NoError(t, err)
	score, err := scanner.Scan(context.Background(), tool)
	require.NoError(t, err)
	assertIssue := func(ruleID string) {
		t.Helper()
		for _, issue := range score.Issues {
			if issue.RuleID == ruleID {
				return
			}
		}
		t.Fatalf("expected %s in scan issues, got %#v", ruleID, score.Issues)
	}
	assertIssue("AS-005")
	assertIssue("AS-010")
	for _, issue := range score.Issues {
		require.NotEqual(t, "AS-011", issue.RuleID, "nested timeout signal should suppress AS-011")
	}
}

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
