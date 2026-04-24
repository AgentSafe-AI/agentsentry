package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestDoSChecker_NoRiskyPermission_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "math_tool",
		Description: "Performs arithmetic operations.",
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestDoSChecker_NetworkPermission_NoRateLimit_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "fetch_url",
		Description: "Fetches a remote URL.",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-011", issues[0].RuleID)
	assert.Equal(t, "MISSING_RATE_LIMIT", issues[0].Code)
	assert.Equal(t, model.SeverityLow, issues[0].Severity)
}

func TestDoSChecker_NetworkPermission_WithRateLimitMetadata_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "fetch_url",
		Description: "Fetches a remote URL.",
		Permissions: []model.Permission{model.PermissionNetwork},
		Metadata:    map[string]any{"rate_limit": 60},
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestDoSChecker_NetworkPermission_WithTimeoutSchema_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "http_client",
		Permissions: []model.Permission{model.PermissionHTTP},
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"url":     {Type: "string"},
				"timeout": {Type: "integer"},
			},
		},
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestDoSChecker_ExecPermission_NoRateLimit_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_command",
		Description: "Executes a shell command.",
		Permissions: []model.Permission{model.PermissionExec},
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
	assert.Equal(t, "AS-011", issues[0].RuleID)
}

func TestDoSChecker_MaxRetriesMetadata_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "resilient_http",
		Permissions: []model.Permission{model.PermissionHTTP},
		Metadata:    map[string]any{"max_retries": 3},
	}
	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestEngine_AS011_NetworkNoRateLimit(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "raw_http",
		Permissions: []model.Permission{model.PermissionNetwork},
	}
	eng_e6aadc, _ := analyzer.NewEngine(false, "")
	report := eng_e6aadc.Scan(tool)
	assert.True(t, report.HasFinding("AS-011"))
}

func TestDoSChecker_NestedTimeoutSchema_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "nested_http_client",
		Permissions: []model.Permission{model.PermissionHTTP},
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"request": {
					Type: "object",
					Properties: map[string]jsonschema.Property{
						"timeout_ms": {Type: "integer"},
					},
				},
			},
		},
	}

	issues, err := analyzer.NewDoSResilienceChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}
