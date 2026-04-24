package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestPermissionChecker_NoPermissions(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "greet",
		Description: "Say hello to the user.",
		Permissions: nil,
	}
	checker := analyzer.NewPermissionChecker()
	issues, err := checker.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPermissionChecker_ExecPermission_HighRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs an arbitrary script.",
		Permissions: []model.Permission{model.PermissionExec},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "HIGH_RISK_PERMISSION", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
	require.Len(t, issues[0].Evidence, 1)
	assert.Equal(t, "permission", issues[0].Evidence[0].Kind)
	assert.Equal(t, "exec", issues[0].Evidence[0].Value)
}

func TestPermissionChecker_DBPermission_MediumRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "query",
		Permissions: []model.Permission{model.PermissionDB},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, model.SeverityMedium, issues[0].Severity)
}

func TestPermissionChecker_MultipleHighRisk(t *testing.T) {
	tool := model.UnifiedTool{
		Permissions: []model.Permission{model.PermissionExec, model.PermissionNetwork},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	assert.Len(t, issues, 2)
}

func TestPermissionChecker_SchemaPropCountNote(t *testing.T) {
	props := make(map[string]jsonschema.Property)
	for i := range 15 {
		props[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}
	tool := model.UnifiedTool{
		InputSchema: jsonschema.Schema{Properties: props},
	}
	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)
	var found bool
	for _, iss := range issues {
		if iss.Code == "LARGE_INPUT_SURFACE" {
			found = true
			require.Len(t, iss.Evidence, 2)
			assert.Equal(t, "schema_property_count", iss.Evidence[0].Kind)
			assert.Equal(t, "15", iss.Evidence[0].Value)
		}
	}
	assert.True(t, found, "expected LARGE_INPUT_SURFACE issue for schemas with >10 properties")
}

func TestPermissionChecker_CountsNestedSchemaProps(t *testing.T) {
	nested := map[string]jsonschema.Property{}
	for i := range 11 {
		nested[string(rune('a'+i))] = jsonschema.Property{Type: "string"}
	}

	tool := model.UnifiedTool{
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"request": {
					Type:       "object",
					Properties: nested,
				},
			},
		},
	}

	issues, err := analyzer.NewPermissionChecker().Check(tool)
	require.NoError(t, err)

	var found bool
	for _, issue := range issues {
		if issue.Code == "LARGE_INPUT_SURFACE" {
			found = true
			assert.Equal(t, "12", issue.Evidence[0].Value)
		}
	}
	assert.True(t, found, "expected nested schema properties to count toward LARGE_INPUT_SURFACE")
}
