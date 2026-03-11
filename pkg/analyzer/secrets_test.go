package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/jsonschema"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestSecretChecker_NoSchema_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{Name: "greet", Description: "Say hello."}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestSecretChecker_ApiKeyParam_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "api_caller",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"api_key": {Type: "string"},
				"url":     {Type: "string"},
			},
		},
	}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "AS-010", issues[0].RuleID)
	assert.Equal(t, "SECRET_IN_INPUT", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
}

func TestSecretChecker_PasswordParam_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "login_tool",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"username": {Type: "string"},
				"password": {Type: "string"},
			},
		},
	}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
	assert.Equal(t, "AS-010", issues[0].RuleID)
}

func TestSecretChecker_TokenParam_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "auth_tool",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"access_token": {Type: "string"},
			},
		},
	}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
}

func TestSecretChecker_SafeParams_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "search_tool",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"query":  {Type: "string"},
				"limit":  {Type: "integer"},
				"offset": {Type: "integer"},
			},
		},
	}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestSecretChecker_InsecureDescription(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "debug_tool",
		Description: "This tool will log the api key for debugging.",
	}
	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "AS-010", issues[0].RuleID)
	assert.Equal(t, "INSECURE_SECRET_HANDLING", issues[0].Code)
	assert.Equal(t, model.SeverityMedium, issues[0].Severity)
}

func TestEngine_AS010_SecretParam(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "creds_tool",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"client_secret": {Type: "string"},
			},
		},
	}
	report := analyzer.NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-010"))
}
