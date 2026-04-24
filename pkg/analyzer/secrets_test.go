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

func TestSecretChecker_PassSubstringFalsePositives_NoFinding(t *testing.T) {
	// "pass" as a bare substring must NOT trigger — passenger, bypass, passthrough,
	// pass_count are all legitimate parameter names that contain "pass".
	for _, propName := range []string{"passenger", "bypass", "passthrough", "pass_count", "compass"} {
		tool := model.UnifiedTool{
			Name: "transit_tool",
			InputSchema: jsonschema.Schema{
				Properties: map[string]jsonschema.Property{
					propName: {Type: "string"},
				},
			},
		}
		issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
		require.NoError(t, err)
		assert.Empty(t, issues, "param %q must not trigger AS-010", propName)
	}
}

func TestSecretChecker_PaginationTokens_NoFalsePositive(t *testing.T) {
	// pageToken, next_token, cursor are pagination cursors, not credentials.
	for _, propName := range []string{"pageToken", "page_token", "next_token", "nextToken", "cursor", "next_cursor", "continuation_token", "sync_token"} {
		tool := model.UnifiedTool{
			Name: "list_items",
			InputSchema: jsonschema.Schema{
				Properties: map[string]jsonschema.Property{
					propName: {Type: "string"},
				},
			},
		}
		issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
		require.NoError(t, err)
		assert.Empty(t, issues, "param %q must not trigger AS-010 (pagination cursor, not secret)", propName)
	}
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
	eng_936989, _ := analyzer.NewEngine(false, "")
	report := eng_936989.Scan(tool)
	assert.True(t, report.HasFinding("AS-010"))
}

func TestSecretChecker_NestedSecretParam_Finding(t *testing.T) {
	tool := model.UnifiedTool{
		Name: "nested_creds_tool",
		InputSchema: jsonschema.Schema{
			Properties: map[string]jsonschema.Property{
				"auth": {
					Type: "object",
					Properties: map[string]jsonschema.Property{
						"client_secret": {Type: "string"},
					},
				},
			},
		},
	}

	issues, err := analyzer.NewSecretHandlingChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Contains(t, issues[0].Location, "auth.client_secret")
}
