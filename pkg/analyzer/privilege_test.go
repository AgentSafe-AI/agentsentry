package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func TestPrivilegeChecker_NoMetadata_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{Name: "safe_tool", Description: "Does something safe."}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPrivilegeChecker_BroadScope_Admin(t *testing.T) {
	tool := model.UnifiedTool{
		Name:     "github_tool",
		Metadata: map[string]any{"oauth_scopes": []any{"admin", "read:user"}},
	}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "AS-005", issues[0].RuleID)
	assert.Equal(t, "BROAD_OAUTH_SCOPE", issues[0].Code)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
}

func TestPrivilegeChecker_BroadScope_WriteWildcard(t *testing.T) {
	tool := model.UnifiedTool{
		Name:     "repo_tool",
		Metadata: map[string]any{"oauth_scopes": []any{"repo:write"}},
	}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
	assert.Equal(t, "AS-005", issues[0].RuleID)
}

func TestPrivilegeChecker_NarrowScope_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:     "read_only_tool",
		Metadata: map[string]any{"oauth_scopes": []any{"read:user", "gist"}},
	}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestPrivilegeChecker_DescriptionEscalation(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "install_tool",
		Description: "Installs software by running commands as sudo.",
	}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	require.NotEmpty(t, issues)
	assert.Equal(t, "AS-005", issues[0].RuleID)
	assert.Equal(t, "PRIVILEGE_ESCALATION", issues[0].Code)
}

func TestPrivilegeChecker_Impersonation(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "auth_tool",
		Description: "This tool can impersonate other users.",
	}
	issues, err := analyzer.NewPrivilegeEscalationChecker().Check(tool)
	require.NoError(t, err)
	assert.NotEmpty(t, issues)
	assert.Equal(t, "AS-005", issues[0].RuleID)
}

func TestEngine_AS005_BroadOAuthScope(t *testing.T) {
	tool := model.UnifiedTool{
		Name:     "admin_tool",
		Metadata: map[string]any{"oauth_scopes": []any{"admin"}},
	}
	report := analyzer.NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-005"))
}
