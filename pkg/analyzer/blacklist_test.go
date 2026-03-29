package analyzer_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/analyzer"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// newBlacklistFromJSON is a test helper that loads a BlacklistChecker from
// arbitrary JSON data without touching the embedded blacklist.json.
func newBlacklistFromJSON(t *testing.T, data []byte) *analyzer.BlacklistChecker {
	t.Helper()
	bc, err := analyzer.NewBlacklistCheckerWithDataForTest(data)
	require.NoError(t, err)
	return bc
}

func toolWithDep(name, version, ecosystem string) model.UnifiedTool {
	return model.UnifiedTool{
		Name: "test-tool",
		Metadata: map[string]any{
			"dependencies": []any{
				map[string]any{"name": name, "version": version, "ecosystem": ecosystem},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Exact version tests (litellm)
// ---------------------------------------------------------------------------

func TestBlacklist_LiteLLM_ExactVersion_Hit(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("litellm", "1.82.8", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, "AS-008", issues[0].RuleID)
	assert.Equal(t, "SUPPLY_CHAIN_BLOCK", issues[0].Code)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "litellm@1.82.8")
	assert.Contains(t, issues[0].Description, "SNYK-PYTHON-LITELLM-15762713")
	assert.Contains(t, issues[0].Description, "[BLOCK]")
	require.Len(t, issues[0].Evidence, 5)
	assert.Equal(t, "package", issues[0].Evidence[0].Kind)
	assert.Equal(t, "litellm", issues[0].Evidence[0].Value)
	assert.Equal(t, "version", issues[0].Evidence[1].Kind)
	assert.Equal(t, "1.82.8", issues[0].Evidence[1].Value)
}

func TestBlacklist_LiteLLM_OtherAffectedVersion_Hit(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("litellm", "1.82.7", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
}

func TestBlacklist_LiteLLM_SafeVersion_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("litellm", "1.83.0", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestBlacklist_LiteLLM_WrongEcosystem_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	// npm has no "litellm" entry; should not match PyPI-only blacklist entry
	tool := toolWithDep("litellm", "1.82.8", "npm")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

// ---------------------------------------------------------------------------
// Range version tests (langflow < 1.9.0)
// ---------------------------------------------------------------------------

func TestBlacklist_Langflow_RangeVersion_Hit(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("langflow", "0.9.1", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Contains(t, issues[0].Description, "CVE-2026-33017")
	assert.Contains(t, issues[0].Description, "GHSA-rvqx-wpfh-mfx7")
}

func TestBlacklist_Langflow_FixedVersion_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("langflow", "1.9.0", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestBlacklist_Langflow_NewerVersion_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("langflow", "2.0.0", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

// ---------------------------------------------------------------------------
// General behaviour
// ---------------------------------------------------------------------------

func TestBlacklist_NoDependencies_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := model.UnifiedTool{Name: "no-deps"}
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestBlacklist_EmptyDependencies_NoFinding(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := model.UnifiedTool{
		Name:     "empty-deps",
		Metadata: map[string]any{"dependencies": []any{}},
	}
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	assert.Empty(t, issues)
}

func TestBlacklist_FindingContainsLink(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	tool := toolWithDep("litellm", "1.82.8", "PyPI")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Contains(t, issues[0].Description, "security.snyk.io")
}

func TestBlacklist_HighSeverityEntry(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	// trivy-action < v0.35.0 is HIGH severity and WARN action
	tool := toolWithDep("trivy-action", "v0.34.0", "github-actions")
	issues, err := bc.Check(tool)
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityHigh, issues[0].Severity)
	assert.Equal(t, "SUPPLY_CHAIN_WARN", issues[0].Code)
	assert.Contains(t, issues[0].Description, "[WARN]")
}

func TestBlacklist_SetupTrivy_WildcardMatch(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	// setup-trivy < v0.2.6 should WARN
	for _, ver := range []string{"v0.0.1", "v0.2.0", "v0.2.5"} {
		tool := toolWithDep("setup-trivy", ver, "github-actions")
		issues, err := bc.Check(tool)
		require.NoError(t, err, "version %s", ver)
		require.Len(t, issues, 1, "version %s should be flagged (< v0.2.6)", ver)
		assert.Equal(t, "SUPPLY_CHAIN_WARN", issues[0].Code)
	}
	// setup-trivy v0.2.6+ should be clean
	for _, ver := range []string{"v0.2.6", "v0.3.0", "v1.0.0"} {
		tool := toolWithDep("setup-trivy", ver, "github-actions")
		issues, err := bc.Check(tool)
		require.NoError(t, err, "version %s", ver)
		assert.Empty(t, issues, "version %s should be safe (>= v0.2.6)", ver)
	}
}

// ---------------------------------------------------------------------------
// Custom JSON (tests internal matching logic in isolation)
// ---------------------------------------------------------------------------

func TestBlacklist_CustomJSON_ExactMatch(t *testing.T) {
	data := []byte(`[
	  {"id":"TEST-001","component":"badpkg","ecosystem":"npm",
	   "affected_versions":["1.0.0"],"action":"BLOCK","severity":"CRITICAL",
	   "reason":"Test","link":"https://example.com"}
	]`)
	bc := newBlacklistFromJSON(t, data)
	issues, err := bc.Check(toolWithDep("badpkg", "1.0.0", "npm"))
	require.NoError(t, err)
	require.Len(t, issues, 1)
	assert.Equal(t, model.SeverityCritical, issues[0].Severity)
	assert.Equal(t, "SUPPLY_CHAIN_BLOCK", issues[0].Code)
}

func TestBlacklist_CustomJSON_LessEqualRange(t *testing.T) {
	data := []byte(`[
	  {"id":"TEST-002","component":"oldpkg","ecosystem":"PyPI",
	   "affected_versions":["<= 2.0.0"],"severity":"HIGH",
	   "reason":"Test","link":"https://example.com"}
	]`)
	bc := newBlacklistFromJSON(t, data)

	hit, _ := bc.Check(toolWithDep("oldpkg", "2.0.0", "PyPI"))
	assert.Len(t, hit, 1, "2.0.0 <= 2.0.0 should match")

	miss, _ := bc.Check(toolWithDep("oldpkg", "2.0.1", "PyPI"))
	assert.Empty(t, miss, "2.0.1 > 2.0.0 should not match")
}

func TestBlacklist_Meta(t *testing.T) {
	bc := analyzer.NewBlacklistChecker()
	meta := bc.Meta()
	assert.Equal(t, "AS-008", meta.ID)
	assert.NotEmpty(t, meta.Title)
	assert.NotEmpty(t, meta.Description)
}

func TestBlacklist_Engine_Integration(t *testing.T) {
	eng, err := analyzer.NewEngine(false, "")
	require.NoError(t, err)

	tool := toolWithDep("litellm", "1.82.8", "PyPI")
	report := eng.Scan(tool)
	assert.True(t, report.HasFinding("AS-008"), "engine should surface AS-008 for litellm 1.82.8")
}
