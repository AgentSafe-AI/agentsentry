package sourcedetect

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectEmbeddedMCP_PositiveFixtures(t *testing.T) {
	cases := []struct {
		name     string
		fixture  string
		language string
	}{
		{"go", "go-embedded", "go"},
		{"go-mark3labs", "go-mark3labs", "go"},
		{"python", "python-fastmcp", "python"},
		{"ts", "ts-mcp-server", "typescript"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join("testdata", "fixtures", tc.fixture)
			got, err := DetectEmbeddedMCP(root, Options{})
			require.NoError(t, err)
			require.True(t, got.HasEmbeddedMCP)
			require.NotEmpty(t, got.Findings)
			assert.Equal(t, "AS-018", got.Findings[0].RuleID)
			require.NotEmpty(t, got.Detection.Matches)
			assert.Equal(t, tc.language, got.Detection.Matches[0].Language)
		})
	}
}

func TestDetectEmbeddedMCP_CoOccurrenceRequired(t *testing.T) {
	cases := []string{"go-import-only", "go-init-only"}
	for _, fixture := range cases {
		t.Run(fixture, func(t *testing.T) {
			got, err := DetectEmbeddedMCP(filepath.Join("testdata", "fixtures", fixture), Options{})
			require.NoError(t, err)
			assert.False(t, got.HasEmbeddedMCP)
			assert.Empty(t, got.Findings)
		})
	}
}

func TestDetectEmbeddedMCP_SkipAndIgnoreRules(t *testing.T) {
	cases := []string{"go-vendor-skip", "go-test-skip", "docs-snippet-skip", "go-ignore-skip"}
	for _, fixture := range cases {
		t.Run(fixture, func(t *testing.T) {
			got, err := DetectEmbeddedMCP(filepath.Join("testdata", "fixtures", fixture), Options{})
			require.NoError(t, err)
			assert.False(t, got.HasEmbeddedMCP)
		})
	}
}

func TestDetectEmbeddedMCP_AS019RouteAuthAsymmetry(t *testing.T) {
	got, err := DetectEmbeddedMCP(filepath.Join("testdata", "fixtures", "go-gin-auth-asymmetry"), Options{})
	require.NoError(t, err)
	require.True(t, got.HasEmbeddedMCP)
	require.Len(t, got.Detection.RouteFindings, 1)
	assert.Equal(t, "/mcp", got.Detection.RouteFindings[0].Authenticated.Path)
	assert.Equal(t, "/mcp_message", got.Detection.RouteFindings[0].Unauthenticated.Path)
	require.NotNil(t, got.Detection.RouteFindings[0].FailOpenEvidence)

	var found bool
	for _, issue := range got.Findings {
		if issue.RuleID == "AS-019" {
			found = true
			assert.Equal(t, "CRITICAL", string(issue.Severity))
			assert.Contains(t, issue.Description, "/mcp_message")
		}
	}
	assert.True(t, found, "expected AS-019 finding")
}

func TestDetectEmbeddedMCP_AS019NoFalsePositiveWhenAuthConsistent(t *testing.T) {
	got, err := DetectEmbeddedMCP(filepath.Join("testdata", "fixtures", "go-gin-auth-consistent"), Options{})
	require.NoError(t, err)
	require.True(t, got.HasEmbeddedMCP)
	assert.Empty(t, got.Detection.RouteFindings)
	for _, issue := range got.Findings {
		assert.NotEqual(t, "AS-019", issue.RuleID)
	}
}
