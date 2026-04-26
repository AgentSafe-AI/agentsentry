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
