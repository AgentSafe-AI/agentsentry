package sourcedetect

import (
	"os"
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

func TestDetectEmbeddedMCP_GoMark3LabsServer(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "server.go"), []byte(`
package main

import "github.com/mark3labs/mcp-go/server"

func main() {
	srv := server.NewMCPServer("demo", "1.0.0")
	srv.AddTool(buildTool(), handleTool)
}
`), 0o644))

	got, err := DetectEmbeddedMCP(root, Options{})
	require.NoError(t, err)
	require.True(t, got.HasEmbeddedMCP)
	require.NotEmpty(t, got.Detection.Matches)
	assert.Equal(t, "go", got.Detection.Matches[0].Language)
}

func TestDetectEmbeddedMCP_CommonJSFile(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "server.cjs"), []byte(`
const { McpServer } = require("@modelcontextprotocol/sdk/server/mcp.js");

const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("demo", {}, async () => ({}));
`), 0o644))

	got, err := DetectEmbeddedMCP(root, Options{})
	require.NoError(t, err)
	require.True(t, got.HasEmbeddedMCP)
	require.NotEmpty(t, got.Detection.Matches)
	assert.Equal(t, "typescript", got.Detection.Matches[0].Language)
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

func TestDetectEmbeddedMCP_MaxMatchesPerLanguageDoesNotHideOtherLanguages(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "server.go"), []byte(`
package main

import "github.com/modelcontextprotocol/go-sdk/mcp"

func main() {
	_ = mcp.NewServer("demo", "1.0.0")
}
`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, "server.py"), []byte(`
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")
`), 0o644))

	got, err := DetectEmbeddedMCP(root, Options{MaxMatchesPerLanguage: 1})
	require.NoError(t, err)

	languages := map[string]bool{}
	for _, match := range got.Detection.Matches {
		languages[match.Language] = true
	}
	assert.True(t, languages["go"], "expected Go match")
	assert.True(t, languages["python"], "expected Python match")
}
