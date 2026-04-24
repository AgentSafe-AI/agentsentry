package sourcedetect

import (
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWalkSourceFiles_RespectsLimits(t *testing.T) {
	root := filepath.Join("testdata", "fixtures", "go-embedded")
	count, err := walkSourceFiles(root, Options{
		MaxFiles:              1,
		MaxFileSizeBytes:      1 << 20,
		MaxMatchesPerLanguage: 3,
	}, func(rel, abs string, d fs.DirEntry) error {
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestShouldIgnore(t *testing.T) {
	assert.True(t, shouldIgnore("internal/server.go", []string{"internal/*"}))
	assert.False(t, shouldIgnore("cmd/server.go", []string{"internal/*"}))
}
