package sourcedetect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var skipDirs = map[string]struct{}{
	".git": {}, "vendor": {}, "node_modules": {}, "target": {}, "dist": {}, "build": {},
	"docs": {}, "examples": {}, "example": {}, "__pycache__": {}, ".venv": {}, "venv": {},
	"tests": {}, "__tests__": {},
}

var skipExtensions = map[string]struct{}{
	".md": {}, ".rst": {}, ".txt": {}, ".lock": {}, ".sum": {}, ".mod": {},
}

func walkSourceFiles(root string, opts Options, visit func(rel, abs string, d fs.DirEntry) error) (int, error) {
	ignorePatterns := loadIgnorePatterns(root)
	filesScanned := 0

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if path == root {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return fmt.Errorf("compute relative path for %s: %w", path, relErr)
		}
		rel = filepath.ToSlash(rel)

		if shouldIgnore(rel, ignorePatterns) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}

		if filesScanned >= opts.MaxFiles {
			return fs.SkipAll
		}
		if shouldSkipFile(rel) {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.Size() > opts.MaxFileSizeBytes {
			return nil
		}

		filesScanned++
		return visit(rel, path, d)
	})
	if err == fs.SkipAll {
		return filesScanned, nil
	}
	if err != nil {
		return filesScanned, fmt.Errorf("walk source files: %w", err)
	}
	return filesScanned, nil
}

func shouldSkipFile(rel string) bool {
	base := filepath.Base(rel)
	ext := strings.ToLower(filepath.Ext(base))
	if _, skip := skipExtensions[ext]; skip {
		return true
	}

	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py"),
		strings.HasSuffix(base, "_test.py"),
		strings.HasSuffix(base, ".test.ts"),
		strings.HasSuffix(base, ".spec.ts"),
		strings.HasSuffix(base, ".test.tsx"),
		strings.HasSuffix(base, ".spec.tsx"),
		strings.HasSuffix(base, ".test.js"),
		strings.HasSuffix(base, ".spec.js"):
		return true
	}

	return false
}

func loadIgnorePatterns(root string) []string {
	path := filepath.Join(root, ".tooltrust-ignore")
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var patterns []string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, filepath.ToSlash(line))
	}
	return patterns
}

func shouldIgnore(rel string, patterns []string) bool {
	for _, pattern := range patterns {
		ok, err := filepath.Match(pattern, rel)
		if err == nil && ok {
			return true
		}
		if strings.HasSuffix(pattern, "/") && strings.HasPrefix(rel, strings.TrimSuffix(pattern, "/")+"/") {
			return true
		}
	}
	return false
}
