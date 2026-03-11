package deepscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/pterm/pterm"
)

// Dummy URLs for Phase 1.
const (
	modelURL  = "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/README.md" // replace when model is ready
	corpusURL = "https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/LICENSE"   // replace when corpus is ready
)

// EnsureModels checks for the local deep-scan ML artifacts.
// If they do not exist, it securely downloads them while displaying a pterm spinner.
func EnsureModels(ctx context.Context) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home dir: %w", err)
	}

	modelDir := filepath.Join(home, ".tooltrust", "models")
	if mkdirErr := os.MkdirAll(modelDir, 0o755); mkdirErr != nil {
		return fmt.Errorf("failed to create models directory %s: %w", modelDir, mkdirErr)
	}

	modelPath := filepath.Join(modelDir, "model.onnx")
	corpusPath := filepath.Join(modelDir, "corpus.json")

	// If already downloaded, fast-path out safely.
	if fileExists(modelPath) && fileExists(corpusPath) {
		return nil
	}

	// Wait up to 2 minutes for downloads.
	dlCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	spinner, err := pterm.DefaultSpinner.Start("Downloading deep-scan ML models (22MB)...")
	if err != nil {
		return fmt.Errorf("failed to start pterm spinner: %w", err)
	}

	if err := downloadFile(dlCtx, modelURL, modelPath); err != nil {
		spinner.Fail("Failed to download model")
		return fmt.Errorf("model download failed: %w", err)
	}

	if err := downloadFile(dlCtx, corpusURL, corpusPath); err != nil {
		spinner.Fail("Failed to download corpus")
		return fmt.Errorf("corpus download failed: %w", err)
	}

	spinner.Success("Deep-scan models loaded!")
	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func downloadFile(ctx context.Context, url, targetPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer func() {
		closeErr := resp.Body.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(targetPath) //nolint:gosec // user local home directory setup
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() {
		closeErr := out.Close()
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed during file download completion: %w", err)
	}
	return nil
}
