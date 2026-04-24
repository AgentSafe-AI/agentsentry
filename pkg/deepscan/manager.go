//go:build cgo
// +build cgo

package deepscan

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/pterm/pterm"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	"github.com/yalue/onnxruntime_go"

	"github.com/AgentSafe-AI/tooltrust-scanner/internal/userhome"
)

// Real ONNX and tokenizer URLs for Phase 3 (all-MiniLM-L6-v2 quantized).
const (
	modelURL     = "https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/onnx/model_quantized.onnx"
	tokenizerURL = "https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/tokenizer.json"
)

var (
	// IsInitialized is set to true if ONNX and the models are successfully loaded.
	IsInitialized bool

	// Global Inference Resources.
	session         *onnxruntime_go.AdvancedSession
	onnxTokenizer   *tokenizer.Tokenizer
	InInputIds      *onnxruntime_go.Tensor[int64]
	InAttentionMask *onnxruntime_go.Tensor[int64]
	InTokenTypeIds  *onnxruntime_go.Tensor[int64]
	OutHiddenState  *onnxruntime_go.Tensor[float32]

	// InferenceMutex prevents concurrent access to the shared tensors.
	InferenceMutex sync.Mutex

	// Precomputed embeddings for high-risk inputs.
	PrecomputedAttackEmbeddings [][]float32
)

// Init checks for the ONNX shared library, downloads ML models if missing, and initializes the ONNX runtime.
// If the shared library is missing, it returns an error gracefully so the engine can fallback to Regex.
func Init(ctx context.Context) error {
	// Developers need to install the ONNX Runtime Shared Library locally.
	//
	// macOS: brew install onnxruntime (typically installs to /opt/homebrew/lib/libonnxruntime.dylib)
	// Linux: Download .so from GitHub releases and place in /usr/lib or set LD_LIBRARY_PATH.
	// Windows: Download .dll from GitHub releases and place in C:\Windows\System32 or in the app dir.

	onnxLibPath := getONNXSharedLibraryPath()
	if onnxLibPath == "" || !fileExists(onnxLibPath) {
		return fmt.Errorf("ONNX shared library not found. Falling back to pure regex mode. Please install onnxruntime (e.g., brew install onnxruntime)")
	}

	onnxruntime_go.SetSharedLibraryPath(onnxLibPath)
	if err := onnxruntime_go.InitializeEnvironment(); err != nil {
		return fmt.Errorf("failed to initialize ONNX environment: %w", err)
	}
	// Note: We don't defer DestroyEnvironment because we want to keep it alive during the CLI run.

	modelPath, tokenizerPath, err := EnsureModels(ctx)
	if err != nil {
		return err
	}

	// Load Tokenizer
	tk, err := pretrained.FromFile(tokenizerPath)
	if err != nil {
		return fmt.Errorf("failed to load tokenizer: %w", err)
	}
	onnxTokenizer = tk

	// Allocate global reusable tensors.
	// miniLM outputs shape [1, seq_length, 384]
	shape := onnxruntime_go.NewShape(1, 128)
	InInputIds, err = onnxruntime_go.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to allocate input_ids tensor: %w", err)
	}

	InAttentionMask, err = onnxruntime_go.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to allocate attention_mask tensor: %w", err)
	}

	InTokenTypeIds, err = onnxruntime_go.NewEmptyTensor[int64](shape)
	if err != nil {
		return fmt.Errorf("failed to allocate token_type_ids tensor: %w", err)
	}

	outShape := onnxruntime_go.NewShape(1, 128, 384)
	OutHiddenState, err = onnxruntime_go.NewEmptyTensor[float32](outShape)
	if err != nil {
		return fmt.Errorf("failed to allocate last_hidden_state tensor: %w", err)
	}

	inNames := []string{"input_ids", "attention_mask", "token_type_ids"}
	outNames := []string{"last_hidden_state"}
	ins := []onnxruntime_go.Value{InInputIds, InAttentionMask, InTokenTypeIds}
	outs := []onnxruntime_go.Value{OutHiddenState}

	s, err := onnxruntime_go.NewAdvancedSession(modelPath, inNames, outNames, ins, outs, nil)
	if err != nil {
		return fmt.Errorf("failed to create ONNX Advanced Session: %w", err)
	}
	session = s

	// Precompute Attack Corpus
	if err := PrecomputeAttackCorpus(); err != nil {
		return fmt.Errorf("failed to precompute attack corpus embeddings: %w", err)
	}

	IsInitialized = true
	pterm.Info.Println("🧪 ONNX ML Engine active (Semantic Inference via all-MiniLM-L6-v2)")
	return nil
}

func getONNXSharedLibraryPath() string {
	switch runtime.GOOS {
	case "darwin":
		if fileExists("/opt/homebrew/lib/libonnxruntime.dylib") {
			return "/opt/homebrew/lib/libonnxruntime.dylib"
		}
		if fileExists("/usr/local/lib/libonnxruntime.dylib") {
			return "/usr/local/lib/libonnxruntime.dylib"
		}
		return "libonnxruntime.dylib"
	case "linux":
		if fileExists("/usr/lib/libonnxruntime.so") {
			return "/usr/lib/libonnxruntime.so"
		}
		if fileExists("/usr/local/lib/libonnxruntime.so") {
			return "/usr/local/lib/libonnxruntime.so"
		}
		return "libonnxruntime.so"
	case "windows":
		return "onnxruntime.dll"
	default:
		return ""
	}
}

// EnsureModels downloads the required ONNX and tokenizer files if they don't exist.
// Returns the absolute paths to the model and tokenizer, or an error.
func EnsureModels(ctx context.Context) (modelPath, tokenizerPath string, err error) {
	home, err := userhome.Resolve()
	if err != nil {
		return "", "", fmt.Errorf("unable to determine user home directory: %w", err)
	}

	modelDir := filepath.Join(home, ".tooltrust", "models")
	if mkdirErr := os.MkdirAll(modelDir, 0o755); mkdirErr != nil {
		return "", "", fmt.Errorf("failed to create models directory %s: %w", modelDir, mkdirErr)
	}

	modelPath = filepath.Join(modelDir, "model.onnx")
	tokenizerPath = filepath.Join(modelDir, "tokenizer.json")

	// If already downloaded, fast-path out safely.
	if fileExists(modelPath) && fileExists(tokenizerPath) {
		return modelPath, tokenizerPath, nil
	}

	dlCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	spinner, err := pterm.DefaultSpinner.Start("Downloading deep-scan ML models (~22MB quantized ONNX model)...")
	if err != nil {
		return "", "", fmt.Errorf("failed to start pterm spinner: %w", err)
	}

	if err := downloadFile(dlCtx, modelURL, modelPath); err != nil {
		spinner.Fail("Failed to download ONNX model")
		return "", "", fmt.Errorf("failed to download model: %w", err)
	}

	if err := downloadFile(dlCtx, tokenizerURL, tokenizerPath); err != nil {
		spinner.Fail("Failed to download tokenizer")
		return "", "", fmt.Errorf("failed to download tokenizer: %w", err)
	}

	spinner.Success("Deep-scan models loaded!")
	return modelPath, tokenizerPath, nil
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
