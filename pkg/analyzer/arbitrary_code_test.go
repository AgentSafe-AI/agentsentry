package analyzer

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ---------------------------------------------------------------------------
// AS-006 — Arbitrary Code Execution (evaluate_script, execute javascript, etc.)
// ---------------------------------------------------------------------------

func TestArbitraryCodeChecker_EvaluateScriptInName(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "evaluate_script",
		Description: "Evaluates a script in the browser context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"), "evaluate_script in name must trigger AS-006")
	assert.GreaterOrEqual(t, report.RiskScore, 25, "must score >= 25 (CRITICAL) to prevent A/S grade")
}

func TestArbitraryCodeChecker_ExecuteJavascriptInDescription(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_in_browser",
		Description: "Execute JavaScript in the page context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_BrowserInjection(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "inject_script",
		Description: "Browser injection of arbitrary code into the target page.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_RunScriptInName(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "run_script",
		Description: "Runs a user-provided script.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_EvalInDescription(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "compute",
		Description: "Uses eval() to evaluate expressions.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_CleanTool_NoFinding(t *testing.T) {
	tool := model.UnifiedTool{
		Name:        "list_files",
		Description: "Returns a list of files in the directory.",
	}
	report := NewEngine(false).Scan(tool)
	assert.False(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_Retrieval_NoFalsePositive(t *testing.T) {
	// "retrieval" contains "eval" but must not trigger (word boundary).
	tool := model.UnifiedTool{
		Name:        "document_retrieval",
		Description: "Retrieval of documents from the index.",
	}
	report := NewEngine(false).Scan(tool)
	assert.False(t, report.HasFinding("AS-006"))
}

func TestArbitraryCodeChecker_GradeCOrWorse(t *testing.T) {
	// chrome-devtools-mcp style: evaluate_script should get at least Grade C.
	tool := model.UnifiedTool{
		Name:        "evaluate_script",
		Description: "Evaluates JavaScript expression in the browser.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
	assert.Contains(t, []model.Grade{model.GradeC, model.GradeD, model.GradeF}, report.Grade,
		"evaluate_script must not get A or B; got %s", report.Grade)
}

// ---------------------------------------------------------------------------
// Regression tests: false negatives caught by Claude Code (chrome-devtools-mcp)
// ---------------------------------------------------------------------------

func TestArbitraryCodeChecker_ChromeEvaluate_NameSuffix(t *testing.T) {
	// chrome_evaluate, cdp_evaluate — real tool names from chrome-devtools-mcp.
	for _, name := range []string{"chrome_evaluate", "cdp_evaluate", "devtools_evaluate"} {
		tool := model.UnifiedTool{
			Name:        name,
			Description: "Evaluates a JavaScript expression in the browser page context.",
		}
		report := NewEngine(false).Scan(tool)
		assert.True(t, report.HasFinding("AS-006"),
			"%q: _evaluate name suffix must trigger AS-006", name)
		assert.GreaterOrEqual(t, report.RiskScore, 25,
			"%q: must score >= 25 to prevent A/B grade", name)
	}
}

func TestArbitraryCodeChecker_NaturalLanguageEvaluatesJavaScript(t *testing.T) {
	// "Evaluates a JavaScript expression" — natural language, not exact phrase.
	tool := model.UnifiedTool{
		Name:        "chrome_runtime_evaluate",
		Description: "Evaluates a JavaScript expression in the runtime context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"),
		"'evaluates a JavaScript expression' must trigger AS-006")
}

func TestArbitraryCodeChecker_ExecuteArbitraryScripts(t *testing.T) {
	// "execute arbitrary scripts" — common in CDP tool descriptions.
	tool := model.UnifiedTool{
		Name:        "chrome_runtime_evaluate",
		Description: "Can execute arbitrary scripts in the browser context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"),
		"'execute arbitrary scripts' must trigger AS-006")
}

func TestArbitraryCodeChecker_PageEvaluate_CDPPattern(t *testing.T) {
	// page.evaluate() — Puppeteer/CDP idiom.
	tool := model.UnifiedTool{
		Name:        "puppeteer_run",
		Description: "Runs page.evaluate() to execute JavaScript in browser context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"),
		"page.evaluate() must trigger AS-006")
}

func TestArbitraryCodeChecker_PuppeteerEvaluate_NameSuffix(t *testing.T) {
	// puppeteer_evaluate — name ends with _evaluate.
	tool := model.UnifiedTool{
		Name:        "puppeteer_evaluate",
		Description: "Runs page.evaluate() to execute JavaScript in browser context.",
	}
	report := NewEngine(false).Scan(tool)
	assert.True(t, report.HasFinding("AS-006"))
	assert.Contains(t, []model.Grade{model.GradeC, model.GradeD, model.GradeF}, report.Grade,
		"puppeteer_evaluate must not get A or B; got %s", report.Grade)
}
