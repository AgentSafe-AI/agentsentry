// Package analyzer provides the scanning engine that runs a set of checkers
// over a UnifiedTool and produces a RiskScore.
package analyzer

import (
	"context"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// ScanReport is the high-level result returned by Engine.Scan.
// It exposes the numeric RiskScore and the full slice of Findings so callers
// can filter by RuleID (e.g. "AS-001") without unpacking a model.RiskScore.
type ScanReport struct {
	ToolName  string
	RiskScore int
	Grade     model.Grade
	Findings  []model.Issue
}

// HasFinding reports whether the report contains at least one finding with the
// given RuleID.
func (r ScanReport) HasFinding(ruleID string) bool {
	for _, f := range r.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// Engine is the public-facing scanner.  It wraps the lower-level Scanner and
// exposes a context-free Scan method suitable for direct use in tests and CLI
// one-shot invocations.
type Engine struct {
	scanner *Scanner
}

// NewEngine returns an Engine pre-wired with all default checkers:
//   - AS-001  Tool Poisoning           (PoisoningChecker)
//   - AS-002  Permission Surface       (PermissionChecker)
//   - AS-003  Scope Mismatch           (ScopeChecker)
//   - AS-004  Supply Chain CVE         (SupplyChainChecker)
//   - AS-005  Privilege Escalation     (PrivilegeEscalationChecker)
//   - AS-006  Arbitrary Code Execution (ArbitraryCodeChecker)
//   - AS-007  Insufficient Tool Data   (InsufficientDataChecker)
//   - AS-008  Known Compromised Pkg    (BlacklistChecker)
//   - AS-009  Typosquatting            (TyposquattingChecker)
//   - AS-010  Secret Handling          (SecretHandlingChecker)
//   - AS-011  DoS Resilience           (DoSResilienceChecker)
//   - AS-013  Tool Shadowing           (ShadowingChecker)
//   - AS-014  Dependency Visibility    (DependencyInventoryChecker)
//   - AS-015  NPM Lifecycle Scripts    (NPMLifecycleScriptChecker)
//   - AS-016  NPM IOC Dependencies     (NPMIOCChecker)
//   - AS-017  Suspicious Data Exfil Description (DataExfilDescriptionChecker)
func NewEngine(enableDeepScan bool, rulesDir string) (*Engine, error) {
	scanner, err := NewScanner(enableDeepScan, rulesDir)
	if err != nil {
		return nil, err
	}
	return &Engine{scanner: scanner}, nil
}

// Scan analyses tool and returns a ScanReport.  It uses a background context.
// context.Background() never cancels, so the only error path is an internal
// checker failure — which the built-in checkers never trigger.  In the
// unlikely event of a failure, a zero ScanReport is returned.
func (e *Engine) Scan(tool model.UnifiedTool) ScanReport {
	score, err := e.scanner.Scan(context.Background(), tool)
	if err != nil {
		return ScanReport{ToolName: tool.Name}
	}
	return ScanReport{
		ToolName:  tool.Name,
		RiskScore: score.Score,
		Grade:     score.Grade,
		Findings:  score.Issues,
	}
}
