// Package analyzer provides the scanning engine that runs a set of checkers
// over a UnifiedTool and produces a RiskScore.
package analyzer

import (
	"context"
	"fmt"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// severityWeight maps a Severity to its numeric risk contribution.
// Weights align with ToolTrust Directory methodology v1.0:
// Critical(25)  High(15)  Medium(8)  Low(2)  Info(0).
var severityWeight = map[model.Severity]int{
	model.SeverityCritical: 25,
	model.SeverityHigh:     15,
	model.SeverityMedium:   8,
	model.SeverityLow:      2,
	model.SeverityInfo:     0,
}

// checker is an internal interface for a single analysis pass.
type checker interface {
	Check(tool model.UnifiedTool) ([]model.Issue, error)
}

// Scanner orchestrates all registered checkers and aggregates their output
// into a single RiskScore.
type Scanner struct {
	checkers []checker
}

// NewScanner returns a Scanner wired with all default checkers.
// Supply chain (AS-004) uses the live OSV API; for tests inject a mock via
// NewScannerWithCheckers or use Engine.Scan which calls the real checker.
func NewScanner(enableDeepScan bool) *Scanner {
	return &Scanner{
		checkers: []checker{
			NewPoisoningChecker(enableDeepScan), // AS-001
			NewPermissionChecker(),              // AS-002
			NewScopeChecker(),                   // AS-003
			NewSupplyChainChecker(),             // AS-004
			NewPrivilegeEscalationChecker(),     // AS-005
			NewArbitraryCodeChecker(),           // AS-006
			NewSecretHandlingChecker(),          // AS-010
			NewDoSResilienceChecker(),           // AS-011
		},
	}
}

// Scan runs all checkers against the tool and returns the aggregated RiskScore.
// It respects ctx cancellation.
func (s *Scanner) Scan(ctx context.Context, tool model.UnifiedTool) (model.RiskScore, error) {
	if err := ctx.Err(); err != nil {
		return model.RiskScore{}, fmt.Errorf("analyzer: context cancelled before scan: %w", err)
	}

	var allIssues []model.Issue
	totalScore := 0

	for _, c := range s.checkers {
		if err := ctx.Err(); err != nil {
			return model.RiskScore{}, fmt.Errorf("analyzer: context cancelled during scan: %w", err)
		}
		issues, err := c.Check(tool)
		if err != nil {
			return model.RiskScore{}, fmt.Errorf("analyzer: checker failed: %w", err)
		}
		allIssues = append(allIssues, issues...)
	}

	for _, issue := range allIssues {
		totalScore += severityWeight[issue.Severity]
	}

	return model.NewRiskScore(totalScore, allIssues), nil
}
