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

// RuleMeta describes a single security rule for catalog enumeration.
type RuleMeta struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// checker is an internal interface for a single analysis pass.
type checker interface {
	Check(tool model.UnifiedTool) ([]model.Issue, error)
	Meta() RuleMeta
}

// Scanner orchestrates all registered checkers and aggregates their output
// into a single RiskScore.
type Scanner struct {
	checkers []checker
}

// NewScanner returns a Scanner wired with all default checkers.
// Supply chain (AS-004) uses the live OSV API; for tests inject a mock via
// NewScannerWithCheckers or use Engine.Scan which calls the real checker.
func NewScanner(enableDeepScan bool, rulesDir string) (*Scanner, error) {
	checkers := []checker{
		NewBlacklistChecker(),               // AS-008 (offline blacklist, runs first)
		NewPoisoningChecker(enableDeepScan), // AS-001
		NewDataExfilDescriptionChecker(),    // AS-017
		NewPermissionChecker(),              // AS-002
		NewScopeChecker(),                   // AS-003
		NewSupplyChainChecker(),             // AS-004
		NewPrivilegeEscalationChecker(),     // AS-005
		NewArbitraryCodeChecker(),           // AS-006
		NewInsufficientDataChecker(),        // AS-007
		NewTyposquattingChecker(),           // AS-009
		NewSecretHandlingChecker(),          // AS-010
		NewDoSResilienceChecker(),           // AS-011
		NewDependencyInventoryChecker(),     // AS-014
		NewNPMLifecycleScriptChecker(),      // AS-015
		NewNPMIOCChecker(),                  // AS-016
		NewShadowingChecker(),               // AS-013
	}

	customCheckers, err := LoadCustomRules(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to load custom rules: %w", err)
	}
	if len(customCheckers) > 0 {
		checkers = append(checkers, customCheckers...)
	}

	return &Scanner{checkers: checkers}, nil
}

// Rules returns the metadata for all registered checkers.
func (s *Scanner) Rules() []RuleMeta {
	rules := make([]RuleMeta, len(s.checkers))
	for i, c := range s.checkers {
		rules[i] = c.Meta()
	}
	return rules
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
