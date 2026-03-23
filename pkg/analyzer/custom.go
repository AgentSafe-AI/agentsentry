package analyzer

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// CustomRule represents a user-defined analysis rule loaded from YAML.
type CustomRule struct {
	ID          string `yaml:"id"`
	Severity    string `yaml:"severity"`
	Pattern     string `yaml:"pattern"`
	Description string `yaml:"description"`
	Location    string `yaml:"location"` // e.g. "description", "name", "permissions"
}

// CustomRuleChecker implements checker using a regex pattern.
type CustomRuleChecker struct {
	Rule CustomRule
	Re   *regexp.Regexp
}

func (c *CustomRuleChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          c.Rule.ID,
		Title:       c.Rule.Description,
		Description: c.Rule.Description,
	}
}

// Check evaluates the tool against the custom regex.
func (c *CustomRuleChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var target string
	switch c.Rule.Location {
	case "description":
		target = tool.Description
	case "name":
		target = tool.Name
	case "permissions":
		target = fmt.Sprintf("%v", tool.Permissions)
	default:
		// Fallback to searching the description if unknown location
		target = tool.Description
	}

	if c.Re.MatchString(target) {
		var sev model.Severity
		switch c.Rule.Severity {
		case "CRITICAL":
			sev = model.SeverityCritical
		case "HIGH":
			sev = model.SeverityHigh
		case "MEDIUM":
			sev = model.SeverityMedium
		case "LOW":
			sev = model.SeverityLow
		case "INFO":
			sev = model.SeverityInfo
		default:
			sev = model.SeverityMedium // Default fallback
		}

		return []model.Issue{{
			RuleID:      c.Rule.ID,
			Severity:    sev,
			Code:        "CUSTOM_RULE_MATCH",
			Description: c.Rule.Description,
			Location:    c.Rule.Location,
		}}, nil
	}
	return nil, nil
}

// LoadCustomRules reads a directory for .yml and .yaml files, compiles their regexes,
// and returns them as a slice of checkers.
func LoadCustomRules(dir string) ([]checker, error) {
	if dir == "" {
		return nil, nil
	}

	stat, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Directory doesn't exist; ignore gracefully.
		}
		return nil, fmt.Errorf("failed to stat rules directory: %w", err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	var checkers []checker

	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error { // #nosec G122 -- custom rules dir is user-specified; TOCTOU risk accepted for CLI tool
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		data, readErr := os.ReadFile(path) // #nosec G304 -- path comes from user-specified rules directory, intentional
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", path, readErr)
		}

		// Support multiple rules in a single file or array format
		var rules []CustomRule
		if unmarshalErr := yaml.Unmarshal(data, &rules); unmarshalErr != nil {
			// fallback: try singular struct
			var single CustomRule
			if errSingle := yaml.Unmarshal(data, &single); errSingle != nil {
				return fmt.Errorf("failed to parse yaml %s: %w", path, unmarshalErr)
			}
			if single.ID != "" {
				rules = append(rules, single)
			}
		}

		for _, rule := range rules {
			if rule.ID == "" || rule.Pattern == "" {
				continue // skip invalid
			}
			re, reErr := regexp.Compile(rule.Pattern)
			if reErr != nil {
				return fmt.Errorf("invalid regex in rule %s: %w", rule.ID, reErr)
			}

			checkers = append(checkers, &CustomRuleChecker{
				Rule: rule,
				Re:   re,
			})
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk rules directory: %w", err)
	}
	return checkers, nil
}
