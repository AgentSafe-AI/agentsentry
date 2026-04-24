package analyzer

import (
	"encoding/json"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

func DependencyVisibilityForTool(tool model.UnifiedTool) (visibility, note string) {
	if tool.Metadata == nil {
		return "No dependency data", "No metadata.dependencies or repo_url were exposed by this MCP server."
	}

	sources := dependencySourcesFromMetadata(tool.Metadata)
	if len(sources) == 0 {
		note = metadataString(tool.Metadata, "dependency_visibility_note")
		if note == "" {
			note = "No metadata.dependencies or repo_url were exposed by this MCP server."
		}
		return "No dependency data", note
	}
	return formatDependencyVisibility(sources), visibilityNote(tool.Metadata, sources)
}

func dependencySourcesFromMetadata(meta map[string]any) []string {
	seen := map[string]bool{}
	var sources []string

	if raw, ok := meta["dependencies"]; ok {
		b, err := json.Marshal(raw)
		if err == nil {
			var deps []struct {
				Source string `json:"source"`
			}
			if err := json.Unmarshal(b, &deps); err == nil {
				for _, dep := range deps {
					source := dep.Source
					if source == "" {
						source = "metadata"
					}
					if !seen[source] {
						seen[source] = true
						sources = append(sources, source)
					}
				}
			}
		}
	}

	if repoURL, ok := meta["repo_url"].(string); ok && strings.TrimSpace(repoURL) != "" {
		if !seen["repo_url"] {
			sources = append(sources, "repo_url")
		}
	}

	return sources
}

func visibilityNote(meta map[string]any, sources []string) string {
	if note := metadataString(meta, "dependency_visibility_note"); note != "" {
		return note
	}
	if len(sources) == 1 && sources[0] == "repo_url" {
		return "repo_url is available, so ToolTrust can try to inspect remote lockfiles for dependency evidence."
	}
	return ""
}

func formatDependencyVisibility(sources []string) string {
	labels := make([]string, 0, len(sources))
	for _, source := range sources {
		switch source {
		case "metadata":
			labels = append(labels, "Declared by MCP metadata")
		case "local_lockfile":
			labels = append(labels, "Verified from local lockfile")
		case "lockfile":
			labels = append(labels, "Verified from remote lockfile")
		case "repo_url":
			labels = append(labels, "Repo URL available")
		default:
			labels = append(labels, source)
		}
	}
	return strings.Join(labels, " + ")
}

func metadataString(meta map[string]any, key string) string {
	if value, ok := meta[key].(string); ok {
		return value
	}
	return ""
}
