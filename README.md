# ToolTrust Scanner

[![CI](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml)
[![GitHub stars](https://img.shields.io/github/stars/AgentSafe-AI/tooltrust-scanner?style=social)](https://github.com/AgentSafe-AI/tooltrust-scanner/stargazers)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner)](https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner)
[![npm](https://img.shields.io/npm/v/tooltrust-mcp?label=npm)](https://www.npmjs.com/package/tooltrust-mcp)
[![npm downloads](https://img.shields.io/npm/dm/tooltrust-mcp?label=npm%20downloads)](https://www.npmjs.com/package/tooltrust-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Scan MCP servers for prompt injection, data exfiltration, and privilege escalation before your AI agent blindly trusts them.**

> **🚨 Urgent Security Update (March 24, 2026)**
> ToolTrust now detects and blocks the LiteLLM / TeamPCP supply chain exploit. If you are adding MCP servers that rely on litellm (v1.82.7/8), ToolTrust will trigger a CRITICAL Grade F warning and block installation to protect your SSH/AWS keys.

![ToolTrust MCP demo](docs/mcp-demo.gif)

## Live UI

![ToolTrust Directory UI](docs/tooltrust-ui.png)

- Browse the public directory: [https://www.tooltrust.dev/](https://www.tooltrust.dev/)
- Look up historical grades for popular MCP servers
- Review findings in a browser before installing or trusting a server

## What it looks like

```
Scan Summary: 14 tools scanned | 13 allowed | 1 need approval | 0 blocked
Tool Grades: A×13  C×1
Findings by Severity: HIGH×1  MEDIUM×14  LOW×1 (16 total)

Flagged Tools:
• search_files  🟡 GRADE C  needs approval
  [AS-002] High: Network access declared
  [AS-011] Low: Missing rate-limit or timeout
  Action now: Keep this tool on manual approval until the risky capabilities are reviewed.
```

## 🤖 Let your AI agent scan its own tools

Add ToolTrust as an MCP server in your `.mcp.json` and your agent can audit every tool it has access to:

> **Note:** First run downloads a ~10MB Go binary from GitHub Releases. Subsequent runs use the cached binary.

```json
{
  "mcpServers": {
    "tooltrust": {
      "command": "npx",
      "args": ["-y", "tooltrust-mcp"]
    }
  }
}
```

Then ask your agent to run:

- `tooltrust_scan_config` to scan all configured MCP servers
- `tooltrust_scan_server` to scan one specific server
- Full MCP tool list: [Usage guide](docs/USAGE.md#mcp-tools)

## 🔍 What it catches

- Prompt injection and tool poisoning hidden in descriptions
- Excessive permissions such as `exec`, `network`, `db`, and `fs`
- Supply-chain CVEs and known compromised package versions
- Privilege escalation and arbitrary code execution patterns
- Typosquatting, tool shadowing, and insecure secret handling
- Missing rate-limit, timeout, or retry configuration on risky tools

Full rule catalog: [docs/RULES.md](docs/RULES.md) · [tooltrust.dev](https://www.tooltrust.dev/)

## More ways to use ToolTrust

- CLI install, examples, and flags: [Usage guide](docs/USAGE.md#cli)
- Scan-before-install workflow: [Gate docs](docs/USAGE.md#gate)
- CI / GitHub Actions examples: [CI integration](docs/USAGE.md#github-actions)
- Pre-commit / alias setup: [Pre-hook integration](docs/USAGE.md#pre-hook-integration)

---

[Usage guide](docs/USAGE.md) · [Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
