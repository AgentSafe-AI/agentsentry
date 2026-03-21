# ToolTrust Scanner

[![CI](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml)
[![Security](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg)](https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml)
[![codecov](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner/branch/main/graph/badge.svg)](https://codecov.io/gh/AgentSafe-AI/tooltrust-scanner)
[![Go Report Card](https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner)](https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.26-00ADD8.svg)](go.mod)

**Scan MCP servers for prompt injection, data exfiltration, and privilege escalation before your AI agent blindly trusts them.**

![ToolTrust Scanner demo](docs/demo.gif)

## 🚀 Quick Start

```bash
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash
```

*(Alternatively, use `go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest`)*

**Verify Installation:**
```bash
tooltrust-scanner version
```

**Install a Specific Version (Optional):**
```bash
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | VERSION=vX.Y.Z bash
```

## 💻 Usage

Scan an MCP server directly by spinning it up:

```bash
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

## 🔍 What it catches

ToolTrust intercepts tool definitions *before* execution and blocks threats at the source.

| ID | Detects |
|----|---------|
| 🛡️&nbsp;**AS&#8209;001** | Prompt poisoning (`ignore previous instructions`, `system:`) |
| 🔑&nbsp;**AS&#8209;002** | Excessive permissions (`exec`, `network`, `db`, `fs` beyond stated purpose) |
| 📐&nbsp;**AS&#8209;003** | Scope mismatch (e.g. `read_config` secretly holding `exec`) |
| 📦&nbsp;**AS&#8209;004** | Supply chain vulnerabilities (CVEs in dependencies via OSV) |
| 🔓&nbsp;**AS&#8209;005** | Privilege escalation (`admin` OAuth scopes, `sudo` keywords) |
| ⚡&nbsp;**AS&#8209;006** | Arbitrary code execution (`evaluate_script`, `execute javascript`) |
| ℹ️&nbsp;**AS&#8209;007** | Insufficient tool data (missing description or schema) |
| 🔤&nbsp;**AS&#8209;009** | Typosquatting (tool name within edit-distance 2 of a well-known MCP tool) |
| 🗝️&nbsp;**AS&#8209;010** | Insecure secret handling (params accepting keys/passwords) |
| ⚡&nbsp;**AS&#8209;011** | DoS resilience (missing rate-limits or timeouts) |
| 🔄&nbsp;**AS&#8209;012** | Rug-pull / silent update (tool set changed between versions without a version bump) ⚠️ *directory pipeline only — requires historical scan data* |
| 👥&nbsp;**AS&#8209;013** | Tool shadowing (duplicate/near-duplicate name hijacks calls to a trusted tool) |

## 🤝 GitHub Actions

Integrate into your CI/CD to block high-risk tools automatically:

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```

## 🤖 AI Agent Integration (Claude Desktop / Cursor)

Give your AI agent the ability to self-scan other MCP servers by adding ToolTrust to your `mcp.json` or `claude_desktop_config.json`:

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

This exposes `tooltrust_scan_server` and `tooltrust_lookup` to your AI, allowing it to evaluate external tools before trusting them!

---

[Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE) © 2026 AgentSafe-AI
