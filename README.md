<p align="center">
  <img src="docs/logo.svg" alt="ToolTrust" width="80" />
</p>

<h1 align="center">ToolTrust Scanner</h1>

<p align="center">
  <strong>Static security scanner for MCP tool definitions</strong><br/>
  Trust grades (A–F) before your agent calls a tool — run as an <strong>MCP server</strong>, <strong>CLI</strong>, or <strong>CI</strong> check.
</p>

<p align="center">
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml"><img src="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml"><img src="https://github.com/AgentSafe-AI/tooltrust-scanner/actions/workflows/security.yml/badge.svg" alt="Security" /></a>
  <a href="https://goreportcard.com/report/github.com/AgentSafe-AI/tooltrust-scanner"><img src="https://goreportcard.com/badge/github.com/AgentSafe-AI/tooltrust-scanner" alt="Go Report Card" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT" /></a>
  <a href="https://github.com/AgentSafe-AI/tooltrust-scanner/stargazers"><img src="https://img.shields.io/github/stars/AgentSafe-AI/tooltrust-scanner?style=social" alt="GitHub stars" /></a>
</p>

---

Every MCP tool your agent calls is an attack surface — prompt injection, data exfiltration, privilege escalation, supply-chain backdoors. ToolTrust scans tool definitions *before* your agent trusts them and assigns a trust grade (A–F) so you know the risk. ToolTrust is an **MCP Server** and a **CLI/CI tool** — not a host, gateway, or runtime proxy. Coverage is expanding beyond today’s MCP-focused workflows; **skills** and additional agent tool formats are on the roadmap.

<p align="center">
  <strong><a href="https://www.tooltrust.dev/">Browse the live ToolTrust Directory</a></strong> — trust grades and scan-backed reports before you install.<br/><br/>
  <a href="https://www.tooltrust.dev/"><img src="docs/tooltrust-ui.png" alt="ToolTrust Directory UI" /></a>
</p>

<p align="center"><em>MCP demo: run a full config scan from your agent.</em></p>

![ToolTrust MCP demo](docs/mcp-demo.gif)

## Scan your setup in 30 seconds

Add ToolTrust as an MCP server and let your agent audit its own tools (stdio transport — no network listener; your host launches it as a subprocess):

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

Then ask your agent: *"Run tooltrust_scan_config"*

It reads your MCP config, connects to each server in parallel, scans every tool, and returns a risk report with grades and enforcement decisions — all in seconds.

Or use the CLI:

```bash
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash
tooltrust-scanner scan --server "npx -y @modelcontextprotocol/server-filesystem /tmp"
```

## Example snapshot (research cohort)

The public **[ToolTrust Directory](https://www.tooltrust.dev/)** holds **current** grades and aggregates as scanning scales. One published research pass illustrates the shape of the problem — **207 MCP servers**, **3,235** tools — not an exhaustive count of everything we scan today:

| Metric | Count |
|--------|-------|
| MCP servers in cohort | 207 |
| Individual tools analyzed | 3,235 |
| Total security findings | 3,613 |
| Servers with at least one finding | 145 (70%) |
| Servers with a clean Grade A | 22 (10%) |
| Servers with arbitrary code execution | 16 |

**Only 10% of servers in that cohort had a clean Grade A.** See **[tooltrust.dev](https://www.tooltrust.dev/)** for up-to-date directory-wide results (and use this table only as a labeled snapshot).

## What it catches

ToolTrust runs **16** static analysis rules against every tool definition in this repo (**AS-001–AS-011**, **AS-013–AS-017**). **AS-012** (tool drift) is evaluated in the **[ToolTrust Directory](https://github.com/AgentSafe-AI/tooltrust-directory)** when new scan results are compared to previous runs.

| Threat | Rule | What it detects |
|--------|------|-----------------|
| Prompt injection | AS-001 | Malicious instructions hidden in tool descriptions that hijack agent reasoning |
| Excessive permissions | AS-002 | Tools requesting `exec`, `network`, `db`, or `fs` access beyond their stated purpose |
| Scope mismatch | AS-003 | Tool names that contradict their actual permissions |
| Supply-chain CVEs | AS-004 | Known vulnerabilities via the OSV database |
| Privilege escalation | AS-005 | Tools requesting `admin`, `root`, or `sudo` scopes |
| Arbitrary code execution | AS-006 | Tools that can run arbitrary scripts or shell commands on your machine |
| Missing metadata | AS-007 | Tools with no description or input schema |
| Known malware | AS-008 | Confirmed compromised package versions (offline blacklist) |
| Typosquatting | AS-009 | Tool names that impersonate legitimate tools via edit-distance |
| Insecure secret handling | AS-010 | Tools whose inputs appear designed to accept API keys, tokens, or passwords in plaintext |
| Missing rate limits | AS-011 | Tools with no timeout or rate-limit configuration |
| Tool shadowing | AS-013 | Duplicate tool names designed to hijack agent behavior |
| Dependency inventory gaps | AS-014 | Tools with no dependency metadata and no repo URL, limiting supply-chain analysis |
| Suspicious npm lifecycle scripts | AS-015 | Dependency versions that run install-time scripts with risky remote-fetch or execution patterns |
| Suspicious npm IOC dependency | AS-016 | Registry metadata or scripts referencing known malicious IOC patterns |
| Suspicious data exfil description | AS-017 | Descriptions suggesting forwarding user data to external endpoints (complements AS-001) |

Full rule details: [docs/RULES.md](docs/RULES.md)

## How it works

1. **Parse** — Connects to a live MCP server (or reads a JSON file) and extracts every tool definition
2. **Analyze** — Runs all 16 rules against each tool's name, description, schema, and permissions
3. **Grade** — Assigns a numeric risk score and letter grade (A–F) per tool
4. **Enforce** — Maps each grade to a gateway policy: `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`

Pure static analysis. No LLM calls. No data leaves your machine (except optional CVE lookups). Runs in milliseconds. Deterministic and reproducible.

## Install

```bash
# One-line install (macOS / Linux)
curl -sfL https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/install.sh | bash

# Go
go install github.com/AgentSafe-AI/tooltrust-scanner/cmd/tooltrust-scanner@latest

# npx (no install needed)
npx -y tooltrust-mcp
```

## MCP tools

When running as an MCP server, ToolTrust exposes these tools to your agent:

| Tool | What it does | Data access |
|------|-------------|-------------|
| `tooltrust_scan_config` | Scan all MCP servers in your `.mcp.json` or `~/.claude.json` | Reads local config; spawns each server as subprocess |
| `tooltrust_scan_server` | Launch and scan a specific MCP server by command | Runs user-supplied command as subprocess (stdio) |
| `tooltrust_scanner_scan` | Scan a raw JSON blob of tool definitions | In-memory only; no subprocess or network |
| `tooltrust_lookup` | Look up a server's trust grade from the ToolTrust Directory | Network request to ToolTrust Directory API |
| `tooltrust_list_rules` | List all built-in security rules | Local catalog only |

## CI / GitHub Actions

Block risky MCP servers in your pipeline:

```yaml
- name: Audit MCP Server
  uses: AgentSafe-AI/tooltrust-scanner@main
  with:
    server: "npx -y @modelcontextprotocol/server-filesystem /tmp"
    fail-on: "approval"
```

## Deployment and security

For deployment, use the install paths in [Install](#install) or the workflow example in [CI / GitHub Actions](#ci--github-actions). For vulnerability reporting and disclosure policy, see [docs/SECURITY.md](docs/SECURITY.md).

## Scan-before-install gate

Never add an untrusted MCP server to your config again:

```bash
# Scans the server, then auto-installs if Grade A/B, prompts on C/D, blocks on F
tooltrust-scanner gate @modelcontextprotocol/server-memory -- /tmp

# Replace `claude mcp add` with a scanned install
alias mcp-add='tooltrust-scanner gate'
```

Full gate options and pre-commit hook setup: [docs/USAGE.md](docs/USAGE.md)

## Add a trust badge to your project

If your MCP server passes ToolTrust, let people know:

```markdown
[![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)
```

> [![ToolTrust Grade A](https://img.shields.io/badge/ToolTrust-Grade%20A-brightgreen)](https://www.tooltrust.dev/)

---

> **Supply-chain alert:** ToolTrust detects and blocks confirmed compromised packages including LiteLLM v1.82.7/8 (TeamPCP backdoor), Trivy v0.69.4–v0.69.6, and Langflow < 1.9.0. If you encounter a Grade F with rule AS-008, remove the package immediately and rotate all credentials.

---

[Usage guide](docs/USAGE.md) · [Developer guide](docs/DEVELOPER.md) · [Contributing](docs/CONTRIBUTING.md) · [Deployment & security](#deployment-and-security) · [Changelog](CHANGELOG.md) · [Security](docs/SECURITY.md) · [License: MIT](LICENSE)
