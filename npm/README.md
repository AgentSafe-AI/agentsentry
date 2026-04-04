# tooltrust-mcp

[![tooltrust-scanner MCP server](https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner/badges/score.svg)](https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner)
[![npm](https://img.shields.io/npm/v/tooltrust-mcp?label=npm&color=blue)](https://www.npmjs.com/package/tooltrust-mcp)

Scan MCP servers for prompt injection, data exfiltration, risky permissions, supply-chain threats, and privilege escalation before your agent blindly trusts them.

> **First run** downloads a ~10MB Go binary from GitHub Releases and caches it at `~/.tooltrust-mcp/bin/`. Subsequent runs use the cached binary with no download.

## What it catches

- Prompt injection and tool poisoning hidden in descriptions
- Excessive permissions such as `exec`, `network`, `db`, and `fs`
- Supply-chain CVEs and known compromised package versions
- Suspicious npm lifecycle scripts that execute during install
- Suspicious npm IOC dependencies and indicators such as `plain-crypto-js`, reviewed install-script patterns, malicious domains, and URLs referenced from published package metadata
- Dependency visibility gaps when an MCP server does not expose dependency metadata
- Privilege escalation and arbitrary code execution patterns
- Typosquatting, tool shadowing, and insecure secret handling
- Missing rate-limit, timeout, or retry configuration on risky tools

## Quick start

Add to your `.mcp.json`:

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

Then ask your agent: `run tooltrust_scan_config`

## Available tools

| Tool | Description |
|------|-------------|
| `tooltrust_scan_config` | Scan all servers in your `.mcp.json` or `~/.claude.json` |
| `tooltrust_scan_server` | Scan a specific MCP server |
| `tooltrust_scanner_scan` | Scan a JSON blob of tool definitions |
| `tooltrust_lookup` | Look up a server's trust grade |
| `tooltrust_list_rules` | List all 16 active security rules |

## Dependency visibility

ToolTrust reports how much dependency evidence it could recover:

- `No dependency data`
- `Declared by MCP metadata`
- `Verified from local lockfile`
- `Verified from remote lockfile`
- `Repo URL available`

For local scans, ToolTrust will also try to inspect nearby `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, and `requirements.txt` files when it can infer the project root from the launch command.

For GitHub-backed `repo_url` scans, ToolTrust also inspects remote `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.sum`, and `requirements.txt` files to recover transitive dependency evidence.

Recent supply-chain incident coverage includes:

- LiteLLM `1.82.7` / `1.82.8` and related TeamPCP compromise indicators
- Axios `1.14.1` / `0.30.4` malicious npm publish
- npm IOC helpers such as `plain-crypto-js`

## Example output

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

## Links

- **GitHub:** https://github.com/AgentSafe-AI/tooltrust-scanner
- **Glama:** https://glama.ai/mcp/servers/AgentSafe-AI/tooltrust-scanner
- **Directory:** https://www.tooltrust.dev/
- **Rules:** https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/RULES.md
