# ToolTrust Scanner

**Scan MCP servers for prompt injection, data exfiltration, and privilege escalation before your AI agent trusts them.**

> **Urgent security update**
> ToolTrust detects and blocks known compromised MCP-related package versions, including the LiteLLM / TeamPCP supply-chain exploit.

![ToolTrust MCP demo](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/mcp-demo.gif)

## Live UI

![ToolTrust Directory UI](https://raw.githubusercontent.com/AgentSafe-AI/tooltrust-scanner/main/docs/tooltrust-ui.png)

- Browse the public registry: [https://www.tooltrust.dev/](https://www.tooltrust.dev/)
- Review findings in the browser before trusting or installing a server
- Compare grades across popular MCP servers

## Use with Claude Code / Cursor / Claude Desktop

Add ToolTrust as an MCP server:

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

Then ask your agent to:

- `tooltrust_scan_config` to scan all configured MCP servers
- `tooltrust_scan_server` to scan one specific MCP server
- Full MCP tool list: [Usage Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/USAGE.md#mcp-tools)

## What It Catches

- Prompt injection and tool poisoning hidden in descriptions
- Excessive permissions such as `exec`, `network`, `db`, and `fs`
- Supply-chain CVEs and known compromised package versions
- Privilege escalation and arbitrary code execution patterns
- Typosquatting, tool shadowing, and insecure secret handling
- Missing rate-limit, timeout, or retry configuration on risky tools

Full rule catalog: [Security Rules](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/RULES.md) · [tooltrust.dev](https://www.tooltrust.dev/)

## More Ways to Use ToolTrust

- [Usage Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/USAGE.md)
- [Developer Guide](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/DEVELOPER.md)
- [Security Docs](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)

## Links

- GitHub: [AgentSafe-AI/tooltrust-scanner](https://github.com/AgentSafe-AI/tooltrust-scanner)
- Live UI: [tooltrust.dev](https://www.tooltrust.dev/)
