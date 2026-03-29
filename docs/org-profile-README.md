<img src="https://github.com/AgentSafe-AI/.github/raw/main/profile/logo.png" alt="AgentSafe AI" width="80" />

# AgentSafe AI

**Making AI agents safe to use.**

AI agents are powerful — but every tool they call is an attack surface. Prompt injection, data exfiltration, privilege escalation, and supply chain attacks hide in tool descriptions that agents blindly trust.

We build open-source tools that let you see the risks before your agent acts on them.

---

### ToolTrust Scanner

Static security scanner for MCP server tool definitions. 13 security rules. Battle-tested against hundreds of production servers.

```bash
# Add to your .mcp.json — your agent scans its own tools
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

[tooltrust-scanner →](https://github.com/AgentSafe-AI/tooltrust-scanner)

### ToolTrust Directory

Public security registry for MCP servers. Every server gets a trust grade (A–F) based on automated scanning. Browse reports, check grades, and verify servers before you install them.

[www.tooltrust.dev →](https://www.tooltrust.dev)

---

### What we detect

| Threat | Example |
|--------|---------|
| Prompt injection | Malicious instructions hidden in tool descriptions |
| Arbitrary code execution | Tools that run `eval()`, `exec()`, or arbitrary scripts |
| Data exfiltration | Tools that send data to external endpoints |
| Privilege escalation | Tools requesting admin/sudo/root access |
| Supply chain CVEs | Known vulnerabilities in server dependencies |
| Tool shadowing | Duplicate tool names designed to hijack agent behavior |

### Get involved

- Report a vulnerability: [SECURITY.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)
- Contribute: [CONTRIBUTING.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/CONTRIBUTING.md)
- Contact: **contact@tooltrust.dev**
- MIT Licensed
