<img src="https://github.com/AgentSafe-AI/.github/raw/main/profile/logo.png" alt="AgentSafe AI" width="80" />

# AgentSafe AI

**We scanned 207 MCP servers. 70% have security issues.**

AI agents are powerful — but every tool they call is an attack surface. Prompt injection, data exfiltration, privilege escalation, and supply-chain backdoors hide in tool descriptions that agents blindly trust. We build open-source tools that expose the risks before your agent acts on them.

---

### ToolTrust Scanner

Static security scanner for MCP server tool definitions. 16 active security rules, plus explicit supply-chain visibility signals for missing dependency data and transitive dependency coverage from common lockfiles. Battle-tested against hundreds of production servers.

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

[tooltrust-scanner →](https://github.com/AgentSafe-AI/tooltrust-scanner)

### ToolTrust Directory

Public trust registry for MCP servers. Every server gets a grade based on automated scanning. Browse reports, compare grades, and verify servers before you install them.

[www.tooltrust.dev →](https://www.tooltrust.dev)

---

### What we detect

| Threat | What happens |
|--------|-------------|
| Prompt injection | Malicious instructions hidden in tool descriptions hijack your agent |
| Arbitrary code execution | Tools run `eval()`, `exec()`, or scripts on your machine |
| Data exfiltration | Tools send your data to external endpoints |
| Privilege escalation | Tools grab admin/sudo/root access beyond their stated purpose |
| Supply-chain attacks | Known compromised packages (LiteLLM, Trivy, Langflow) |
| Tool shadowing | Duplicate tool names hijack agent behavior |

### The numbers

| | |
|-|-|
| 3,235 tools analyzed | 3,613 security findings |
| 70% of servers have issues | Only 10% get a clean Grade A |
| 16 servers allow arbitrary code execution | 97 tools leak secrets through plaintext params |

### Get involved

- Report a vulnerability: [SECURITY.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/SECURITY.md)
- Contribute: [CONTRIBUTING.md](https://github.com/AgentSafe-AI/tooltrust-scanner/blob/main/docs/CONTRIBUTING.md)
- Contact: **contact@tooltrust.dev**
- MIT Licensed
