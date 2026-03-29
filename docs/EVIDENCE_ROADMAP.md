# Evidence, Behavior, and Confirmed-Malicious Roadmap

This document defines a practical roadmap for making ToolTrust reports more convincing without pretending static analysis can prove runtime behavior.

The goal is to add three layers on top of the current `AS-xxx` findings:

1. `Evidence` — what the scanner concretely saw in tool metadata, schema, dependencies, or source.
2. `Behavior / Destination Context` — what the tool appears able to access or where it appears able to send data.
3. `Confirmed Malicious` — a separate high-confidence state for known bad versions or strong malicious indicators.

This is intentionally static-first. It improves trust decisions before install or use, without requiring sandboxed execution.

---

## 1. Product Positioning

ToolTrust is strongest when answering:

- Should an agent trust this MCP server?
- Should this server be `ALLOW`, `REQUIRE_APPROVAL`, or `BLOCK`?
- What specific risk signals justify that decision?

ToolTrust is weaker when trying to claim:

- this code definitely exfiltrated data at runtime
- this endpoint was definitely contacted in production
- this branch definitely executed on a live host

So the report model should distinguish:

- `risk signal`
- `static evidence`
- `high-confidence malicious indicator`

instead of collapsing everything into a single severity line.

---

## 2. Design Principles

### 2.1 Evidence-first, not adjective-first

Instead of only returning:

- `AS-002 Excessive Permissions`

return:

- `AS-002 Excessive Permissions`
- `Evidence: declares exec permission`
- `Evidence: input schema accepts arbitrary url`
- `Evidence: tool name implies read-only behavior but requests network + exec`

This keeps the scanner explainable and helps users decide whether a finding is real, acceptable, or a false positive.

### 2.2 Separate high-confidence malicious states from normal grading

Grades are useful for trust decisions, but they are not expressive enough for cases like:

- known malicious package version
- hardcoded attacker-controlled destination
- postinstall downloader
- reverse shell pattern

These should not look like ordinary `grade D` or `grade F` risk.

### 2.3 Behavior summaries should remain static and honest

ToolTrust can say:

- `reads env variables`
- `sends network requests`
- `accepts user-controlled destinations`
- `declares exec capability`

ToolTrust should not say:

- `exfiltrates AWS credentials`

unless there is a high-confidence signature or known-bad version match that justifies that wording.

---

## 3. Layer 1: Evidence Panel

### 3.1 What it should do

Each finding should be able to surface one or more concrete evidence items:

- matched tool name pattern
- matched description phrase
- matched schema field name
- matched permission declaration
- matched package/version
- matched literal URL/domain/email
- matched install script or shell pattern

### 3.2 Report shape

Add optional `Evidence` entries to findings:

```json
{
  "rule_id": "AS-002",
  "severity": "HIGH",
  "title": "Excessive Permission Surface",
  "description": "tool declares network permission",
  "evidence": [
    {
      "kind": "permission",
      "value": "network"
    },
    {
      "kind": "tool_name",
      "value": "send_email"
    }
  ]
}
```

Suggested evidence kinds:

- `tool_name`
- `description`
- `schema_field`
- `permission`
- `package`
- `version`
- `url`
- `domain`
- `email`
- `script`
- `code_pattern`

### 3.3 Where ToolTrust can populate this immediately

#### AS-001 Prompt Injection

Evidence examples:

- matched description substring: `ignore previous instructions`
- matched instruction prefix: `system:`
- matched exfil directive: `send to https://...`

#### AS-002 Excessive Permissions

Evidence examples:

- declared permission: `exec`
- declared permission: `network`
- schema field name: `url`
- schema field name: `path`
- schema field name: `command`

#### AS-006 Arbitrary Code Execution

Evidence examples:

- tool name suffix: `_execute`
- description phrase: `run arbitrary commands`
- schema field: `script`
- code pattern: `page.evaluate`

Important note:

When AS-006 fires only because of name or description heuristics, the report should say so explicitly:

- `Evidence type: heuristic-name-match`
- `Evidence type: heuristic-description-match`

This avoids overstating cases like `n8n_execute_workflow`, where the signal may be real but is not direct proof of host-level arbitrary code execution.

#### AS-008 Known Compromised Package

Evidence examples:

- package name: `lite-serper-mcp-server`
- matched version: `1.0.x`
- blacklist source: `offline compromised package feed`

### 3.4 UI treatment

In detail pages and MCP tool output:

- keep the current finding title
- show a short `Evidence` subsection
- cap the default view to the top 2-3 evidence items
- allow expanding for more

Example:

```text
AS-002 Excessive Permissions
Evidence:
- declares network permission
- declares exec permission
- schema accepts arbitrary url
```

---

## 4. Layer 2: Behavior / Destination Context

### 4.1 What it should answer

Users want to know:

- what can this tool touch?
- what can it send data to?
- is the destination fixed or user-controlled?

These questions are often more useful than the raw rule name.

### 4.2 Behavior summary model

Add a per-tool or per-report behavior summary:

```json
{
  "behavior": {
    "reads_env": true,
    "reads_files": true,
    "writes_files": false,
    "executes_commands": true,
    "uses_network": true,
    "destinations": [
      {
        "type": "hardcoded_domain",
        "value": "api.postmarkapp.com"
      },
      {
        "type": "dynamic_url_input",
        "value": "attachmentUrl"
      }
    ]
  }
}
```

### 4.3 Destination categories

ToolTrust should distinguish:

- `hardcoded domain`
- `hardcoded email recipient`
- `known API host`
- `dynamic destination from user input`
- `computed / unknown destination`

That distinction matters a lot:

- hardcoded attacker destination is much stronger than generic network access
- dynamic destination is risky but not automatically malicious

### 4.4 Static sources for destination context

This is doable without runtime tracing by analyzing:

- tool descriptions
- input schemas
- URLs or domains in source/config
- package scripts
- common fetch/client patterns

Useful patterns to detect:

- `fetch(...)`
- `axios(...)`
- SMTP/email client configuration
- webhook URLs
- `bcc`, `cc`, `recipient`, `to`
- `postinstall` download URLs

### 4.5 Rule mapping

This layer should enrich existing rules rather than replace them:

- `AS-002` → behavior capability summary
- `AS-010` → reads secrets / accepts credential-like inputs
- future destination-specific rule(s) → hardcoded or dynamic remote sinks

### 4.6 UI treatment

Short form:

```text
Behavior:
- reads env vars
- sends network requests
- accepts dynamic attachment URLs
```

Destination form:

```text
Destinations:
- fixed domain: api.postmarkapp.com
- dynamic URL input: attachmentUrl
```

This is the closest ToolTrust can get to Koi-style “Dynamic Network Destination” reporting while staying honest about being static-first.

---

## 5. Layer 3: Confirmed Malicious

### 5.1 Why it should exist separately

Some cases are not just “high risk” or “needs approval”.
They are known bad and should be surfaced as such.

Examples:

- known malicious package versions
- clear backdoor signatures
- reverse shell patterns
- hardcoded exfil recipient or domain strongly associated with a public incident

These should not be buried inside normal grading semantics.

### 5.2 Proposed states

Add a top-level classification in addition to grade:

- `NORMAL`
- `STRONG_MALICIOUS_SIGNAL`
- `CONFIRMED_MALICIOUS`

Definitions:

#### NORMAL

Risk exists, but there is no high-confidence evidence of intentional malware.

#### STRONG_MALICIOUS_SIGNAL

Static evidence strongly suggests malicious intent, but confidence is below “confirmed”.

Examples:

- suspicious hardcoded external domain in exfil context
- postinstall curl-to-shell pattern
- reverse shell primitives
- persistence paths with attacker-controlled fetch

#### CONFIRMED_MALICIOUS

Reserved for the highest-confidence cases.

Examples:

- matched compromised package/version in offline blacklist
- matched IOC from a published incident
- hardcoded BCC or recipient associated with a known malicious campaign

### 5.3 What ToolTrust can do now

Immediately:

- `AS-008` known compromised package versions → `CONFIRMED_MALICIOUS`

Next:

- add high-confidence IOC signatures
- add postinstall downloader signatures
- add reverse shell signatures

### 5.4 What not to do

Do not mark something `CONFIRMED_MALICIOUS` just because:

- it declares `exec`
- it has network access
- its name includes `execute`
- it has many findings

Those are risk signals, not confirmation of malware.

---

## 6. Real-World Case Mapping

### postmark-mcp

Public reporting says the malicious version always BCC'd a third-party address on outgoing mail.

ToolTrust fit:

- `Behavior / Destination Context`
  - sends email
  - reads env vars for credentials
  - hardcoded extra recipient / BCC
- `Confirmed Malicious`
  - if the malicious version is added to blacklist

### @lanyer640/mcp-runcommand-server

Public reporting describes reverse shell behavior and command execution capability.

ToolTrust fit:

- `AS-006`
- `AS-002`
- `Confirmed Malicious` if versioned blacklist entry or strong shell/persistence IOC exists

### lite-serper-mcp-server

Supply-chain compromise after account takeover.

ToolTrust fit:

- `AS-008`
- `CONFIRMED_MALICIOUS`

---

## 7. Implementation Plan

### Phase 1 — Evidence Panel

Scope:

- add `Evidence` structure to model
- populate evidence for AS-001, AS-002, AS-006, AS-008
- update CLI / MCP / directory output to show evidence

Why first:

- lowest risk
- highest explainability gain
- immediately improves trust and reduces “why did this fire?” confusion

### Phase 2 — Behavior / Destination Context

Scope:

- add per-tool behavior summary
- detect destination types:
  - hardcoded domains
  - hardcoded email recipients
  - dynamic URL-like inputs
- surface short behavior summary in reports

Why second:

- strongest product differentiation from pure metadata linting
- closest feature to Koi’s report style
- still feasible with static analysis

### Phase 3 — Confirmed Malicious

Scope:

- introduce `classification` field
- map AS-008 blacklist hits to `CONFIRMED_MALICIOUS`
- add a small high-confidence signature pack for:
  - postinstall download-and-exec
  - reverse shell patterns
  - known malicious destinations

Why third:

- higher false-positive risk if rushed
- requires tighter confidence calibration

---

## 8. Output Examples

### Current style

```text
AS-002 HIGH: tool declares network permission
```

### Proposed style

```text
AS-002 HIGH: Excessive Permission Surface
Evidence:
- declares network permission
- schema accepts attachmentUrl

Behavior:
- sends network requests
- accepts dynamic destination from user input
```

### Confirmed malicious example

```text
Classification: CONFIRMED_MALICIOUS
AS-008 CRITICAL: Known Compromised Package
Evidence:
- package: lite-serper-mcp-server
- version: 1.0.6
- matched offline compromised package blacklist
```

---

## 9. What Static Analysis Still Cannot Prove

ToolTrust should stay honest about these limits:

- it cannot prove a runtime branch executed
- it cannot prove a real exfiltration happened on a live host
- it cannot prove which host was contacted at runtime unless the destination is statically visible
- it cannot prove a server is safe just because static analysis is clean

That is acceptable.

The product value is not “full malware sandbox”.
The product value is:

- trust decisions before install or use
- high-signal static warnings
- explainable risk reporting
- policy mapping for agent workflows

---

## 10. Recommended Next Build Order

If only three things are built next:

1. `Evidence` entries for current findings
2. `Behavior / Destination Context` for network, env, file, exec
3. `CONFIRMED_MALICIOUS` top-level classification for AS-008 and a tiny IOC pack

That sequence gives ToolTrust the biggest improvement in report credibility without overpromising dynamic detection.
