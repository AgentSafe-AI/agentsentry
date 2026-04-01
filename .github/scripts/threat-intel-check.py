#!/usr/bin/env python3
"""Check security blog RSS feeds, create GitHub issues, and draft IOC candidates."""

import feedparser
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

STATE_FILE = ".github/threat-intel-state.json"
CANDIDATE_DIR = Path('.github/ioc-candidates')

FEEDS = [
    {"source": "Embrace The Red", "url": "https://embracethered.com/blog/index.xml"},
    {"source": "Trail of Bits",   "url": "https://blog.trailofbits.com/index.xml"},
]

PACKAGE_NAME_RE = re.compile(r"\b[a-z0-9][a-z0-9._-]*[a-z0-9]\b", re.IGNORECASE)

state = {}
if Path(STATE_FILE).exists():
    state = json.loads(Path(STATE_FILE).read_text())

new_state = dict(state)
issues_created = 0
repo = os.environ["REPO"]
CANDIDATE_DIR.mkdir(parents=True, exist_ok=True)


def slugify(value: str) -> str:
    value = value.lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-") or "candidate"


def build_candidate_template(source: str, title: str, link: str, date: str):
    title_lower = title.lower()
    candidates = []
    hints = []
    for token in PACKAGE_NAME_RE.findall(title_lower):
        if token in {"axios", "npm", "supply-chain", "supply", "chain", "attack"}:
            hints.append(token)
    if "axios" in hints:
        candidates.append({
            "ecosystem": "npm",
            "ioc_type": "package_name",
            "value": "plain-crypto-js",
            "confidence": "medium",
            "reason": f"Candidate IOC from {source} post: {title}",
            "source": link,
            "first_seen": date,
            "suggested_action": "flag",
            "promote_to": "npm_iocs",
            "notes": "Auto-drafted candidate. Human review required before promotion."
        })
    return candidates


for feed_info in FEEDS:
    source = feed_info["source"]
    url = feed_info["url"]
    last_seen = state.get(source, "2020-01-01T00:00:00+00:00")
    last_seen_dt = datetime.fromisoformat(last_seen)
    latest_dt = last_seen_dt

    try:
        feed = feedparser.parse(url)
    except Exception as e:
        print(f"[{source}] fetch error: {e}")
        continue

    if feed.bozo and not feed.entries:
        print(f"[{source}] could not parse feed: {url}")
        continue

    for entry in feed.entries:
        pub = entry.get("published_parsed") or entry.get("updated_parsed")
        if not pub:
            continue
        entry_dt = datetime(*pub[:6], tzinfo=timezone.utc)
        if entry_dt <= last_seen_dt:
            continue

        title = entry.get("title", "Untitled")
        link = entry.get("link", url)
        date = entry_dt.strftime("%Y-%m-%d")

        candidate_path = CANDIDATE_DIR / f"{date}-{slugify(source)}-{slugify(title)}.json"
        if not candidate_path.exists():
            candidate_path.write_text(json.dumps(build_candidate_template(source, title, link, date), indent=2) + "\n")

        body = (
            f"**Source:** {source}\n"
            f"**URL:** {link}\n"
            f"**Date:** {date}\n"
            f"**Attack pattern:** *(fill in after reading)*\n\n"
            f"**Candidate IOC file:** `{candidate_path}`\n\n"
            f"### ToolTrust coverage\n"
            f"- [ ] Existing rule covers this\n"
            f"- [ ] Rule needs pattern update\n"
            f"- [ ] New rule needed\n"
            f"- [ ] Needs source-code analysis (not coverable today)\n\n"
            f"### Candidate handling\n"
            f"- [ ] Candidate IOC file reviewed\n"
            f"- [ ] Promoted to `npm_iocs.json`\n"
            f"- [ ] Promoted to `blacklist.json`\n"
            f"- [ ] Left as watch-only\n\n"
            f"### Test fixture added?\n"
            f"- [ ] Yes — added to `tests/fixtures/`\n"
        )
        result = subprocess.run(
            ["gh", "issue", "create",
             "--repo", repo,
             "--title", f"[threat-intel] {source}: {title}",
             "--body", body,
             "--label", "threat-intel"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[{source}] created issue: {title}")
            issues_created += 1
            if entry_dt > latest_dt:
                latest_dt = entry_dt
        else:
            print(f"[{source}] issue creation failed: {result.stderr.strip()}")

    new_state[source] = latest_dt.isoformat()

Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
Path(STATE_FILE).write_text(json.dumps(new_state, indent=2) + "\n")
print(f"\nDone. {issues_created} new issue(s) created.")
