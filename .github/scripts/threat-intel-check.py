#!/usr/bin/env python3
"""Check security blog RSS feeds and create GitHub issues for new posts."""

import feedparser
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

STATE_FILE = ".github/threat-intel-state.json"

# Blogs with confirmed RSS feeds
RSS_FEEDS = [
    {"source": "Embrace The Red", "url": "https://embracethered.com/blog/index.xml"},
    {"source": "Trail of Bits",   "url": "https://blog.trailofbits.com/index.xml"},
]

# Blogs without RSS — scraped directly from their listing pages
SCRAPED_BLOGS = [
    {"source": "Koi Security",    "url": "https://www.koi.security/blog"},
    {"source": "Invariant Labs",  "url": "https://invariantlabs.ai/blog"},
    {"source": "Pillar Security", "url": "https://www.pillar.security/blog"},
    {"source": "Wiz Research",    "url": "https://wiz.io/blog"},
]

HEADERS = {"User-Agent": "ToolTrust threat-intel monitor (github.com/AgentSafe-AI/tooltrust-scanner)"}


def scrape_blog_posts(source: str, listing_url: str) -> list[dict]:
    """Scrape a blog listing page and return posts as {title, link, date}."""
    try:
        resp = requests.get(listing_url, headers=HEADERS, timeout=15)
        resp.raise_for_status()
    except Exception as e:
        print(f"[{source}] fetch error: {e}")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    base = f"{urlparse(listing_url).scheme}://{urlparse(listing_url).netloc}"

    posts = []
    seen_links = set()

    # Heuristic: find <a> tags that look like blog post links
    # Blog post links typically: contain the listing URL path, have meaningful text, aren't nav links
    blog_path = urlparse(listing_url).path.rstrip("/")

    for a in soup.find_all("a", href=True):
        href = a["href"]
        full_url = urljoin(base, href)
        link_path = urlparse(full_url).path

        # Must be on the same domain, under the blog path, and deeper than it
        if urlparse(full_url).netloc != urlparse(listing_url).netloc:
            continue
        if not link_path.startswith(blog_path + "/"):
            continue
        # Skip if it's just the listing page itself
        if link_path.rstrip("/") == blog_path:
            continue
        if full_url in seen_links:
            continue

        title = a.get_text(strip=True)
        if len(title) < 10:
            continue  # skip nav links with short text

        seen_links.add(full_url)

        # Try to find a date near this link
        date_str = None
        parent = a.parent
        for _ in range(4):  # walk up a few levels
            if parent is None:
                break
            text = parent.get_text(" ", strip=True)
            # Look for common date patterns
            m = re.search(r"\b(\d{4}[-/]\d{2}[-/]\d{2}|\w+ \d{1,2},? \d{4})\b", text)
            if m:
                date_str = m.group(1)
                break
            parent = parent.parent

        posts.append({"title": title, "link": full_url, "date_str": date_str})

    return posts


def parse_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%B %d, %Y", "%B %d %Y", "%b %d, %Y", "%b %d %Y"):
        try:
            return datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


state = {}
if Path(STATE_FILE).exists():
    state = json.loads(Path(STATE_FILE).read_text())

new_state = dict(state)
issues_created = 0
repo = os.environ["REPO"]


def create_issue(source: str, title: str, link: str, date: str) -> bool:
    body = (
        f"**Source:** {source}\n"
        f"**URL:** {link}\n"
        f"**Date:** {date}\n"
        f"**Attack pattern:** *(fill in after reading)*\n\n"
        f"### ToolTrust coverage\n"
        f"- [ ] Existing rule covers this\n"
        f"- [ ] Rule needs pattern update\n"
        f"- [ ] New rule needed\n"
        f"- [ ] Needs source-code analysis (not coverable today)\n\n"
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
        return True
    print(f"[{source}] issue creation failed: {result.stderr.strip()}")
    return False


# ── RSS feeds ────────────────────────────────────────────────────────────────
for feed_info in RSS_FEEDS:
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

        if create_issue(source, title, link, date):
            issues_created += 1
            if entry_dt > latest_dt:
                latest_dt = entry_dt

    new_state[source] = latest_dt.isoformat()


# ── Scraped blogs ─────────────────────────────────────────────────────────────
for blog in SCRAPED_BLOGS:
    source = blog["source"]
    url = blog["url"]
    last_seen = state.get(source, "2020-01-01T00:00:00+00:00")
    last_seen_dt = datetime.fromisoformat(last_seen)
    latest_dt = last_seen_dt

    posts = scrape_blog_posts(source, url)
    if not posts:
        new_state[source] = latest_dt.isoformat()
        continue

    print(f"[{source}] found {len(posts)} posts on listing page")

    for post in posts:
        entry_dt = parse_date(post["date_str"])
        date_label = post["date_str"] or "unknown date"

        # If we can parse the date, skip old posts
        if entry_dt and entry_dt <= last_seen_dt:
            continue
        # If no date found, always create issue (can't tell if it's new)
        # to avoid missing posts — rely on duplicate detection via issue title

        if create_issue(source, post["title"], post["link"], date_label):
            issues_created += 1
            if entry_dt and entry_dt > latest_dt:
                latest_dt = entry_dt

    new_state[source] = latest_dt.isoformat()


# ── Persist state ─────────────────────────────────────────────────────────────
Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
Path(STATE_FILE).write_text(json.dumps(new_state, indent=2) + "\n")
print(f"\nDone. {issues_created} new issue(s) created.")
