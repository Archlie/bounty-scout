#!/usr/bin/env python3
"""bounty-scout: scan GitHub for funded/open bounty issues and flag scam patterns.

Quick scan with 3 targeted queries. Requires GITHUB_PAT env var.
"""

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

KNOWN_SPAM = [
    "UnsafeLabs/Bounty-Hunters", "SecureBananaLabs/bug-bounty",
    "xevrion-v2/agent-playground", "claude-builders-bounty/claude-builders-bounty",
    "jahmeergnlt/traefik", "Scottcjn/rustchain-bounties", "mergeos-bounties",
    "0xddneto/AI-Proof-of-Us", "theselfish/SlopStation13", "jflournoy/for-funsies",
    "relayhop/sn-monetization-runtime", "relayhop/ClaudeEarnSelf-runtime",
    "riteshekbote/whale-hunt", "riteshekbote/spare-hunt",
    "rohitdash08/FinMind", "iii123iii/Crystal-PDF", "daydreamsai/agent-bounties",
    "watney-ai/open-source-bounties", "tine1117/oss-hunter-livefire",
    "Pay-Per-Token-LLM-Gateway/pay-per-token-llm-gateway",
        "Bitcoindefi/OpenAO", "liubaining-louis/louis-os",
    "DenesePothoven54/cli", "LiliannaBruflat83/chi", "TrudieMasenheimer3/prometheus",
    "CinnamonFaldet48/cli", "EstefanyLonsway6/traefik", "CurtFigone19/pgx",
    "CornelParsch21/client-go", "KentonMaverick47/cobra", "aLexzzz430/Cognitive-OS",
]
OPIRE_IMPERSONATORS = {"rasoolharlym8", "colmev080", "morriganreza973", "Kristywvs22", "EncarnacionP", "WillSmithTE", "ClankerNation", "DenesePothoven54", "LiliannaBruflat83", "TrudieMasenheimer3", "CinnamonFaldet48", "EstefanyLonsway6", "CurtFigone19", "CornelParsch21", "KentonMaverick47", "aLexzzz430"}
SPAM_ORGS = {"MyZubster-Ecosystem", "DanielIoni-creator", "jaxassistant55"}
TOKEN_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(RTC|MRG|GOLD|EGGS?|MYZ|AIPOU|GSD|TOKEN|COIN)\b", re.IGNORECASE)
REWARD_RE = re.compile(r"\$\s?\d+(?:\.\d+)?|USDC\b|USDT\b", re.IGNORECASE)


def api(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": "bounty-scout"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def flag(issue, meta):
    tags = []
    body = (issue.get("body") or "")[:4000]
    title = issue.get("title") or ""
    hay = (body + " " + title).lower()
    labels = [l.get("name", "") for l in issue.get("labels", [])]
    if "AI only allowed - no humans" in labels: tags.append("AI-ONLY-HONEYPOT")
    if "Maybe Rewarded" in labels: tags.append("UNFUNDED")
    if "AI agent friendly" in labels: tags.append("AGENT-BAIT")
    if "opire" in hay:
        tags.append("OPIRE-IMPERSONATION" if (meta.get("stargazers_count", 0) or 0) < 20 else "OPIRE")
    if "frantic" in hay: tags.append("FRANTIC-MICRO")
    if TOKEN_RE.search(hay): tags.append("TOKEN-NOT-CASH")
    stars = meta.get("stargazers_count", 0) or 0
    forks = meta.get("forks_count", 0) or 0
    if re.search(r"\$\s?[5-9]\d|\$\s?\d{3,}", hay) and stars < 10 and forks < 5:
        tags.append("NEW-LITTLE-REPO-BIG-CLAIM")
    if "grantfox" in hay and "maybe rewarded" in hay: tags.append("GRANTFOX-UNFUNDED")
    return sorted(tags)


def main():
    token = os.environ.get("GITHUB_PAT", "")
    if not token:
        sys.exit("GITHUB_PAT env var required")
    queries = [
        'label:"$100" OR label:"$200" OR label:"$250" OR label:"$500" is:issue is:open',
        'label:bounty label:bug is:issue is:open no:assignee',
        'label:"💎 Bounty" state:open',
    ]
    seen = {}
    for q in queries:
        url = "https://api.github.com/search/issues?q=" + urllib.parse.quote(q) + "&sort=created&order=desc&per_page=8"
        try:
            data = api(url, token)
        except Exception as e:
            print(f"# query failed: {e}", file=sys.stderr)
            continue
        for it in data.get("items", []):
            if it.get("pull_request") or it["number"] in seen:
                continue
            seen[it["number"]] = it
            time.sleep(0.3)
    print(f"# raw: {len(seen)}")
    rows = []
    for num, it in seen.items():
        ow, rn = it["repository_url"].rsplit("/", 2)[-2:]
        try:
            meta = api(f"https://api.github.com/repos/{ow}/{rn}", token)
        except Exception:
            meta = {"stargazers_count": 0, "forks_count": 0, "name": rn}
        full = f"{ow}/{rn}".lower()
        if full in [s.lower() for s in KNOWN_SPAM] or ow.lower() in OPIRE_IMPERSONATORS or ow.lower() in SPAM_ORGS:
            continue
        if (meta.get("stargazers_count", 0) or 0) < 5:
            continue
        tags = flag(it, meta)
        rewards = REWARD_RE.findall((it.get("body") or "") + " " + (it.get("title") or ""))
        rows.append((it.get("created_at", "")[:10], it.get("comments", 0), num, ow, rn, tags, rewards[:3], it["title"][:80], it["html_url"]))
        time.sleep(0.2)
    rows.sort(reverse=True)
    if not rows:
        print("# No viable bounty issues found.")
        return
    print(f"# viable: {len(rows)}")
    for created, cmts, num, ow, rn, tags, rewards, title, url in rows:
        tagstr = ",".join(tags) if tags else "-"
        rew = ",".join(rewards) if rewards else "-"
        print(f"[{created}] [{cmts:2d}c] {ow}/{rn}#{num} tags={tagstr} reward~{rew}")
        print(f"      {title}")
        print(f"      {url}")
        print()


if __name__ == "__main__":
    main()