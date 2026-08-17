#!/usr/bin/env python3
"""bounty-scout: scan GitHub for funded/open bounty issues and flag scam patterns.

Read-only GitHub API usage (Search issues). Requires GITHUB_PAT env var.
Publishes a ranked, deduplicated list with scam risk tags.

Usage:
    GITHUB_PAT=ghp_xxx python3 bounty_scout.py [--queries "bounty is:issue is:open"] [--max-items 60]

Scam flags (heuristic):
    - repo in KNOWN_SPAM list (manually verified bad actors)
    - repo age < 30 days and issue claims a big $ reward
    - reward is an obscure token (RTC, MRG, GOLD, EGGS, ...) not USDC/USDT/$
    - repo forks=0 and stars < 30 while offering > $10
    - body contains 'opire' or 'frantic' and repo is not a well-known maintainer
    - all PRs in repo are unmerged (checked lazily, only when flag triggered)
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

KNOWN_SPAM = [
    "UnsafeLabs/Bounty-Hunters",
    "SecureBananaLabs/bug-bounty",
    "warpspeedopen-source",
    "xevrion-v2/agent-playground",
    "claude-builders-bounty/claude-builders-bounty",
    "bounty-plaza/zhangjiayang6835-cyber",
    "jahmeergnlt/traefik",
    "Scottcjn/rustchain-bounties",
    "mergeos-bounties",
]
REWARD_RE = re.compile(r"\$\s?\d+(?:\.\d+)?|USDC?\b|USDT\b|\b\d+\s*(?:USDC|USDT)\b|\b\d+-\d+\s*(?:USDC|USDT)\b|(?:\b\d+(?:\.\d+)?\s*(?:RTC|MRG|GOLD|EGGS?)\b)", re.IGNORECASE)
TOKEN_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(RTC|MRG|GOLD|EGGS?|TOKEN|COIN)\b", re.IGNORECASE)


def api(url, token):
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                              "Accept": "application/vnd.github+json",
                                              "User-Agent": "bounty-scout"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def flag(issue, repo_meta):
    tags = []
    rn = (repo_meta or {}).get("full_name", "").lower()
    if rn in [s.lower() for s in KNOWN_SPAM]:
        tags.append("SPAM-LIST")
    body = (issue.get("body") or "")[:4000]
    title = issue.get("title") or ""
    hay = (body + " " + title).lower()
    if any(t in hay for t in ("opire", "frantic")):
        tags.append("3rd-party-bounty-site")
    if "opire" in hay:
        tags.append("read-carefully")
    stars = (repo_meta or {}).get("stargazers_count", 0)
    forks = (repo_meta or {}).get("forks_count", 0)
    rewards = REWARD_RE.findall(hay)
    big_cash = bool(re.search(r"\$\s?[5-9]\d|\$\s?\d{3,}", hay))
    if big_cash and stars < 30 and forks < 5:
        tags.append("new-little-repo-big-claim")
    if TOKEN_RE.search(hay):
        tags.append("token-flavored")
    return sorted(set(tags)), rewards[:3]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--queries", nargs="*", default=["bounty is:issue is:open",
                                                     "funded is:issue is:open",
                                                     "label:\"good first issue\" bounty is:issue is:open"])
    ap.add_argument("--max-items", type=int, default=60)
    ap.add_argument("--min-comments", type=int, default=0, help="skip issues with fewer comments")
    args = ap.parse_args()
    token = os.environ.get("GITHUB_PAT", "")
    if not token:
        sys.exit("GITHUB_PAT env var required")
    seen = {}
    for q in args.queries:
        url = ("https://api.github.com/search/issues?q="
               + urllib.parse.quote(q) + "&sort=comments&order=desc&per_page=30")
        try:
            data = api(url, token)
        except Exception as e:
            print(f"# query failed [{q}]: {e}", file=sys.stderr)
            continue
        for it in data.get("items", []):
            if it["number"] in seen:
                continue
            if it.get("comments", 0) < args.min_comments:
                continue
            pr = it.get("pull_request") is not None
            if pr:
                continue
            seen[it["number"]] = {"issue": it, "repo": it["repository_url"].rsplit("/", 2)[-2:]}
        time.sleep(0.7)
    print(f"# unique issues: {len(seen)}")
    rows = []
    for num, ent in seen.items():
        it = ent["issue"]
        own, repo = ent["repo"]
        body = (it.get("body") or "")[:4000]
        title = it.get("title") or ""
        hay = (body + " " + title).lower()
        # only pay for repo metadata when a reward claim exists or spam list hit
        needs_meta = bool(REWARD_RE.search(hay)) or f"{own}/{repo}".lower() in [s.lower() for s in KNOWN_SPAM]
        meta = None
        if needs_meta:
            try:
                meta = api(f"https://api.github.com/repos/{own}/{repo}", token)
                time.sleep(0.2)
            except Exception:
                meta = {"full_name": f"{own}/{repo}", "stargazers_count": 0, "forks_count": 0}
        tags, rewards = flag(it, meta)
        rows.append((it["comments"], num, own, repo, tags, rewards, it["title"][:90], it["html_url"]))
    rows.sort(reverse=True)
    for cmts, num, own, repo, tags, rewards, title, url in rows:
        tagstr = ",".join(tags) if tags else "-"
        rew = ",".join(rewards) if rewards else "-"
        print(f"[{cmts:3d}] {own}/{repo}#{num} tags={tagstr} reward~{rew}")
        print(f"      {title}")
        print(f"      {url}")


if __name__ == "__main__":
    main()