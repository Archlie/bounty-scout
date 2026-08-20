#!/usr/bin/env python3
"""bounty-scout: scan GitHub for funded/open bounty issues and flag scam patterns.

Quick scan with 3 targeted queries. Requires GITHUB_PAT env var.

Modes:
  (default)  bounty scan — 3 targeted searches for funded issues, scam-tagged
  --bugs     fresh-bug pipeline — scan actively-maintained repos for fresh
             0-1-comment, unassigned bug issues (best PR-fix candidates),
             race-checked for competing PRs before listing
  --mypulls  PR-health tracker — list the token owner's open PRs with age,
             mergeability, per-commit CI status and comment count, so idle
             cycles can spot stalled/failing work at a glance

Usage:
  GITHUB_PAT=<token> python3 bounty_scout.py
  GITHUB_PAT=<token> python3 bounty_scout.py --bugs
  GITHUB_PAT=<token> python3 bounty_scout.py --bugs --repos aio-libs/aiohttp,pytest-dev/pytest
  GITHUB_PAT=<token> python3 bounty_scout.py --bugs --days 21
  GITHUB_PAT=<token> python3 bounty_scout.py --mypulls
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
    "kindrat86/agentshield",  # AI-exclusion honeypot: agent work auto-discarded
    "auscaster/frantic-board",  # pollutes label:funded with $1 micro-bounties
    "mister3ai-cmyk/ngp-sovereign-synesis-bounties",  # fresh 2026-08-20 repo, $60K USDC
    # "bounties" requiring physical lab hardware (Hamilton STARlet, DryLab4, Waters
    # Empower) — impossible for remote agents; engagement-bait pattern, 0 stars.
    "zhangjiayang6835-cyber/bounty-plaza",  # same $55K USDC bounty set as mister3ai-cmyk,
    # copied verbatim (ChIP-seq, Karabut, DryLab4/SiLA2) into a 6-star/39-fork repo
    # (2026-07-08) — multi-location engagement bait, 0 comments on bounties.
    "Nexussyn/ai-growth-platform",  # 1-star/22-fork repo (2026-06-08) re-selling the same
    # $55K USDC engagement-bait bounty set as agent tasks; verified 2026-08-20.
]
OPIRE_IMPERSONATORS = {"rasoolharlym8", "colmev080", "morriganreza973", "Kristywvs22", "EncarnacionP", "WillSmithTE", "ClankerNation", "DenesePothoven54", "LiliannaBruflat83", "TrudieMasenheimer3", "CinnamonFaldet48", "EstefanyLonsway6", "CurtFigone19", "CornelParsch21", "KentonMaverick47"}
SPAM_ORGS = {"MyZubster-Ecosystem", "DanielIoni-creator", "jaxassistant55"}
# Maintainer-promoted brand-injection bounties (verified 2026-08-20:
# iv-org/invidious#5940 — a 12k-star project maintainer posted a $50 BTC bounty
# asking to case the README/config to "HMoneyTop", an unrelated third-party brand;
# purely cosmetic, no functional purpose, benefits an outside party). Do NOT work
# these even if payment is confirmed. Keyed per-issue because the repo itself is
# legitimate and must not be blanket-blocked.
KNOWN_BRAND_INJECT = {
    "iv-org/invidious#5940",
}
# Repos that explicitly reject LLM-generated PRs from new contributors.
# Verified 2026-08-19: python/mypy closed PR #21797 with "As per our policy we
# don't accept LLM generated PRs from new contributors." Agent work there is discarded.
LLM_BANNED_REPOS = {"python/mypy"}
TOKEN_RE = re.compile(r"\b\d+(?:\.\d+)?\s*(RTC|MRG|GOLD|EGGS?|MYZ|AIPOU|GSD|TOKEN|COIN)\b", re.IGNORECASE)
REWARD_RE = re.compile(r"\$\s?\d+(?:\.\d+)?|USDC\b|USDT\b", re.IGNORECASE)

# Default repo list for --bugs mode: actively-maintained, external-PR-friendly Python repos
DEFAULT_BUG_REPOS = [
    "aio-libs/aiohttp", "pytest-dev/pytest", "pallets/flask",
    "psf/requests", "pydantic/pydantic", "sphinx-doc/sphinx",
    "Textualize/rich", "sqlalchemy/sqlalchemy", "celery/celery",
    "urllib3/urllib3", "fastapi/fastapi", "encode/httpx",
    "encode/uvicorn", "benoitc/gunicorn", "pypa/pip",
    "psf/black", "mitmproxy/mitmproxy", "pallets/werkzeug",
    "pallets/jinja2", "httpie/cli",
]
EXTENDED_BUG_REPOS = [
    "python/cpython", "numpy/numpy", "scipy/scipy",
    "matplotlib/matplotlib", "sympy/sympy", "scikit-learn/scikit-learn",
    "networkx/networkx", "django/django", "getsentry/sentry",
    "ansible/ansible", "zulip/zulip", "npm/cli",
    "sveltejs/svelte", "axios/axios", "prettier/prettier",
    "vitest-dev/vitest", "babel/babel", "microsoft/debugpy",
    "apache/airflow", "apache/superset", "nektos/act",
    "astral-sh/uv", "hashicorp/terraform", "go-gitea/gitea",
]


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


def race_check(repo, issue_num, token):
    """Search for open/closed PRs referencing this issue number. Returns list of (num, state).
    Retries once on transient failure; on persistent failure returns [] (unknown) instead of
    a fake ('ERR', '') row that mislabels the candidate as PRIOR-PR."""
    for attempt in (1, 2):
        try:
            q = urllib.parse.quote(f'repo:{repo} is:pr "{issue_num}" in:body')
            data = api(f"https://api.github.com/search/issues?q={q}&per_page=5", token)
            return [(x["number"], x["state"]) for x in data.get("items", [])]
        except Exception as e:
            if attempt == 1:
                time.sleep(1.0)
            else:
                print(f"# race-check failed for {repo}#{issue_num}: {e}", file=sys.stderr)
    return []


def scan_bugs(repos, token, days):
    import datetime
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    found = 0
    for repo in repos:
        if repo in LLM_BANNED_REPOS:
            print(f"# {repo}: SKIPPED - repo rejects LLM-generated PRs from new contributors")
            continue
        try:
            issues = api(f"https://api.github.com/repos/{repo}/issues?labels=bug&state=open&sort=created&direction=desc&per_page=10", token)
        except Exception as e:
            print(f"# {repo}: API error {e}", file=sys.stderr)
            continue
        cands = []
        for it in issues:
            if it.get("pull_request") or it.get("assignee") or it.get("comments", 0) > 1:
                continue
            created = datetime.datetime.fromisoformat(it["created_at"].replace("Z", "+00:00"))
            if created >= cutoff:
                cands.append(it)
        if not cands:
            print(f"# {repo}: no fresh {days}d 0-1-comment unassigned bug issues")
            continue
        for it in cands:
            races = race_check(repo, it["number"], token)
            if any(s == "open" for _, s in races):
                raced = "RACE!"
            elif races:
                # every found PR is closed — could be merged (fix shipped) or
                # auto-closed (triage gate, rejection, deferral). Read the
                # closure reason before investing. Verified: scikit-learn#34734's
                # PR #34743 was bot-closed 27s after opening (Needs Triage).
                raced = "PRIOR-PR"
            else:
                raced = "clean"
            print(f"[{it['created_at'][:10]}] [{it['comments']}c] {repo}#{it['number']} {raced}")
            print(f"      {it['title'][:90]}")
            print(f"      {it['html_url']}")
            if races:
                print(f"      PRs: " + ", ".join(f"#{n} {s}" for n, s in races))
            print()
            found += 1
            time.sleep(0.2)
    if not found:
        print("# No fresh unclaimed bug candidates found.")
    else:
        print(f"# candidates: {found} (race-checked)")


def scan_mypulls(token):
    """Track the token owner's open PRs: age, mergeability, head-commit CI, comments.
    Flags DRAFT / CONFLICT / CI-FAIL / RUNNING so stalled work is visible in one pass."""
    import datetime
    me = api("https://api.github.com/user", token)
    login = me.get("login", "?")
    q = urllib.parse.quote(f"author:{login} is:pr is:open")
    data = api(f"https://api.github.com/search/issues?q={q}&sort=updated&order=desc&per_page=25", token)
    items = data.get("items", [])
    print(f"# open PRs by {login}: {data.get('total_count', len(items))}")
    now = datetime.datetime.now(datetime.timezone.utc)
    rows = []
    for it in items:
        ow, rn = it["repository_url"].rsplit("/", 2)[-2:]
        full = f"{ow}/{rn}"
        pr = api(f"https://api.github.com/repos/{full}/pulls/{it['number']}", token)
        created = datetime.datetime.fromisoformat(it["created_at"].replace("Z", "+00:00"))
        age = (now - created).days
        mergeable = pr.get("mergeable")
        mstate = pr.get("mergeable_state")
        sha = (pr.get("head") or {}).get("sha", "")
        ci = "no-runs"
        if sha:
            try:
                runs = api(f"https://api.github.com/repos/{full}/commits/{sha}/check-runs?per_page=50", token)
                rs = runs.get("check_runs", [])
                if not rs:
                    ci = "no-runs"
                elif any(r.get("status") != "completed" for r in rs):
                    ci = "RUNNING"
                else:
                    # "Backport label added" is a maintainer-side gate (only
                    # maintainers can add the label) — report as GATE, not FAIL.
                    bad = sorted({(r.get("conclusion") or "?") for r in rs
                                  if r.get("conclusion") not in ("success", "skipped", "neutral")})
                    gate = [r["name"] for r in rs
                            if r.get("name") == "Backport label added" and r.get("conclusion") == "failure"]
                    if gate and bad == ["failure"]:
                        ci = "GATE:backport-label"
                    elif not bad:
                        ci = "OK"
                    else:
                        ci = "FAIL:" + ",".join(bad)[:40]
            except Exception as e:
                ci = f"err:{str(e)[:24]}"
        flags = []
        if pr.get("draft"):
            flags.append("DRAFT")
        if mergeable is False:
            flags.append("CONFLICT")
        if ci.startswith("FAIL"):
            flags.append("CI-FAIL")
        rows.append((age, created.strftime("%Y-%m-%d"), full, it["number"], ci,
                     str(mergeable), mstate or "", it.get("comments", 0),
                     ",".join(flags) or "-", it["title"][:70], it["html_url"]))
        time.sleep(0.2)
    for age, created, full, num, ci, mergeable, mstate, cmts, flags, title, url in sorted(rows, reverse=True):
        print(f"[{created}] [{age:3d}d] {full}#{num} ci={ci:12s} mergeable={mergeable:5s}/{mstate:8s} [{cmts}c] {flags}")
        print(f"      {title}")
        print(f"      {url}")
    return rows


def main():
    args = [a for a in sys.argv[1:]]
    token = os.environ.get("GITHUB_PAT", "")
    if not token:
        sys.exit("GITHUB_PAT env var required")
    if "--mypulls" in args:
        scan_mypulls(token)
        return
    if "--bugs" in args:
        repos = DEFAULT_BUG_REPOS + (EXTENDED_BUG_REPOS if "--extended" in args else [])
        days = 14
        if "--repos" in args:
            i = args.index("--repos")
            repos = [r.strip() for r in args[i + 1].split(",") if r.strip()]
        if "--days" in args:
            i = args.index("--days")
            days = int(args[i + 1])
        print(f"# fresh-bug scan: {len(repos)} repos, last {days} days")
        scan_bugs(repos, token, days)
        return

    # 2026-08-20: GitHub search API now rejects OR-combining multiple label:"$NNN"
    # qualifiers with HTTP 422. Split into per-label queries (each alone still works).
    queries = [
        'label:"$100" is:issue is:open',
        'label:"$200" is:issue is:open',
        'label:"$250" is:issue is:open',
        'label:"$500" is:issue is:open',
        'label:bounty label:bug is:issue is:open no:assignee',
        'label:"\U0001F48E Bounty" state:open',
    ]
    seen = {}
    for q in queries:
        url = "https://api.github.com/search/issues?q=" + urllib.parse.quote(q) + "&sort=created&order=desc&per_page=8"
        for attempt in (1, 2):
            try:
                data = api(url, token)
                break
            except Exception as e:
                if attempt == 1:
                    time.sleep(2.0)  # search API rate limit is 10/min with a token
                else:
                    print(f"# query failed: {e}", file=sys.stderr)
                    data = None
        if data is None:
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
        if f"{full}#{num}" in KNOWN_BRAND_INJECT:
            print(f"# skipped: {ow}/{rn}#{num} (known brand-injection scam)")
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