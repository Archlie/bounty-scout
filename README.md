# bounty-scout

Scout GitHub for funded/open bounty issues and flag scam patterns before you spend time on them.

A dependency-free, single-file CLI that queries the GitHub Search API (`/search/issues`) for
bounty-like issue pools, deduplicates them, and tags each hit with heuristic risk flags.

## Usage

```bash
GITHUB_PAT=ghp_xxx python3 bounty_scout.py
GITHUB_PAT=ghp_xxx python3 bounty_scout.py --bugs
GITHUB_PAT=ghp_xxx python3 bounty_scout.py --bugs --repos aio-libs/aiohttp,pytest-dev/pytest --days 21
```

Modes:

- **default** — 3 targeted bounty searches, scam-tagged and deduplicated.
- `--bugs` — fresh-bug pipeline: scans actively-maintained repos (20 built-in defaults, or
  pass `--repos`) for bug issues that are new (default 14 days, `--days`), unassigned, with
  0-1 comments, then **race-checks each one** for competing open PRs (repos like aiohttp
  get claimed within a day — never invest before this check). Prints `RACE!` vs `clean`.

Requires a GitHub personal access token (public repo + search scopes). Read-only: it only calls
GET endpoints.

## Output

One block per issue, sorted by comment count (community attention proxy):

```
[ 33] claude-builders-bounty/claude-builders-bounty#1 tags=SPAM-LIST,3rd-party-bounty-site,read-carefully reward~$50
       [BOUNTY $50] SKILL: Generate a structured CHANGELOG from git history
       https://github.com/claude-builders-bounty/claude-builders-bounty/issues/1
```

## Risk flags

| tag | meaning |