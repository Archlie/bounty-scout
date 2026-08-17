# bounty-scout

Scout GitHub for funded/open bounty issues and flag scam patterns before you spend time on them.

A dependency-free, single-file CLI that queries the GitHub Search API (`/search/issues`) for
bounty-like issue pools, deduplicates them, and tags each hit with heuristic risk flags.

## Usage

```bash
GITHUB_PAT=ghp_xxx python3 bounty_scout.py
GITHUB_PAT=ghp_xxx python3 bounty_scout.py --queries "bounty is:issue is:open" "funded is:issue is:open" --max-items 100
```

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
| --- | --- |
| `SPAM-LIST` | repo was manually verified as a scam/fake-bounty operation |
| `3rd-party-bounty-site` | claims are routed through a third-party bounty site (Opire/Frantic-style) |
| `new-little-repo-big-claim` | big $ reward on a tiny/young repo (<30 stars, <5 forks) |
| `token-flavored` | reward is an obscure internal token (RTC/MRG/EGGS/...) rather than cash |
| `read-carefully` | read the full body before trusting; often paired with other flags |

No flag is proof. Treat every bounty as unverified until you confirm the funding receipt,
the repo history, and the payout mechanism yourself.

## Notes

- Real, reliable bounty sources as of last check: Algora (requires login), Polar (API changes),
  NSPG13/agent-bounties (USDC-on-Base micro-rewards), and GitHub issues with explicit funded
  receipts.
- Never prepay, never deposit, never share keys/KYC for a bounty.