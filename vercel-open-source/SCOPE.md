# Vercel Open Source — Scope & Rules (quick reference)

Program: **vercel-open-source** on HackerOne · Launched Feb 2026 · Contact: security@vercel.com
Policy snapshot saved: 2026-08-23. Re-check the live policy before submitting — scope changes.

## Rewards (CVSS 4.0, at Vercel's discretion)

| Severity | Tier 1 OSS | Tier 2 OSS |
|---|---|---|
| Low | $200–$500 | $50–$200 |
| Medium | $550–$1,000 | $250–$500 |
| High | $1,250–$5,000 | $750–$2,500 |
| Critical | $5,250–$10,000 | $2,750–$5,000 |

90-day avg bounty ≈ $274 (low) … $8,213 (critical). Top range paid: $4,750–$10,250.
Bonuses possible for: exceptional impact, high-quality report + patch, or bugs in code shipped
within the last week (Vercel Changelog).

## Tier 1 (highest priority / highest pay)
Next.js · Nuxt · SWR · Svelte · Turborepo · AI SDK · Vercel CLI · workflow · flags · Nitro ·
Agent-Skills · Skills

## Tier 2 (standard)
Eve · chat · ms · SvelteKit · all other vercel / vercel-labs OSS repos.
Note: a critical/high on a Tier 2 asset with a clean exploit chain *may* be paid at Tier 1 rates.

## HARD REQUIREMENTS (report is rejected without these)
1. **Working PoC in a .zip** that an independent reviewer can run and reproduce.
2. **Affected version(s)** field filled in correctly.
3. **End-to-end impact demonstrated** — not just an entry point. Show what an attacker
   concretely reads / writes / executes / extracts.
4. **Reproducible on a stable release** (supported, in-scope versions).
   - Canary/RC is in scope ONLY if no stable release has superseded it.
5. One vulnerability per report (unless a chain is needed for impact).

## AUTO-REJECTED
- SAST / scanner output with no working exploit chain.
- AI/LLM-generated findings not manually verified with a functional PoC.
- Theoretical chains needing unrealistic conditions.
- Bugs requiring the attacker to already have privileged/local access.
- "Dependency has a CVE" with no demonstrated in-context exploit.
- Bugs only in a canary/RC already superseded by stable.
- Examples / templates / docs snippets / starter projects.
- Missing security headers not set by default.
- Build-time tooling (webpack/babel/terser), dev-mode-only DoS, DoS via legitimate use.

## RULES OF ENGAGEMENT (important)
- **NEVER test against Vercel production systems** (live services, prod sites/APIs, deployed
  customer envs, Vercel-maintained CI/CD, Vercel infra). Test only **locally against source**,
  using standard/documented dev setups and the latest stable release.
- No social engineering. Good-faith testing only. Don't access data you don't own.
- **Confidentiality**: reports, PoCs, and comms are confidential for 2 years. Don't publish
  without Vercel's written consent. Any related PRs go via **private forks** unless told otherwise.
- Use HackerOne alias email for test accounts: `<h1username>@wearehackerone.com`.

## CVE thresholds
- Tier 1: adjusted CVSS ≥ 3.8 → CVE-eligible.
- Tier 2: adjusted CVSS ≥ 7.0 → CVE-eligible.
- Must be in distributable code (npm/pypi/etc), not experimental/dev-mode.

## SLAs
First response ~1 business day · Triage ~7 business days · Bounty decision ~10 business days after triage.
