# Vercel Open Source — Hunting Plan

> Goal: find real, reproducible vulnerabilities in in-scope Vercel OSS, with a working PoC,
> and submit high-quality reports. Read `SCOPE.md` first for the rules that get reports rejected.

## The one idea that matters

The program's **Per-Asset Focus Areas** are not fluff — they are a menu of the exact bug
*shapes* Vercel will pay for. Each concrete bullet ("basicAuth bypass via percent-encoded
characters", "javascript: URIs in NuxtLink") is a **hypothesis**. Your job for each one:

1. Find the code path that would contain that bug.
2. Read it in the **latest stable release**.
3. Decide: does the described weakness actually exist here, right now?
4. If yes → build a minimal PoC that proves end-to-end impact → write the report.

Most hypotheses will be "already fixed / not present." That's normal. You're looking for the
one that's still live. Don't submit a guess — the program explicitly rejects unverified
AI/scanner output. Every submission needs a PoC you ran yourself.

## How to not waste effort (beginner ROI)

- **Start small and concrete.** A tiny SDK with one sharply-described bug class (flags, Nitro,
  Skills) is far better than diving into Next.js, which is enormous and already picked over by
  the top hunters on the leaderboard.
- **Prefer bugs you can test on a laptop** with a documented `dev` setup — no cloud, no Vercel
  prod (which is forbidden anyway).
- **One target at a time.** Fully exhaust its focus list, log results, move on.
- **Check the fix history.** Before going deep, `git log`/GitHub Security Advisories for the
  target — if your idea was patched last month, it's a dup. Newly shipped code (last week per
  the Changelog) is bonus-eligible and less picked-over.

## Recommended attack order (best beginner ROI first)

| # | Target | Tier | Why start here | Core hypothesis to test |
|---|--------|------|----------------|--------------------------|
| 1 | **Nuxt** | T1 | Small navigation surface, testable in a browser | `javascript:`/`data:`/`vbscript:` URI reaches DOM via NuxtLink / `reloadNuxtApp` / router |
| 2 | **flags** | T1 | Tiny SDK, HTTP endpoint, easy to reason about | well-known/discovery endpoint unauth → enumerate flags; override not session-scoped |
| 3 | **Nitro** | T1 | Concrete middleware bugs, local repro | basicAuth bypass via `%`-encoding; route-rule composition skips auth |
| 4 | **Skills / Agent-Skills** | T1 | Small CLIs, very concrete bugs | path traversal on install (out-of-bounds write); ANSI/OSC escape in SKILL.md metadata; covert curl\|bash |
| 5 | **AI SDK** | T1 | Concrete MCP bugs, high interest | MCP allowlist bypass via prototype inheritance; `file://` passes OAuth URL schema check |
| 6 | **chat** | T2* | Clear framework property to break | tool approval / inputs rebuilt from client `messages[]`; session/message IDOR |
| 7 | **Turborepo** | T1 | High value, needs a local cache server | token exfil to attacker cache origin; symlink traversal on cache extract |
| 8 | **SvelteKit** | T2 | Concrete request-handling bugs | `BODY_SIZE_LIMIT` bypass via encoding; `$lib/server` guard bypass; devalue proto-pollution |
| 9 | **SWR** | T1 | Narrow, high-impact class | module-global state shared across concurrent SSR requests |
| 10 | **Svelte** | T1 | Needs compiler depth | SSR template-literal injection via HTML-entity sequences in attribute strings |
| 11 | **workflow** | T1 | Newer code, less picked-over | step injection / step bypass / cross-workflow state access |
| 12 | **Vercel CLI** | T1 | | token exposure to other processes; malicious project config → code exec on deploy/build |
| 13 | **Next.js** | T1 | Highest value but crowded/hard | cache poisoning; middleware/route authz bypass; image optimizer SSRF |
| 14 | **Eve** | T2 | | framework-owned tool exec / channel auth bypass / secret leak |
| 15 | **ms** | T2 | Low ceiling (ReDoS only) | parsing DoS with a production-reachable path |

\* chat is Tier 2 but a clean session-ownership/tool-approval break can be paid at Tier 1.

## Per-target playbooks

Detailed, checkable hypotheses and "where to look" for each target live in `notes/<target>.md`.
Each starts as the focus-area bullets rephrased as yes/no questions against the code. Fill in
real file paths as you read (the clones populate `repos/`).

## Per-hunt workflow

For each target:
1. `cd repos/<target>`, check the released version: `git describe --tags` / `package.json`.
2. Skim the README + the module named in the focus area. Find the exact function.
3. Read the code against the hypothesis. Write findings in `notes/<target>.md`
   (even negatives — "checked X, sanitized at line N" saves you re-reading later).
4. If a hypothesis holds, build the **minimal** reproducing app in `poc/<target>-<bug>/`.
   - Real dependency install, latest stable version, documented setup.
   - A script or steps a reviewer runs to see the impact.
5. Confirm end-to-end impact (actual XSS fires / file written outside dir / token leaves / etc).
6. Search GitHub issues/PRs/advisories to confirm it isn't already tracked → else it's a dup.
7. Write the report from `notes/REPORT-TEMPLATE.md`, zip the PoC, fill "Affected version(s)".

## Definition of done for a submission
- [ ] Bug reproduces on a current **stable** release (version noted).
- [ ] PoC zip runs and shows concrete impact end-to-end.
- [ ] Not already fixed / tracked in an open issue or PR.
- [ ] Impact + severity (CVSS 4.0) argued honestly.
- [ ] Report written like a human, clear repro steps, optional patch suggestion (bonus).
