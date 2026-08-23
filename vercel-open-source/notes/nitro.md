# Nitro (Tier 1) — hunting notes

Cloned: `repos/nitro` — main is **3.0.x-beta**. ⚠️ IMPORTANT SCOPE NOTE:

Nitro 3 **removed `basicAuth` as a route rule** — see
`repos/nitro/src/config/resolvers/route-rules.ts:15` which now *throws*:
"`basicAuth` is not a route rule ... Register h3's `basicAuth` middleware instead."

So the focus-area bugs **(1) basicAuth bypass via percent-encoding** and **(2) basicAuth + a
terminating route rule (proxy/redirect/cache) skipping auth** apply to **Nitro 2.x (the current
stable line)**, NOT this Nitro 3 beta. To hunt those: clone Nitro 2 stable separately:
`git clone https://github.com/nitrojs/nitro -b v2 repos/nitro-v2` (or install `nitropack@^2`).

## Focus areas & where to look

### A. basicAuth percent-encoding bypass (test on Nitro 2 stable)
Hypothesis: the encoded form of a path passes the basicAuth check but the decoded form reaches
the protected handler (e.g. auth matches on `/admin%2f..` but routing decodes to a protected
path, or auth is applied to a normalized path while the handler sees the raw one).
- In Nitro 2: find the `basicAuth` route-rule handler + the order of URL decoding vs auth match.
- Test: `/protected` guarded; try `/protected%2e`, `/%70rotected`, `/protected/..%2f`,
  trailing-dot/`%2f` tricks, double-encoding. Does any decoded variant reach the handler unauthed?

### B. Route-rule composition skips auth (test on Nitro 2 stable)
Hypothesis: on overlapping paths, a *terminating* rule (`proxy`, `redirect`, `cache`) executes
**before** the basicAuth rule, so auth never runs.
- Config `routeRules` with both `basicAuth` and e.g. `proxy`/`redirect` on the same/overlapping
  path. Check the rule-application order in the runtime.

### C. Path traversal in proxy / prerender (applies to Nitro 3 too — testable in the clone)
- `repos/nitro/src/runtime/internal/route-rule-handlers.ts` — proxy route-rule handler.
- Prerender pipeline: grep `prerender` under `src/`.
- Hypothesis: a proxy target or prerender output path derived from user input escapes the project
  workspace → arbitrary file read/write. Look for `path.join`/`resolve` on request-derived data
  without containment, and for `..` handling in the proxy `target` / static file serving.

### D. (lower priority) SSRF via proxy target
Only in scope if a **framework-owned** path bypasses developer allowlist config entirely.
Also: WebSocket upgrade bypassing global middleware auth.

## PoC shape
For A/B: minimal Nitro 2 app with `routeRules` (basicAuth + proxy) → show an unauthenticated
request reaching the protected handler / terminating rule. For C: show a request reading a file
outside the intended dir.

## RESULT (2026-08-23): basicAuth route rule DOES NOT EXIST in supported versions → A/B DEAD
- Cloned Nitro 2 stable (v2 branch, 2.13.4) into `repos/nitro-v2`.
- `createRouteRulesHandler` (src/runtime/internal/route-rules.ts) handles ONLY headers/redirect/proxy;
  route-rule TYPES (src/types/route-rules.ts:8-25) are cache/headers/redirect/prerender/proxy/isr/
  swr/cors/static. **No `basicAuth`/`auth` route rule.** grep `basicAuth` = 0 hits in the whole repo.
- Nitro 3 removed it explicitly (points to h3's basicAuth middleware). So focus-area A (percent-encode
  bypass) and B (rule-composition skip) target a feature that isn't a Nitro route rule in supported
  versions → NOT reportable against Nitro. DEAD.
- Residual (agent ae6af4ff is covering on Nitro 3): proxy route-rule path handling
  `joinURL(target, event.path)` for wildcard `/**` proxies (route-rules.ts ~56-79) — SSRF/traversal.
  Nitro 2 already collapses leading `//`; looks guarded. Low priority.

## Status: basicAuth focus area DEAD (feature absent). Proxy traversal delegated to Nitro-3 agent.
