# Progress Tracker — Vercel Open Source bounty

Last updated: 2026-08-23. Update the Status line in each `notes/<target>.md` as you go.

## Setup
- [x] Folder structure + docs (SCOPE.md, PLAN.md, notes/, poc/)
- [x] All 16 in-scope repos cloned shallow into `repos/` (see `repos/clone.log`)
- [ ] Nitro 2.x stable checkout for basicAuth focus areas (`repos/nitro-v2`) — Nitro 3 removed it
- [ ] Confirm each target's latest **stable** version before reporting (clones are main/canary)

## Target status
| # | Target | Tier | Note file | Status |
|---|--------|------|-----------|--------|
| 1 | Nuxt | T1 | notes/nuxt.md | DONE — guards solid; only low dev-config gap (route-rules.ts) |
| 2 | flags | T1 | notes/flags.md | DONE (1st pass) — hardened, deprioritized |
| 3 | Nitro | T1 | notes/nitro.md | not started (need v2 for basicAuth) |
| 4 | Skills / Agent-Skills | T1 | notes/skills.md | DONE — no write bug; PLAUSIBLE symlink-deref file READ (git-source) |
| 5 | AI SDK | T1 | notes/ai-sdk.md | CONFIRMED SSRF (OAuth AS URL) — PoC pending |
| 6 | chat | T2 | notes/chat.md | CONFIRMED telegram fail-open — verify+PoC pending |
| 7 | Turborepo | T1 | notes/turborepo.md | ✅ DONE — CONFIRMED token exfil, PoC+report ready |
| 8 | SvelteKit / Svelte | T2 / T1 | notes/sveltekit.md | not started |
| 9 | SWR | T1 | notes/other-targets.md | not started |
| 10 | workflow | T1 | notes/other-targets.md | not started |
| 11 | Vercel CLI | T1 | notes/other-targets.md | not started |
| 12 | Next.js | T1 | notes/other-targets.md | not started |
| 13 | Eve | T2 | notes/other-targets.md | not started |
| 14 | ms | T2 | notes/other-targets.md | not started |

## Wave 2 (in flight, 2026-08-23): deep-hunt agents on Next.js (middleware/cache + image/RSC),
## workflow, Vercel CLI, Nitro-3 proxy traversal, Svelte SSR compiler. Verifying results as they land.
- nitro basicAuth (A/B): DEAD — feature absent in Nitro 2.13.4 stable + Nitro 3 (not a route rule).
- nitro path traversal / proxy SSRF / WS-auth-bypass (Nitro 3 beta): ALL DEAD — prerender decodes+
  checks `..`+startsWith(publicDir); static/vfs are hashmap lookups (no path join); proxy target is
  dev-config (h3); WS upgrade runs full pipeline incl. middleware; dev endpoints loopback-gated.
  Nitro fully cleared — do not pursue.

## Wave 2 results so far
- next.js image-optimizer SSRF/DoS + RSC/Server Actions (16.4.0-canary.2): ALL DEAD/not-worth-filing.
  Validator reuses normalized URL (no parser differential); isPrivateIp via ipaddr.js blocks
  metadata/encodings/IPv6; redirects re-check internal; Server Actions Origin==Host + preflight
  gate CSRF; action-id lookup null-proto + length-checked. Only residual: A4 DNS-rebind TOCTOU —
  blind, gated by remotePatterns '**', behind new-canary defense w/ dangerouslyAllowLocalIP opt-out
  → accepted-risk, DON'T file. RSC deserialization is React's surface, not Next's.

- next.js middleware authz + cache poisoning (16.4.0-canary.2): ALL DEAD. x-middleware-subrequest
  (CVE-2025-29927) mechanism REMOVED entirely; filterInternalHeaders strips all x-middleware-*/
  x-matched-path/etc unconditionally; path normalization consistent (WHATWG URL before matcher,
  bslash+// → 308); RSC cache-busting header validation ON by default; `use cache` shared bodies
  can't read cookies/headers (cleared ALS). Next.js cleared on both slices — DON'T pursue.

- vercel-cli (58.4.4): DEAD. apiUrl NOT project-overridable (global config only, no vercel.json
  field); no repo-controlled absolute URL reaches token-bearing client.fetch; deploy upload uses
  lstat (no symlink deref); vercel build/dev code-exec is by-design. Residual (latent, not live):
  client._fetch attaches bearer to ANY host + env-overridable AI-gateway URL, but no command loads
  repo .env into process.env before an AI-gateway fetch → chain incomplete. Well-built.
- workflow @workflow/core 5.0.0-beta.44: CONFIRMED mechanism — predictable webhook/hook tokens
  (CWE-338). VM seeds Math.random with runId:workflowName:deploymentId (vm/index.ts:55,61,
  workflow.ts:353); token = seeded generateNanoid (workflow.ts:406, hook.ts:100); createWebhook
  forces it (create-hook.ts:63) into a public URL. PoC (poc/workflow-token-predict/) derives the
  token from the non-secret seed. ⚠️ TRIAGE-RISKY: docs say token "not a security contract" +
  beta + needs runId exposure → NOT a safe trial-report bet. Report/zip ready but HOLD; file the 2
  clean ones first. Details in poc README.
- workflow Finding 2 (unauth /flow step-exec on self-hosted world-postgres/local): PLAUSIBLE but
  docs assign endpoint security to the operator → weak/hardening-only. Not filing.

## Findings log (candidate bugs)
Format: date | target | file:line | hypothesis | verdict (confirmed/dead/needs-poc).
- 2026-08-23 | skills | sanitize.ts:32 | C1 (0x80-0x9f) escape bypass | DEAD — already stripped
- 2026-08-23 | flags | verify-access.ts:32 | verifyAccess fail-open | DEAD — false/throws
- 2026-08-23 | flags | create-flags-discovery-endpoint.ts:23 | discovery endpoint unauth by default | DEAD — 401 by default
- 2026-08-23 | flags | lib/crypto.ts | override cookie forgery / not session-scoped | DEAD — JWE A256GCM, 256-bit key required, purpose-claim enforced, not forgeable w/o FLAGS_SECRET
- 2026-08-23 | flags | VERDICT | core hardened on all obvious classes | DEPRIORITIZE flags
- 2026-08-23 | skills | install.ts/archive.ts | install write-path traversal / symlink escape | DEAD — sanitizeName+isPathSafe recheck at every sink; archives reject ../abs/symlink
- 2026-08-23 | skills | installer.ts:487 use.ts:594 | cp {dereference:true} on git-source install → arbitrary FILE READ into workspace (CWE-59/200) | PLAUSIBLE-NEEDS-POC (read primitive; git-source only; maybe known)
- 2026-08-23 | ai-sdk | packages/mcp/src/tool/oauth.ts:1216 + :385 + oauth-types.ts:19 | SSRF via OAuth PRM authorization_servers[0] (SafeUrlSchema allows internal http), optional validateAuthorizationServerURL hook, redirect-follow | ✅ CONFIRMED + WORKING PoC on @ai-sdk/mcp 2.0.36; report+zip ready | MED
- 2026-08-23 | turborepo | turbo_json.rs + run/builder.rs + auth/mod.rs | token exfil via turbo.json remoteCache.apiUrl (trust gate only in login flow) | ✅ CONFIRMED + WORKING PoC on turbo 2.10.11 stable; report+zip in reports/ | HIGH
- 2026-08-23 | chat | packages/adapter-telegram/src/index.ts:485 | webhook auth fail-open by default (all other adapters fail-closed) → unauth inbound, forge from.id | CONFIRMED by agent — verify + PoC needed | MED
- 2026-08-23 | nuxt | app/middleware/route-rules.ts:11 | redirect missing isScriptProtocol before location.href | LOW/DEAD — input is build-time dev config, not attacker-controlled
- 2026-08-23 | swr | helper.ts:46 (INITIAL_CACHE) | module-global defeats per-request provider (PoC test2b confirms mechanically) | PARKED — no realistic server-side trigger to populate it with victim data
- 2026-08-23 | sveltekit | runtime/shared.js:197,213,242,321 | polynomial/exponential CPU DoS via nested Map/Set revivers in remote-function arg parse (unauth GET) | CONFIRMED at parser level, repro on stable 2.70.3 — BUT gated on experimental.remoteFunctions + it's a DoS → likely OUT OF SCOPE (program excludes DoS + experimental-gated). Park unless reframed.

## Reports drafted (ready to submit on HackerOne) — both have working PoCs + form-ready text
1. **Turborepo token exfil via turbo.json remoteCache.apiUrl** — HIGH, Tier 1.
   Form-ready: `reports/SUBMISSION-1-turborepo.md` · zip: `reports/turbo-token-exfil-poc.zip`
   · full write-up: `reports/turbo-token-exfil.md`. Confirmed on turbo 2.10.11 (stable).
2. **AI SDK MCP OAuth SSRF** — MEDIUM, Tier 1 (named focus area).
   Form-ready: `reports/SUBMISSION-2-ai-sdk.md` · zip: `reports/ai-sdk-mcp-oauth-ssrf-poc.zip`.
   Confirmed on @ai-sdk/mcp 2.0.36.
   SUBMIT ORDER: Turborepo first (higher confidence/severity), then AI SDK. Signal requirement is
   active (4 trial reports) — only these two are PoC-backed; do NOT submit the caveated ones.

## Submitted reports
_None yet. Format: date | H1 report link | target | severity | status | bounty._
