# Remaining targets — condensed hypotheses

Lower on the priority list (harder, crowded, or lower ceiling). Promote to a full note when you
start one. Always repro on the latest **stable** release.

## SWR (Tier 1) — `repos/swr` (v2.5.1) — IN PROGRESS, promising lead
Headline class: **SSR request isolation failure** — module-global internal state shared across
concurrent server-side requests, so one request's data leaks into another's.

### First-pass analysis (2026-08-23)
Module-global mutable singletons found:
- `src/_internal/utils/config.ts` — default `cache = initCache(new Map())` created ONCE at module
  scope; shared by every SSR request unless the app supplies a per-request `provider`.
- `src/_internal/utils/helper.ts:6` — `INITIAL_CACHE: Record<string,any> = {}` — module-global,
  keyed by SWR key string, **write-once per key, NEVER reset** (grep confirms no clear anywhere).
  Crucially it's NOT part of the cache provider, so `provider: () => new Map()` per-request
  isolation does NOT isolate it.
- `src/_internal/utils/timestamp.ts` — global `__timestamp` counter (low risk).

Mechanism (`use-swr.ts:225` createCacheHelper → `use-swr.ts:273-345` getSnapshot →
`useSyncExternalStore(..., getSnapshot[1])` at :350):
- `getInitialCache()` (helper.ts:44-49) returns `INITIAL_CACHE[key]` if the key is present, else
  `cache.get(key)`.
- serverSnapshot (`use-swr.ts:309-312`): if `cachedData === initialData` it's the client snapshot,
  else derived from `initialData`. **For a key NOT yet in INITIAL_CACHE, initialData ===
  cache.get(key)** → serverSnapshot = current cache value. On a long-lived server the default
  cache holds the previous request's data → **user B's SSR HTML can contain user A's data.**
- The setter (helper.ts:31-38) does `if (!(key in INITIAL_CACHE)) INITIAL_CACHE[key] = prev`. On a
  fresh process the first setCache for a key usually has prev=undefined, locking it to undefined;
  the sharper leak is the default-cache path above and the provider-bypass property of INITIAL_CACHE.

### Empirical PoC results (poc/swr-ssr-leak/ — swr@2.5.1, react-dom@18)
- test.js: plain default-cache + mutate seeding → server render shows `data=undefined` (NO leak).
  Reason: mutate's setCache locks INITIAL_CACHE[key]=undefined (prev was undefined), and the server
  snapshot returns that undefined, so SSR renders empty and relies on request-scoped `fallback`.
- test2.js (a): suspense SSR requires `fallback` (throws otherwise) → request-scoped, no cache read.
- test2.js (b): ✅ **MECHANISM CONFIRMED** — after forcing INITIAL_CACHE[key]=Alice's value, a
  DIFFERENT request with a fresh empty `provider: () => new Map()` still rendered Alice's token in
  its SSR HTML. So the module-global INITIAL_CACHE genuinely defeats per-request provider isolation
  (`helper.ts:46`).

### Verdict: PLAUSIBLE-BUT-NOT-YET-EXPLOITABLE. The leak is real mechanically, but populating
INITIAL_CACHE[key] with a victim's real data ON THE SERVER requires a non-`undefined` prev at the
first-ever setCache for that key — which normal SSR (effects don't run; mutate's first write has
prev=undefined) does not produce. NOT reportable until a realistic default-config app pattern that
populates INITIAL_CACHE server-side with user data is found. Residual idea to chase: any SWR
integration that does raw `cache.set` (bypassing the setter) before a mutate, or a long-lived
server where a client-like write path runs server-side. Parked.
- Lower priority: proto-pollution via crafted cache keys (needs full chain to impact).

## workflow (Tier 1) — `repos/workflow` (packages/* @ 5.0.0-beta.44)
⚠️ beta — many packages are beta; confirm which are published/stable enough to be in scope.
Classes: **step injection** (runtime executes a step not in the definition / a substituted
malicious step); **step bypass** (skip a step that does authz/validation); **cross-workflow
access** (read/trigger another workflow's steps/state); **authz boundary / replay or forge step
completions**; injection into step scheduling / state persistence / event handling (broadest blast
radius → highest priority).
- Read `packages/core/src` and `packages/workflow/src`: how step identities are derived, how step
  completions are validated (signed? replayable?), how state is keyed per workflow instance/tenant.

## Vercel CLI (Tier 1) — `repos/vercel-cli`
Classes: **credential/token exposure** to other local processes or the network during CLI ops;
**arbitrary code execution from malicious project config** during deploy/build; **path traversal /
file exfil** during build/deploy; **privilege escalation between project/team scopes**.
- Hunt: where the CLI reads project config (`vercel.json`, build settings) and whether any field
  triggers command execution; how the auth token is stored/passed (env to child processes? logged?
  sent to a config-controlled URL?); what files get uploaded on deploy (does an ignore/traversal
  bug include files outside the project?).

## Next.js (Tier 1) — `repos/next.js` (huge, crowded — go here last / only if you have an angle)
Priority classes: **middleware/routing authz bypass** (reach a protected route you shouldn't) —
grep the middleware matcher/normalization; **cache poisoning / cache-key confusion** (ISR,
full-route cache, `use cache`) — a crafted response stored and served to others; **RSC / Server
Actions / Flight** deserialization, CSRF bypass, data exposure; **image optimizer SSRF** (bypass
the internal allowlist in `next/dist/server/image-optimizer`) & DoS via malformed images;
**SSRF via host/forwarded-header reflection**.
- Dev-server bugs are lower priority (need a production path). Check recent CVEs/advisories first
  to avoid dups — this repo is heavily hunted.

## Eve (Tier 2) — `repos/eve`
Framework-owned issues only (not insecure agent implementations): framework executing tools its
own security model should block; secret leakage through framework runtime / built-in channel
handlers (HTTP/Slack/Discord); **unauthenticated control via framework channel endpoints** (auth
is Eve's responsibility); sandbox/isolation escape between agent contexts.

## ms (Tier 2) — `repos/ms` (v4.0.0) — low ceiling
Only ReDoS/parsing DoS, and only with a concrete production-reachable path. Check the parse regex
in `src/` for catastrophic backtracking. Small payoff; do only if quick.
