# flags (Tier 1) — hunting notes

Cloned: `repos/flags` — `packages/flags` is **v4.3.0**.

Focus area: framework's own **flag discovery endpoint** left unauthenticated (enumerate all
flags/variants — leaks unreleased features); **flag override** not scoped to the setting session
or triggerable without auth; evaluation responses leaking a user's segment/cohort.

## Key files
- `packages/flags/src/next/create-flags-discovery-endpoint.ts:16` — `createFlagsDiscoveryEndpoint()`
  the framework helper that wires up `.well-known/vercel/flags`. **Read whether it enforces
  `verifyAccess` by default or leaves it to the developer.**
- `packages/flags/src/lib/verify-access.ts:24` — `verifyAccess(authHeader, secret=FLAGS_SECRET)`.
  Note line ~35: if called without a secret it warns and (check!) returns what? If it returns
  `true`/undefined-as-pass when `FLAGS_SECRET` is unset, that's an auth-open-by-misconfig path.
- `packages/flags/src/lib/crypto.ts` — `encryptOverrides` / `decryptOverrides` /
  `verifyAccessProof`. Override cookie = `vercel-flag-overrides`.
- `packages/flags/src/next/overrides.ts` — reads/decrypts the override cookie.
- `packages/flags/src/types.ts:58` — "encryption mode for the vercel-flag-overrides cookie".

## Hypotheses to test (yes → candidate bug)
1. **Discovery endpoint open by default.** Does `createFlagsDiscoveryEndpoint` call
   `verifyAccess` itself, or only if the developer opts in? If a default wiring returns flag
   definitions to an unauthenticated request, that's the headline focus-area bug. Trace the
   returned handler: does it 401 on a missing/invalid `Authorization`?
2. **verifyAccess fail-open.** In `verify-access.ts`, when `secret` is `undefined` (env unset),
   what does it return? A `return`/`undefined` that the caller treats as "allow" = fail-open.
   Also check timing-safe compare in `verifyAccessProof`.
3. **Override forgery / weak crypto.** In `crypto.ts`: what key derives the override encryption?
   If overrides are signed/encrypted with a *guessable* or *absent* key (e.g. falls back when
   `FLAGS_SECRET` unset, or an `encryptionMode: 'plaintext'`), an attacker can craft a
   `vercel-flag-overrides` cookie to force any flag on for themselves → access unreleased features.
4. **Override not session-scoped.** Does an override set for one session leak to/affect another?
   Check whether override state is bound to a per-session identifier or is global.
5. **Segment/cohort leak.** Does the discovery/evaluation response reveal which cohort a user is
   in when that segmentation isn't otherwise exposed?

## PoC shape if confirmed
Minimal Next.js app using `flags` + `createFlagsDiscoveryEndpoint`. Show an unauthenticated
`curl .well-known/vercel/flags` returning flag names/variants (endpoint bug), OR craft a
`vercel-flag-overrides` cookie that forces a gated flag `true` (override bug). Impact: disclosure
of unreleased features / unauthorized feature access.

## First-pass results (2026-08-23, v4.3.0)
- ❌ **H2 fail-open DEAD.** `verify-access.ts:32-36`: no `authHeader` → returns `false`; no
  `secret` → **throws** (not pass). Not fail-open.
- ❌ **H1 discovery-endpoint-open DEAD.** `create-flags-discovery-endpoint.ts:23-27`: the
  framework helper calls `verifyAccess` and returns `401` when access fails. Secure by default.
- 🔎 **Still open — best remaining lead: H3 override crypto** (`lib/crypto.ts`
  `encryptOverrides`/`decryptOverrides`/`verifyAccessProof`). Check the key source, whether the
  encryption/signing can be forged or falls back to a weak/absent key, timing-safe compare, and
  whether overrides are session-scoped (H4). This is where a live bug would be. NOT yet read.

- ❌ **H3 override forgery + H4 session-scope DEAD.** `lib/crypto.ts`: overrides are a JWE
  (`alg: dir`, `enc: A256GCM` — authenticated encryption) under a mandatory 256-bit key
  (throws if `base64url` decode ≠ 32 bytes). `decryptOverrides` enforces the `pur: 'overrides'`
  purpose claim + `Object.hasOwn(data,'o')`, so cross-purpose token reuse fails. Missing secret
  throws everywhere (no fail-open). Forging an override cookie requires `FLAGS_SECRET`; the
  Toolbar only gets one via the access proof (also FLAGS_SECRET-gated). Not attacker-forgeable.
  No obvious alg-confusion (jose binds `dir` to the symmetric key).

## Verdict: flags v4.3.0 core is HARDENED on all obvious focus-area classes → DEPRIORITIZE.
Only remaining low-probability surface: the adapters (`adapter-vercel`/others `getProviderData`)
and whether any app-facing helper returns definitions without the endpoint wrapper. Move on to
higher-EV targets (Nuxt / AI SDK MCP / chat / Skills install paths).

## Status: DONE (first pass) — hardened, deprioritized
