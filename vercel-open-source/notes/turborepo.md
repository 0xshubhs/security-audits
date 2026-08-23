# Turborepo (Tier 1) — hunting notes

Cloned: `repos/turborepo` — Rust. Remote-cache logic in `crates/turborepo-lib/src` (see
`run/mod.rs`, `config/funnel.rs`, `commands/`). Remote cache = the primary attack surface.

Focus areas: **remote cache poisoning** (serve a crafted artifact restored into a victim's build —
signing/HMAC weaknesses, symlink traversal on extract); **token exfil via repo-controlled config**
(point remote cache at attacker origin, receive the user's auth token — must show actual exfil);
**SSRF via untrusted remote-cache API URL** (internal network access demonstrated); **command
injection** in CLI processing user-controlled strings; **dependency confusion** in published pkgs.

## Hypotheses to test (yes → candidate bug)
1. **Token sent to a repo-controlled origin.** If `turbo.json` / env / CLI args let a repo specify
   the remote-cache API URL (`--api`, `apiUrl`, `TURBO_API`), does the CLI send the user's auth
   token (`Authorization`/`x-artifact-*`) to that attacker-chosen host? A malicious repo a victim
   clones + `turbo build` → token leaves to attacker. **PoC must show the token actually sent.**
   Trace `config/funnel.rs` (token/timeout wiring) → the HTTP client that attaches the token → is
   the host validated/pinned, or taken from config?
2. **Symlink traversal on cache extraction.** When restoring a cached artifact (tarball), are
   entry paths and symlink targets validated to stay within the workspace? A crafted artifact with
   `../` entries or a symlink escaping the output dir → arbitrary write into the victim's tree =
   cache poisoning → code exec on next build. Find the extract/untar code.
3. **Artifact integrity / signature enforcement.** With `signature: true`, is the HMAC actually
   verified on restore, and is the key required? Is there a downgrade where an unsigned/wrongly
   signed artifact is still accepted? (Note: "signature:false is default" alone is NOT a valid
   report — need a full poisoning chain.)
4. **SSRF via cache API URL.** Same config-controlled URL → can it reach internal addresses
   (`169.254.169.254`, localhost, internal hosts) with a response that influences the build?
5. **Command injection.** Any CLI path that shells out with a user/config-controlled string
   (task names, package names, git refs)?

## Where to read
`crates/turborepo-lib/src/run/mod.rs`, `config/funnel.rs`, `commands/`, and grep the crate for
`reqwest`/`Client`, `Authorization`, `x-artifact`, `symlink`, `unpack`/`extract`, `tar`.
Also `crates/turborepo-cache*` if present.

## PoC shape
- Token exfil: a repo whose config points the cache at a localhost listener you control; run
  `turbo build`; capture the inbound request carrying the auth token.
- Poisoning: a crafted artifact with a traversal/symlink entry; show a file written outside the
  cache/output dir on restore.

## RESULT (2026-08-23): ✅ CONFIRMED-LIVE + WORKING PoC — H1 (token exfil)
- H1 token exfil via repo-controlled `remoteCache.apiUrl`: CONFIRMED on **turbo 2.10.11 (stable)**.
  turbo.json can set apiUrl+teamId; the run/cache path attaches the victim's Bearer token to the
  attacker host. Trust gate (is_trusted_vercel_origin) only runs in the login flow. PoC captured 4
  requests carrying the token → `poc/turbo-token-exfil/`. Report: `reports/turbo-token-exfil.md`
  (+ .zip). Severity HIGH. Root cause: turbo_json.rs (accepts apiUrl), lib.rs merge, run/builder.rs
  + commands/mod.rs (attach token, no source check), auth/mod.rs (gate login-only).
- H2 tar-slip/symlink on extract: DEAD (restore.rs validates ../abs, realpath symlink check, refuses
  write-through-symlink).
- H3 signature verify: DEAD as standalone (HMAC verified when signature:true; no downgrade).
- H4 SSRF via apiUrl: same root cause as H1, bundle with it (lower standalone severity).

## Status: DONE — H1 reported (draft ready). SSRF (H4) bundled.
