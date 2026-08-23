# AI SDK (Tier 1) — hunting notes

Cloned: `repos/ai` — core `packages/ai` is **v7.0.77**. MCP code is a separate package:
`repos/ai/packages/mcp/` (and `packages/ai/src/tool/mcp`, `packages/react/src/mcp-apps`).

Focus areas: **MCP client allowlist bypass** (incl. prototype-based); **tool execution control
bypass** (RCE / data access); **prototype pollution** in SDK internals → SSRF / auth-header theft;
**MCP OAuth metadata** URL-validation bypass (`file://` passing the schema check) or SSRF via
redirect-follow during discovery; **structured-output** validation bypass (raw LLM output reaches
app without the declared schema enforced).

## Where to look
- `repos/ai/packages/mcp/src/` — MCP client, transports (`mcp-stdio`), tool listing/allowlist.
- `repos/ai/packages/ai/src/tool/mcp` — tool integration.
- Grep the MCP client for: how it filters which tools are exposed (allowlist), OAuth metadata
  discovery (URL parsing/validation), and any `Object.assign`/spread merging server-supplied data.

## Hypotheses to test (yes → candidate bug)
1. **Allowlist via prototype inheritance.** If the allowed-tools check uses `obj[toolName]` or
   `toolName in allowMap` on a plain object, a tool named `__proto__`, `constructor`, or
   `toString` may pass because it's inherited. Or if the allowlist is keyed by an object and a
   server returns a tool whose name collides with an inherited property. Check the exact lookup.
2. **Allowlist enforced at list-time but not exec-time.** Does the restriction on callable tools
   hold when the model actually invokes one, or only when tools are enumerated? Find both paths.
3. **Prototype pollution in response merge.** Does the MCP client merge server-provided JSON into
   objects via a recursive merge / `foo[key]=val` without guarding `__proto__`/`constructor`? A
   malicious MCP server response could pollute `Object.prototype` → then SSRF (polluted
   `baseURL`/proxy) or auth-header injection. Trace where server responses are deserialized.
4. **OAuth metadata URL validation.** In the OAuth metadata discovery flow, is the metadata URL
   validated only by a schema (e.g. zod `.url()`) that accepts `file://`, `gopher://`, etc.? Does
   it follow redirects to internal addresses? A `file://` passing the check → local file read;
   redirect-follow → SSRF. Find the fetch + validation.
5. **Structured-output not enforced.** When a tool/generateObject declares a schema, is the raw
   LLM output actually validated against it before reaching app code, or can malformed output slip
   through (e.g. on `experimental_` paths, streaming, or repair mode)?

## Out of scope here
- Example/doc snippets. Provider packages (OpenAI/Anthropic/Fireworks integrations) — report to
  that provider, not here. Tool-approval bypass relying purely on forged client message history.

## PoC shape
- Stand up a **malicious local MCP server** (stdio or HTTP) returning crafted tool lists /
  metadata / JSON, connect the AI SDK MCP client to it, and demonstrate: a disallowed tool
  becomes callable, OR prototype pollution changes SDK behavior (e.g. redirects a request), OR a
  `file://` metadata URL is fetched. Show concrete impact (RCE/data read/SSRF).

## RESULT (2026-08-23): CONFIRMED-LIVE (code) — SSRF via OAuth metadata discovery
Package `@ai-sdk/mcp` (packages/mcp), MCP OAuth client. Verified myself:
- `oauth-types.ts:19-29` `SafeUrlSchema` blocks ONLY javascript:/data:/vbscript: → internal
  `http://169.254.169.254/`, `http://127.0.0.1/`, etc. all pass. `authorization_servers` (line 50)
  uses it.
- `oauth.ts:1216` `authorizationServerUrl = resourceMetadata.authorization_servers[0]` — taken
  straight from attacker-controlled Protected Resource Metadata. `assertResourceMetadataUrlSameOrigin`
  (:1203) only constrains the PRM URL, NOT the AS URL.
- `oauth.ts:1233` `await provider.validateAuthorizationServerURL?.(...)` — OPTIONAL app hook, no
  default. Developers who don't implement it get zero AS-URL validation.
- `oauth.ts:385` `fetchWithCorsRetry` calls `fetchFn(url,{headers})` with NO `redirect:'error'`
  (defaults to follow) — unlike the JSON-RPC transports which set redirect:'error'. Attacker can 302
  the discovery/token/registration fetches to any internal URL. Also bypasses the repo's own
  `validateUrl`/`credentialedOrigin` SSRF discipline (see repo CLAUDE.md / secure-url-handling.md).
- Threat model: victim's MCP client with an authProvider connects to an untrusted MCP server →
  server returns 401 + PRM with authorization_servers[0] = internal URL → client fetches it.
- Impact: blind SSRF (GET discovery fires unconditionally) + POST SSRF (token/registration); cloud
  metadata / internal port probing. Severity ~Medium.
- DEAD siblings (per agent, spot-checked): allowlist proto bypass (hasOwnProperty guard), exec-time
  bypass (name captured in closure), server-JSON proto pollution (zod.parse), SSE endpoint origin
  check, Authorization override, PKCE/state/issuer-pinned confused-deputy.

## TODO: build PoC — mock MCP server (HTTP transport) returning 401 + PRM → local listener.
## Status: CONFIRMED (code) — PoC pending. Second-best report candidate after Turborepo.
