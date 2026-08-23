# PoC: SSRF via MCP OAuth metadata discovery in `@ai-sdk/mcp`

**Target:** `@ai-sdk/mcp` — **confirmed on 2.0.36** (the MCP client package of the Vercel AI SDK).
**Class:** Server-Side Request Forgery (CWE-918) — matches the AI SDK focus area
"MCP OAuth metadata handling … SSRF via redirect-follow during OAuth metadata discovery".
**Severity:** Medium.

## Summary
When an AI SDK MCP client is configured with OAuth (an `authProvider`) and connects to a malicious
MCP server, the server's Protected Resource Metadata (PRM) can set `authorization_servers[0]` to
any `http(s)` URL — including internal/loopback hosts. The AI SDK fetches that URL during
authorization-server metadata discovery with:
- only `SafeUrlSchema` validation, which blocks solely `javascript:`/`data:`/`vbscript:`
  (so `http://169.254.169.254/`, `http://127.0.0.1:port/`, internal hostnames all pass), and
- `provider.validateAuthorizationServerURL` being an **optional** hook with no default — a client
  that doesn't implement it (the common case) performs zero validation of the discovered AS URL, and
- the discovery fetch following redirects (no `redirect: 'error'`), unlike the JSON-RPC transports.

## Reproduce
```bash
npm install          # installs @ai-sdk/mcp@2.0.36
node poc.mjs
```
`poc.mjs` starts two local servers — a malicious MCP server (serves crafted PRM) and an "internal"
service that should be unreachable — then calls the SDK's exported `auth()` against the MCP server.

## Observed result
```
[MCP SERVER] GET /.well-known/oauth-protected-resource
[INTERNAL SERVICE] >>> SSRF! received GET /.well-known/oauth-authorization-server
================ RESULT ================
VULNERABLE: the SDK issued an SSRF request to the attacker-chosen internal host.
```
The SDK issued a request to the attacker-chosen internal host (`http://127.0.0.1:9098/`), driven
purely by the malicious MCP server's metadata.

## Root cause (repo pointers)
- `packages/mcp/src/tool/oauth-types.ts:19-29` — `SafeUrlSchema` only blocks js/data/vbscript.
  `authorization_servers` uses it (`:50`).
- `packages/mcp/src/tool/oauth.ts:1216` — `authorizationServerUrl = resourceMetadata.authorization_servers[0]`.
- `packages/mcp/src/tool/oauth.ts:1203` — `assertResourceMetadataUrlSameOrigin` constrains only the
  PRM URL, not the AS URL.
- `packages/mcp/src/tool/oauth.ts:1233` — `provider.validateAuthorizationServerURL?.()` is optional,
  no default.
- `packages/mcp/src/tool/oauth.ts:385` — `fetchWithCorsRetry` calls `fetch(url,{headers})` with no
  `redirect:'error'` (defaults to follow), so the attacker can also 302 to arbitrary internal URLs.
  This diverges from the transports (`mcp-http-transport.ts` / `mcp-sse-transport.ts` set
  `redirect:'error'`) and bypasses the repo's own `validateUrl`/`credentialedOrigin` SSRF discipline.

## Impact
Blind SSRF from the host running the MCP client to internal/loopback/cloud-metadata endpoints
(the discovery GET fires unconditionally). The token/registration POSTs give arbitrary-URL POST
SSRF. Triggered by connecting an OAuth-enabled MCP client to an untrusted MCP server — a realistic
scenario given MCP's third-party-server trust model.

## Suggested fix
Restrict `SafeUrlSchema` to `http:`/`https:`; validate `authorization_servers` origin by default
(don't rely on the optional hook); and set `redirect:'error'` on the `oauth.ts` fetches to match
the transports.
