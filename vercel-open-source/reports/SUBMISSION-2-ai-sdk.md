# HackerOne submission — copy/paste into the form fields

=====================================================================
FIELD: Asset
=====================================================================
AI SDK

=====================================================================
FIELD: Weakness
=====================================================================
Server-Side Request Forgery (SSRF) (CWE-918)

=====================================================================
FIELD: Severity
=====================================================================
Medium

=====================================================================
FIELD: Affected version(s)
=====================================================================
@ai-sdk/mcp 2.0.36 (the MCP client package of the AI SDK). Confirmed with a working PoC.

=====================================================================
FIELD: Affected File  (GitHub link)
=====================================================================
https://github.com/vercel/ai/blob/main/packages/mcp/src/tool/oauth.ts
(related: packages/mcp/src/tool/oauth-types.ts — SafeUrlSchema)

=====================================================================
FIELD: Description
=====================================================================
## Summary:
When an AI SDK MCP client is configured with OAuth (an `authProvider`) and connects to a malicious
MCP server, that server's Protected Resource Metadata (PRM) can set `authorization_servers[0]` to
any http(s) URL, including internal/loopback hosts. During authorization-server metadata discovery
the SDK fetches that URL with essentially no protection:

- `SafeUrlSchema` (packages/mcp/src/tool/oauth-types.ts:19-29) blocks only `javascript:`, `data:`,
  and `vbscript:` schemes, so `http://169.254.169.254/`, `http://127.0.0.1:<port>/`, and internal
  hostnames all pass. `authorization_servers` uses this schema (oauth-types.ts:50).
- `authInternal` reads the attacker value directly: `authorizationServerUrl =
  resourceMetadata.authorization_servers[0]` (oauth.ts:1216). The same-origin guard at oauth.ts:1203
  (`assertResourceMetadataUrlSameOrigin`) constrains only the PRM URL, not the AS URL.
- `provider.validateAuthorizationServerURL?.()` (oauth.ts:1233) is an OPTIONAL hook with no default;
  a client that does not implement it (the common case) performs zero validation of the discovered
  AS URL.
- The discovery fetch (`fetchWithCorsRetry`, oauth.ts:385 → `fetch(url,{headers})`) sets no
  `redirect` option, so it follows redirects — the attacker can 302 it to any internal URL. The
  JSON-RPC transports deliberately set `redirect:'error'`, and the repo documents a
  `validateUrl`/`credentialedOrigin` SSRF discipline; the OAuth path uses neither.

## Steps To Reproduce:
(Self-contained PoC attached as ai-sdk-mcp-oauth-ssrf-poc.zip. Pure Node, uses the exported
`auth()` — no external network needed.)

  1. `npm install`  (installs @ai-sdk/mcp@2.0.36)
  2. `node poc.mjs`
     The script starts (a) a malicious MCP server that serves crafted PRM whose
     `authorization_servers[0]` = `http://127.0.0.1:9098/` (an "internal" service), and (b) that
     internal service, then calls `auth(provider, { serverUrl: 'http://127.0.0.1:9097' })` with a
     provider that (like most) does not implement `validateAuthorizationServerURL`.
  3. Observe the internal service receive a request driven solely by the MCP server's metadata.

## Supporting Material/References:
  * ai-sdk-mcp-oauth-ssrf-poc.zip — runnable PoC (package.json, poc.mjs, README, evidence.txt)
  * Observed output on @ai-sdk/mcp 2.0.36:
      [MCP SERVER] GET /.well-known/oauth-protected-resource
      [INTERNAL SERVICE] >>> SSRF! received GET /.well-known/oauth-authorization-server
      RESULT: VULNERABLE — the SDK issued an SSRF request to the attacker-chosen internal host.
  * Root cause files: packages/mcp/src/tool/oauth.ts (lines 1216, 1203, 1233, 385) and
    packages/mcp/src/tool/oauth-types.ts (lines 19-29, 50).

## Suggested fix (optional):
Restrict `SafeUrlSchema` to `http:`/`https:`; validate `authorization_servers` origin by default
rather than relying on the optional hook; and set `redirect:'error'` on the oauth.ts discovery,
token, and registration fetches to match the transports.

=====================================================================
FIELD: Impact
=====================================================================
## Summary:
An untrusted MCP server can make the host running an OAuth-enabled AI SDK MCP client issue requests
to internal/loopback/cloud-metadata endpoints (blind SSRF; the discovery GET fires unconditionally,
and token/registration give arbitrary-URL POST SSRF). This enables internal port/service probing and
reaching metadata endpoints (e.g. 169.254.169.254) from the client host. The trigger — connecting an
OAuth-configured MCP client to a third-party/untrusted MCP server — is a realistic scenario under
MCP's server trust model, which is exactly the trust boundary this program's AI SDK focus area calls
out.
