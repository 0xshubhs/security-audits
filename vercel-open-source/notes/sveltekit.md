# SvelteKit (Tier 2) + Svelte (Tier 1) — hunting notes

Cloned: `repos/sveltekit` (`packages/kit` = **3.0.0-next.25** ⚠️ prerelease — repro on stable) and
`repos/svelte` (`packages/svelte` = **5.56.10**).

## SvelteKit focus areas
XSS, CSRF bypass, SSRF, path traversal, cache poisoning, cross-request data leakage;
**prototype pollution / CPU-memory blowup via untrusted serialized data (incl. `devalue`)**;
**`BODY_SIZE_LIMIT` bypass via encoding tricks in the Node adapter**; **server-only module guard
bypass** (`$lib/server` / `*.server.js` bundled into a public asset); auth/session compromise.

### Hypotheses
1. **BODY_SIZE_LIMIT bypass** — the exact function is
   `repos/sveltekit/packages/kit/src/exports/node/index.js:13` `get_raw_body(req, body_size_limit)`
   (checks `content_length` at :42 and streamed `size` at :70). Test: chunked transfer-encoding
   with no/false `content-length`; a `content-length` smaller than the real body; gzip/deflate
   `content-encoding` where decompressed size >> limit; multiple content-length headers. Does any
   path let a body exceed the limit reach the handler? (memory-exhaustion / limit bypass).
2. **Server-only guard bypass** — `$lib/server` and `*.server.js` must never end up in a client
   bundle. Grep `prevent_import`/`server-only`/the Vite plugin guard; find a build pipeline (a
   specific adapter, dynamic import, re-export chain, or `experimental` path) where a server-only
   module's contents leak into a public asset → secret disclosure.
3. **devalue proto-pollution / DoS** — SvelteKit uses `devalue` to (de)serialize server→client
   data and form actions. Feed crafted serialized input (`__proto__`, deeply nested, huge)
   through the parse path; check for prototype pollution or quadratic CPU/memory.
4. **CSRF / path traversal / cache poisoning** in request handling and adapters
   (`packages/adapter-node`, `adapter-static`).

## Svelte focus areas (Tier 1 — needs compiler depth)
Primary surface = SSR compiler output path (spread attributes, element-tag interpolation, bind
directives, template-literal generation, hydration markers).
1. **SSR template-literal injection** — HTML-entity sequences in attribute strings that produce
   *unescaped expressions* in the generated JS. Read the SSR codegen in
   `repos/svelte/packages/svelte/src/compiler/phases/3-transform/server/` — how attribute values
   and spread attrs become template literals; can a crafted attribute string break out of the
   generated backtick/quote context?
2. **XSS where documented escaping guarantees fail** during SSR/hydration/dynamic element
   (`<svelte:element this={...}>`) rendering, or spread attributes.
3. DOM clobbering / prototype pollution affecting framework internals.
Out of scope: passing unsafe input to `{@html}`; experimental-gated features; dev-only DoS.

## PoC shape
- SvelteKit: minimal `sv create` app; for BODY_SIZE_LIMIT show an over-limit body accepted; for
  server-guard show a secret from `$lib/server` in the built client bundle.
- Svelte: a component whose compiled SSR output emits unescaped attacker markup; show XSS in the
  rendered HTML string.

## Svelte SSR compiler RESULT (2026-08-23): DEAD — escaping airtight (verified via harness)
All dynamic attr values → escape_html(x,true) (attr()/attributes()/attr_class/attr_style); spread
attr NAMES validated by INVALID_ATTR_NAME_CHAR_REGEX (blocks `> / = " '` + whitespace); dynamic tag
<svelte:element> regex-validated (REGEX_VALID_TAG_NAME); content sinks (textarea/title/option) use
content-mode escape_html (blocks `<`); DOM-clobber/proto-pollution guarded (defineProperty).
Residual (informational, NOT XSS): attr-NAME regex allows bare `<`/C0 controls → malformed HTML only
(can't break out w/o `>`/`/`/`=`/quote/space). Not filable. Svelte cleared.

## SvelteKit status: DoS lead PARKED (experimental+DoS, out of scope). Svelte compiler DEAD.
