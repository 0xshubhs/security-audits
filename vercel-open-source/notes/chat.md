# chat (Tier 2, can pay Tier 1) — hunting notes

Cloned: `repos/chat` — a unified TypeScript SDK for chat bots (Slack/Teams/Discord/GChat/etc.).
Monorepo: `packages/adapter-*`, `packages/state-*` (memory, ioredis), `packages/adapter-shared`,
`packages/tests`.

Core security property Vercel treats as framework-level: **a session, its messages, and tool
execution state belong to a specific authenticated owner**, and **tool authorization must derive
from server-verified state, NOT the client-supplied `messages[]` array**.

## Hypotheses to test (yes → candidate bug)
1. **Tool approval reconstructed from client messages.** THE headline framework bug: does tool
   execution logic read approval state / tool inputs from the caller-supplied `messages` array
   rather than server state? If a forged assistant/tool-result message in the request can make the
   framework execute a tool the user never approved → vulnerability regardless of app code. Find
   where incoming messages are parsed and where tool-call approvals are decided.
2. **Session/message IDOR.** Can an authenticated actor read/write/append/delete/change-visibility
   of a session or message they don't own, using a session/message ID taken from client input?
   Check the state layer (`packages/state-memory`, `packages/state-ioredis`) and adapters: is the
   owner/tenant checked on every session/message access, or only on creation?
3. **Cross-role access.** Team-level role boundaries not enforced in session listing/message
   access (lower-privileged member reads another user's sessions).
4. **Cache key scoping.** A cached response for one session/user served to another (incorrect
   cache-key scoping across user/session). Check any caching in adapters/state.
5. **Auth on session endpoints.** Adapter webhook/endpoint handlers — is the inbound request
   authenticated (signature/bearer verification) before it can trigger agent actions / reach paid
   model APIs? E.g. `adapter-gchat` verifies a Bearer token "when set" — is it optional/default-off?
   `adapter-slack` signature verification — enforced by default?
6. **Stored XSS** in message rendering (markdown / shared views / third-party render libs) →
   session/token theft.

## Where to read
- `packages/adapter-shared/src` — shared message/session handling (best place for a framework-wide
  bug affecting all adapters).
- `packages/state-memory/src`, `packages/state-ioredis/src` — ownership checks on state access.
- `packages/adapter-slack/src`, `packages/adapter-gchat/src/types.ts:68` (bearer "when set"),
  each adapter's inbound request verification.

## Out of scope
App-code that explicitly omitted ownership checks; client-side manipulation affecting only the
attacker's own session.

## PoC shape
Minimal bot built on the SDK; as user A, craft a request with a forged `messages[]` (or another
user's session ID) and show you executed an unapproved tool / read another owner's session.

## RESULT (2026-08-23): CONFIRMED-LIVE (agent) — adapter-telegram webhook fail-open
- `packages/adapter-telegram/src/index.ts:485-509` (`@chat-adapter/telegram` v4.38.1): `handleWebhook`
  verifies the Telegram `secret_token` header ONLY if `secretToken` is configured; otherwise it logs
  one warning and processes the request. Constructor throws only for missing botToken, never for
  missing secretToken (:327-344). The dedupe/replay guard is also gated on `secretToken` (:525).
- Every OTHER adapter is fail-CLOSED (slack/github/gchat/whatsapp/messenger/x/twilio/linear/discord
  throw or reject without a secret). Telegram is the lone outlier → framework-default inconsistency.
- Telegram webhooks have no HMAC; the secret_token header is the only inbound auth. If unset, anyone
  hitting the endpoint can POST a fully attacker-controlled Update JSON: forge `from.id` (defeats
  user-ID authz in handlers), `chat.id`, `text`, callback_query → unauth bot invocation (paid model
  calls / cost abuse), impersonation, history injection. Severity ~Medium.
- HEADLINE hypothesis (tool approval from client messages[]) — DEAD: approvals are server-anchored
  (verified platform button clicks, opaque callback tokens); state layer is keyed by server-derived
  ids (no IDOR). Stored XSS — N/A (no server-side HTML sink).
- Finding 2 (adapter-teams empty-credential inbound): PLAUSIBLE, needs a @microsoft/teams.apps PoC.

## TODO: verify index.ts:485 myself + build PoC (POST forged Update to the webhook, no secret set).
## Status: CONFIRMED (agent) — self-verify + PoC pending.
