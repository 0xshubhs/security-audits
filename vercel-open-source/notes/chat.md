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

## ✅ VERIFIED FINDING (2026-08-26): Telegram webhook fail-open by default (CWE-306)
`packages/adapter-telegram/src/index.ts` `handleWebhook()`:
- L485-509: if `this.secretToken` unset → **logs one warning and proceeds** (no rejection).
- L525-563: the dedup / bot-identity guard is ALSO gated on `this.secretToken`, so with no token
  the request skips straight to L566 `processUpdate(update)` with a fully attacker-controlled body.
- `processUpdate` routes forged updates: `message`→`chat.handleIncomingMessage`,
  `callback_query`→`chat.handleAction`, `message_reaction`→`handleReaction`, etc.
- `secretToken` defaults to `TELEGRAM_WEBHOOK_SECRET_TOKEN` env (types.ts:38) — OPTIONAL.

Impact: an attacker who reaches the webhook path (default `/api/webhooks/telegram`) can inject
updates that appear to come from ANY Telegram user/chat — forge `from.id`, `chat.id`, text,
commands, callback_data — driving the bot to act on unauthenticated input / impersonate an admin
for bot commands / poison thread state. No auth required.

Cross-adapter contrast (this is the crux — Telegram is the LONE fail-open adapter):
- Slack: throws at construction if no signingSecret/webhookVerifier (index.ts:971-976) — fail-closed.
- Messenger: `appSecret` REQUIRED, factory throws if absent (index.ts:940-943); always HMAC-verifies.
- WhatsApp: `verifySignature` returns false when no `x-hub-signature-256` → 401 (index.ts:378,482).
- Twilio: signature header required, throws → 401 (webhook/verify.ts:30-33,47-48).
- Discord: Ed25519 publicKey verification.
Every other adapter refuses to process an unverified webhook; Telegram silently processes it.

Triage risk (MODERATE — file AFTER the 2 clean ones): Telegram's Bot API has no payload signature
(unlike the HMAC adapters), so its only auth is the optional secret_token + URL secrecy, and the
adapter AGENTS.md/docs say "secret_token is the only line of defence — do not skip configuring it
in production." A triager could close as "inherent to Telegram / documented." COUNTER for the
report: the framework's own contract (every sibling adapter) is "refuse unverified webhooks";
Telegram breaks it by default. Fix is trivial + consistent: throw in webhook mode when no
secretToken (mirror Slack), or require explicit opt-out. Class = CWE-306 Missing Authentication.
Stronger bet than the workflow finding (recognized vuln class, not a "not a security contract"
disclaimer), but weaker than Turborepo/AI-SDK. Verdict: CANDIDATE #3 — needs PoC + dup check.

## LEAD (2026-08-26, not yet confirmed): ai/scope.ts read-scope confinement differential
`src/ai/scope.ts` `createScopeGuard` confines AI read-tools to the active conversation's channel.
`channelOf()` resolves a channel from an id via `adapter.channelIdFromThreadId?.(id)` and FALLS BACK
to `id.split(":").slice(0,2).join(":")` when the adapter or that method is absent/returns undefined.
Possible bypass: a crafted target `id` (model-supplied, e.g. prompt injection) where the fallback
string-slice yields `targetChannel === activeChannel` while the raw id, passed to the actual read
sink, points into a DIFFERENT real channel/thread → cross-channel read (IDOR). Requires a concrete
adapter whose `channelIdFromThreadId` normalization differs from the naive slice AND a read tool that
uses the raw id. Soft trust boundary (prompt-injected model), adapter-specific. NEEDS a concrete
adapter + read-sink trace to confirm/kill. Lower priority than the telegram finding.

## ✅ FINDING (2026-08-31, VERIFIED in source) — Discord adapter: timing-unsafe `!==` on the bot token gates an Ed25519-bypassing injection entry
Class: CWE-208 (observable timing discrepancy / non-constant-time secret compare); impact-if-bypassed
CWE-345 (message/identity spoofing). Adapter @chat-adapter/discord 4.38.1.
- `packages/adapter-discord/src/index.ts:368` — `if (gatewayToken !== botToken)` — native JS `!==`
  (short-circuits at first differing byte) is the ONLY gate on the `x-discord-gateway-token` forwarded-
  gateway branch (:362-378), which is an ALTERNATE webhook entry that SKIPS Ed25519 and dispatches
  GATEWAY_MESSAGE_CREATE/REACTION straight into handleForwardedGatewayEvent (:907) → chat.processMessage
  with attacker-chosen author/channel/content. Bot token is reused AS the shared secret (:2510
  `x-discord-gateway-token: botToken`).
- STRONG DIFFERENTIAL (verified): maintainers fixed the IDENTICAL pattern in Slack — `timingSafeStringEqual`
  (adapter-slack/src/index.ts:106, called :1680) against a dedicated `socketForwardingSecret`
  (:1025-1026 `?? appToken`). CHANGELOG (adapter-slack/CHANGELOG.md:329, changeset 9824d33):
  "Replace timing-unsafe `!==` with `crypto.timingSafeEqual` when validating the `x-slack-socket-token`
  header on forwarded socket-mode events." Discord's identical `!==` was MISSED. Every HMAC adapter +
  telegram secret-token use timingSafeEqual; Discord gateway path is the lone hold-out.
- NO fail-open here (resolveBotToken throws on empty). So the only bug is the non-constant-time compare.
- HONEST caveat: practical exploit = REMOTE timing oracle over a high-entropy token → LOW practical
  exploitability; H1 often marks remote-timing-only Informative. FILE on the differential + maintainer-
  precedent narrative ("you fixed this in Slack, missed the identical `!==` in Discord"), NOT a working
  timing PoC. Realistic Low-Med. Secondary candidate. Dup lead: changeset 9824d33; no GHSA located.
- Precond: deployment uses Discord gateway-forwarding (external listener POSTs with x-discord-gateway-token).

## Adapter coverage matrix (2026-08-31 sweep, all @ 4.38.1) — CLEARED except telegram + discord
15 adapters. slack/messenger/instagram/whatsapp/github/x/notion/twilio/gchat/linear all FAIL-CLOSED on
missing secret + constant-time compare + sign raw body; slack also enforces ±300s timestamp replay window.
teams/linear delegate auth to 3rd-party SDK (out of scope). web = no inbound sig surface. No re-serialization
desync, no algo-downgrade, no credentialed-SSRF, no secret logging/echo. Only telegram (fail-open, known)
and discord (timing-unsafe `!==`, above) are weak.
