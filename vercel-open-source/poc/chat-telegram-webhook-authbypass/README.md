# PoC — Chat SDK Telegram adapter: webhook auth bypass (fail-open, no `secret_token`)

**Target:** `@chat-adapter/telegram` **4.38.1** (+ `chat` 4.38.1, `@chat-adapter/state-memory` 4.38.1), all published.
**Class:** CWE-306 (Missing Authentication for a Critical Function) — webhook request forgery.

## Summary
When no webhook `secretToken` is configured (the default; env `TELEGRAM_WEBHOOK_SECRET_TOKEN`),
`TelegramAdapter.handleWebhook` logs a one-time warning and **processes the request anyway**. An
unauthenticated attacker who reaches the bot's webhook route (conventionally
`POST /api/webhooks/telegram`) can submit a forged Telegram `Update` and have it processed as
genuine — forging the sender (`from.id`), chat, message text, commands, and `callback_data`.

Confirmed in the published build (`node_modules/@chat-adapter/telegram/dist/index.js`):
- no `secretToken` → only warns "Telegram webhook verification is disabled…" and continues;
- the dedup / bot-identity guard is itself gated on `secretToken`, so an unsigned request goes
  straight to `processUpdate(update)` with a fully attacker-controlled body.

## Telegram is the lone fail-open adapter (this is the crux)
Every other adapter in the same SDK refuses to process an unverified webhook:
| Adapter | Missing-secret behavior |
|---|---|
| Slack | throws at construction without `signingSecret`/`webhookVerifier` |
| Messenger | `appSecret` required — factory throws if absent; always HMAC-verifies |
| WhatsApp | no `x-hub-signature-256` → 401 |
| Twilio | signature header required → 401 |
| Discord | Ed25519 `publicKey` verification |
| **Telegram** | **logs a warning, processes the request** |

## Run
```bash
npm install     # chat@4.38.1, @chat-adapter/telegram@4.38.1, @chat-adapter/state-memory@4.38.1
node poc.mjs
```
The PoC is fully offline (global `fetch` is stubbed to fail-fast on `api.telegram.org`; nothing is
sent to Telegram or Vercel).

### Expected output
```
[A] no secretToken … forged update, NO auth header  -> HTTP 200 ; HANDLER FIRED, senderId 1337421337  (VULNERABLE)
[B] secretToken configured … same request, no header -> HTTP 401 ; handler NOT fired               (rejected)
```

## Impact
Unauthenticated message injection / sender-ID spoofing into the bot: an attacker drives the bot on
forged input, impersonates an arbitrary Telegram user (including an admin for privileged bot
commands), and can poison per-thread state — with no credentials.

## Precedent (same class, different project)
`openclaw` shipped a HIGH-severity advisory for the identical bug:
GHSA-mp5h-m6qj-6292 — "Telegram webhook request forgery (missing `channels.telegram.webhookSecret`) → auth bypass."

## Fix
Refuse webhook mode when no `secretToken` is configured (throw at construction, mirroring Slack), or
require an explicit opt-out — so the framework enforces webhook authentication for Telegram the way
it already does for every other adapter.
