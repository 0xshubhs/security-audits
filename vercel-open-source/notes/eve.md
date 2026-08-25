# eve (Tier 2 framework) — hunting notes

`repos/eve`, package `eve` @ 0.0.0 (repo) — filesystem-first framework for durable AI agents.
Attack surfaces: channel HTTP/WS, ACP, connections/secrets, sandbox file tools, source-change.

## ✅ FINDING E1 (STRONGEST NEW) — BOLA / missing per-session authorization on eve channel routes
Class: CWE-639 / CWE-862, OWASP API1:2023 (Broken Object Level Authorization). Self-verified.

Every ID-addressed session route in `src/public/channels/eve.ts` AUTHENTICATES the caller
(`routeAuth(req, input.auth)`) but NEVER authorizes them against the session's owner:
- POST message / inject turn: eve.ts:365-402 → `attachSession(sessionId).send(message, {auth})` (WRITE)
- cancel: eve.ts:444-453 · compact: 479-488 · clear: 511-520 · reset: 543-552
- GET event-stream (READ conversation): eve.ts:572-577 → `createSessionStreamResponse(..., attachSession(sessionId))`
In all of them `authResult` is used only as a pass/fail gate and discarded; `sessionId` comes
straight from the URL. Runtime dispatch confirms no deeper check:
- `dispatchSession` → `dispatchWorkflowCommand(sessionCommandHookToken(input.sessionId), cmd)` — by id only (workflow-runtime.ts:222-226)
- `getEventStream(sessionId)` → `getRun(sessionId).getReadable()` — any run by id (workflow-runtime.ts:228-235)
- the `owner.runId !== sessionId` checks (191-195, 343-347, 369-370) are session-command↔session
  consistency checks, NOT principal ownership.
Channel-created sessions carry NO owner-principal attribute at all (grep: only operationId-dedup
"owner" at eve.ts:286,336).

SMOKING GUN (defeats "by design"): the A2A invocation API DOES bind resource→owner and enforces it:
`src/internal/invocation/workflow-execution.ts:160` →
`run.attributes[INVOCATION_OWNER_ATTRIBUTE] === invocationOwnerKey(auth) ? run : undefined`
(owner key = `invocationOwnerKey(auth)`, metadata.ts:21; attr set at create, workflow-execution.ts:51).
The framework knows the pattern; channel sessions just omit it.

Impact: any principal accepted by the route's `auth` policy can READ (stream) or CONTROL
(inject a turn / cancel / clear / reset) ANY other principal's session given its ID.
Preconditions (honest): (1) multi-principal deployment — route auth accepts >1 end user
(e.g. `vercelOidc()` user tokens; the per-user Connect / forwardPrincipal machinery exists for
exactly this); (2) attacker must learn a victim's session id — opaque high-entropy workflow runId,
so not enumerable, but leaks via URLs/Referer/logs/the subagent-stream route (eve.ts:580)/client code.
Severity ~MEDIUM (write-into-session pushes toward MED-HIGH). No documented pre-emption.
STATUS: code-path CONFIRMED end-to-end + WORKING PoC on published eve@0.44.4
(poc/eve-session-bola/, shows unauth=401, Bob-writes-Alice=202, Bob-reads-Alice-stream=200).
❌ DUP — DO NOT FILE. Public issue vercel/eve#1130 "Add a session authorization boundary for
continue, stream, and cancel" (open, labels: security/p1, filed 2026-07-23) describes it verbatim:
"it doesn't authorize the supplied session ID. Any authenticated user who gets another session ID
can continue it, stream its events, or cancel it." Vercel-acknowledged + documented workaround
(proxy routes / persist ownership). Known & public → filing = duplicate, hurts Signal. Related
known authz gaps: #1021 (authorize HITL approvals). PoC kept for reference only.

## ⚠️ FINDING E2 (confirmed path, arguable) — VERCEL_AUTOMATION_BYPASS_SECRET leaked cross-origin
`src/execution/workflow-callback-url.ts:63-73` `createWorkflowCallbackUrl` appends
`x-vercel-protection-bypass=<VERCEL_AUTOMATION_BYPASS_SECRET>` to ANY callback URL unconditionally.
That URL is placed in `callback.url` (`remote-agent-dispatch.ts:103-106`) and the whole body is
POSTed to `remote.url` (`:132`, `createRemoteAgentSessionUrl`), which the type doc calls the
"Base URL of the remote eve **deployment**" (`definitions/remote-agent.ts:57,61`) — a separate
trust domain (the forwardPrincipal doc even stresses "never tokens or credentials" cross that wire,
remote-agent.ts:35-36). Same leak via `agent-handle-dispatch.ts:357` and the
`authorization.required` stream event (`harness/authorization.ts:174-183` → tool-loop.ts:982,2798 →
protocol/message.ts:633,1119). The secret is DEPLOYMENT-WIDE (bypasses all preview/protected routes,
not just the callback), and the per-callback `token` already authenticates the callback → over-scoped.
Guarded sibling exists: `createRemoteTaskInputCallbackUrl` (:79-89) gates the same secret behind an
`isCurrentVercelHost` check with docstring "without disclosing this deployment's protection bypass
secret to an authored external origin."
HONEST CAVEAT: that guard checks the callback DESTINATION host, not the request recipient; on the
remote-agent path the callback points back at OUR host, so the guarded fn would ALSO embed the secret.
And handing an automation-bypass secret to a party you WANT to call you back through Deployment
Protection is partly the intended mechanism. => "by design / inherent to Deployment Protection" is a
real triage counter. Still worth raising as over-scoping/secret-in-URL-to-3rd-party, but weaker than E1.
STATUS: code path CONFIRMED; NOT publicly tracked (dup-checked vercel/eve issues — no match).
Two "framework is careful elsewhere" tells: (1) guarded sibling helper, (2) forwardPrincipal is
opt-in/defaults-false for mere identity metadata while the bypass SECRET ships unconditionally with
no opt-out. Still has a plausible "intended Deployment-Protection callback mechanism" defense →
ARGUABLE/triage-risky. Possible file as a lower-confidence report; weaker than telegram. Lower priority.

## DEAD / cleared on eve
- ACP (`src/acp/*`): stdio-only, local trust-by-design; cwd validated-then-discarded (equality
  realpath), prompts text-only, tool exec behind permission gate, remote creds origin-bound. DEAD.
- Channel auth H1-H4: routeAuth never default-allows (401 on empty), principal is server-assigned
  from verified crypto (no alg:none), CORS default-off + no arbitrary-origin-reflect mode, WS upgrade
  is an authored opt-in. DEAD.
- Host FS: source-change absolutePath is framework-derived (DEAD); skill-package paths validated
  (DEAD); just-bash `..`/symlink escape is PLAUSIBLE but root cause is 3rd-party just-bash@3.1.0 +
  fallback-only backend → weak, upstream fix. Low priority.
- Secret leakage (other than E2): connection tokens header-only + virtual cache, model-facing output
  redacted, tool/model errors don't surface auth headers, MCP bearer only to authored url. CLEARED.
