# PoC — eve channel session routes: Broken Object-Level Authorization (BOLA / IDOR)

**Target:** `eve@0.44.4` (published; latest). **Class:** CWE-639 / CWE-862, OWASP API1:2023 (BOLA).

## Summary
eve's ID-addressed channel session routes authenticate the caller but never authorize the
caller against the session's owner. Any principal the route's `auth` policy accepts can **read**
(event stream) and **control** (inject a turn, cancel, compact, clear, reset) **any other
principal's session**, given only the (opaque) session id.

## Affected routes (`src/public/channels/eve.ts`)
All call `routeAuth(req, input.auth)` (authentication) and then `attachSession(sessionId)` — with
no owner comparison:
- `POST /eve/v1/session/:sessionId` — inject a turn (eve.ts:365) **[write]**
- `GET  /eve/v1/session/:sessionId/stream` — read the event stream (eve.ts:572) **[read]**
- `POST /eve/v1/session/:sessionId/cancel|compact|clear|reset` (eve.ts:444/479/511/543)

The runtime confirms dispatch is by id only, with no principal check:
- `dispatchSession` → `dispatchWorkflowCommand(sessionCommandHookToken(input.sessionId), cmd)` (`src/execution/workflow-runtime.ts:222-226`)
- `getEventStream(sessionId)` → `getRun(sessionId).getReadable()` (`workflow-runtime.ts:228-235`)

Channel-created sessions carry no owner-principal attribute at all.

## The framework already knows the correct pattern (defeats "by design")
The A2A invocation API binds every run to an owner and enforces it on read:
`src/internal/invocation/workflow-execution.ts:160`
```
run.attributes[INVOCATION_OWNER_ATTRIBUTE] === invocationOwnerKey(auth) ? run : undefined
```
(owner key = `invocationOwnerKey(auth)`, `metadata.ts:21`; attribute stamped at create,
`workflow-execution.ts:51`). The channel session routes omit this exact check.

## Run
```bash
npm install     # eve@0.44.4
node poc.mjs
```

### Expected output
```
[1] Unauthenticated POST to Alice's session  -> HTTP 401   (authentication IS enforced)
[2] Bob POSTs a turn into ALICE's session     -> HTTP 202   caller 'bob' drove alice's session
[3] Bob GETs ALICE's session event stream     -> HTTP 200   Bob receives Alice's private events
```
So the gap is authorization, not authentication: a fully-authenticated *other* user reads and
drives a session they do not own.

## Impact
In any multi-principal eve deployment (the route `auth` policy accepts more than one end user —
e.g. `vercelOidc()` user tokens; the per-user Connect / `forwardPrincipal` machinery exists for
exactly this), an attacker who learns a victim's session id can read the victim's entire agent
conversation and inject turns into it (drive the agent, exfiltrate via its tools, corrupt state).

## Preconditions / honest scope
- **Multi-principal deployment**: the channel `auth` array authenticates more than one distinct
  end user. Single-tenant (one API key = one user) deployments have no cross-user boundary.
- **Knowing a victim's session id**: ids are opaque, high-entropy workflow run ids, so they are
  not enumerable — the attacker must learn one (leaked in a URL/Referer/log, the subagent-stream
  route `eve.ts:580`, client-side code, a shared link, etc.). This bounds the issue to targeted
  abuse, not untargeted mass exploitation.

## PoC fidelity note (read this)
The PoC drives the **real** published route handlers (`eveChannel(...).routes`) and the **real**
`httpBasic` auth strategy from `eve@0.44.4`. It supplies `attachSession` itself, which is the
faithful analogue of the framework's own `createAttachSessionFn(runtime, ...)` — verified in
source to resolve a session by id with no caller filter (`src/channel/session.ts:171`,
`workflow-runtime.ts:222-235`). The missing authorization is entirely in the route-handler code
that the PoC exercises unmodified; only the runtime's by-id session resolution is stubbed (and
independently verified to be by-id-only).

## Fix
Stamp an owner attribute (`invocationOwnerKey(auth)`) on channel session creation and enforce
`session.owner === invocationOwnerKey(caller)` on every ID-addressed route — i.e. reuse the check
the invocation API already performs at `workflow-execution.ts:160`.
