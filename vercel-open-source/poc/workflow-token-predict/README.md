# PoC: Workflow SDK — predictable webhook/hook tokens (weak PRNG, CWE-338)

**Target:** `@workflow/core` **5.0.0-beta.44** (Vercel Workflow SDK). ⚠️ BETA channel.
**Class:** Use of a cryptographically weak (seeded) PRNG for a security token (CWE-338 / CWE-330).

## Mechanism (verified in code)
- The workflow VM installs a SEEDED PRNG as `Math.random`:
  `packages/core/src/vm/index.ts:55,61` → `const rng = seedrandom(seed); g.Math.random = rng;`
- The seed is entirely non-secret:
  `packages/core/src/workflow.ts:353` → `` seed: `${runId}:${workflowName}:${deploymentId}` ``
- The hook/webhook token is drawn from that seeded stream:
  `packages/core/src/workflow.ts:406-408` (`generateNanoid` uses `Math.random`) →
  `packages/core/src/workflow/hook.ts:100` → `const token = options.token ?? ctx.generateNanoid();`
- `createWebhook()` FORBIDS a developer-supplied token and always uses the seeded one, then puts it
  in the PUBLIC URL: `packages/core/src/workflow/create-hook.ts:63-67, 79`.
- On self-hosted world-postgres, `deploymentId` is the constant string `'postgres'`
  (`packages/world-postgres/src/queue.ts:135`), so the seed reduces to `runId:workflowName:postgres`.

## PoC
```bash
npm install        # seedrandom@3.0.5 + nanoid@5.1.6 (exact framework versions)
node poc.mjs
```
Shows an attacker who knows only `runId` + `workflowName` + `deploymentId` re-derives the exact
webhook token the server minted — without ever seeing it — and that the draw-offset uncertainty is
a trivially small (sliding-window) brute-force space.

## Impact
The webhook token is the only credential on a public-by-design endpoint
(`POST /.well-known/workflow/v1/webhook/<token>` → `resumeWebhook`). Deriving it lets an attacker
forge the external callback a webhook guards (payment/approval/verification callbacks), resuming the
run with an attacker-controlled payload. The same primitive derives `createHook()` tokens.

## Fix
Mint the token from a host CSPRNG on first execution and read it back from the persisted
`hook_created` event on replay (`packages/world/src/hooks.ts:98` already stores it) instead of
regenerating it from the seeded VM PRNG.

## ⚠️ HONEST triage assessment — read before filing
This is a real, code-confirmed weakness, but it is NOT as clean/safe as the Turborepo and AI-SDK
findings. Weigh these before spending a trial report (Signal requirement is active):
1. **Docs pre-emption (biggest risk).** The framework docs and `create-hook.ts:123-126` state the
   generated token "is not trivial to guess but is not a security contract." Vercel may triage this
   as a documented/known limitation → Not Applicable → hurts Signal. Counter-argument to make in
   the report: "not trivial to guess" is factually wrong — the token is deterministically DERIVABLE
   from non-secret inputs (≈0 entropy given the seed), and `createWebhook()` provides NO secure
   alternative, so the framework forces reliance on a non-secure credential.
2. **Beta channel.** All packages are 5.0.0-beta.44; severity may be reduced and CVE is excluded for
   experimental/beta. It IS the current published release of a Tier-1 asset, so likely in scope.
3. **Exploitability depends on runId exposure.** The attacker needs the `runId`. The framework
   treats runId as non-secret (returns it from `start()`, `Run.toJSON`, uses it in status/stream
   URLs), so it is often exposed — but a PoC that demonstrates a concrete runId leak in a realistic
   app would materially strengthen the report.

RECOMMENDATION: file the two clean findings first. Consider this one as a follow-up hardening report
framed around "createWebhook forces a non-CSPRNG token with no alternative," only if comfortable with
the docs-caveat triage risk. Do not lead your trial-report budget with it.
