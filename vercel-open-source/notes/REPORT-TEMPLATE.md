# HackerOne Report Template — Vercel Open Source

Write like a human engineer: plain prose, no filler, no AI throat-clearing. Prove impact, don't
assert it. Attach the PoC zip. Fill the "Affected version(s)" field on the H1 form.

---

**Title:** `<Component>: <bug class> allows <concrete impact>` (e.g. "flags: unauthenticated
.well-known/vercel/flags discovery endpoint leaks all flag definitions")

**Asset / Tier:** <target> (Tier 1/2)

**Affected version(s):** <exact stable version(s) tested, e.g. flags@4.3.0>. Confirmed present on
the latest stable release. (Note if a canary range is also affected.)

## Summary
Two or three sentences: what the bug is, where it lives, and what an attacker achieves.

## Root cause
The specific code path. Cite `file:line` in the published package (map from source repo to the
distributed npm file if relevant). Explain *why* it's wrong (missing check, wrong order, fail-open
default, unsanitized sink).

## Impact
What an attacker concretely reads / writes / executes / extracts, and the pre-conditions (default
config? auth needed? attacker role?). Map to CVSS 4.0 and argue the severity honestly.

## Steps to reproduce
Numbered, exact. Assume a clean machine. Include the setup (versions, install commands), the
trigger, and the observed result. Reference the attached PoC:

1. `npm create ...` / clone the PoC in the zip
2. `npm install` (locks to affected version)
3. Run `<command>` / send `<request>`
4. Observe `<concrete evidence of impact>`

## Proof of concept
Describe what's in `poc.zip` (a runnable minimal app + a script/README). Add screenshots or a
short video if it helps. The PoC must run on a production-equivalent setup, no unrealistic steps.

## Suggested fix (optional — bonus-eligible)
The minimal change (sanitize here / verify there / reorder rules / pin host). Offer to send a PR
via a **private fork** (per program rules).

## Notes
- Reproduced against stable, not just canary.
- Searched issues/PRs/advisories: not already tracked (link your search or say "no existing
  issue/PR found as of <date>").
