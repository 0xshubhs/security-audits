# Vercel Open Source — HackerOne workspace

Everything for hunting the **vercel-open-source** bug bounty program (HackerOne).

## Read in this order
1. **`SCOPE.md`** — rules, rewards, hard requirements, what gets auto-rejected. Read first.
2. **`PLAN.md`** — the strategy and prioritized target order (best beginner ROI first).
3. **`notes/<target>.md`** — per-target checkable hypotheses with real `file:line` pointers.
4. **`PROGRESS.md`** — live tracker: target status, findings log, submitted reports.
5. **`notes/REPORT-TEMPLATE.md`** — how to write the submission when you find something.

## Layout
```
hackerone/vercel-open-source/
├── README.md            ← you are here
├── SCOPE.md             ← rules + rewards + rejection criteria
├── PLAN.md              ← strategy + attack order
├── PROGRESS.md          ← tracker (update as you go)
├── repos/               ← all 16 in-scope repos (shallow clones) + clone-all.sh + clone.log
├── notes/               ← per-target hunting notes (hypotheses + file pointers)
│   ├── nuxt.md  flags.md  nitro.md  skills.md  ai-sdk.md  chat.md
│   ├── turborepo.md  sveltekit.md  other-targets.md  REPORT-TEMPLATE.md
└── poc/                 ← one folder per PoC you build (poc/<target>-<bug>/)
```

## The method (repeat per target)
Each focus-area bullet in the program = a **hypothesis**. Find the code path → read it in the
**latest stable release** → confirm or kill → if it holds, build a minimal PoC proving end-to-end
impact → check it's not already fixed/tracked → write the report + zip the PoC.

## Critical reminders
- **Never test against Vercel production systems.** Local, source-based testing only.
- Reproduce on a **stable** release (the clones are on `main`/canary — versions in each note).
- Every submission needs a **working PoC zip** + the **Affected version(s)** field.
- Reports are **confidential** (2 yrs); related PRs go via **private forks**.
- Use HackerOne alias email for any test accounts: `<h1username>@wearehackerone.com`.

## Where things stand (2026-08-23)
Workspace built, 16 repos cloned, all notes drafted. First-pass code reads done on **flags** and
**Skills**: the most obvious hypotheses there are already mitigated (see `PROGRESS.md` findings
log). Best live leads to pursue next: **flags override crypto** (`crypto.ts`) and **Skills install
write-paths** (`install.ts`/`archive.ts`), then the untouched high-ROI targets (Nuxt navigation
bypasses, AI SDK MCP, chat session ownership).
