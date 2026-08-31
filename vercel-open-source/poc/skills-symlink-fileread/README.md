# PoC — `skills` CLI: arbitrary local file read via symlink dereference in a malicious skill

**Target:** `skills` **1.5.23** (published npm; repo `vercel-labs/skills`; CLI `npx skills` / `add-skill`).
**Class:** CWE-59 (Link Following) → CWE-200 (Information Exposure). Supply-chain / malicious-package.

## Summary
`skills add <source>` fetches a skill tree and copies it into the install location with
`copyDirectory(src, dest, { dereference: true })` (`src/installer.ts:487-494`; sibling
`copySkillDirectory` `src/use.ts:594`). `dereference: true` **follows any symlink and copies the
target's contents**. There is **no confinement of the symlink target** — it may point to an
absolute host path (`/etc/passwd`, `~/.ssh/id_rsa`, `/proc/self/environ`) or use a relative
`../` traversal that escapes the skill. Only **broken** (ENOENT) symlinks are skipped
(`installer.ts:498-506`); a symlink to a real host file is not broken, so its contents are copied
into `~/.claude/skills/<skill>/…` (or the project `.agents/skills/…`) at install time — a location
the agent then reads into its context, and that users frequently commit.

## Why the "name" path-traversal guards don't help
The `isPathSafe` / `sanitizeName` checks (`installer.ts:303-319`) validate the destination **skill
name**. They do nothing about **where a symlink inside the skill points**. The copy walk never
calls `lstat`/`realpath` to reject or contain symlink targets.

## Reachability (the canonical `skills add owner/repo` already hits the clone path)
`src/source-parser.ts` routing → `src/add.ts`:
- **Any third-party `github.com owner/repo`** (the normal shorthand form, and exactly what an
  attacker publishes) **always clones.** The safe blob/API fast-path (`tryBlobInstall`) is attempted
  **only** for first-party owners — `BLOB_ALLOWED_OWNERS = ['vercel','vercel-labs','heygen-com']` — or
  an allow-listed self-hosted repo (add.ts:1182-1203). For every other owner that `if` is false,
  `blobResult` stays null, and the `else` branch calls `cloneRepo(parsed.url)` **unconditionally**
  (add.ts:1208-1218). `git clone` **preserves symlinks** → `copyDirectory` dereferences them.
  (No GitHub-API-failure precondition is required; that only matters for first-party repos, which
  also fall back to clone when blob discovery fails.)
- **Any direct git URL, SSH URL, GitLab repo, or GitHub Enterprise host** → `type: 'git'/'gitlab'`
  → `cloneRepo()` (add.ts:1223), always clones.
- **`--full-depth`** always clones. **Local-path installs** copy directly (dereference too).

## Run
```bash
bash poc.sh
```
Fully self-contained and offline: installs the real published `skills@latest`, builds a malicious
skill **git repo** (valid `SKILL.md` + two escaping symlinks), runs the **real CLI** to `add` it
into a sandbox `$HOME`, and shows the victim files materialized inside the installed skill. Nothing
touches your real `~/.claude`; no network beyond the npm install.

### Expected output (observed on 1.5.23)
```
installed stolen-key is a REAL FILE (not a symlink):  -rw-rw-r-- … references/stolen-key
  -----BEGIN OPENSSH PRIVATE KEY-----
  VICTIM-PRIVATE-KEY-abc123-DO-NOT-LEAK
  -----END OPENSSH PRIVATE KEY-----
host-name (relative ../ traversal -> /etc/hostname):  <your hostname>
>> VULNERABLE: arbitrary host-file contents copied into ~/.claude/skills/<skill>/ on install.
```
`stolen-key` demonstrates absolute-path exfil; `host-name` demonstrates relative `../` traversal to
a universal path (no knowledge of the victim's home path required). `/proc/self/environ` similarly
exfiltrates the CLI process's environment (tokens) with no path knowledge.

## Impact
Installing an untrusted community skill — the tool's **primary, encouraged use case** ("browse and
install skills") — silently copies arbitrary host files the user can read into an agent-readable
(and often git-committed) location. Targets include SSH/cloud credentials, `.env`, and, via
`/proc/self/environ`, every environment variable of the `skills` process (in CI/dev these routinely
hold `GITHUB_TOKEN`, `NPM_TOKEN`, `VERCEL_TOKEN`, `AWS_*`). No prior compromise or special privilege
is required — only that the victim adds the attacker's skill.

## Prior public discussion / novelty (read this — dup context)
- **No GHSA/CVE** for `vercel-labs/skills`, and **no security issue** tracks this in the repo.
- The symlink-to-sensitive-file technique against Vercel's tool is described in a public blog
  ("Agent SkillSlip", oddguan.com) — **but that writeup incorrectly reports it as fixed**, crediting
  PR #108 ("dereference symlinked files…") as the remedy. PR #108 *added* `dereference: true`; that
  is the **cause**, not a fix. This PoC demonstrates the issue is **still live on the latest
  published 1.5.23**. The reportable framing is therefore *incomplete/incorrect fix — still
  exploitable*, distinct from re-reporting a known-fixed bug.
- Same bug **class** already accepted in a sibling tool: `skilo` GHSA-6xx4-9wp6-65p7
  ("`skilo add` follows symbolic links → arbitrary local file disclosure from a malicious skill
  source"), fixed by **rejecting** symlink entries.

## Fix
Reject symbolic-link entries during the install copy (mirror `skilo`'s fix), OR resolve each entry's
`realpath` and refuse any target that escapes the cloned skill root, for **both** `copyDirectory`
(`installer.ts:487`) and `copySkillDirectory` (`use.ts:594`). Dereferencing to copy contents does not
make this safe — it copies the secret out eagerly.
