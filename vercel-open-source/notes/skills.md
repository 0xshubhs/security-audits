# Skills + Agent-Skills (Tier 1) — hunting notes

Cloned: `repos/skills` (CLI `npx skills`, **v1.5.23**) and `repos/agent-skills` (Vercel's skill
collection). Attack surface = the **framework/CLI/install pipeline**, NOT individual third-party
skills (those are the author's responsibility and explicitly out of scope).

Focus areas: path traversal on install (real out-of-bounds write); terminal-escape injection via
SKILL.md metadata (ANSI/OSC); prompt injection / covert `curl|bash` payload delivery in SKILL.md;
supply-chain against the registry/install pipeline.

## Current mitigations (so hunt BYPASSES)
- `repos/skills/src/sanitize.ts` — strips CSI/OSC/DCS/PM/APC + simple ESC sequences from
  untrusted metadata. Regexes are all **`\x1b`-prefixed**.
- `repos/skills/src/skills.ts:166–190` — rejects subpaths whose `..` segments resolve outside the
  base dir (`Invalid subpath ... resolves outside the repository directory`).

## Hypotheses to test (yes → candidate bug)

### Terminal-escape bypass (sanitize.ts)
1. **8-bit C1 controls not stripped.** The regexes only match ESC (`\x1b`, `0x1B`). Many
   terminals also honor single-byte C1 codes: **CSI = `0x9B`**, OSC = `0x9D`, ST = `0x9C`.
   These are not `\x1b`-prefixed → not matched by `CSI_RE`/`OSC_RE`. If a skill name/description
   containing raw `\x9b...m` (or in UTF-8, ``) is printed to the terminal, escape injection
   survives sanitization. **Check every site that prints name/description** and whether sanitize
   is applied there and whether these bytes survive.
2. **Un-sanitized print site.** Grep every `console.log`/`process.stdout.write`/logger that
   includes `data.name`/`data.description`/skill title. Any path (list, add, search, update,
   error messages) that prints metadata WITHOUT calling the sanitizer = injection.
3. **Sanitizer applied post-formatting.** If color codes are added *after* content is embedded,
   or truncation splits a stripped sequence, a partial ESC could recombine.

### Path traversal on install (real write outside target)
4. **Guard covers subpath but not the write.** `skills.ts` guards a `subpath`, but the actual
   install/extract happens in `install.ts` / `installer.ts` / `archive.ts` / `blob.ts` /
   `download-source.ts`. Read those: is the *final write path* re-validated after join, or can a
   skill name / archive entry name / lockfile field contain `..`, an absolute path, or a symlink
   that escapes the install dir? (Focus area demands a demonstrated **out-of-bounds write**.)
5. **Archive/symlink escape.** If install downloads a tarball/zip, are entry names checked for
   `..` and are symlink entries refused? A symlink whose target is `../../` then a follow-up write
   through it = escape.
6. **Skill `name` used as a path component.** If `name` from frontmatter becomes a directory name
   without sanitization → `name: ../../x`.

### Covert payload / supply chain
7. Does the install pipeline ever execute skill-provided commands (`curl|bash`, postinstall,
   opaque redirect URLs) **without a confirmation gate**? Trace `install.ts` for any exec.
8. Telemetry: does it leak private repo metadata when `DISABLE_TELEMETRY=1`? (`telemetry.ts`) —
   only in scope if demonstrated on a fixed release with no open tracking issue.

## Where to read (skills/src)
`sanitize.ts`, `skills.ts`, `install.ts`, `installer.ts`, `archive.ts`, `blob.ts`,
`download-source.ts`, `source-parser.ts`, `frontmatter.ts`, `cli.ts`, `add.ts`, `list.ts`,
`init.ts` (init subcommand path traversal is lower priority per policy).

## PoC shape
- Terminal escape: a local skill dir with `name`/`description` containing `\x9b` C1 CSI; run the
  CLI command that lists/adds it; capture terminal manipulation (title change, output spoof).
- Path traversal: a crafted skill source (archive entry or name) that, on `npx skills add`,
  writes a file OUTSIDE the intended dir. Show the out-of-bounds file appearing.

## Agent-Skills specifics
Focus: skills embedding external trust deps (remote URLs / third-party pipelines) without user
awareness; tool invocation without confirmation for high-impact ops; cross-skill state/credential
access. Read the execution/trust model, not individual skill content.

## First-pass results (2026-08-23, v1.5.23)
- ❌ **H1 C1-control bypass DEAD.** `sanitize.ts:32` `C1_RE = /[\x80-\x9f]/g` already strips 8-bit
  C1 controls (incl. 0x9B CSI / 0x9D OSC), plus OSC/DCS/PM/APC/CSI/simple-ESC and raw controls.
  The sanitizer itself is thorough (keeps only `\t`/`\n`; `sanitizeMetadata` collapses `\n`).
- 🔎 **Still open — best remaining leads:**
  - **H2 un-sanitized print site.** The bug (if any) is a code path that prints
    `data.name`/`data.description`/frontmatter WITHOUT calling `sanitizeMetadata`/
    `stripTerminalEscapes`. Grep every print of metadata across `src/` and check each. NOT done.
  - **H4/H5 path traversal / archive-symlink escape** in `install.ts`/`installer.ts`/`archive.ts`/
    `blob.ts`/`download-source.ts` — the `..` guard in `skills.ts:166` covers a *subpath*, but is
    the final write path re-validated? Are tar/zip entry names + symlink targets checked? NOT read.
  - Note: `stripTerminalEscapes` keeps `\n`; any site using it (not `sanitizeMetadata`) on
    multi-line metadata could allow newline-based output spoofing (lower severity).

## RESULT (2026-08-23, agent + partial self-verify): no out-of-bounds WRITE; one PLAUSIBLE READ
- Path traversal WRITE (a)-(e): DEAD. Every write sink pairs `sanitizeName` (installer.ts:50) with
  an `isPathSafe` recheck (installer.ts:73), and all three archive readers (zip archive.ts, tar via
  node-tar strict, well-known tar.gz) reject `..`/absolute/symlink entries before any write.
- Terminal-escape print sites: DEAD — `sanitizeMetadata` applied at parse time (skills.ts:125,
  blob.ts:582, wellknown.ts:570); downstream prints are pre-sanitized. Minor: `warnSkippedSkill`
  uses `stripTerminalEscapes` (keeps \n) → newline output-spoofing only (cosmetic).
- Covert RCE / postinstall: DEAD (no postinstall, execFile/spawn no-shell, yaml safe-load).
- **PLAUSIBLE-NEEDS-POC — arbitrary FILE READ via symlink dereference on git-source installs**:
  `copyDirectory` (installer.ts:487) / `copySkillDirectory` (use.ts:594) use `cp(..., {dereference:
  true, recursive:true})`. Git clone preserves symlinks (archives strip them). A git skill repo with
  `creds.md -> /home/<user>/.ssh/id_rsa` (or `../../../etc/passwd`) → the target's CONTENTS get
  copied into `~/.agents/skills/<skill>/creds.md` (in-bounds dest, so NOT a write-escape) = CWE-59/200
  arbitrary read into a dir whose SKILL.md is attacker-authored → prompt-injection/exfil chain for
  the consuming agent. Default install mode (symlink) still copies via copyDirectory first, so
  reachable with default flags. Frame as file-disclosure, not path-traversal-write. Lower value than
  a write bug; may be argued as known (maintainers handle broken-symlink cleanup at :497).

## ✅ CONFIRMED (2026-08-31) — arbitrary local file READ via symlink dereference (CWE-59 → CWE-200)
WORKING PoC on published **skills@1.5.23**: `poc/skills-symlink-fileread/` (`bash poc.sh`, self-contained).
- Mechanism: `copyDirectory(..., {dereference:true})` (installer.ts:487-494) FOLLOWS symlinks and copies
  the TARGET's contents; only ENOENT/broken symlinks are skipped (installer.ts:498-506). No realpath/
  target confinement. Same in `copySkillDirectory` (use.ts:594). The `isPathSafe`/`sanitizeName` guards
  (installer.ts:303-319) validate the destination NAME, not symlink targets.
- Reachability (CORRECTED — stronger than first stated): the SAFE blob/API path is FIRST-PARTY ONLY
  (`BLOB_ALLOWED_OWNERS=['vercel','vercel-labs','heygen-com']` + self-hosted allowlist, add.ts:1182-1203).
  ANY third-party `github.com owner/repo` (what an attacker publishes) has that `if` false → blobResult
  null → `else` calls `cloneRepo` UNCONDITIONALLY (add.ts:1208-1218). So the canonical
  `skills add attacker/evil-skill` ALWAYS clones → symlinks preserved (mode 120000) → copyDirectory
  dereferences. No API-failure precondition. git/gitlab/SSH URLs + `--full-depth` also always clone;
  local installs copy directly. (First-party repos additionally fall back to clone on blob failure.)
- PoC proves: malicious skill repo w/ `references/stolen-key -> /abs/victim/id_rsa` and
  `host-name -> ../../../../etc/hostname` → after `skills add`, both are REAL FILES in
  `~/.claude/skills/<skill>/references/` containing the victim key + /etc/hostname. `/proc/self/environ`
  target leaks the CLI process env (tokens) with no path knowledge.
- Impact: installing an untrusted community skill (the tool's PRIMARY use case) silently exfiltrates
  arbitrary user-readable host files into an agent-readable + often-committed location. No prior compromise.
- DUP/NOVELTY (honest): NO GHSA/CVE for vercel-labs/skills, NO tracked repo security issue. The technique
  is PUBLICLY BLOGGED against Vercel's tool ("Agent SkillSlip", oddguan.com) — BUT that post WRONGLY marks
  it fixed, crediting PR #108 (which ADDED dereference:true = the CAUSE) as the fix. Still live on 1.5.23
  (PoC). Same class accepted for sibling tool `skilo` GHSA-6xx4-9wp6-65p7 (fixed by REJECTING symlinks).
  → Filable framing = "incomplete/incorrect fix, still exploitable on latest." Signal risk ELEVATED by the
  public blog → rank BELOW the 2 clean reports (turbo, ai-sdk). MED(-HIGH) impact.
- Fix: reject symlink entries (like skilo) OR realpath-confine targets to the skill root, in BOTH
  copyDirectory + copySkillDirectory.

## Status: DONE — symlink-deref READ **CONFIRMED + PoC** (filable w/ elevated Signal risk); write bug DEAD.
