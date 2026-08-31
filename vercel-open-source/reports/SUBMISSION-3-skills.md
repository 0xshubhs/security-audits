# HackerOne submission — copy/paste into the form fields

=====================================================================
FIELD: Asset
=====================================================================
skills  (repo: vercel-labs/skills; npm package: `skills`, CLI `npx skills` / `add-skill`)

=====================================================================
FIELD: Weakness
=====================================================================
Improper Link Resolution Before File Access ('Link Following') (CWE-59)
(secondary: CWE-61 UNIX Symbolic Link Following; impact: CWE-200 Exposure of Sensitive Information)

=====================================================================
FIELD: Severity
=====================================================================
Medium
(the primitive is arbitrary local file disclosure of anything the invoking user can read — incl.
SSH/cloud credentials and, via /proc/self/environ, the CLI's environment tokens — so Medium–High
depending on what the victim's machine/CI holds.)

=====================================================================
FIELD: Affected version(s)
=====================================================================
skills 1.5.23 (latest published release at test time — confirmed exploitable). Present on `main`.
The two copy sinks and the first-party-only blob gating are unchanged across current releases.

=====================================================================
FIELD: Affected File  (GitHub link)
=====================================================================
https://github.com/vercel-labs/skills/blob/main/src/installer.ts  (copyDirectory, ~line 487)
(related: src/use.ts ~line 594 (copySkillDirectory); src/add.ts ~lines 1182-1223 (clone routing))

=====================================================================
FIELD: Description
=====================================================================
## Summary:
`skills add <source>` copies a skill's files into the install location with
`cp(src, dest, { dereference: true, recursive: true })` — `copyDirectory` at
src/installer.ts:487-494 (and the sibling `copySkillDirectory` at src/use.ts:594). With
`dereference: true`, Node follows any symbolic link and copies the CONTENTS OF THE LINK TARGET.
Nothing constrains where a symlink inside the skill may point: the copy walk never calls
`lstat`/`realpath` to reject links or to confine their targets to the skill root, and only BROKEN
(ENOENT) symlinks are skipped (installer.ts:498-506). A symlink to a real host file is not broken,
so its contents are copied out.

A skill is fetched from an attacker-controlled Git repository. `git clone` preserves symbolic links
(stored as mode 120000). So a malicious skill repo that contains, e.g.:

    references/stolen-key -> /home/<victim>/.ssh/id_rsa        (absolute host path)
    references/host       -> ../../../../../../etc/hostname    (relative traversal out of the repo)
    references/env        -> /proc/self/environ                (the CLI process's own environment)

causes those host files' CONTENTS to be written into
`~/.claude/skills/<skill>/references/...` (or the project `.agents/skills/...`) at install time — a
location the agent then reads into its context, and that users routinely commit to a repo.

This is reachable from the ordinary invocation, not an exotic one:
- The safe path (GitHub blob/API fetch via `writeSafeFile`, which writes file contents and has no
  symlinks) is attempted ONLY for first-party owners:
  `BLOB_ALLOWED_OWNERS = ['vercel','vercel-labs','heygen-com']` plus an allow-listed self-hosted
  repo (src/add.ts:1182-1203).
- For ANY other `owner/repo` — i.e. exactly what an attacker publishes — that branch is skipped,
  `blobResult` stays null, and the `else` branch calls `cloneRepo(parsed.url)` UNCONDITIONALLY
  (src/add.ts:1208-1218). So `skills add attacker/evil-skill` always clones → symlinks preserved →
  `copyDirectory` dereferences them. Direct git/GitLab/SSH URLs, `--full-depth`, and local-path
  installs reach the same dereferencing copy as well.

The `isPathSafe` / `sanitizeName` guards (installer.ts:303-319) validate the destination skill NAME
only; they do nothing about symlink targets, so they do not mitigate this.

## Steps To Reproduce:
(A self-contained PoC is attached as skills-symlink-fileread-poc.zip. It installs the real published
`skills@latest`, runs the real CLI, and touches nothing outside a temp dir / sandbox $HOME.)

  1. Create a victim secret at a known path (stands in for ~/.ssh/id_rsa), e.g. /tmp/victim/id_rsa.
  2. Build a malicious skill as a Git repo:
       - a valid SKILL.md (name + description) as the lure;
       - references/stolen-key  ->  /tmp/victim/id_rsa            (ln -s, absolute)
       - references/host-name   ->  ../../../../../../etc/hostname (ln -s, relative traversal)
       - git init && git add -A && git commit   (git stores both as mode 120000 symlinks)
  3. As the victim, install it with the real CLI (any of these reaches the clone→copy path):
       npx skills add file:///path/to/malicious-skill --skill '*' --agent claude-code --copy -g -y
     (In the wild: `npx skills add attacker/evil-skill` on github.com — a third-party owner always
      clones.)
  4. Inspect the installed skill:
       ~/.claude/skills/helpful-formatter/references/stolen-key   -> a REAL FILE containing the
       victim private key; references/host-name contains /etc/hostname. The symlinks were
       dereferenced and the host files copied out.

## Supporting Material/References:
  * skills-symlink-fileread-poc.zip — poc.sh (self-contained, offline apart from the npm install)
    + README. Observed on skills 1.5.23:
        installed references/stolen-key is a regular file (-rw-rw-r--) containing
        "-----BEGIN OPENSSH PRIVATE KEY----- VICTIM-PRIVATE-KEY-... -----END ...-----"
        installed references/host-name contains the machine hostname (from /etc/hostname).
  * Root cause: src/installer.ts:487-494 (copyDirectory, dereference:true, no target confinement;
    only ENOENT skipped at :498-506); src/use.ts:594 (copySkillDirectory, same); src/add.ts:1182-1223
    (third-party GitHub repos and all git/gitlab/SSH URLs reach cloneRepo → the dereferencing copy).
  * Prior art / novelty: there is no published GitHub Security Advisory or tracked security issue for
    vercel-labs/skills covering this. The same bug CLASS was accepted and fixed in a sibling tool —
    `skilo`, GHSA-6xx4-9wp6-65p7 ("skilo add follows symbolic links, allowing arbitrary local file
    disclosure from a malicious skill source"), whose fix was to REJECT symlink entries. A public
    write-up ("Agent SkillSlip") mentions symlink handling in this tool but mischaracterizes it as
    already fixed by the change that ADDED `dereference: true`; that change is the cause, not a fix,
    and the current published 1.5.23 is still exploitable (attached PoC).

## Suggested fix (optional):
In both copy sinks (copyDirectory at installer.ts:487 and copySkillDirectory at use.ts:594), do NOT
dereference. Either (a) refuse symbolic-link entries outright (mirroring the skilo fix), or (b) for
each entry, resolve `realpath` and reject any target that escapes the cloned skill root before
copying. Dereferencing to "make the copy self-contained" does not make it safe — it eagerly copies
the secret's contents into the workspace.

=====================================================================
FIELD: Impact
=====================================================================
## Summary:
Installing an untrusted community skill — the tool's primary, encouraged workflow ("browse and
install skills", `npx skills add owner/repo`) — silently reads arbitrary files the invoking user can
access and deposits their contents into an agent-readable, frequently-committed location. With no
prior compromise and no special privilege, an attacker who publishes a skill can exfiltrate a
victim's SSH keys, cloud credentials, `.env` files, and — via `/proc/self/environ`, which needs no
knowledge of the victim's paths — every environment variable of the `skills` process (in developer
and CI environments these routinely include GITHUB_TOKEN, NPM_TOKEN, VERCEL_TOKEN, AWS_* and
similar). Because the copied files land under the installed skill and the skill's own SKILL.md is
attacker-authored, the disclosure also feeds directly into the consuming agent's context, enabling a
second-stage prompt-injection/exfiltration chain. The only precondition is that the victim installs
the attacker's skill, which is exactly what the tool exists to do.
