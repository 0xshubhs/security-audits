#!/usr/bin/env bash
# Shallow-clones all in-scope Vercel Open Source bounty repos.
# Re-runnable: skips repos already cloned.
set -u
cd "$(dirname "$0")" || exit 1

# name|tier|url
REPOS=(
  "next.js|T1|https://github.com/vercel/next.js"
  "nuxt|T1|https://github.com/nuxt/nuxt"
  "swr|T1|https://github.com/vercel/swr"
  "svelte|T1|https://github.com/sveltejs/svelte"
  "turborepo|T1|https://github.com/vercel/turborepo"
  "ai|T1|https://github.com/vercel/ai"
  "vercel-cli|T1|https://github.com/vercel/vercel"
  "workflow|T1|https://github.com/vercel/workflow"
  "flags|T1|https://github.com/vercel/flags"
  "nitro|T1|https://github.com/nitrojs/nitro"
  "agent-skills|T1|https://github.com/vercel-labs/agent-skills"
  "skills|T1|https://github.com/vercel-labs/skills"
  "ms|T2|https://github.com/vercel/ms"
  "sveltekit|T2|https://github.com/sveltejs/kit"
  "eve|T2|https://github.com/vercel/eve"
  "chat|T2|https://github.com/vercel/chat"
)

ok=0; skip=0; fail=0
for entry in "${REPOS[@]}"; do
  IFS='|' read -r name tier url <<< "$entry"
  if [ -d "$name/.git" ]; then
    echo "SKIP  [$tier] $name (already cloned)"
    skip=$((skip+1))
    continue
  fi
  echo ">>> Cloning [$tier] $name from $url"
  if git clone --depth 1 --single-branch "$url" "$name" 2>&1 | tail -1; then
    ok=$((ok+1))
    echo "DONE  [$tier] $name"
  else
    fail=$((fail+1))
    echo "FAIL  [$tier] $name"
  fi
done

echo ""
echo "===================================="
echo "Cloned OK: $ok | Skipped: $skip | Failed: $fail"
echo "Disk usage:"
du -sh */ 2>/dev/null | sort -h
echo "ALL-CLONES-COMPLETE"
