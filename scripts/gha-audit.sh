#!/usr/bin/env bash
# gha-audit.sh — supply-chain diff between two refs of a GitHub Action.
#
# Usage: gha-audit.sh <owner/repo> <from-ref> <to-ref>
# Example: gha-audit.sh dawidd6/action-download-artifact v3.1.4 v14
#          gha-audit.sh actions/checkout 09f2f74... 5c98f0b...   (refs may be tags OR SHAs)
#
# A `uses: owner/repo@ref` step runs third-party code in your CI with the workflow
# token (and any secrets you pass it). Pinning by commit SHA is best practice; a
# Dependabot github_actions bump moves that ref. The core trust check — like docker's
# digest<->tag — is REF INTEGRITY: does the new commit correspond to a real published
# tag/release, or to an injected/untagged commit (or a tag that was moved)?
#
# Surfaces: ref->commit resolution + tag mapping, repo/owner status & author change,
# the action.yml execution model (node/docker/composite) and its diff, changed
# high-signal files (manifest/Dockerfile/shell/workflow) vs. vendored node_modules
# noise, a suspicious-pattern scan over added non-vendored code, and known advisories.
#
# Requires: gh (authenticated), jq, diff, grep, sed. Uses the GitHub API for all I/O.
set -uo pipefail

repo="${1:?usage: gha-audit.sh <owner/repo> <from-ref> <to-ref>}"
from="${2:?usage: gha-audit.sh <owner/repo> <from-ref> <to-ref>}"
to="${3:?usage: gha-audit.sh <owner/repo> <from-ref> <to-ref>}"
case "$repo" in */*) :;; *) echo "ERROR: <owner/repo> must look like owner/repo (got '$repo')"; exit 1;; esac
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

echo "================================================================"
echo "GITHUB ACTIONS SUPPLY-CHAIN AUDIT: $repo   $from -> $to"
echo "================================================================"

# ---- repo / owner status ----
meta="$(gh api "repos/$repo" 2>/dev/null)"
if [ -z "$meta" ]; then
  echo "ERROR: cannot fetch repos/$repo — private, renamed/transferred, or gh is not authenticated."
  echo "       (If the action moved, that rename is itself worth investigating.)"; exit 1
fi
echo "---- REPO / OWNER ----"
echo "$meta" | jq -r '
  "  owner:       \(.owner.login) (\(.owner.type))",
  "  full_name:   \(.full_name)",
  "  archived:    \(.archived)   fork: \(.fork)   stars: \(.stargazers_count)",
  "  created:     \(.created_at)   last push: \(.pushed_at)",
  "  license:     \(.license.spdx_id // "none")",
  "  description: \(.description // "")"'
real_fn="$(echo "$meta" | jq -r '.full_name')"
if [ "$(printf '%s' "$real_fn" | tr 'A-Z' 'a-z')" != "$(printf '%s' "$repo" | tr 'A-Z' 'a-z')" ]; then
  echo "  ⚠️ referenced as '$repo' but the repo now resolves to '$real_fn' — a rename/transfer; verify it's expected."
fi
if [ "$(echo "$meta" | jq -r '.archived')" = "true" ]; then
  echo "  ⚠️ repository is ARCHIVED — no longer maintained; a bump to an unmaintained action is worth a second look."
fi

# ---- ref / tag integrity (the core check) ----
echo
echo "---- REF / TAG INTEGRITY (does each ref resolve to a published-tag commit?) ----"
gh api --paginate "repos/$repo/tags" --jq '.[] | "\(.commit.sha)\t\(.name)"' > "$work/tags.tsv" 2>/dev/null
tags_for_sha() { awk -F'\t' -v s="$1" '$1==s{printf "%s ",$2}' "$work/tags.tsv" | sed 's/ *$//'; }
FROM_SHA=""; TO_SHA=""; TO_TAGS=""
for label in from to; do
  ref="$from"; [ "$label" = to ] && ref="$to"
  sha="$(gh api "repos/$repo/commits/$ref" --jq '.sha' 2>/dev/null)"
  if [ -z "$sha" ]; then
    echo "  $label: $ref -> ❌ could not resolve to a commit in $repo (bad tag/branch/SHA?)"; continue
  fi
  tg="$(tags_for_sha "$sha")"
  printf '  %-5s %s -> %s   tag(s): %s\n' "$label:" "$ref" "${sha:0:12}" "${tg:-(none — untagged commit)}"
  if [ "$label" = from ]; then FROM_SHA="$sha"; else TO_SHA="$sha"; TO_TAGS="$tg"; fi
done
echo
if [ -n "$TO_SHA" ]; then
  if [ -n "$TO_TAGS" ]; then
    echo "  ✅ the 'to' commit is published as tag(s): $TO_TAGS"
    echo "     Confirm that matches the version comment Dependabot wrote in the workflow (e.g. '# v14')."
  else
    echo "  ⚠️ NO tag points at the 'to' commit. Dependabot normally pins a tagged release —"
    echo "     an untagged commit (or a tag that was moved off it) warrants a manual check that this is real."
  fi
fi

# ---- action manifest: execution model ----
echo
echo "---- ACTION MANIFEST: execution model (what the action actually runs) ----"
fetch_manifest() { # <ref> <outfile> ; echoes the filename used, or nothing
  local f
  for f in action.yml action.yaml; do
    if gh api "repos/$repo/contents/$f?ref=$1" -H "Accept: application/vnd.github.raw" > "$2" 2>/dev/null && [ -s "$2" ]; then
      echo "$f"; return 0
    fi
  done
  return 1
}
mf_from="$(fetch_manifest "$from" "$work/m_from")" || true
mf_to="$(fetch_manifest "$to" "$work/m_to")" || true
runs_summary() { # <manifest-file>
  local f="$1" k v out=""
  [ -s "$f" ] || { echo "(no action.yml — composite-less/JS dist, or a Dockerfile-only action?)"; return; }
  for k in using main pre post image; do
    v="$(grep -iE "^[[:space:]]*$k:" "$f" | head -1 | sed -E "s/.*$k:[[:space:]]*[\"']?([^\"' ]+).*/\1/")"
    [ -n "$v" ] && out="$out $k=$v"
  done
  echo "${out# }"
}
echo "  from (${mf_from:-none}): $(runs_summary "$work/m_from")"
echo "  to   (${mf_to:-none}): $(runs_summary "$work/m_to")"
u_from="$(runs_summary "$work/m_from" | sed -nE 's/.*using=([^ ]+).*/\1/p')"
u_to="$(runs_summary "$work/m_to" | sed -nE 's/.*using=([^ ]+).*/\1/p')"
fam() { printf '%s' "$1" | sed 's/[0-9].*$//'; }   # node20 -> node, docker -> docker
if [ -n "$u_from" ] && [ -n "$u_to" ]; then
  if [ "$(fam "$u_from")" != "$(fam "$u_to")" ]; then
    echo "  ⚠️ execution model CHANGED: using $u_from -> $u_to (node<->docker<->composite is a major shift — review in full)."
  elif [ "$u_from" != "$u_to" ]; then
    echo "  • runtime bump: using $u_from -> $u_to (routine — older node runtimes are EOL; not a model change)."
  fi
fi
grep -qiE '^[[:space:]]*image:[[:space:]]*["'"'"']?docker://' "$work/m_to" 2>/dev/null && \
  echo "  ⚠️ 'to' runs an EXTERNAL container (image: docker://...) — audit that image separately (see docker-audit.sh)."
{ grep -qiE '^[[:space:]]*pre:' "$work/m_to" 2>/dev/null && ! grep -qiE '^[[:space:]]*pre:' "$work/m_from" 2>/dev/null; } && \
  echo "  ⚠️ a 'pre:' hook was ADDED — it runs before the job's main step; review what it does."

echo
echo "---- action.yml DIFF (inputs / defaults / runs)   [< old | > new] ----"
if [ -s "$work/m_from" ] && [ -s "$work/m_to" ]; then
  md="$(diff "$work/m_from" "$work/m_to" | grep -E '^[<>]' | head -60)"
  [ -n "$md" ] && echo "$md" || echo "  (action.yml identical)"
  echo "  ^ watch for a default flipping to a less-safe value, a new 'run:' shell step (composite),"
  echo "    a new input that takes a token/URL, or the 'main'/'image' entrypoint being repointed."
else
  echo "  (could not fetch action.yml at one or both refs)"
fi

# ---- code delta ----
echo
echo "---- CODE DELTA ($from -> $to) ----"
cmp="$(gh api "repos/$repo/compare/$from...$to" 2>/dev/null)"
if [ -n "$cmp" ]; then
  echo "$cmp" | jq -r '"  status: \(.status)   commits: \(.total_commits)   ahead: \(.ahead_by)   behind: \(.behind_by)   files: \(.files|length)"'
  [ "$(echo "$cmp" | jq -r '.behind_by // 0')" != "0" ] && \
    echo "  ⚠️ 'to' is BEHIND 'from' by $(echo "$cmp" | jq -r '.behind_by') commit(s) — a downgrade or divergent history; investigate."
  echo "$cmp" | jq -r '.files[]?.filename' > "$work/files.txt"
  vend='(^|/)(node_modules|dist|vendor)/|\.map$|\.min\.(js|css)$|package-lock\.json$'
  echo "  vendored/built files changed (expected churn for a JS action, not inspected line-by-line): $(grep -cE "$vend" "$work/files.txt")"
  echo "  HIGH-SIGNAL files changed:"
  hs="$(grep -ivE "$vend" "$work/files.txt" | grep -iE 'action\.ya?ml|Dockerfile|entrypoint|\.sh$|\.ps1$|(^|/)\.github/workflows/|main\.js$|index\.js$|\.py$|\.rb$|\.cjs$|\.mjs$|run\.js$' | head -30)"
  [ -n "$hs" ] && echo "$hs" | sed 's/^/     /' || echo "     (none beyond the manifest — only vendored/doc/test files changed)"
else
  echo "  (could not fetch compare $from...$to — refs may be on divergent histories; check the releases page)"
fi

# ---- suspicious patterns in added, non-vendored code ----
echo
echo "---- SUSPICIOUS PATTERNS in ADDED code (non-vendored)   [> added] ----"
if [ -n "$cmp" ]; then
  # Scan only files that can execute in a CONSUMER's pipeline: exclude vendored
  # bundles plus the action's own tests/docs/fixtures (they run in the action's CI,
  # never in yours) — those are the dominant URL/secret false positives.
  echo "$cmp" | jq -r '.files[]? | select((.filename|test("(^|/)(node_modules|dist|vendor|__tests?__|tests?|spec|specs|examples?|docs?|fixtures?|e2e|images)/|\\.(map|md|markdown|snap)$|\\.min\\.(js|css)$|\\.(test|spec)\\.(ts|js|tsx|jsx|mjs|cjs)$"))|not) | select(.patch!=null) | .patch' 2>/dev/null \
    | grep '^+' | grep -vE '^\+\+\+' \
    | grep -niE 'curl |wget |Invoke-WebRequest|\| *(ba)?sh\b|\bnc \b|/dev/tcp/|\beval\b|child_process|os\.system|subprocess|base64 (-d|--decode)|atob\(|fromCharCode|::(set-env|add-path|add-mask)|>> *"?\$?\{?GITHUB_(ENV|PATH)|ACTIONS_(RUNTIME|ID)_TOKEN|\$\{\{ *secrets|secrets\.[A-Z]|pull_request_target|docker://|https?://' \
    | grep -ivE 'github\.com|githubusercontent|docs\.github|api\.github|json-schema\.org|schemastore|nodejs\.org|registry\.npmjs|w3\.org|aka\.ms|github\.token' \
    | head -40 > "$work/sus.txt"
  if [ -s "$work/sus.txt" ]; then
    sed 's/^/  /' "$work/sus.txt"
    echo "  ^ TRIAGE: in an Action the real risks are NEW external network calls (exfil), reads of secrets /"
    echo "    ACTIONS_*_TOKEN, writes to \$GITHUB_ENV/\$GITHUB_PATH (env-injection -> later-step code exec),"
    echo "    pull_request_target, curl|sh, or a swapped external container. The action's own GitHub API use is fine."
  else
    echo "  (no suspicious added patterns in non-vendored files)"
  fi
  echo "  note: GitHub omits patches for very large diffs — if 'files' is high and this is sparse, the vendored"
  echo "  bundle changed too much to inline; judge from action.yml + the changelog rather than assuming clean."
fi

# ---- known advisories ----
echo
echo "---- KNOWN ADVISORIES ----"
{ gh api "repos/$repo/security-advisories" --jq '.[]? | "\(.ghsa_id)\t\(.severity // "?")\t\(.summary)"' 2>/dev/null
  gh api "/advisories?ecosystem=actions&affects=$repo&per_page=30" --jq '.[]? | "\(.ghsa_id)\t\(.severity // "?")\t\(.summary)"' 2>/dev/null
} | sort -u -t"$(printf '\t')" -k1,1 > "$work/adv.tsv"
if [ -s "$work/adv.tsv" ]; then
  awk -F'\t' '{printf "  [%s] %s: %s\n",$1,$2,$3}' "$work/adv.tsv"
  echo "  ^ Check whether the FROM version is in the affected range and the TO version includes the fix."
  echo "    An upgrade that CROSSES the fix is a reason TO merge (it patches a known hole), not to block."
else
  echo "  (none found via repo security-advisories or the Actions advisory DB — absence isn't proof; read the changelog)"
fi

echo
echo "================================================================"
echo "INTERPRETATION GUIDE (GitHub Actions)"
echo "  RED FLAGS (escalate): the TO commit has no tag / a tag that was moved (injected pin); an execution-model"
echo "    change (node<->docker<->composite) or a new 'image: docker://' external container; an added pre/post"
echo "    hook; new external network calls, curl|sh, base64-decode, or eval in added code; writes to"
echo "    \$GITHUB_ENV/\$GITHUB_PATH or ::set-env/::add-path (env-injection); secret/token reads paired with"
echo "    network egress; an owner rename/transfer or the repo going archived."
echo "  EXPECTED: large node_modules/dist churn on a JS action; @actions/* library bumps; new optional inputs;"
echo "    a default tightening for safety (e.g. allow_forks true->false). 'using: node20' staying put is good."
echo "  CONTEXT: an upgrade that crosses a published advisory's fix version is a reason to MERGE. Pinning by SHA"
echo "    is the goal — confirm the SHA maps to the tag named in Dependabot's version comment."
echo "================================================================"
