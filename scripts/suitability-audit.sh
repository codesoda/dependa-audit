#!/usr/bin/env bash
# suitability-audit.sh — static CI/build compatibility review for a Dependabot PR.
#
# Usage: suitability-audit.sh <pr-number-or-url> [owner/repo]
#
# This deliberately does not build, test, checkout, or mutate the target repo. It
# compares the final PR tree with the original Dependabot commit, then inventories
# toolchain/image pins and nearby contract tests through the GitHub API.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: suitability-audit.sh <pr-number-or-url> [owner/repo]

Runs a read-only CI/build suitability review. It may be run on an open, closed,
or merged PR; the dependa-audit skill performs the normal open/Dependabot gate.
EOF
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

arg="$1"
repo=""
if [[ "$arg" =~ ^https?://github\.com/([^/]+/[^/]+)/pull/([0-9]+)(/|$) ]]; then
  repo="${BASH_REMATCH[1]}"
  pr="${BASH_REMATCH[2]}"
elif [[ "$arg" =~ ^[0-9]+$ ]]; then
  pr="$arg"
  if [ "$#" -eq 2 ]; then
    repo="$2"
  fi
else
  echo "ERROR: expected a PR number or GitHub PR URL" >&2
  exit 2
fi

if [ -n "$repo" ] && [[ ! "$repo" =~ ^[^/]+/[^/]+$ ]]; then
  echo "ERROR: expected owner/repo, got $repo" >&2
  exit 2
fi

pr_view=(gh pr view "$pr")
if [ -n "$repo" ]; then
  pr_view+=(--repo "$repo")
fi
if ! meta="$("${pr_view[@]}" --json state,title,author,baseRefName,baseRefOid,headRefName,headRefOid,commits,url)"; then
  echo "ERROR: could not fetch PR $pr${repo:+ in $repo}" >&2
  exit 1
fi
url="$(jq -r '.url' <<<"$meta")"
if [ -z "$repo" ]; then
  repo="$(awk -F/ '{print $4 "/" $5}' <<<"$url")"
fi
if [[ ! "$repo" =~ ^[^/]+/[^/]+$ ]]; then
  echo "ERROR: could not resolve owner/repo from $url" >&2
  exit 2
fi

head="$(jq -r '.headRefOid' <<<"$meta")"
base="$(jq -r '.baseRefOid' <<<"$meta")"
state="$(jq -r '.state' <<<"$meta")"
title="$(jq -r '.title' <<<"$meta")"
author="$(jq -r '.author.login' <<<"$meta")"

work="$(mktemp -d "${TMPDIR:-/tmp}/dependa-suitability.XXXXXX")"
trap 'rm -rf "$work"' EXIT
snapshot="$work/snapshot"
mkdir -p "$snapshot"

printf '%s\n' '================================================================'
printf 'SUITABILITY AUDIT: %s#%s\n' "$repo" "$pr"
printf '  state:  %s\n' "$state"
printf '  title:  %s\n' "$title"
printf '  author: %s\n' "$author"
printf '  base:   %s (%s)\n' "$base" "$(jq -r '.baseRefName' <<<"$meta")"
printf '  head:   %s (%s)\n' "$head" "$(jq -r '.headRefName' <<<"$meta")"
printf '%s\n' '================================================================'

# ---------- PR history and diffs ----------
if ! gh pr diff "$pr" --repo "$repo" > "$work/final.diff"; then
  echo "ERROR: could not fetch the final PR diff" >&2
  exit 1
fi

commits=()
while IFS= read -r sha; do
  [ -n "$sha" ] && commits+=("$sha")
done < <(jq -r '.commits[]?.oid' <<<"$meta")

if [ "${#commits[@]}" -eq 0 ]; then
  echo "ERROR: PR has no visible commits; cannot reconstruct history" >&2
  exit 1
fi

first="${commits[0]}"
first_json="$work/first.json"
if ! gh api "repos/$repo/commits/$first" > "$first_json"; then
  echo "ERROR: could not fetch the first PR commit $first" >&2
  exit 1
fi
first_author="$(jq -r '[.author.login // empty, .committer.login // empty] | map(select(length > 0)) | .[0] // "unknown"' "$first_json")"
if [[ "$first_author" != *dependabot* ]]; then
  echo "WARNING: first PR commit author is $first_author; the history comparison is not confirmed as a Dependabot baseline."
fi
parent="$(jq -r '.parents[0].sha // empty' "$first_json")"

if [ -n "$parent" ]; then
  # Keep the first commit separate from the final diff because later commits can revert a bump.
  if ! gh api "repos/$repo/compare/$parent...$first" > "$work/original.json"; then
    echo "ERROR: could not compare the first PR commit with its parent" >&2
    exit 1
  fi
  jq -r '.files[]? | "diff --git a/\(.previous_filename // .filename) b/\(.filename)\n\(.patch // "")"' \
    "$work/original.json" > "$work/original.diff"
else
  : > "$work/original.diff"
fi

relevant_lines() {
  local file="$1"
  [ -s "$file" ] || return 0
  awk '
    /^diff --git / { file=$4; sub(/^b\//, "", file) }
    /^[+-][^+-]/ && $0 ~ /(FROM[[:space:]]|RUST_TOOLCHAIN|NODE_VERSION|PNPM_VERSION|NPM_VERSION|rust-toolchain|muslrust:|node:[0-9]|node-version[[:space:]]*:|image:[[:space:]]|uses:[[:space:]]|cargo-chef|sccache|packageManager|engines|rust-version)/ {
      print file ": " $0
    }
  ' "$file" | head -n 160
}

printf '\n%s\n' '---- ORIGINAL PR RELEVANT CHANGES ----'
if [ -s "$work/original.diff" ]; then
  relevant_lines "$work/original.diff" || true
else
  echo 'history unavailable: could not fetch the first commit comparison'
fi

: > "$work/human-context.txt"
if [ "${#commits[@]}" -gt 1 ]; then
  for ((i=1; i<${#commits[@]}; i++)); do
    sha="${commits[$i]}"
    json="$work/commit-$i.json"
    gh api "repos/$repo/commits/$sha" > "$json"
    login="$(jq -r '[.author.login // empty, .committer.login // empty, .commit.author.name // empty] | map(select(length > 0)) | .[0] // "unknown"' "$json")"
    login_lower="$(printf '%s' "$login" | tr '[:upper:]' '[:lower:]')"
    case "$login_lower" in
      *dependabot*) continue ;;
    esac
    message="$(jq -r '.commit.message' "$json")"
    printf 'COMMIT %s (%s)\n%s\n' "$sha" "$login" "$message" >> "$work/human-context.txt"
    jq -r '.files[]? | "diff --git a/\(.filename) b/\(.filename)\n\(.patch // "")"' "$json" \
      > "$work/commit-$i.diff"
    relevant_lines "$work/commit-$i.diff" >> "$work/human-context.txt" || true
    printf '\n' >> "$work/human-context.txt"
  done
fi

# Comments often carry the rationale for an intentional compatibility decision.
{
  gh api --paginate "repos/$repo/issues/$pr/comments" \
    --jq '.[] | "COMMENT \(.user.login)\n\(.body)\n"' 2>/dev/null || true
  gh api --paginate "repos/$repo/pulls/$pr/comments" \
    --jq '.[] | "REVIEW_COMMENT \(.user.login)\n\(.body)\n"' 2>/dev/null || true
} > "$work/comments.txt"

printf '\n%s\n' '---- HUMAN CHANGE / REVIEW CONTEXT ----'
if [ -s "$work/human-context.txt" ]; then
  head -n 220 "$work/human-context.txt"
else
  echo '(no later non-Dependabot commit found)'
fi
if grep -Eiq 'toolchain|version skew|skew|align|compatib|production|builder|ci|revert|keep ' "$work/comments.txt"; then
  echo 'Relevant rationale comments:'
  grep -Ein 'toolchain|version skew|skew|align|compatib|production|builder|ci|revert|keep ' "$work/comments.txt" \
    | head -n 80
else
  echo 'Relevant rationale comments: none found'
fi

# ---------- final tree snapshot ----------
tree_json="$work/tree.json"
if ! gh api "repos/$repo/git/trees/$head?recursive=1" > "$tree_json" 2>/dev/null; then
  echo "ERROR: could not fetch the PR tree at $head" >&2
  exit 1
fi
if [ "$(jq -r '.truncated // false' "$tree_json")" = true ]; then
  echo 'WARNING: GitHub returned a truncated tree; context inventory may be incomplete.'
fi

changed_paths="$work/changed-paths"
grep '^diff --git ' "$work/final.diff" | awk '{print $3}' | sed 's#^a/##' > "$changed_paths" || true

is_context_path() {
  local path="$1"
  # Always fetch a changed file, including a changed test/contract file. This
  # catches the exact assertion update even when its basename is project-specific.
  if grep -Fqx "$path" "$changed_paths" 2>/dev/null; then
    return 0
  fi
  case "$path" in
    rust-toolchain|rust-toolchain.toml|rust-toolchain.*|\
    .github/workflows/*|.github/actions/*/action.yml|.github/actions/*/action.yaml|\
    Dockerfile|Dockerfile.*|*/Dockerfile|*/Dockerfile.*|*.dockerfile|\
    docker-compose*.yml|docker-compose*.yaml|*/docker-compose*.yml|*/docker-compose*.yaml|\
    package.json|web/package.json|desktop/package.json|\
    Cargo.toml|go.mod|pyproject.toml|\
    pnpm-lock.yaml|package-lock.json|Cargo.lock|\
    requirements*.txt|pom.xml|build.gradle|build.gradle.kts|\
    */requirements*.txt|*/pom.xml|*/build.gradle|*/build.gradle.kts|\
    */.nvmrc|*/.node-version|*/.tool-versions|\
    scripts/probe*|scripts/*contract*.test.*|scripts/*infra*.test.*|\
    scripts/*workflow*.test.*|scripts/*docker*.test.*|scripts/*toolchain*.test.*|\
    tests/*contract*|tests/*infra*|tests/*workflow*|tests/*docker*|\
    yarn.lock|*/yarn.lock|\
    Makefile|*/Makefile|justfile|*/justfile|Taskfile.yml|*/Taskfile.yml|\
    infra/variables.tf|infra/main.tf|infra/*ecs*.tf|infra/*image*.tf|\
    infra/*container*.tf|infra/*deploy*.tf|*/infra/variables.tf|*/infra/main.tf)
      return 0 ;;
  esac
  return 1
}

decode_base64() {
  local encoded="$1" output="$2"
  if printf '%s' "$encoded" | tr -d '\n' | base64 --decode > "$output" 2>/dev/null; then
    return 0
  fi
  printf '%s' "$encoded" | tr -d '\n' | base64 -D > "$output"
}

fetched=0
while IFS= read -r path; do
  is_context_path "$path" || continue
  dest="$snapshot/$path"
  mkdir -p "$(dirname "$dest")"
  content="$(gh api "repos/$repo/contents/$path?ref=$head" --jq '.content // empty' 2>/dev/null || true)"
  if [ -n "$content" ]; then
    decode_base64 "$content" "$dest" || rm -f "$dest"
    [ -f "$dest" ] && fetched=$((fetched + 1))
  fi
done < <(jq -r '.tree[]? | select(.type == "blob") | .path' "$tree_json")

printf '\n%s\n' '---- FINAL NET-DIFF RELEVANT CHANGES ----'
if [ -s "$work/final.diff" ]; then
  relevant_lines "$work/final.diff" || true
else
  echo '(no final diff returned)'
fi
printf '\n%s\n' '---- VERSION MATRIX (FINAL TREE) ----'
printf 'context files fetched: %s\n' "$fetched"
matrix_pattern='FROM[[:space:]]|RUST_TOOLCHAIN|NODE_VERSION|PNPM_VERSION|NPM_VERSION|rust-toolchain|dtolnay/rust-toolchain@|muslrust:|node:[0-9]|node-version[[:space:]]*:|image:[[:space:]]|cargo-chef|sccache|packageManager|rust-version'
matrix_output=""
while IFS= read -r file; do
  rel="${file#"$snapshot/"}"
  case "$rel" in
    *.lock) continue ;;
  esac
  matches="$(grep -InaE "$matrix_pattern" "$file" 2>/dev/null || true)"
  if [ -n "$matches" ]; then
    prefixed_matches="$(awk -v prefix="$rel:" '{print prefix $0}' <<<"$matches")"
    if [ -n "$matrix_output" ]; then
      matrix_output="$matrix_output
$prefixed_matches"
    else
      matrix_output="$prefixed_matches"
    fi
  fi
done < <(find "$snapshot" -type f 2>/dev/null | sort)
if [ -n "$matrix_output" ]; then
  printf '%s\n' "$matrix_output" | awk 'NR <= 240'
else
  echo '(no CI/build version references found)'
fi
printf '\n%s\n' '---- PACKAGE ENGINE / MANAGER CONSTRAINTS ----'
engine_output="$(grep -RInaE 'engines|packageManager|rust-version' "$snapshot" 2>/dev/null | head -n 120 || true)"
if [ -n "$engine_output" ]; then
  printf '%s\n' "$engine_output"
else
  echo '(no package engine or manager constraints found)'
fi

# ---------- normalized pin comparisons ----------
first_match() {
  local pattern="$1"
  grep -RhoE "$pattern" "$snapshot" 2>/dev/null | head -n 1 || true
}
all_matches() {
  local pattern="$1"
  grep -RhoE "$pattern" "$snapshot" 2>/dev/null | sort -u | paste -sd, - || true
}
version_from_text() {
  grep -oE '[0-9]+\.[0-9]+\.[0-9]+([.-][[:alnum:]]+)*' <<<"$1" | head -n 1 || true
}
version_core() {
  sed -E 's/^v?([0-9]+\.[0-9]+\.[0-9]+).*$/\1/' <<<"$1"
}
major_minor() {
  cut -d. -f1-2 <<<"$(version_core "$1")"
}

rust_toolchain="$(version_from_text "$(first_match 'channel[[:space:]]*=[[:space:]]*\"[0-9]+\.[0-9]+\.[0-9]+')")"
rust_env="$(version_from_text "$(first_match 'RUST_TOOLCHAIN:[[:space:]]*\"?[0-9]+\.[0-9]+\.[0-9]+')")"
rust_action="$(version_from_text "$(first_match 'dtolnay/rust-toolchain@[0-9]+\.[0-9]+\.[0-9]+')")"
rust_image="$(version_from_text "$(first_match 'clux/muslrust:[0-9]+\.[0-9]+\.[0-9]+')")"
node_ci="$(version_from_text "$(first_match 'NODE_VERSION:[[:space:]]*\"?[0-9]+\.[0-9]+\.[0-9]+')")"
node_images="$(all_matches 'FROM[[:space:]]+node:[0-9]+\.[0-9]+\.[0-9]+[-[:alnum:].]*')"
node_image_first="$(version_from_text "$node_images")"
pnpm_ci="$(version_from_text "$(first_match 'PNPM_VERSION:[[:space:]]*\"?[0-9]+\.[0-9]+\.[0-9]+')")"
npm_image="$(version_from_text "$(first_match 'NPM_VERSION[=:][[:space:]]*[0-9]+\.[0-9]+\.[0-9]+')")"

printf '\n%s\n' '---- NORMALIZED COMPARISONS ----'
printf 'Rust declarations: toolchain=%s ci-env=%s action=%s builder-image=%s\n' \
  "${rust_toolchain:-none}" "${rust_env:-none}" "${rust_action:-none}" "${rust_image:-none}"
printf 'Node declarations: ci-env=%s docker-images=%s\n' \
  "${node_ci:-none}" "${node_images:-none}"
printf 'Package managers: pnpm-ci=%s probe-npm=%s\n' \
  "${pnpm_ci:-none}" "${npm_image:-none}"

severity=0
notes=()
concerns=()
add_note() {
  notes+=("$1")
  if (( severity < 1 )); then severity=1; fi
}
add_concern() {
  concerns+=("$1")
  severity=2
}

compare_pair() {
  local label="$1" left="$2" right="$3"
  [ -n "$left" ] && [ -n "$right" ] || return 0
  local left_core right_core
  left_core="$(version_core "$left")"
  right_core="$(version_core "$right")"
  if [ "$(major_minor "$left")" != "$(major_minor "$right")" ]; then
    add_note "$label differs by major/minor: $left vs $right; verify the distinction is intentional and covered."
  elif [ "$left_core" != "$right_core" ]; then
    add_note "$label differs by patch: $left vs $right; evaluate compiler/runtime patch compatibility rather than requiring exact equality."
  fi
}

compare_pair 'Rust CI/toolchain vs builder image' "${rust_env:-${rust_toolchain:-}}" "$rust_image"
compare_pair 'Node CI vs Docker image' "$node_ci" "$node_image_first"

# If the original Dependabot commit proposed a build-image change that is absent
# from the final diff, keep it visible and demand rationale rather than silently
# dropping it from the audit.
orig_musl_from="$(grep -E '^-FROM[[:space:]]+clux/muslrust:' "$work/original.diff" \
  | sed -E 's/.*clux\/muslrust:([^[:space:]]+).*/\1/' | head -n 1 || true)"
orig_musl_to="$(grep -E '^\+FROM[[:space:]]+clux/muslrust:' "$work/original.diff" \
  | sed -E 's/.*clux\/muslrust:([^[:space:]]+).*/\1/' | head -n 1 || true)"
final_musl="$(grep -RhoE 'clux/muslrust:[^[:space:]]+' "$snapshot" 2>/dev/null | sort -u | head -n 1 | sed -E 's/.*://; s/[),]$//' || true)"

printf '\n%s\n' '---- PROPOSED UPDATES ABSENT FROM FINAL TREE ----'
# General history signal: a relevant build/toolchain line added by the initial
# Dependabot commit is a candidate reverted decision if its new value is not
# present anywhere in the final snapshot. The later human context below supplies
# the required explanation; this is deliberately a candidate, not an automatic
# incompatibility verdict.
original_build_additions="$work/original-build-additions"
awk '
  /^diff --git / { file=$3; sub(/^a\//, "", file) }
  /^\+[+-]?[^+-]/ && $0 ~ /(FROM[[:space:]]|RUST_TOOLCHAIN|NODE_VERSION|PNPM_VERSION|NPM_VERSION|rust-toolchain|muslrust:|node:|image:[[:space:]]|uses:[[:space:]]|cargo-chef|packageManager|rust-version)/ {
    line=substr($0, 2)
    print file "\t" line
  }
' "$work/original.diff" > "$original_build_additions" || true
candidate_count=0
while IFS=$'\t' read -r file added_line; do
  [ -n "$added_line" ] || continue
  ref="$(grep -oE '(clux/muslrust|node|[[:alnum:]._-]+/[[:alnum:]._-]+):[0-9]+\.[0-9]+\.[0-9]+[-._[:alnum:]]*' <<<"$added_line" | head -n 1 || true)"
  [ -n "$ref" ] || continue
  if ! grep -R -Fq "$ref" "$snapshot" 2>/dev/null; then
    printf 'CANDIDATE_REVERTED: %s: +%s (new reference absent from final tree)\n' "$file" "$added_line"
    candidate_count=$((candidate_count + 1))
  fi
done < "$original_build_additions"
if [ "$candidate_count" -eq 0 ]; then
  echo 'No relevant initial build/toolchain reference was absent from the final tree.'
fi

printf '\n%s\n' '---- PROPOSED / REVERTED DEPENDENCY DECISIONS ----'
if [ -n "$orig_musl_from" ] && [ -n "$orig_musl_to" ] && [ "$orig_musl_from" != "$orig_musl_to" ]; then
  printf 'PROPOSED_UPDATE: clux/muslrust %s -> %s in the initial Dependabot commit\n' "$orig_musl_from" "$orig_musl_to"
  printf 'FINAL_VALUE: clux/muslrust %s\n' "${final_musl:-not-found}"
  if [ "$final_musl" = "$orig_musl_from" ] && ! grep -q 'clux/muslrust' "$work/final.diff"; then
    echo 'DECISION_STATUS: proposed update was reverted/absent from the final net diff'
    rationale="$(grep -Ein 'toolchain|version skew|skew|align|compatib|production|builder|ci|revert|keep ' \
      "$work/human-context.txt" "$work/comments.txt" 2>/dev/null | head -n 20 || true)"
    if [ -n "$rationale" ]; then
      echo 'RATIONALE_STATUS: explanatory human rationale found'
      echo "$rationale"
    else
      echo 'RATIONALE_STATUS: no explanatory human rationale found'
      add_concern 'A proposed build-image update disappeared from the final diff without a recorded compatibility rationale.'
    fi
  else
    echo 'DECISION_STATUS: proposed update remains represented or final value differs; audit the resulting image directly'
  fi
else
  echo 'No clux/muslrust proposal detected in the initial Dependabot comparison.'
fi

# ---------- coverage inventory ----------
printf '\n%s\n' '---- EXISTING TEST / CI COVERAGE ----'
test_files="$(find "$snapshot" -type f 2>/dev/null | grep -Ei '(^|/)(test|tests)/|\.(test|spec)\.|_test\.' || true)"
coverage_node=""
coverage_rust=""
coverage_node_ci=""
if [ -n "$test_files" ]; then
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    rel="${file#"$snapshot/"}"
    if grep -Eq 'FROM[[:space:]]+node:|node:[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null; then
      coverage_node="${coverage_node}${coverage_node:+, }$rel"
    fi
    if grep -Eq 'clux/muslrust|rust-toolchain(\.toml)?' "$file" 2>/dev/null; then
      coverage_rust="${coverage_rust}${coverage_rust:+, }$rel"
    fi
    if grep -Eq 'NODE_VERSION' "$file" && grep -Eq 'FROM[[:space:]]+node:' "$file"; then
      coverage_node_ci="${coverage_node_ci}${coverage_node_ci:+, }$rel"
    fi
  done <<<"$test_files"
fi
printf 'Docker Node exact-image contract: %s\n' "${coverage_node:-NOT_FOUND}"
printf 'Docker Rust-builder/toolchain contract: %s\n' "${coverage_rust:-NOT_FOUND}"
printf 'CI Node-to-Docker version cross-check: %s\n' "${coverage_node_ci:-NOT_FOUND}"
if [ -n "$rust_image" ] && [ -z "$coverage_rust" ]; then
  add_note 'A Rust builder image is present but no test/spec contract cross-checks it against the repository toolchain.'
fi
if [ -n "$node_ci" ] && [ -n "$node_image_first" ] && [ -z "$coverage_node_ci" ]; then
  add_note 'CI Node and Docker Node pins coexist without an exact cross-document version contract test.'
fi

printf '\n%s\n' '---- SUITABILITY RESULT ----'
case "$severity" in
  0)
    echo 'SUITABILITY_VERDICT: CLEAR'
    echo 'RECOMMENDATION: no CI/build compatibility signal requiring follow-up was found'
    ;;
  1)
    echo 'SUITABILITY_VERDICT: NOTE'
    echo 'RECOMMENDATION: safe to merge only with the compatibility notes recorded below'
    ;;
  *)
    echo 'SUITABILITY_VERDICT: CONCERN'
    echo 'RECOMMENDATION: hold for human review until the compatibility concern is resolved'
    ;;
esac
if [ "${#notes[@]}" -gt 0 ]; then
  echo 'NOTES:'
  printf '  - %s\n' "${notes[@]}"
fi
if [ "${#concerns[@]}" -gt 0 ]; then
  echo 'CONCERNS:'
  printf '  - %s\n' "${concerns[@]}"
fi
printf '%s\n' '================================================================'
