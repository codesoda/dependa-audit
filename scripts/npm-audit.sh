#!/usr/bin/env bash
# npm-audit.sh — supply-chain diff between two versions of an npm package.
#
# Usage: npm-audit.sh <package> <from-version> <to-version>
# Example: npm-audit.sh @statsig/client-core 3.33.0 3.33.1
#
# Prints a bounded, structured report covering the highest-signal supply-chain
# checks for an npm version bump:
#   - publisher identity + npm provenance (SLSA attestation) for each version
#   - install lifecycle hooks (preinstall/install/postinstall) — the #1 vector
#   - dependency additions/changes
#   - maintainer list
#   - network endpoint (URL/host) set diff — new exfiltration destinations
#   - suspicious-pattern scan over ADDED code (filtered for known false positives)
#   - security-relevant string-literal diff (works on minified single-line bundles)
#   - file-count + line-count change summary
#
# Designed to be read by a Sonnet subagent. Output is bounded (no raw bundle dumps).
# Requires: curl, jq, npm, tar, diff, grep.
set -uo pipefail

pkg="${1:?usage: npm-audit.sh <package> <from> <to>}"
v1="${2:?usage: npm-audit.sh <package> <from> <to>}"
v2="${3:?usage: npm-audit.sh <package> <from> <to>}"

enc="${pkg/@/%40}"; enc="${enc//\//%2F}"
doc="$(curl -fsSL "https://registry.npmjs.org/${enc}" 2>/dev/null)" || { echo "ERROR: cannot fetch registry doc for $pkg"; exit 1; }

jqv() { echo "$doc" | jq -r --arg v "$1" "$2"; }

echo "================================================================"
echo "NPM SUPPLY-CHAIN AUDIT: $pkg   $v1 -> $v2"
echo "================================================================"

for v in "$v1" "$v2"; do
  exists="$(jqv "$v" '.versions[$v] // empty | "yes"')"
  if [ -z "$exists" ]; then echo "WARNING: version $v not found in registry"; continue; fi
  echo "---- $v ----"
  echo "  published:   $(jqv "$v" '.time[$v] // "?"')"
  echo "  npm user:    $(jqv "$v" '"\(.versions[$v]._npmUser.name // "?") <\(.versions[$v]._npmUser.email // "?")>"')"
  echo "  provenance:  $(jqv "$v" '.versions[$v].dist.attestations.provenance.predicateType // "NONE"')"
  echo "  signatures:  $(jqv "$v" 'if (.versions[$v].dist.signatures|length) > 0 then "present" else "none" end')"
  echo "  integrity:   $(jqv "$v" '.versions[$v].dist.integrity // "?"')"
  echo "  unpacked:    $(jqv "$v" '.versions[$v].dist.unpackedSize // "?"') bytes"
done

echo
echo "---- INSTALL LIFECYCLE HOOKS (preinstall/install/postinstall/prepare) ----"
for v in "$v1" "$v2"; do
  hooks="$(jqv "$v" '.versions[$v].scripts // {} | to_entries[] | select(.key|test("^(pre|post)?install$|^prepare$|^prepublish")) | "    "+.key+": "+.value')"
  echo "  $v: ${hooks:-(none)}"
done

# diffblock prints captured diff lines (or a "none" message). Avoids the pipefail
# trap where `diff` exits 1 on differences and falsely triggers `|| echo`.
diffblock() { local out; out="$(diff <(printf '%s\n' "$1") <(printf '%s\n' "$2") | grep -E '^[<>]')"; [ -n "$out" ] && echo "$out" || echo "  $3"; }

echo
echo "---- FULL scripts DIFF ($v1 -> $v2) ----"
diffblock "$(jqv "$v1" '.versions[$v].scripts // {} | to_entries[] | .key+": "+.value' | sort)" \
          "$(jqv "$v2" '.versions[$v].scripts // {} | to_entries[] | .key+": "+.value' | sort)" \
          "(no script changes)"

echo
echo "---- dependency DIFF ($v1 -> $v2)   [< removed | > added] ----"
diffblock "$(jqv "$v1" '.versions[$v].dependencies // {} | to_entries[] | .key+" "+.value' | sort)" \
          "$(jqv "$v2" '.versions[$v].dependencies // {} | to_entries[] | .key+" "+.value' | sort)" \
          "(no dependency changes)"

echo
echo "---- maintainers (current registry state) ----"
jqv "_" '.maintainers[]? | "    "+.name+" <"+(.email // "?")+">"'

# ---- tarball-level checks ----
work="$(mktemp -d)"; ok=1
for v in "$v1" "$v2"; do
  ( mkdir -p "$work/$v" && cd "$work/$v" && npm pack "${pkg}@${v}" --silent >/dev/null 2>&1 && tar xzf ./*.tgz >/dev/null 2>&1 && rm -f ./*.tgz ) || ok=0
done

if [ "$ok" = 1 ] && [ -d "$work/$v1/package" ] && [ -d "$work/$v2/package" ]; then
  echo
  echo "---- NETWORK ENDPOINT diff (hosts/URLs in shipped code)   [< removed | > added] ----"
  urls() { grep -rohE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' "$1/package" 2>/dev/null \
            | grep -ivE 'w3\.org|schema\.org|spdx\.org|github\.com/[^/]+/[^/]+(\.git)?$|npmjs|jsdelivr|unpkg|json-schema\.org|json\.schemastore|googleapis\.com/.*fonts|mozilla\.org|opensource\.org' \
            | sort -u; }
  d="$(diff <(urls "$work/$v1") <(urls "$work/$v2") | grep -E '^[<>]')"
  if [ -n "$d" ]; then echo "$d"; echo "  ^ INSPECT any ADDED (>) host that is not the package's own documented API/CDN."; else echo "  (identical endpoint set — no new network destinations)"; fi

  echo
  echo "---- FILE-level changes ----"
  qdiff="$(diff -rq "$work/$v1/package" "$work/$v2/package" 2>/dev/null | sed "s#$work/$v1/package#OLD#g; s#$work/$v2/package#NEW#g")"
  only_new="$(echo "$qdiff" | grep -c 'Only in NEW')"
  only_old="$(echo "$qdiff" | grep -c 'Only in OLD')"
  modified="$(echo "$qdiff" | grep -c '^Files')"
  echo "  files only in NEW version: $only_new   |   only in OLD: $only_old   |   modified: $modified"
  # Flag any ADDED file whose name/extension suggests executable or install-time code.
  added_exec="$(echo "$qdiff" | grep 'Only in NEW' | grep -iE '\.(sh|bash|cmd|ps1|py|rb|exe|bin|node|wasm)([^a-z]|$)|postinstall|preinstall|\.gyp|binding|install\.js' | head -15)"
  if [ -n "$added_exec" ]; then echo "  !! ADDED files that may run code (INSPECT):"; echo "$added_exec" | sed 's/^/     /'; fi
  echo "  sample of added files:"; echo "$qdiff" | grep 'Only in NEW' | head -8 | sed 's/^/     /'

  echo
  echo "---- CODE-SIZE change ----"
  s1=$(du -sk "$work/$v1/package" 2>/dev/null | cut -f1); s2=$(du -sk "$work/$v2/package" 2>/dev/null | cut -f1)
  echo "  $v1: ${s1}KB   ->   $v2: ${s2}KB   (delta: $((s2 - s1))KB)"

  echo
  echo "---- SUSPICIOUS-PATTERN scan over ADDED lines (false positives filtered) ----"
  # Note: single-line minified bundles make line-diff noisy; the endpoint diff and
  # string-literal diff below are the reliable signals for those. This catches
  # readable-source injections.
  hits="$(diff -rN "$work/$v1/package" "$work/$v2/package" 2>/dev/null | grep '^>' \
    | grep -niE 'child_process|execSync|spawnSync|\bspawn\(|require\(["'"'"']https?:|eval\(|new Function\(|atob\(|Buffer\.from\([^,]*,["'"'"']base64|document\.cookie|navigator\.sendBeacon|localStorage\.getItem|os\.homedir|/etc/passwd|\.ssh/|\.npmrc|process\.env\.[A-Z]|crypto\.create(Cipher|Hash).*upload|fromCharCode\(|\bwget\b|\bcurl\b.*http' \
    | grep -vE 'process\.env\.(NODE_ENV|TZ|DEBUG|CI|PATH|HOME|PWD|FORCE_COLOR|NODE_OPTIONS|npm_)' \
    | grep -vE 'function exec\(|RegExp|\.exec\(' \
    | head -40)"
  if [ -n "$hits" ]; then echo "$hits"; echo "  ^ TRIAGE each: confirm it is real injected behavior, not a renamed helper or a library's own feature."; else echo "  (no suspicious patterns in readable added lines)"; fi

  echo
  echo "---- SECURITY-RELEVANT new string literals (catches minified bundles)   [> added] ----"
  strs() { grep -rhoE '"[^"]{4,512}"|'"'"'[^'"'"']{4,512}'"'"'' "$1/package" --include='*.js' --include='*.cjs' --include='*.mjs' 2>/dev/null | sort -u; }
  sdiff="$(diff <(strs "$work/$v1") <(strs "$work/$v2") 2>/dev/null | grep '^>' \
    | grep -oE '"[^"]+"|'"'"'[^'"'"']+'"'"'' \
    | grep -iE 'https?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|\b[a-z0-9-]+\.(ru|cn|xyz|top|tk|gq|ml|sh|icu|click|link)\b|webhook|pastebin|ngrok|discord\.com/api|telegram|\.onion|base64,|child_process|/tmp/[a-z]' \
    | sort -u | head -30)"
  if [ -n "$sdiff" ]; then echo "$sdiff"; echo "  ^ INSPECT any IP, unusual TLD, paste/webhook service, or shell path. Known package endpoints are fine."; else echo "  (no security-relevant new string literals)"; fi
else
  echo
  echo "WARNING: could not pack/extract one or both versions — tarball checks skipped (metadata above still valid)."
fi
rm -rf "$work"
echo
echo "================================================================"
echo "INTERPRETATION GUIDE"
echo "  RED FLAGS (escalate): a NEW install/postinstall hook; a NEW external"
echo "    dependency you don't recognize; a NEW network host/IP/unusual-TLD; an"
echo "    added child_process/eval/env-secret read; an unexplained publisher or"
echo "    maintainer change; a size jump with no changelog basis."
echo "  WEAK ASSURANCE (note, don't block): provenance=NONE; single maintainer;"
echo "    publisher change EXPLAINED by a public acquisition (verify via web)."
echo "  STRONG ASSURANCE: provenance=slsa v1 via GitHub Actions OIDC (build is"
echo "    cryptographically tied to the source repo)."
echo "================================================================"
