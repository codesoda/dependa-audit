#!/usr/bin/env bash
# python-audit.sh — supply-chain diff between two versions of a PyPI package.
#
# Usage: python-audit.sh <package> <from-version> <to-version>
# Example: python-audit.sh requests 2.31.0 2.32.3
#
# Python's analogue of an npm install hook is setup.py: when pip installs from an
# sdist it executes setup.py, so a malicious setup.py runs code on `pip install`.
# PEP 517 build backends / backend-path run code at BUILD time, and a .pth file
# placed in site-packages runs code at every interpreter startup. This script
# surfaces those plus provenance, ownership, dependency, and code-level changes.
#
# Provenance uses PyPI's PEP 740 Integrity API (200 = attested, 404 = none). The
# public JSON API does NOT expose the per-version uploader identity, so PEP 740
# attestations — which bind a release to a source repo/workflow — are the strongest
# publisher signal available. Treat their ABSENCE as weak assurance, not a block.
#
# Bounded, structured output for a Sonnet subagent (no raw source dumps).
# Requires: curl, jq, tar, diff, grep.
set -uo pipefail

pkg="${1:?usage: python-audit.sh <package> <from> <to>}"
v1="${2:?usage: python-audit.sh <package> <from> <to>}"
v2="${3:?usage: python-audit.sh <package> <from> <to>}"

# PEP 503 normalized project name for the Integrity API path.
norm="$(printf '%s' "$pkg" | tr '[:upper:]' '[:lower:]' | sed -E 's/[-_.]+/-/g')"
UA="User-Agent: dependa-audit-security-review (https://github.com)"
work="$(mktemp -d)"

echo "================================================================"
echo "PYPI SUPPLY-CHAIN AUDIT: $pkg   $v1 -> $v2"
echo "================================================================"

# bash 3.2 (macOS default) has no associative arrays — stash per-version JSON and
# the sdist URL in temp files under $work, keyed by the (filename-safe) version.
J=""; jqj() { printf '%s' "$J" | jq -r "$1" 2>/dev/null; }
for v in "$v1" "$v2"; do
  j="$(curl -fsSL -H "$UA" "https://pypi.org/pypi/$pkg/$v/json" 2>/dev/null)"
  if [ -z "$j" ] || [ "$(printf '%s' "$j" | jq -r '.info.version // "null"' 2>/dev/null)" = "null" ]; then
    echo "---- $v ----"; echo "  WARNING: version not found on PyPI"; continue
  fi
  J="$j"; printf '%s' "$j" > "$work/$v.json"
  sdist_fn="$(jqj '([.urls[]|select(.packagetype=="sdist")][0].filename) // empty')"
  jqj '([.urls[]|select(.packagetype=="sdist")][0].url) // empty' > "$work/$v.url"
  pfile="${sdist_fn:-$(jqj '.urls[0].filename // empty')}"

  # provenance via PEP 740 Integrity API (on the sdist, else any file)
  prov="n/a (no files)"
  if [ -n "$pfile" ]; then
    code="$(curl -fsS -o "$work/prov.json" -w '%{http_code}' -H 'Accept: application/vnd.pypi.integrity.v1+json' \
            "https://pypi.org/integrity/$norm/$v/$pfile/provenance" 2>/dev/null)"
    case "$code" in
      200) who="$(jq -r '[.attestation_bundles[].publisher | "\(.kind):\(.repository // "?")" + (if (.workflow // "")!="" then " ("+.workflow+")" else "" end)] | unique | join(", ")' "$work/prov.json" 2>/dev/null)"
           prov="PEP740 attested -> ${who:-unknown publisher}";;
      404) prov="none (no attestations)";;
      *)   prov="unknown (integrity HTTP $code)";;
    esac
  fi

  auth="$(jqj '[.info.author,.info.author_email]|map(select(.!=null and .!=""))|join(" ")')"; [ -z "$auth" ] && auth="(none)"
  maint="$(jqj '[.info.maintainer,.info.maintainer_email]|map(select(.!=null and .!=""))|join(" ")')"; [ -z "$maint" ] && maint="(none listed)"

  echo "---- $v ----"
  echo "  published:   $(jqj '([.urls[].upload_time_iso_8601]|min) // "?"')"
  echo "  author:      $auth"
  echo "  maintainer:  $maint"
  echo "  provenance:  $prov"
  echo "  sdist:       ${sdist_fn:-<none — wheel-only release; code checks limited>}"
  echo "  sha256:      $(jqj '(([.urls[]|select(.packagetype=="sdist")][0].digests.sha256) // .urls[0].digests.sha256) // "?"')"
  echo "  requires_py: $(jqj '.info.requires_python // "unspecified"')"
  echo "  artifacts:   $(jqj '[.urls[].packagetype]|group_by(.)|map("\(length)× \(.[0])")|join(", ")')"
  echo "  yanked:      $(jqj 'if ([.urls[]|select(.yanked)]|length)>0 then "YES" else "no" end')"
done

echo
echo "---- dependency DIFF (requires_dist, $v1 -> $v2)   [< removed | > added] ----"
# Normalize away PEP 508 formatting noise (case, spaces, parens, quote style,
# underscores in extras) so only GENUINE dependency changes surface — not a metadata
# re-serialization between two build-tool versions. Same transform on both sides.
deps() { jq -r '(.info.requires_dist // [])[]' "$work/$1.json" 2>/dev/null \
  | tr '[:upper:]' '[:lower:]' | tr -d " ()\"'" | sed 's/_/-/g' | sort; }
dd="$(diff <(deps "$v1") <(deps "$v2") | grep -E '^[<>]')"
[ -n "$dd" ] && { echo "$dd"; echo "  ^ INSPECT any ADDED (>) distribution you don't recognize (especially one with a URL or odd name)."; } || echo "  (no declared-dependency changes)"

# ---- code-level checks (download + extract sdists) ----
ok=1
for v in "$v1" "$v2"; do
  url="$(cat "$work/$v.url" 2>/dev/null)"
  [ -z "$url" ] && { ok=0; continue; }
  ( mkdir -p "$work/$v" && cd "$work/$v" && curl -fsSL -H "$UA" "$url" -o s.tgz 2>/dev/null && tar xzf s.tgz >/dev/null 2>&1 && rm -f s.tgz ) || ok=0
done
d1="$(find "$work/$v1" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"
d2="$(find "$work/$v2" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -1)"

if [ "$ok" = 1 ] && [ -n "$d1" ] && [ -n "$d2" ] && [ -d "$d1" ] && [ -d "$d2" ]; then
  echo
  echo "---- BUILD BACKEND (runs at build time; backend-path = in-tree build code) ----"
  hookline() { local v="$1" d="$2" be bp sp
    be="$(grep -iE '^[[:space:]]*build-backend[[:space:]]*=' "$d/pyproject.toml" 2>/dev/null | head -1 | tr -s ' ')"
    bp="$(grep -iE '^[[:space:]]*backend-path[[:space:]]*=' "$d/pyproject.toml" 2>/dev/null | head -1 | tr -s ' ')"
    [ -f "$d/setup.py" ] && sp="present" || sp="absent"
    echo "  $v: setup.py=$sp | ${be:-build-backend=(legacy/none)}${bp:+ | $bp}"
  }
  hookline "$v1" "$d1"; hookline "$v2" "$d2"

  echo
  echo "---- setup.py (arbitrary code at INSTALL time from an sdist — HIGHEST-RISK Python vector) ----"
  s1="$d1/setup.py"; s2="$d2/setup.py"
  if [ ! -f "$s2" ]; then echo "  no setup.py in $v2 (fully declarative build — good)";
  elif [ ! -f "$s1" ]; then echo "  !! setup.py ADDED in $v2 — REVIEW IN FULL:"; sed 's/^/     /' "$s2" | head -120;
  else
    sd="$(diff "$s1" "$s2" 2>/dev/null)"
    [ -n "$sd" ] && { echo "  !! setup.py CHANGED — review diff:"; echo "$sd" | sed 's/^/     /' | head -120; } || echo "  setup.py present but UNCHANGED"
  fi

  echo
  echo "---- pyproject [build-system] DIFF   [< old | > new] ----"
  bs() { awk '/^\[build-system\]/{f=1;next} /^\[/{f=0} f' "$1/pyproject.toml" 2>/dev/null | grep -vE '^[[:space:]]*$'; }
  bd="$(diff <(bs "$d1") <(bs "$d2") | grep -E '^[<>]')"
  [ -n "$bd" ] && { echo "$bd"; echo "  ^ a changed build-backend, new backend-path, or new build requirement can introduce build-time code execution."; } || echo "  (build-system unchanged or absent)"

  echo
  echo "---- NETWORK ENDPOINT diff (hosts/URLs in shipped code)   [< removed | > added] ----"
  urls() { grep -rohE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' "$1" --include='*.py' --include='*.cfg' --include='*.toml' --include='*.txt' 2>/dev/null \
            | grep -ivE 'w3\.org|schema\.org|spdx\.org|github\.com/[^/]+/[^/]+(\.git)?$|pypi\.org|pythonhosted\.org|python\.org|readthedocs|json-schema\.org|mozilla\.org|opensource\.org|sphinx-doc|setuptools|pylint|pytest|127\.0\.0\.1|localhost|0\.0\.0\.0|example\.(com|org)|httpbin\.org' \
            | sort -u; }
  nd="$(diff <(urls "$d1") <(urls "$d2") | grep -E '^[<>]')"
  [ -n "$nd" ] && { echo "$nd"; echo "  ^ INSPECT any ADDED (>) host that is not the package's own documented API/CDN/docs."; } || echo "  (identical endpoint set — no new network destinations)"

  echo
  echo "---- FILE-level changes ----"
  qdiff="$(diff -rq "$d1" "$d2" 2>/dev/null | sed "s#$d1#OLD#g; s#$d2#NEW#g")"
  echo "  only in NEW: $(echo "$qdiff" | grep -c 'Only in NEW')   |   only in OLD: $(echo "$qdiff" | grep -c 'Only in OLD')   |   modified: $(echo "$qdiff" | grep -c '^Files')"
  added_exec="$(echo "$qdiff" | grep 'Only in NEW' | grep -iE 'setup\.py|setup\.cfg|\.pth([^a-z]|$)|\.(so|pyd|dll|dylib)([^a-z]|$)|conftest\.py|(^|[/_])build\.py|hatch_build\.py|\.sh([^a-z]|$)' | head -15)"
  [ -n "$added_exec" ] && { echo "  !! ADDED files that may run/contain code (INSPECT):"; echo "$added_exec" | sed 's/^/     /'; }
  echo "  sample of added files:"; echo "$qdiff" | grep 'Only in NEW' | head -8 | sed 's/^/     /'

  echo
  echo "---- CODE-SIZE change ----"
  s1k=$(du -sk "$d1" 2>/dev/null | cut -f1); s2k=$(du -sk "$d2" 2>/dev/null | cut -f1)
  echo "  $v1: ${s1k:-?}KB   ->   $v2: ${s2k:-?}KB   (delta: $(( ${s2k:-0} - ${s1k:-0} ))KB)"

  echo
  echo "---- SUSPICIOUS-PATTERN scan over ADDED lines (false positives filtered) ----"
  # Scan only real code: lockfiles and packaging metadata (uv.lock, PKG-INFO,
  # METADATA, *.egg-info) just restate dependency URLs/hashes we parse elsewhere.
  hits="$(diff -rN -x '*.lock' -x 'PKG-INFO' -x 'METADATA' -x '*.egg-info' -x '*.dist-info' "$d1" "$d2" 2>/dev/null | grep '^>' \
    | grep -niE 'subprocess|os\.system|os\.popen|pty\.spawn|commands\.getstatusoutput|\beval\(|\bexec\(|\bcompile\(|__import__\(|marshal\.loads|pickle\.loads|base64\.b(64|85|16|32)?decode|codecs\.decode|\bfromhex\(|\bsocket\.(socket|create_connection)|urllib\.request|\burlopen\(|http\.client|httpx\.|requests\.(get|post|put)|ftplib|smtplib|\bctypes\b|\bcffi\b|os\.environ|getenv|\.pth([^a-z]|$)|/etc/passwd|\.ssh/|\.aws/|\.netrc|\.pypirc|id_rsa|os\.fork|mmap\.mmap' \
    | grep -vE 'os\.environ(\.get)?[\(\[]["'"'"'](PATH|HOME|PWD|USER|USERNAME|LANG|LC_|TERM|SHELL|PYTHON|VIRTUAL_ENV|CONDA|CI|TZ|TMPDIR|TEMP|HOSTNAME|COLUMNS|LINES|PYTEST|TOX|SOURCE_DATE_EPOCH|SETUPTOOLS|PIP_|DEBUG|NO_COLOR|FORCE_COLOR)' \
    | grep -vE 'getenv\(["'"'"'](PATH|HOME|PYTHON|VIRTUAL_ENV|CI|TZ|TMPDIR|PYTEST|SOURCE_DATE_EPOCH)' \
    | grep -vE '/(tests?|testing|_test|examples?|docs?|fixtures?|benchmarks?)/' \
    | grep -vE 'def exec_|def eval_|test_exec|\.compile\(|>>>' \
    | head -40)"
  [ -n "$hits" ] && { echo "$hits"; echo "  ^ TRIAGE each: is this the package's legitimate function (e.g. an HTTP client using sockets) or NEW/out-of-place behavior — especially anything network/exec inside setup.py or an __init__.py?"; } || echo "  (no suspicious patterns in added lines)"

  echo
  echo "---- new long base64/hex literals in RUNTIME .py (possible embedded payloads) ----"
  # Per-file; separate test/fixture vectors (the dominant false positive) from runtime src.
  src_blob=0; test_blob=0
  while IFS= read -r f; do
    rel="${f#"$d2"/}"
    n="$(grep -oE '[A-Za-z0-9+/]{200,}={0,2}' "$f" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$n" -eq 0 ] && continue
    if echo "$rel" | grep -qiE '/(tests?|testing|fixtures?|examples?|benchmarks?)/|test_|_test\.py'; then test_blob=$((test_blob+n));
    else src_blob=$((src_blob+n)); echo "  !! $n long literal(s) in RUNTIME file: $rel"; fi
  done < <(find "$d2" -type f -name '*.py' 2>/dev/null)
  [ "$src_blob" -eq 0 ] && echo "  runtime src: none"
  echo "  test/fixture/example literals (low concern, likely hashes/vectors): $test_blob"
  [ "$src_blob" -gt 0 ] && echo "  ^ INSPECT runtime-src blobs: long base64/hex runs can hide payloads."

  echo
  echo "---- SECURITY-RELEVANT new string literals (catches obfuscation)   [> added] ----"
  strs() { grep -rhoE '"[^"]{4,512}"|'"'"'[^'"'"']{4,512}'"'"'' "$1" --include='*.py' 2>/dev/null | sort -u; }
  sdiff="$(diff <(strs "$d1") <(strs "$d2") 2>/dev/null | grep '^>' \
    | grep -oE '"[^"]+"|'"'"'[^'"'"']+'"'"'' \
    | grep -iE 'https?://|[0-9]{1,3}(\.[0-9]{1,3}){3}|\b[a-z0-9-]+\.(ru|cn|xyz|top|tk|gq|ml|sh|icu|click|link)\b|webhook|pastebin|ngrok|discord\.com/api|telegram|\.onion|base64,|/tmp/[a-z]' \
    | sort -u | head -30)"
  [ -n "$sdiff" ] && { echo "$sdiff"; echo "  ^ INSPECT any IP, unusual TLD, paste/webhook service, or shell path. Known package endpoints are fine."; } || echo "  (no security-relevant new string literals)"
else
  echo
  echo "WARNING: could not download/extract an sdist for one or both versions — code checks skipped (metadata above still valid)."
  echo "  A wheel-only release ships no sdist; inspect the wheel manually, e.g.: pip download --no-deps --no-binary :all: $pkg==$v2"
fi
rm -rf "$work"
echo
echo "================================================================"
echo "INTERPRETATION GUIDE (Python / PyPI)"
echo "  RED FLAGS (escalate): a setup.py ADDED or changed to do network/exec/env-or-file"
echo "    reads (it runs on \`pip install\` from an sdist); a NEW .pth file (a line starting"
echo "    'import' runs at every interpreter startup); a changed build-backend or new"
echo "    backend-path pointing at in-tree code; NEW subprocess/eval/exec/marshal/pickle/"
echo "    base64-decode in a RUNTIME module; a new network host/IP/unusual-TLD; reads of"
echo "    ~/.ssh, ~/.aws, ~/.pypirc, id_rsa; an unexplained author/maintainer change; a"
echo "    size jump with no changelog basis."
echo "  WEAK ASSURANCE (note, don't block): provenance=none (PyPI doesn't require PEP 740;"
echo "    trust then rests on maintainer identity + the source repo — verify the tag exists"
echo "    upstream); an author/maintainer change EXPLAINED by a public handoff."
echo "  STRONG ASSURANCE: PEP 740 attested via Trusted Publishing where the publisher"
echo "    identity is the EXPECTED source repo/workflow (build is cryptographically tied to"
echo "    that repo). A provenance publisher pointing at an UNEXPECTED repo is itself a flag."
echo "================================================================"
