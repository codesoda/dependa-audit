#!/usr/bin/env bash
# crate-audit.sh — supply-chain diff between two versions of a Rust crate.
#
# Usage: crate-audit.sh <crate> <from-version> <to-version>
# Example: crate-audit.sh serde_json 1.0.149 1.0.150
#
# Rust's analogue of an npm install hook is build.rs (runs arbitrary code at
# BUILD time) and proc-macro crates (run code at COMPILE time). This script
# surfaces those plus ownership, dependency, and code-level changes.
#
# Requires: curl, jq, tar, diff, grep.
set -uo pipefail

crate="${1:?usage: crate-audit.sh <crate> <from> <to>}"
v1="${2:?usage: crate-audit.sh <crate> <from> <to>}"
v2="${3:?usage: crate-audit.sh <crate> <from> <to>}"
UA="User-Agent: dependa-audit-security-review (https://github.com)"
api() { curl -fsSL -H "$UA" "https://crates.io/api/v1/$1" 2>/dev/null; }

echo "================================================================"
echo "CARGO SUPPLY-CHAIN AUDIT: $crate   $v1 -> $v2"
echo "================================================================"

for v in "$v1" "$v2"; do
  j="$(api "crates/$crate/$v")"
  if [ -z "$j" ] || [ "$(echo "$j" | jq -r '.version.num // "null"')" = "null" ]; then echo "WARNING: version $v not found on crates.io"; continue; fi
  echo "---- $v ----"
  echo "  published:    $(echo "$j" | jq -r '.version.created_at // "?"')"
  echo "  published_by: $(echo "$j" | jq -r '.version.published_by.login // "?(token publish — no user attached)"')"
  echo "  crate_size:   $(echo "$j" | jq -r '.version.crate_size // "?"') bytes"
  echo "  yanked:       $(echo "$j" | jq -r '.version.yanked')"
  echo "  checksum:     $(echo "$j" | jq -r '.version.checksum')"
  echo "  rust_version: $(echo "$j" | jq -r '.version.rust_version // "unspecified"')"
done

echo
echo "---- OWNERS (current crates.io state) ----"
api "crates/$crate/owners" | jq -r '.users[]? | "    "+.login+" ("+(.name // "?")+")"'

echo
echo "---- dependency DIFF ($v1 -> $v2)   [< removed | > added] ----"
deps() { api "crates/$crate/$1/dependencies" | jq -r '.dependencies[]? | select(.kind!="dev") | .crate_id+" "+.req+" ["+.kind+(if .optional then ",optional" else "" end)+"]"' | sort; }
dd="$(diff <(deps "$v1") <(deps "$v2") | grep -E '^[<>]')"
[ -n "$dd" ] && echo "$dd" || echo "  (no non-dev dependency changes)"

# ---- code-level checks ----
work="$(mktemp -d)"; ok=1
for v in "$v1" "$v2"; do
  ( mkdir -p "$work/$v" && cd "$work/$v" \
    && curl -fsSL -H "$UA" "https://crates.io/api/v1/crates/$crate/$v/download" -o c.crate 2>/dev/null \
    && tar xzf c.crate >/dev/null 2>&1 && rm -f c.crate ) || ok=0
done
d1="$work/$v1/$crate-$v1"; d2="$work/$v2/$crate-$v2"

if [ "$ok" = 1 ] && [ -d "$d1" ] && [ -d "$d2" ]; then
  echo
  echo "---- proc-macro? (runs code at COMPILE time) ----"
  for v in "$v1" "$v2"; do
    d="$work/$v/$crate-$v"
    pm="$(grep -isA2 '^\[lib\]' "$d/Cargo.toml" 2>/dev/null | grep -ic 'proc-macro *= *true')"
    [ "$pm" -gt 0 ] && echo "  $v: YES — proc-macro crate" || echo "  $v: no"
  done

  echo
  echo "---- build.rs (runs code at BUILD time — HIGHEST-RISK Rust vector) ----"
  b1="$d1/build.rs"; b2="$d2/build.rs"
  if [ ! -f "$b2" ]; then echo "  no build.rs in $v2 (good — no build script)";
  elif [ ! -f "$b1" ] && [ -f "$b2" ]; then echo "  !! build.rs ADDED in $v2 — REVIEW IN FULL:"; sed 's/^/     /' "$b2" | head -120;
  else
    bd="$(diff "$b1" "$b2" 2>/dev/null)"
    if [ -n "$bd" ]; then echo "  !! build.rs CHANGED — review diff:"; echo "$bd" | sed 's/^/     /' | head -120; else echo "  build.rs present but UNCHANGED"; fi
  fi

  echo
  echo "---- SUSPICIOUS-PATTERN scan over ADDED lines (src/, build.rs) ----"
  hits="$(diff -rN "$d1" "$d2" 2>/dev/null | grep '^>' \
    | grep -nE 'std::process|Command::new|std::net::|TcpStream|reqwest|hyper::Client|ureq::|isahc|include_bytes!|include_str!|std::env::var|env::var\(|\.ssh|\.cargo/credentials|/etc/passwd|/proc/self|base64::decode|from_base64|hex::decode|libc::(exec|fork|system|socket)|asm!|extern *"C"' \
    | grep -vE 'env::var\("(CARGO|OUT_DIR|TARGET|HOST|PROFILE|RUST|NUM_JOBS|OPT_LEVEL|DEBUG|PATH|CARGO_CFG|CARGO_PKG|CARGO_FEATURE)' \
    | head -40)"
  if [ -n "$hits" ]; then echo "$hits"; echo "  ^ TRIAGE: is this the crate's legitimate function (e.g. an HTTP crate using hyper) or NEW/out-of-place behavior?"; else echo "  (no suspicious patterns in added lines)"; fi

  echo
  echo "---- new long string/byte literals (possible embedded payloads) ----"
  # Per-file so we can attribute paths and separate runtime src from test vectors,
  # which are the dominant false positive (hashes/fixtures look like payloads).
  # Threshold 120 chars skips SHA-256 (64) hex test vectors; real payloads are long.
  src_blob=0; test_blob=0
  while IFS= read -r f; do
    rel="${f#"$d2"/}"
    n="$(grep -oE '"[A-Za-z0-9+/=]{120,}"|b"[^"]{120,}"|\[[0-9, ]{200,}\]' "$f" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$n" -eq 0 ] && continue
    if echo "$rel" | grep -qiE 'test|fixture|bench|example'; then test_blob=$((test_blob+n));
    else src_blob=$((src_blob+n)); echo "  !! $n long literal(s) in RUNTIME file: $rel"; fi
  done < <(find "$d2" -type f \( -name '*.rs' \) 2>/dev/null)
  [ "$src_blob" -eq 0 ] && echo "  runtime src: none"
  echo "  test/fixture/bench/example literals (low concern, likely hashes/vectors): $test_blob"
  [ "$src_blob" -gt 0 ] && echo "  ^ INSPECT runtime-src blobs: long base64/hex/byte arrays can hide payloads."

  echo
  echo "---- FILE-level changes ----"
  qdiff="$(diff -rq "$d1" "$d2" 2>/dev/null | sed "s#$d1#OLD#g; s#$d2#NEW#g")"
  echo "  only in NEW: $(echo "$qdiff" | grep -c 'Only in NEW')   |   only in OLD: $(echo "$qdiff" | grep -c 'Only in OLD')   |   modified: $(echo "$qdiff" | grep -c '^Files')"
  newexec="$(echo "$qdiff" | grep 'Only in NEW' | grep -iE 'build\.rs|\.sh$|\.py$|/bin/|\.so$|\.dll$|\.dylib$' | head -10)"
  [ -n "$newexec" ] && { echo "  !! ADDED files that may run/contain code:"; echo "$newexec" | sed 's/^/     /'; }
else
  echo
  echo "WARNING: could not download/extract one or both versions — code checks skipped (metadata above still valid)."
fi
rm -rf "$work"
echo
echo "================================================================"
echo "INTERPRETATION GUIDE (Rust)"
echo "  RED FLAGS (escalate): build.rs ADDED or changed to do I/O/network/exec;"
echo "    a crate newly becoming proc-macro; NEW std::process / std::net / http"
echo "    client in a crate with no reason for it; reads of ~/.ssh, ~/.cargo"
echo "    credentials, or non-CARGO env vars; embedded base64/byte-array blobs;"
echo "    an unexplained publisher/owner change; a token-only publish (no user)."
echo "  WEAK ASSURANCE (note): crates.io has no SLSA provenance; trust rests on"
echo "    owner identity + the source repo. Verify the tag exists upstream."
echo "================================================================"
