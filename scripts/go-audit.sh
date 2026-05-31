#!/usr/bin/env bash
# go-audit.sh — supply-chain diff between two versions of a Go module.
#
# Usage: go-audit.sh <module-path> <from-version> <to-version>
# Example: go-audit.sh github.com/stretchr/testify v1.8.4 v1.9.0
#
# Go runs no install scripts, so the reachable surface is different from npm/pip:
#   - init() functions run when the consumer IMPORTS the package (program start)
#   - cgo (import "C" + #cgo CFLAGS/LDFLAGS) compiles/links C at BUILD time
#   - //go:generate runs only on an explicit `go generate` (lower risk, still noted)
#   - unsafe / assembly / //go:linkname are low-level escape hatches
#   - a `replace` directive can redirect a dependency to other code
# Integrity comes from the checksum transparency log (sum.golang.org): a module@version
# has one globally-notarised hash, so a tampered/per-victim build is detectable.
#
# Data: proxy.golang.org (.info/.mod/.zip) + sum.golang.org. Bounded output for a
# Sonnet subagent. Requires: curl, jq, unzip (or bsdtar), diff, grep, awk.
set -uo pipefail

mod="${1:?usage: go-audit.sh <module-path> <from> <to>}"
v1="${2:?usage: go-audit.sh <module-path> <from> <to>}"
v2="${3:?usage: go-audit.sh <module-path> <from> <to>}"
UA="User-Agent: dependa-audit-security-review (https://github.com)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# Go module/version path escaping: every uppercase letter -> '!' + lowercase.
esc() { printf '%s' "$1" | awk '{o="";for(i=1;i<=length($0);i++){c=substr($0,i,1);if(c~/[A-Z]/)o=o"!"tolower(c);else o=o c}print o}'; }
emod="$(esc "$mod")"
PROXY="https://proxy.golang.org/$emod/@v"

echo "================================================================"
echo "GO MODULE SUPPLY-CHAIN AUDIT: $mod   $v1 -> $v2"
echo "================================================================"

for v in "$v1" "$v2"; do
  ev="$(esc "$v")"
  info="$(curl -fsSL -H "$UA" "$PROXY/$ev.info" 2>/dev/null)"
  if [ -z "$info" ]; then echo "---- $v ----"; echo "  WARNING: $v not found on the module proxy"; continue; fi
  curl -fsSL -H "$UA" "$PROXY/$ev.mod" -o "$work/$v.mod" 2>/dev/null
  sum="$(curl -fsSL -H "$UA" "https://sum.golang.org/lookup/$emod@$ev" 2>/dev/null)"
  h1="$(printf '%s' "$sum" | awk -v m="$mod" -v vv="$v" '$1==m && $2==vv{print $3}' | head -1)"
  echo "---- $v ----"
  echo "  published:   $(printf '%s' "$info" | jq -r '.Time // "?"')"
  echo "  vcs origin:  $(printf '%s' "$info" | jq -r '(.Origin.URL // "?")+"  ref="+(.Origin.Ref // "?")+"  commit="+((.Origin.Hash // "?")[0:12])')"
  echo "  checksum db: $([ -n "$h1" ] && echo "present in transparency log ($h1)" || echo "NOT FOUND in sum.golang.org — unusual; verify the module isn't GONOSUMCHECK/private")"
  echo "  go directive:$(grep -E '^go [0-9]' "$work/$v.mod" 2>/dev/null | head -1 | sed 's/^go/ /')"
done

# ---- go.mod diff ----
echo
echo "---- go.mod require DIFF ($v1 -> $v2)   [< removed | > added] ----"
godeps() { awk '
  /^require[ \t]*\(/{r=1;next} r&&/^\)/{r=0;next}
  r{print $1" "$2;next}
  /^require[ \t]+[^(]/{print $2" "$3}' "$1" 2>/dev/null | sort -u; }
if [ -f "$work/$v1.mod" ] && [ -f "$work/$v2.mod" ]; then
  dd="$(diff <(godeps "$work/$v1.mod") <(godeps "$work/$v2.mod") | grep -E '^[<>]')"
  [ -n "$dd" ] && { echo "$dd"; echo "  ^ INSPECT any ADDED (>) module you don't recognise (a new direct/indirect dependency)."; } || echo "  (no require changes)"
  echo
  echo "---- replace / exclude directives in $v2 (a replace can REDIRECT a dependency's code) ----"
  re="$(grep -nE '^[ \t]*(replace|exclude)[ \t]' "$work/$v2.mod" 2>/dev/null; awk '/^(replace|exclude)[ \t]*\(/{p=1} p{print} /^\)/{p=0}' "$work/$v2.mod" 2>/dev/null | grep -E '=>|[ \t]v[0-9]')"
  re="$(printf '%s\n' "$re" | grep -vE '^[[:space:]]*$' | sort -u)"
  [ -n "$re" ] && { echo "$re" | sed 's/^/  /'; echo "  ^ a replace (=> fork/local path) or exclude is worth a look — it only binds in a main module, but it signals intent."; } || echo "  (none)"
else
  echo "  (could not fetch go.mod for one or both versions)"
fi

# ---- download + extract module zips ----
getzip() { # <version> <escaped-version>
  curl -fsSL -H "$UA" "$PROXY/$2.zip" -o "$work/$1.zip" 2>/dev/null || return 1
  mkdir -p "$work/src/$1"
  if command -v unzip >/dev/null 2>&1; then unzip -q -o "$work/$1.zip" -d "$work/src/$1" >/dev/null 2>&1
  else ( cd "$work/src/$1" && tar -xf "$work/$1.zip" ) >/dev/null 2>&1; fi
}
ok=1
getzip "$v1" "$(esc "$v1")" || ok=0
getzip "$v2" "$(esc "$v2")" || ok=0
d1="$(find "$work/src/$v1" -type d -name "*@$v1" 2>/dev/null | head -1)"
d2="$(find "$work/src/$v2" -type d -name "*@$v2" 2>/dev/null | head -1)"

if [ "$ok" = 1 ] && [ -n "$d1" ] && [ -n "$d2" ] && [ -d "$d1" ] && [ -d "$d2" ]; then
  # exclude tests/testdata/vendor from the code diffs (run in the module's own CI, not yours)
  DX=( -x '*_test.go' -x 'testdata' -x 'vendor' )

  echo
  echo "---- BUILD / RUNTIME HOOKS (Go has no install scripts — these are the reachable surfaces) ----"
  hooks() { # <label> <dir>
    local d="$2"
    echo "  $1:"
    echo "    cgo (import \"C\" / #cgo, C compiled at build): $(grep -rlE '^[[:space:]]*import[[:space:]]+"C"|^//[[:space:]]*#cgo' "$d" --include='*.go' 2>/dev/null | grep -v '_test.go' | wc -l | tr -d ' ') file(s)"
    echo "    init() functions (run on import):              $(grep -rhE '^func init\(\)' "$d" --include='*.go' 2>/dev/null | wc -l | tr -d ' ')"
    echo "    //go:generate directives:                      $(grep -rhE '//go:generate' "$d" --include='*.go' 2>/dev/null | grep -vc '_test')"
    echo "    //go:linkname (reach into other packages):     $(grep -rhE '//go:linkname' "$d" --include='*.go' 2>/dev/null | wc -l | tr -d ' ')"
    echo "    assembly (.s) files:                           $(find "$d" -name '*.s' 2>/dev/null | wc -l | tr -d ' ')"
    echo "    unsafe import:                                 $(grep -rlE '^[[:space:]]*"unsafe"|[[:space:]]"unsafe"' "$d" --include='*.go' 2>/dev/null | grep -vc '_test.go')"
  }
  hooks "$v1" "$d1"; hooks "$v2" "$d2"
  echo "  ADDED hook lines ($v1 -> $v2):"
  ah="$(diff -rN "${DX[@]}" "$d1" "$d2" 2>/dev/null | grep '^>' | grep -E '#cgo|import "C"|//go:generate|//go:linkname|^>func init\(\)' | head -20)"
  [ -n "$ah" ] && echo "$ah" | sed 's/^/    /' || echo "    (no new cgo / go:generate / linkname / init lines)"

  echo
  echo "---- NETWORK ENDPOINT diff (hosts/URLs in shipped .go)   [< removed | > added] ----"
  urls() { grep -rohE 'https?://[a-zA-Z0-9._~:/?#@!$&()*+,;=%-]+' "$1" --include='*.go' 2>/dev/null \
            | grep -ivE 'golang\.org|go\.dev|pkg\.go\.dev|github\.com/[^/]+/[^/]+(\.git)?$|w3\.org|json-schema|google\.golang\.org|gopkg\.in|opensource\.org' \
            | sort -u; }
  nd="$(diff <(urls "$d1") <(urls "$d2") | grep -E '^[<>]')"
  [ -n "$nd" ] && { echo "$nd"; echo "  ^ INSPECT any ADDED (>) host that isn't the module's own repo/docs/API."; } || echo "  (identical endpoint set — no new network destinations)"

  echo
  echo "---- FILE-level changes ----"
  qdiff="$(diff -rq "${DX[@]}" "$d1" "$d2" 2>/dev/null | sed "s#$d1#OLD#g; s#$d2#NEW#g")"
  echo "  only in NEW: $(echo "$qdiff" | grep -c 'Only in NEW')   |   only in OLD: $(echo "$qdiff" | grep -c 'Only in OLD')   |   modified: $(echo "$qdiff" | grep -c '^Files')"
  addc="$(echo "$qdiff" | grep 'Only in NEW' | grep -iE '\.(s|c|h|cpp|cc)$|\.go$' | head -15)"
  newexec="$(echo "$addc" | grep -iE '\.(s|c|h|cpp|cc)$')"
  [ -n "$newexec" ] && { echo "  !! ADDED native (asm/C) files — compiled into the binary, INSPECT:"; echo "$newexec" | sed 's/^/     /'; }
  echo "  sample of added files:"; echo "$qdiff" | grep 'Only in NEW' | head -8 | sed 's/^/     /'

  echo
  echo "---- CODE-SIZE change (.go + native) ----"
  s1=$(du -sk "$d1" 2>/dev/null | cut -f1); s2=$(du -sk "$d2" 2>/dev/null | cut -f1)
  echo "  $v1: ${s1:-?}KB   ->   $v2: ${s2:-?}KB   (delta: $(( ${s2:-0} - ${s1:-0} ))KB)"

  echo
  echo "---- SUSPICIOUS-PATTERN scan over ADDED lines (tests excluded, false positives filtered) ----"
  hits="$(diff -rN "${DX[@]}" "$d1" "$d2" 2>/dev/null | grep '^>' \
    | grep -niE 'os/exec|exec\.Command(Context)?|\bsyscall\.[A-Z]|net\.Dial|net\.Listen|http\.(Get|Post|Do|NewRequest)|\.Getenv\(|os\.UserHomeDir|os\.ReadFile|ioutil\.ReadFile|encoding/base64|base64\.(Std|URL|Raw)|plugin\.Open|unsafe\.Pointer|//go:linkname|#cgo (C|LD)FLAGS|import "C"|/etc/passwd|\.ssh/|\.netrc|\.aws/cred|reflect\.NewAt' \
    | grep -vE '\.Getenv\(["'"'"'](GO[A-Z]*|HOME|PATH|PWD|USER|TMPDIR|TEMP|XDG_|HTTP_PROXY|HTTPS_PROXY|NO_PROXY|TERM|LANG|LC_|CI|HOSTNAME|SHELL|SOURCE_DATE_EPOCH)' \
    | head -40)"
  [ -n "$hits" ] && { echo "$hits"; echo "  ^ TRIAGE each: is this the module's legitimate job (an HTTP client using net/http, a crypto lib using cgo) or NEW/out-of-place behaviour — especially exec/network/secret reads inside an init() or a new cgo block?"; } || echo "  (no suspicious patterns in added lines)"

  echo
  echo "---- new long base64/hex literals in non-test .go (possible embedded payloads) ----"
  src_blob=0
  while IFS= read -r f; do
    n="$(grep -oE '[A-Za-z0-9+/]{200,}={0,2}|\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){40,}' "$f" 2>/dev/null | wc -l | tr -d ' ')"
    [ "$n" -eq 0 ] && continue
    src_blob=$((src_blob+n)); echo "  !! $n long literal(s) in: ${f#"$d2"/}"
  done < <(find "$d2" -type f -name '*.go' ! -name '*_test.go' 2>/dev/null)
  [ "$src_blob" -eq 0 ] && echo "  (none)" || echo "  ^ INSPECT: long base64/hex/byte runs in runtime code can hide payloads."
else
  echo
  echo "WARNING: could not download/extract the module zip for one or both versions — code checks skipped (metadata above still valid)."
fi

echo
echo "================================================================"
echo "INTERPRETATION GUIDE (Go modules)"
echo "  RED FLAGS (escalate): a NEW init() / cgo block / #cgo LDFLAGS doing network/exec/file I/O (init runs on"
echo "    import; cgo runs the C toolchain at build); a new external network host/IP/unusual-TLD; reads of"
echo "    ~/.ssh, ~/.netrc, ~/.aws, /etc/passwd; a new \`replace\` pointing at a fork; embedded base64/hex blobs"
echo "    in runtime code; a module NOT present in the checksum transparency log; a changed VCS origin URL."
echo "  EXPECTED: net/http inside an HTTP library; cgo in a crypto/DB driver; //go:generate that only runs on"
echo "    explicit \`go generate\`; indirect-dependency bumps; a higher \`go\` directive."
echo "  ASSURANCE: presence in sum.golang.org means the version's hash is globally notarised (tamper-evident)."
echo "    The .info Origin ties the version to a VCS tag+commit — confirm that tag exists upstream."
echo "================================================================"
