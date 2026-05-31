#!/usr/bin/env bash
# docker-audit.sh — supply-chain diff between two digests of a Docker Hub image.
#
# Usage: docker-audit.sh <image> <from-digest> <to-digest> [tag]
#   <image>       e.g. clux/muslrust, library/postgres, postgres (official → library/)
#   <from-digest> sha256:... (old, from the PR's "-" line)
#   <to-digest>   sha256:... (new, from the PR's "+" line)
#   [tag]         e.g. stable — if given, verifies the NEW digest is what the
#                 registry currently serves for that tag (the key trust check).
#
# Uses the anonymous Docker Hub registry API (no daemon, no pull). For non-Docker-Hub
# registries (ghcr.io, etc.) this won't apply — fall back to
# `docker buildx imagetools inspect <image>@<digest>` in that case.
#
# Requires: curl, jq.
set -uo pipefail

image="${1:?usage: docker-audit.sh <image> <from-digest> <to-digest> [tag]}"
from="${2:?need from-digest}"
to="${3:?need to-digest}"
tag="${4:-}"
case "$image" in */*) repo="$image";; *) repo="library/$image";; esac

REG="https://registry-1.docker.io/v2/$repo"
# Arrays preserve argument boundaries (the "Bearer <token>" space must stay in one -H arg).
ACC=( -H 'Accept: application/vnd.docker.distribution.manifest.list.v2+json'
      -H 'Accept: application/vnd.oci.image.index.v1+json'
      -H 'Accept: application/vnd.docker.distribution.manifest.v2+json'
      -H 'Accept: application/vnd.oci.image.manifest.v1+json' )
tok="$(curl -fsSL "https://auth.docker.io/token?service=registry.docker.io&scope=repository:$repo:pull" 2>/dev/null | jq -r '.token // empty')"
[ -z "$tok" ] && { echo "ERROR: could not get anonymous pull token for $repo (private image or non-Docker-Hub registry?). Use: docker buildx imagetools inspect $image@$to"; exit 1; }
AUTH=( -H "Authorization: Bearer $tok" )

echo "================================================================"
echo "DOCKER IMAGE AUDIT: $image"
echo "  from: $from"
echo "  to:   $to"
echo "================================================================"

# --- key trust check: does the NEW digest match what the tag currently serves? ---
if [ -n "$tag" ]; then
  cur="$(curl -fsSL "${AUTH[@]}" "${ACC[@]}" -o /dev/null -w '%header{docker-content-digest}' "$REG/manifests/$tag" 2>/dev/null)"
  echo "---- TAG INTEGRITY ----"
  echo "  registry currently serves '$image:$tag' = ${cur:-<unknown>}"
  if [ "$cur" = "$to" ]; then echo "  ✅ NEW digest matches the live '$tag' tag — Dependabot pinned the legit current image.";
  elif [ -n "$cur" ]; then echo "  ⚠️ NEW digest does NOT match live '$tag' ($cur). Could be a newer push since the PR, or an injected digest — verify.";
  else echo "  (could not resolve live tag digest)"; fi
  echo
fi

# Resolve a digest to its linux/amd64 image manifest, then fetch the config blob JSON.
config_for() {
  local dig="$1" mani amd cfgdig
  mani="$(curl -fsSL "${AUTH[@]}" "${ACC[@]}" "$REG/manifests/$dig" 2>/dev/null)"
  if echo "$mani" | jq -e '.manifests' >/dev/null 2>&1; then
    amd="$(echo "$mani" | jq -r '.manifests[] | select(.platform.os=="linux" and .platform.architecture=="amd64") | .digest' | head -1)"
    [ -z "$amd" ] && amd="$(echo "$mani" | jq -r '.manifests[0].digest')"
    mani="$(curl -fsSL "${AUTH[@]}" "${ACC[@]}" "$REG/manifests/$amd" 2>/dev/null)"
  fi
  cfgdig="$(echo "$mani" | jq -r '.config.digest // empty')"
  echo "$mani" | jq -c '{layers:(.layers|length)}' > /tmp/.da_layers_$$ 2>/dev/null
  [ -z "$cfgdig" ] && return 1
  curl -fsSL "${AUTH[@]}" -H "Accept: application/vnd.docker.container.image.v1+json" "$REG/blobs/$cfgdig" 2>/dev/null
}

summarize() { # config-json label
  local j="$1" tag="$2"
  echo "  [$tag]"
  echo "    created:    $(echo "$j" | jq -r '.created // "?"')"
  echo "    os/arch:    $(echo "$j" | jq -r '(.os // "?")+"/"+(.architecture // "?")')"
  echo "    entrypoint: $(echo "$j" | jq -c '.config.Entrypoint // .container_config.Entrypoint // "none"')"
  echo "    cmd:        $(echo "$j" | jq -c '.config.Cmd // "none"')"
  echo "    user:       $(echo "$j" | jq -r '.config.User // "(root/unset)"')"
  echo "    env:        $(echo "$j" | jq -c '.config.Env // []')"
  echo "    source:     $(echo "$j" | jq -r '.config.Labels["org.opencontainers.image.source"] // .config.Labels["org.label-schema.vcs-url"] // "(no source label)"')"
  echo "    layers:     $(cat /tmp/.da_layers_$$ 2>/dev/null | jq -r '.layers // "?"')"
}

cf="$(config_for "$from")"; cfg_from="$cf"; lay_from="$(cat /tmp/.da_layers_$$ 2>/dev/null)"
cf="$(config_for "$to")";   cfg_to="$cf";   lay_to="$(cat /tmp/.da_layers_$$ 2>/dev/null)"

if [ -n "$cfg_from" ] && [ -n "$cfg_to" ]; then
  echo "---- IMAGE CONFIG ----"
  echo "$lay_from" > /tmp/.da_layers_$$; summarize "$cfg_from" "OLD $from"
  echo "$lay_to"   > /tmp/.da_layers_$$; summarize "$cfg_to" "NEW $to"
  echo
  echo "---- CONFIG DIFF (OLD -> NEW)   [< old | > new] ----"
  cdiff="$(diff <(echo "$cfg_from" | jq -S '{Env:.config.Env, Entrypoint:.config.Entrypoint, Cmd:.config.Cmd, User:.config.User, Labels:(.config.Labels|del(.["org.opencontainers.image.created"],.["org.opencontainers.image.revision"]))}') \
                <(echo "$cfg_to"   | jq -S '{Env:.config.Env, Entrypoint:.config.Entrypoint, Cmd:.config.Cmd, User:.config.User, Labels:(.config.Labels|del(.["org.opencontainers.image.created"],.["org.opencontainers.image.revision"]))}') \
            | grep -E '^[<>]' | head -40)"
  [ -n "$cdiff" ] && { echo "$cdiff"; echo "  ^ INSPECT non-timestamp changes to Env/Entrypoint/Cmd/User/Labels."; } || echo "  (Env/Entrypoint/Cmd/User/Labels identical, ignoring build timestamp/revision)"
  echo
  echo "---- LAYER-COMMAND history DIFF (what build steps changed)   [> added in NEW] ----"
  hist() { echo "$1" | jq -r '.history[]?.created_by // empty' | sed 's/#(nop) *//'; }
  ldiff="$(diff <(hist "$cfg_from") <(hist "$cfg_to") | grep -E '^[<>]' | cut -c1-160 | head -40)"
  [ -n "$ldiff" ] && echo "$ldiff" || echo "  (identical build history)"
else
  echo "WARNING: could not fetch image config for one or both digests."
  echo "Fall back to: docker buildx imagetools inspect $image@$to"
fi
rm -f /tmp/.da_layers_$$
echo
echo "================================================================"
echo "INTERPRETATION GUIDE (Docker)"
echo "  RED FLAGS: NEW digest doesn't match the live tag (injected pin); a changed"
echo "    ENTRYPOINT/CMD; User dropping to root; new/altered ENV pointing at"
echo "    unexpected hosts; a base-image MAJOR jump not in the changelog; the"
echo "    source/publisher label changing repos."
echo "  EXPECTED: same tag re-pinned to a newer official build; patch-level base"
echo "    OS/toolchain bumps in the layer history; created-date advancing."
echo "  Trust rests on the registry + publisher — Docker Hub digests carry no SLSA"
echo "    provenance unless the publisher attaches it. Confirm the image's source"
echo "    label points at the expected upstream repo."
echo "================================================================"
