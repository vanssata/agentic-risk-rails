#!/usr/bin/env bash
# Builds the agent image for a real rr run and prints its pinned reference.
# Usage: e2e/runner/build.sh [tag]   (needs claude and codex on PATH)
set -euo pipefail
tag=${1:-rr-agent:local}
here=$(cd "$(dirname "$0")" && pwd)
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT
(cd "$here/../.." && CGO_ENABLED=0 go build -o "$ctx/rr" ./cmd/rr)
cp "$(readlink -f "$(command -v claude)")" "$ctx/claude"
# codex 0.166 spawns its sibling helpers (codex-code-mode-host, codex-exec-server)
# from the same dir; without them every tool call fails closed (wave 4.2)
codex_bin=$(dirname "$(readlink -f "$(command -v codex)")")
cp "$codex_bin"/codex "$codex_bin"/codex-code-mode-host "$codex_bin"/codex-exec-server "$ctx/"
docker build -q -t "$tag" -f "$here/Dockerfile" "$ctx" >/dev/null
echo "${tag%%:*}@$(docker image inspect --format '{{.Id}}' "$tag")"
