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
cp "$(readlink -f "$(command -v codex)")" "$ctx/codex"
docker build -q -t "$tag" -f "$here/Dockerfile" "$ctx" >/dev/null
echo "${tag%%:*}@$(docker image inspect --format '{{.Id}}' "$tag")"
