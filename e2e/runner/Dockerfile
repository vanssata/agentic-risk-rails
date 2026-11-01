# Agent image for real `rr run` runs (wave 4.2). Build context (assembled by
# e2e/runner/build.sh): rr (static), claude, codex — the exact host binaries the
# contract tests pin (docs/research/verified/runner.md). Go is for the sandbox's
# close run (`go test ./...`, offline). Pin the result by digest: rr run --image name@sha256:...
FROM golang:1.27.3-bookworm
COPY rr claude codex /usr/local/bin/
ENV GOFLAGS=-mod=mod GOTOOLCHAIN=local GOCACHE=/tmp/.cache/go-build GOPATH=/tmp/go
RUN rr --version && claude --version && codex --version
