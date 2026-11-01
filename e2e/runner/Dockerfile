# Agent image for real `rr run` runs (wave 4.2). Build context (assembled by
# e2e/runner/build.sh): rr (static), claude, codex + its helpers — the exact host binaries the
# contract tests pin (docs/research/verified/runner.md). Go is for the sandbox's
# close run (`go test ./...`, offline). Pin the result by digest: rr run --image name@sha256:...
FROM golang:1.27.3-bookworm
COPY rr claude codex codex-code-mode-host codex-exec-server /usr/local/bin/
ENV GOFLAGS=-mod=mod GOTOOLCHAIN=local GOCACHE=/tmp/.cache/go-build GOPATH=/tmp/go
# codex runs commands in a login shell (bash -lc): Debian's /etc/profile resets PATH
# and drops /usr/local/go/bin, so go would be "command not found" (wave 4.2)
RUN ln -s /usr/local/go/bin/go /usr/local/go/bin/gofmt /usr/local/bin/ && \
    rr --version && claude --version && codex --version && bash -lc 'go version'

