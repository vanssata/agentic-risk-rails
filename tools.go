//go:build tools

// Package tools pins the frozen wave-0 dependencies so `go mod tidy` keeps
// them before any module imports them. Adding a dependency is an orchestrator
// change between waves (docs/plan/implementation-plan.md §1.1).
package tools

import (
	_ "github.com/bmatcuk/doublestar/v4"
	_ "github.com/google/go-github/v93/github"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "github.com/pelletier/go-toml/v2"
	_ "mvdan.cc/sh/v3/syntax"
)
