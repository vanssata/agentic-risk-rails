// Package precommit embeds the pre-commit hook script generated into
// .githooks/pre-commit by the degrade generator.
package precommit

import _ "embed"

// Script is the pre-commit hook: it runs `rr guard --staged`.
//
//go:embed pre-commit
var Script []byte
