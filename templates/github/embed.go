// Package githubtpl embeds the GitHub CODEOWNERS and workflow templates (DES §3.4 step 3).
package githubtpl

import "embed"

// FS holds CODEOWNERS.tmpl, rr-verify.yml.tmpl and rr-policy-check.yml.tmpl.
//
//go:embed *.tmpl
var FS embed.FS
