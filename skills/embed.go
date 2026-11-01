// Package skills embeds the SKILL.md sources (one per skill, runtime-neutral).
package skills

import "embed"

// FS holds <name>/SKILL.md for every skill.
//
//go:embed */SKILL.md
var FS embed.FS
