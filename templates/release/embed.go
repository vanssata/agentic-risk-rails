// Package releasetpl embeds the release CI workflows (DES §9.1).
package releasetpl

import "embed"

// FS holds one <ecosystem>.yml per release adapter.
//
//go:embed *.yml
var FS embed.FS
