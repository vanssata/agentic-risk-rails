// Package researchtpl embeds the scout brief templates (DES §5.2).
package researchtpl

import "embed"

// FS holds one <role>.tmpl per scout role.
//
//go:embed *.tmpl
var FS embed.FS
