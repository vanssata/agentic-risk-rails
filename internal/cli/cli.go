// Package cli is the command registry. Each module adds its commands from
// cmd/rr/cmd_<module>.go via Register in init(); nobody edits main.go.
package cli

import (
	"runtime/debug"
	"sort"
	"sync"

	"github.com/spf13/cobra"
)

var (
	mu       sync.Mutex
	builders []func() *cobra.Command
)

// Register adds a top-level command builder.
func Register(b func() *cobra.Command) {
	mu.Lock()
	defer mu.Unlock()
	builders = append(builders, b)
}

// Root builds the rr root command with every registered subcommand.
// Without -ldflags (`go install …@v0.4.1`) the version is the module version.
func Root(version string) *cobra.Command {
	if bi, ok := debug.ReadBuildInfo(); ok && version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
	root := &cobra.Command{
		Use:           "rr",
		Short:         "RiskRails: risk engine and enforcement for AI coding agents",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	mu.Lock()
	cmds := make([]*cobra.Command, 0, len(builders))
	for _, b := range builders {
		cmds = append(cmds, b())
	}
	mu.Unlock()
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].Name() < cmds[j].Name() })
	root.AddCommand(cmds...)
	return root
}
