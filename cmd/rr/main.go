// Command rr is the RiskRails CLI. Subcommands live in cmd_<module>.go files
// and register themselves through internal/cli; do not add them here.
package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/vanssata/agentic-risk-rails/internal/cli"
)

var version = "dev" // set by -ldflags "-X main.version=…"

// ExitError lets a command choose its process exit code (hooks need exit 2).
type ExitError struct{ Code int }

func (e ExitError) Error() string { return fmt.Sprintf("exit %d", e.Code) }

func main() {
	if err := cli.Root(version).Execute(); err != nil {
		var ee ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		fmt.Fprintln(os.Stderr, "rr:", err)
		os.Exit(1)
	}
}
