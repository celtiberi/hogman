// Command registrar is the source of truth for one Hogman network: members,
// invites, devices, names, removal and the audit log. It drives Headscale
// (devices, access policy) and serves authoritative DNS for the network's zone.
//
// The same binary is the server ("registrar serve") and the owner's command
// line on the core node ("registrar member kick alice").
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"

	"hogman/registrar/internal/registrar"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	log.SetFlags(0)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	configureTestCA()
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0
	}
	switch args[0] {
	case "health":
		if err := healthCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			return 1
		}
		return 0
	case "derp-map":
		if err := derpMapCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "derp-map:", err)
			return 1
		}
		return 0
	case "gate-cert":
		if err := gateCertCmd(args[1:], logger); err != nil {
			fmt.Fprintln(os.Stderr, "gate-cert:", err)
			return 1
		}
		return 0
	case "serve":
		s, closeStore := setup()
		defer closeStore()
		serve(s, logger)
		return 0
	}

	s, closeStore := setup()
	defer closeStore()
	if err := cli(context.Background(), s, args); err != nil {
		var de *registrar.Error
		if errors.As(err, &de) {
			fmt.Fprintln(os.Stderr, "error:", de.Msg)
			return 1
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	return 0
}
