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
)

func main() {
	log.SetFlags(0)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	configureTestCA()
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return
	}
	switch args[0] {
	case "health":
		if err := healthCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	case "derp-map":
		if err := derpMapCmd(); err != nil {
			fmt.Fprintln(os.Stderr, "derp-map:", err)
			os.Exit(1)
		}
		return
	case "gate-cert":
		if err := gateCertCmd(args[1:], logger); err != nil {
			fmt.Fprintln(os.Stderr, "gate-cert:", err)
			os.Exit(1)
		}
		return
	case "serve":
		s := setup()
		defer s.st.Close()
		serve(s, logger)
		return
	}

	s := setup()
	err := cli(context.Background(), s, args)
	_ = s.st.Close()
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			fmt.Fprintln(os.Stderr, "error:", p.Msg)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}
