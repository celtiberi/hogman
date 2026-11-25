package main

import "tailscale.com/envknob"

// Hogman never sends logs to Tailscale Inc. The embedded tsnet node uploads
// its internal logs to log.tailscale.com by default; opting out here, before
// any tsnet.Server starts, keeps every log on this machine (keep-less-data,
// and our privacy policy names no such recipient). With this set, tailscale's
// log transport is a no-op that never dials out.
func init() { envknob.SetNoLogsNoSupport() }
