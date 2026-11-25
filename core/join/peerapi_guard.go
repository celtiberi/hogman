//go:build !ts_omit_peerapiserver

package main

// Hogman must always be built with -tags ts_omit_peerapiserver (I-27) so
// embedded tsnet never opens a PeerAPI TCP listener on host interfaces or
// bypasses the WireGuard packet filter.
var _ = hogmanMustBuildWith_ts_omit_peerapiserver
