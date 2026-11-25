//go:build !ts_omit_peerapiserver

package main

// Registrar embeds tsnet and must always be built with -tags ts_omit_peerapiserver
// (I-27) so tsnet never opens a PeerAPI TCP listener or bypasses the packet filter.
var _ = registrarMustBuildWith_ts_omit_peerapiserver
