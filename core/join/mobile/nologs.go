package mobile

import "tailscale.com/envknob"

// Disable Tailscale logtail uploads at process init, matching desktop nologs.go.
func init() {
	envknob.SetNoLogsNoSupport()
}
