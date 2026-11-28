//go:build android

package mobile

import "tailscale.com/net/netns"

func registerPlatformProtectFunc(fn func(fd int) error) {
	netns.SetAndroidProtectFunc(fn)
}
