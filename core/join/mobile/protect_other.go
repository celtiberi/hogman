//go:build !android

package mobile

func registerPlatformProtectFunc(_ func(fd int) error) {}
