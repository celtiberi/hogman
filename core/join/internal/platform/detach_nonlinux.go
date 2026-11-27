//go:build !windows && !linux

package platform

func isZombiePID(int) bool { return false }
