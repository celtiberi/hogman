//go:build !windows && !linux

package main

func isZombiePID(pid int) bool {
	return false
}
