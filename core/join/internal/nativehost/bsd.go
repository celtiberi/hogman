//go:build !windows && !linux

package nativehost

import "syscall"

func dup2FD(oldfd, newfd int) error {
	return syscall.Dup2(oldfd, newfd)
}
