//go:build linux

package nativehost

import "syscall"

func dup2FD(oldfd, newfd int) error {
	return syscall.Dup3(oldfd, newfd, 0)
}
