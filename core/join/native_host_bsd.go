//go:build !windows && !linux

package main

import "syscall"

func dup2FD(oldfd, newfd int) error {
	return syscall.Dup2(oldfd, newfd)
}
