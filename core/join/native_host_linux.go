//go:build linux

package main

import "syscall"

func dup2FD(oldfd, newfd int) error {
	return syscall.Dup3(oldfd, newfd, 0)
}
