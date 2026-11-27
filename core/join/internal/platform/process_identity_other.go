//go:build !windows && !linux && !darwin

package platform

func processExePath(int) (string, bool) { return "", false }
