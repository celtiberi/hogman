//go:build !windows && !linux && !darwin

package fsutil

func processStartTag(int) string { return "" }
