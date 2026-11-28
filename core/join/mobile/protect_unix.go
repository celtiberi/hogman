//go:build linux || android || darwin || ios

package mobile

import (
	"net"
	"syscall"
)

func protectedDialerControl(protect func(fd int) error) func(network, address string, c syscall.RawConn) error {
	if protect == nil {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var perr error
		if err := c.Control(func(fd uintptr) {
			perr = protect(int(fd))
		}); err != nil {
			return err
		}
		return perr
	}
}

func newProtectedDialer(protect func(fd int) error) *net.Dialer {
	return &net.Dialer{
		Control: protectedDialerControl(protect),
	}
}
