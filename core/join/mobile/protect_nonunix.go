//go:build !linux && !android && !darwin && !ios

package mobile

import "net"

func newProtectedDialer(_ func(fd int) error) *net.Dialer {
	return &net.Dialer{}
}
