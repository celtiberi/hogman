//go:build darwin || ios

package mobile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

const (
	darwinSysprotoControl = 2
	darwinUtunOptIfname   = 2
)

// darwinUnmonitoredTUN wraps a NetworkExtension-provided utun file descriptor
// without opening an AF_ROUTE raw socket or issuing SIOCSIFMTU ioctls, both of
// which are denied inside the iOS NEPacketTunnelProvider sandbox.
type darwinUnmonitoredTUN struct {
	file      *os.File
	name      string
	mtu       int
	events    chan tun.Event
	closeOnce sync.Once
}

var _ tun.Device = (*darwinUnmonitoredTUN)(nil)

func openTUNFromFD(fd, mtu int) (tun.Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid TUN fd %d", fd)
	}
	rawName, err := unix.GetsockoptString(fd, darwinSysprotoControl, darwinUtunOptIfname)
	if err != nil {
		return nil, fmt.Errorf("resolve utun interface name for fd %d: %w", fd, err)
	}
	name := strings.TrimRight(rawName, "\x00")
	if !isValidDarwinUtunName(name) {
		return nil, fmt.Errorf("fd %d did not resolve to a valid utun interface name", fd)
	}
	return wrapDarwinTUNFD(fd, mtu, name)
}

func isValidDarwinUtunName(name string) bool {
	suffix, ok := strings.CutPrefix(name, "utun")
	if !ok || len(suffix) == 0 || len(suffix) > 6 {
		return false
	}
	for i := 0; i < len(suffix); i++ {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}
	return true
}

func wrapDarwinTUNFD(fd, mtu int, name string) (tun.Device, error) {
	if fd < 0 {
		return nil, fmt.Errorf("invalid TUN fd %d", fd)
	}
	if name == "" {
		return nil, errors.New("utun interface name is required")
	}
	if mtu < MinTunnelMTU || mtu > MaxTunnelMTU {
		mtu = DefaultTunnelMTU
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("set nonblock on utun fd %d: %w", fd, err)
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		return nil, fmt.Errorf("could not wrap utun fd %d", fd)
	}
	events := make(chan tun.Event, 4)
	events <- tun.EventUp
	return &darwinUnmonitoredTUN{
		file:   f,
		name:   name,
		mtu:    mtu,
		events: events,
	}, nil
}

func (d *darwinUnmonitoredTUN) File() *os.File { return d.file }

func (d *darwinUnmonitoredTUN) Name() (string, error) { return d.name, nil }

func (d *darwinUnmonitoredTUN) MTU() (int, error) { return d.mtu, nil }

func (d *darwinUnmonitoredTUN) Events() <-chan tun.Event { return d.events }

func (d *darwinUnmonitoredTUN) BatchSize() int { return 1 }

func (d *darwinUnmonitoredTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	if len(packets) == 0 {
		return 0, errors.New("read packet slice is empty")
	}
	if len(slab) <= 2*tun.ReadPacketSpacing {
		return 0, io.ErrShortBuffer
	}
	buf := slab[tun.ReadPacketSpacing-4 : len(slab)-tun.ReadPacketSpacing]
	n, err := d.file.Read(buf)
	if n < 4 {
		return 0, err
	}
	packets[0].Offset = tun.ReadPacketSpacing
	packets[0].Size = n - 4
	return 1, err
}

func (d *darwinUnmonitoredTUN) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 4 {
		return 0, io.ErrShortBuffer
	}
	for i, buf := range bufs {
		if len(buf) <= offset {
			return i, io.ErrShortBuffer
		}
		frame := buf[offset-4:]
		frame[0] = 0x00
		frame[1] = 0x00
		frame[2] = 0x00
		switch frame[4] >> 4 {
		case 4:
			frame[3] = unix.AF_INET
		case 6:
			frame[3] = unix.AF_INET6
		default:
			return i, unix.EAFNOSUPPORT
		}
		if _, err := d.file.Write(frame); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}

func (d *darwinUnmonitoredTUN) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.file.Close()
		close(d.events)
	})
	return err
}
