package mobile

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/tailscale/wireguard-go/tun"
)

// SwappableTUN implements wireguard-go's tun.Device so wgengine can start and
// authenticate with Headscale before the OS creates a TUN interface, and swap
// to a new OS TUN descriptor whenever routes change (e.g. Android VpnService
// rebuild on netmap peer updates).
type SwappableTUN struct {
	mu      sync.Mutex
	cur     tun.Device
	mtu     int
	name    string
	closed  bool
	changed chan struct{}
	events  chan tun.Event
}

var _ tun.Device = (*SwappableTUN)(nil)

func NewSwappableTUN(mtu int) *SwappableTUN {
	if mtu < MinTunnelMTU || mtu > MaxTunnelMTU {
		mtu = DefaultTunnelMTU
	}
	s := &SwappableTUN{
		mtu:     mtu,
		name:    "hogman0",
		changed: make(chan struct{}),
		events:  make(chan tun.Event, 4),
	}
	s.events <- tun.EventUp
	return s
}

// Attach swaps the underlying OS tun.Device, waking any blocked Read and
// closing the previous device after swapping.
func (s *SwappableTUN) Attach(dev tun.Device) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		if dev != nil {
			_ = dev.Close()
		}
		return os.ErrClosed
	}
	old := s.cur
	s.cur = dev
	if dev != nil {
		if m, err := dev.MTU(); err == nil && m > 0 {
			s.mtu = m
		}
		if n, err := dev.Name(); err == nil && n != "" {
			s.name = n
		}
	}
	prevChanged := s.changed
	s.changed = make(chan struct{})
	s.mu.Unlock()

	close(prevChanged)
	if old != nil {
		_ = old.Close()
	}
	select {
	case s.events <- tun.EventMTUUpdate:
	default:
	}
	return nil
}

// AttachFD wraps a platform TUN file descriptor and attaches it.
func (s *SwappableTUN) AttachFD(fd int) error {
	dev, err := openTUNFromFD(fd, s.mtu)
	if err != nil {
		return err
	}
	return s.Attach(dev)
}

func (s *SwappableTUN) Read(slab []byte, packets []tun.ReadPacket) (int, error) {
	for {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return 0, io.EOF
		}
		cur := s.cur
		wait := s.changed
		s.mu.Unlock()

		if cur == nil {
			<-wait
			continue
		}
		n, err := cur.Read(slab, packets)
		if err != nil {
			s.mu.Lock()
			swapped := !s.closed && s.cur != cur
			closed := s.closed
			s.mu.Unlock()
			if swapped {
				// Expected error from closing the old TUN during live route swap.
				continue
			}
			if closed {
				return 0, io.EOF
			}
			return 0, err
		}
		return n, nil
	}
}

func (s *SwappableTUN) Write(bufs [][]byte, offset int) (int, error) {
	s.mu.Lock()
	cur := s.cur
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return 0, os.ErrClosed
	}
	if cur == nil {
		// Drop outbound packets cleanly while waiting for OS TUN attachment.
		return len(bufs), nil
	}
	return cur.Write(bufs, offset)
}

func (s *SwappableTUN) File() *os.File {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return nil
	}
	return s.cur.File()
}

func (s *SwappableTUN) MTU() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mtu, nil
}

func (s *SwappableTUN) Name() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.name, nil
}

func (s *SwappableTUN) Events() <-chan tun.Event {
	return s.events
}

func (s *SwappableTUN) BatchSize() int {
	// Must remain constant across the lifetime of the Device (wireguard-go contract).
	return 1
}

func (s *SwappableTUN) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	cur := s.cur
	s.cur = nil
	prevChanged := s.changed
	s.mu.Unlock()

	close(prevChanged)
	close(s.events)
	if cur != nil {
		return cur.Close()
	}
	return nil
}

var errTUNFDUnsupported = errors.New("TUN file descriptors are unsupported on this platform")
