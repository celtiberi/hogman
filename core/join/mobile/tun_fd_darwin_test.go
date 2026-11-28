//go:build darwin || ios

package mobile

import (
	"bytes"
	"os"
	"testing"

	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
)

func TestOpenTUNFromFDRejectsNonUtunFDNoFallback(t *testing.T) {
	// 1. Non-socket fd (pipe): UTUN_OPT_IFNAME fails with ENOTSOCK.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()
	if dev, err := openTUNFromFD(int(r.Fd()), 1280); err == nil {
		_ = dev.Close()
		t.Fatal("openTUNFromFD succeeded on pipe fd; expected error with no utun0 fallback")
	}

	// 2. Non-utun socketpair fd: must also reject invalid non-"utun<N>" name.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if dev, err := openTUNFromFD(fds[0], 1280); err == nil {
		_ = dev.Close()
		t.Fatal("openTUNFromFD succeeded on AF_UNIX socketpair; expected error with no utun0 fallback")
	}
}

func TestDarwinUnmonitoredTUNRoundTrip(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[1])

	dev, err := wrapDarwinTUNFD(fds[0], 1280, "utun_test")
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("wrapDarwinTUNFD: %v", err)
	}
	defer dev.Close()

	if name, err := dev.Name(); err != nil || name != "utun_test" {
		t.Fatalf("Name = (%q, %v), want (utun_test, nil)", name, err)
	}
	if mtu, err := dev.MTU(); err != nil || mtu != 1280 {
		t.Fatalf("MTU = (%d, %v), want (1280, nil)", mtu, err)
	}

	// Simulate an inbound IPv4 packet with Darwin's 4-byte utun header.
	ip4Payload := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad, 0xbe, 0xef}
	utunFrame := append([]byte{0x00, 0x00, 0x00, unix.AF_INET}, ip4Payload...)
	if _, err := unix.Write(fds[1], utunFrame); err != nil {
		t.Fatalf("peer write: %v", err)
	}

	slab := make([]byte, 4096)
	var pkts [1]tun.ReadPacket
	n, err := dev.Read(slab, pkts[:])
	if err != nil || n != 1 {
		t.Fatalf("Read = (%d, %v), want (1, nil)", n, err)
	}
	got := slab[pkts[0].Offset : pkts[0].Offset+pkts[0].Size]
	if !bytes.Equal(got, ip4Payload) {
		t.Fatalf("Read payload = %x, want %x", got, ip4Payload)
	}

	// Write an outbound IPv4 packet and verify the 4-byte AF_INET prefix on peer.
	outBuf := make([]byte, tun.ReadPacketSpacing+len(ip4Payload))
	copy(outBuf[tun.ReadPacketSpacing:], ip4Payload)
	if wn, err := dev.Write([][]byte{outBuf}, tun.ReadPacketSpacing); err != nil || wn != 1 {
		t.Fatalf("Write = (%d, %v), want (1, nil)", wn, err)
	}
	peerBuf := make([]byte, 256)
	rn, err := unix.Read(fds[1], peerBuf)
	if err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(peerBuf[:rn], utunFrame) {
		t.Fatalf("peer received %x, want %x", peerBuf[:rn], utunFrame)
	}
}
