package bridge

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestValidateLoopbackTCPTarget(t *testing.T) {
	t.Parallel()
	if got, err := ValidateLoopbackTCPTarget("127.0.0.1:8080"); err != nil || got != "127.0.0.1:8080" {
		t.Fatalf("127.0.0.1:8080 = (%q, %v)", got, err)
	}
	if got, err := ValidateLoopbackTCPTarget("[::1]:9000"); err != nil || got != "[::1]:9000" {
		t.Fatalf("[::1]:9000 = (%q, %v)", got, err)
	}
	for _, bad := range []string{"localhost:8080", "10.0.0.1:8080", "0.0.0.0:8080", "127.0.0.1:0", "127.0.0.1:99999", "not-an-addr"} {
		if _, err := ValidateLoopbackTCPTarget(bad); err == nil {
			t.Errorf("ValidateLoopbackTCPTarget(%q) succeeded, want error", bad)
		}
	}
}

func TestBridgeForwardsAndRefusesNonSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix domain sockets tested on Unix")
	}
	t.Parallel()

	for _, bad := range []string{"", "@abstract", "rel/app.sock", "/tmp/../etc/app.sock", "/tmp/dir/"} {
		if _, err := ValidateUnixSocketPath(bad); err == nil {
			t.Errorf("ValidateUnixSocketPath(%q) succeeded, want error", bad)
		}
	}

	// Start a loopback TCP echo server.
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	dir, err := os.MkdirTemp("/tmp", "hb-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	// Regular file at sockPath must be refused.
	regFile := filepath.Join(dir, "regular")
	if err := os.WriteFile(regFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), regFile, tcpLn.Addr().String(), 4, nil); err == nil {
		t.Fatal("Run overwrote a regular file")
	}

	sockPath := filepath.Join(dir, "app.sock")
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, sockPath, tcpLn.Addr().String(), 4, func() { close(ready) })
	}()
	select {
	case <-ready:
	case err := <-done:
		t.Fatalf("bridge exited early: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not become ready")
	}

	if err := RunCommand(Options{CheckUnix: sockPath}); err != nil {
		t.Fatalf("healthcheck failed: %v", err)
	}

	dial := UnixSocketDialContext(sockPath)
	c, err := dial(ctx, "unix", sockPath)
	if err != nil {
		t.Fatalf("dial bridge socket: %v", err)
	}
	_, _ = c.Write([]byte("ping"))
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
	got, err := io.ReadAll(c)
	_ = c.Close()
	if err != nil || string(got) != "ping" {
		t.Fatalf("echo = %q (err=%v), want ping", string(got), err)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("bridge shutdown error: %v", err)
	}
}
