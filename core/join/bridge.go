package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type bridgeOptions struct {
	listenUnix string
	forwardTCP string
	checkUnix  string
	maxConns   int
}

func validateLoopbackTCPTarget(addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", errorf("invalid --forward-tcp address %q (expected 127.0.0.1:<port> or [::1]:<port>)", addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return "", errorf("invalid --forward-tcp port %q", portStr)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
		return "", errorf("--forward-tcp %q must be a loopback IP literal (127.0.0.1 or [::1])", addr)
	}
	return net.JoinHostPort(ip.Unmap().String(), portStr), nil
}

// bridgeCmd runs a minimal Unix-domain-socket to loopback-TCP forwarder for
// sealed Docker deployments (`network_mode: none` bridge container sharing lo
// with an unmodified app container).
func bridgeCmd(bo bridgeOptions) error {
	if bo.checkUnix != "" {
		sockPath, err := validateUnixSocketPath(bo.checkUnix)
		if err != nil {
			return err
		}
		if err := verifyUnixSocketNoSymlink(sockPath); err != nil {
			return err
		}
		d := &net.Dialer{Timeout: 2 * time.Second}
		conn, err := d.Dial("unix", sockPath)
		if err != nil {
			return errorf("bridge socket %s is not accepting connections: %v", sockPath, err)
		}
		_ = conn.Close()
		return nil
	}

	sockPath, err := validateUnixSocketPath(bo.listenUnix)
	if err != nil {
		return err
	}
	targetAddr, err := validateLoopbackTCPTarget(bo.forwardTCP)
	if err != nil {
		return err
	}
	maxConns := bo.maxConns
	if maxConns <= 0 {
		maxConns = 256
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runBridge(ctx, sockPath, targetAddr, maxConns, nil)
}

func runBridge(ctx context.Context, sockPath, targetAddr string, maxConns int, onReady func()) error {
	parent := filepath.Dir(sockPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return errorf("cannot create socket directory %s: %v", parent, err)
	}
	// Remove an old stale socket ONLY if it is actually a socket (never follow
	// symlinks or delete a regular file).
	if fi, err := os.Lstat(sockPath); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode()&os.ModeSocket == 0 {
			return errorf("refusing to overwrite non-socket path %s", sockPath)
		}
		if err := os.Remove(sockPath); err != nil {
			return errorf("cannot remove stale socket %s: %v", sockPath, err)
		}
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return errorf("cannot listen on Unix socket %s: %v", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(sockPath)
		return errorf("cannot chmod Unix socket %s: %v", sockPath, err)
	}
	defer func() {
		_ = ln.Close()
		_ = os.Remove(sockPath)
	}()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	if onReady != nil {
		onReady()
	}

	sem := make(chan struct{}, maxConns)
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var wg sync.WaitGroup

	for {
		inConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = inConn.Close()
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			defer c.Close()

			outConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				return
			}
			defer outConn.Close()
			stopClose := context.AfterFunc(ctx, func() {
				_ = c.Close()
				_ = outConn.Close()
			})
			defer stopClose()
			proxyBidirectional(c, outConn)
		}(inConn)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return nil
}

func proxyBidirectional(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	copyOne := func(dst, src net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}
	go copyOne(b, a)
	go copyOne(a, b)
	wg.Wait()
}
