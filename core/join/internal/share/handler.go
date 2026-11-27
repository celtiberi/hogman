package share

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tsnet"

	"hogman/join/internal/bridge"
	"hogman/join/internal/link"
	"hogman/join/internal/state"
)

// noDotfilesFS wraps a folder share's fs.FS to deny hidden dotfiles/directories
// (like .git, .env, .DS_Store) on both direct Open and directory listings,
// while allowing .well-known.
type noDotfilesFS struct{ inner fs.FS }

func isHiddenDotEntry(name string) bool {
	return strings.HasPrefix(name, ".") && name != "." && name != ".well-known"
}

func (f noDotfilesFS) Open(name string) (fs.File, error) {
	if name != "." {
		for _, seg := range strings.Split(name, "/") {
			if isHiddenDotEntry(seg) {
				return nil, fs.ErrNotExist
			}
		}
	}
	file, err := f.inner.Open(name)
	if err != nil {
		return nil, err
	}
	if rdf, ok := file.(fs.ReadDirFile); ok {
		return noDotfilesDir{ReadDirFile: rdf}, nil
	}
	return file, nil
}

type noDotfilesDir struct{ fs.ReadDirFile }

func (d noDotfilesDir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		all, err := d.ReadDirFile.ReadDir(n)
		return filterDotDirEntries(all), err
	}
	var out []fs.DirEntry
	for len(out) < n {
		batch, err := d.ReadDirFile.ReadDir(n - len(out))
		out = append(out, filterDotDirEntries(batch)...)
		if err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				return out, nil
			}
			return out, err
		}
		if len(batch) == 0 {
			break
		}
	}
	return out, nil
}

func filterDotDirEntries(entries []fs.DirEntry) []fs.DirEntry {
	out := entries[:0]
	for _, e := range entries {
		if !isHiddenDotEntry(e.Name()) {
			out = append(out, e)
		}
	}
	return out
}

// hasPathTraversal reports whether a request's path or raw escaped path attempts
// to traverse out of a subpath-scoped reverse-proxy target using dot-segments,
// backslashes, or percent-encoded dots/backslashes (while allowing legitimate
// percent-encoded slashes like %2F inside non-traversal path parameters).
func hasPathTraversal(u *url.URL) bool {
	if u.Opaque != "" {
		return true
	}
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, "%2e") || strings.Contains(raw, "%5c") || strings.Contains(raw, "\\") {
		return true
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

var shareHandleRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}[a-z0-9]$`)

// PeerIdentity holds the mesh-authenticated peer identity resolved from tsnet
// WhoIs for an incoming request to a shared local app.
type PeerIdentity struct {
	Handle string
	Node   string
	IP     string
	Tags   []string
}

type PeerResolver func(ctx context.Context, remoteAddr string) (*PeerIdentity, error)

func cleanHeaderToken(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(raw))
	for _, r := range raw {
		if r <= 0x20 || r == 0x7f || r > 0x7e {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func PeerIdentityFromWhoIs(remoteAddr string, who *apitype.WhoIsResponse) *PeerIdentity {
	if who == nil || who.Node == nil {
		return nil
	}
	rawIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		rawIP = host
	}
	ip := ""
	if addr, err := netip.ParseAddr(strings.TrimSpace(rawIP)); err == nil {
		ip = addr.Unmap().String()
	}

	var tags []string
	for _, t := range who.Node.Tags {
		clean := cleanHeaderToken(t)
		if clean == "" || strings.Contains(clean, ",") {
			continue
		}
		tags = append(tags, clean)
	}
	sort.Strings(tags)

	nodeName := cleanHeaderToken(who.Node.ComputedName)
	if nodeName == "" {
		rawName := strings.TrimSuffix(strings.TrimSpace(who.Node.Name), ".")
		if before, _, ok := strings.Cut(rawName, "."); ok {
			rawName = before
		}
		nodeName = cleanHeaderToken(rawName)
	}

	handle := ""
	// Tagged nodes (such as tag:server) are not personal users and must never
	// receive X-Hogman-Handle.
	if len(tags) == 0 && !who.Node.IsTagged() && who.UserProfile != nil {
		cand := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(who.UserProfile.LoginName)), "@")
		if shareHandleRE.MatchString(cand) {
			handle = cand
		}
	}

	return &PeerIdentity{
		Handle: handle,
		Node:   nodeName,
		IP:     ip,
		Tags:   tags,
	}
}

func TsnetPeerResolver(node *tsnet.Server) PeerResolver {
	return func(ctx context.Context, remoteAddr string) (*PeerIdentity, error) {
		if node == nil {
			return nil, errors.New("no mesh node")
		}
		lc, err := node.LocalClient()
		if err != nil {
			return nil, err
		}
		who, err := lc.WhoIs(ctx, remoteAddr)
		if err != nil {
			return nil, err
		}
		return PeerIdentityFromWhoIs(remoteAddr, who), nil
	}
}

func IsHogmanHeaderName(k string) bool {
	norm := strings.ReplaceAll(strings.ToLower(k), "_", "-")
	return strings.HasPrefix(norm, "x-hogman-")
}

func StripHogmanHeaders(h http.Header) {
	for k := range h {
		if IsHogmanHeaderName(k) {
			delete(h, k)
		}
	}
}

func NewHandler(c *state.ShareConfig) (http.Handler, func(), error) {
	return NewHandlerWithResolver(c, nil)
}

func NewHandlerWithResolver(c *state.ShareConfig, resolve PeerResolver) (http.Handler, func(), error) {
	if c.IdentityHeaders {
		if err := ValidateIdentityTarget(c.Target, c.Folder); err != nil {
			return nil, nil, Permanent(err)
		}
	}
	if c.Folder {
		// os.Root keeps every read inside the folder: a symlink pointing out
		// of it (to ~/.ssh, say) is refused, not followed; noDotfilesFS also
		// hides .git/.env and similar dotfiles.
		root, err := os.OpenRoot(c.Target)
		if err != nil {
			return nil, nil, link.Errorf("cannot open the folder %s: %v", c.Target, err)
		}
		return http.FileServerFS(noDotfilesFS{inner: root.FS()}), func() { _ = root.Close() }, nil
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil // always connect directly to the local/LAN or Unix socket share target
	tr.MaxResponseHeaderBytes = 64 << 10
	tr.MaxConnsPerHost = 128
	tr.MaxIdleConnsPerHost = 32

	var targetURL *url.URL
	var rewriteHost string
	if strings.HasPrefix(c.Target, "unix://") {
		sockPath, err := bridge.ValidateUnixSocketPath(strings.TrimPrefix(c.Target, "unix://"))
		if err != nil {
			return nil, nil, Permanent(err)
		}
		tr.ResponseHeaderTimeout = 60 * time.Second
		tr.DialContext = bridge.UnixSocketDialContext(sockPath)
		rewriteHost = strings.TrimSpace(c.UpstreamHost)
		if rewriteHost == "" {
			rewriteHost = c.FQDN()
		}
		targetURL = &url.URL{Scheme: "http", Host: rewriteHost}
	} else {
		u, err := url.Parse(c.Target)
		if err != nil {
			return nil, nil, Permanent(err)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, nil, Permanent(link.Errorf("share target %q must use http://, https://, or unix://", c.Target))
		}
		if IsBlockedMetadataHost(u.Hostname()) {
			return nil, nil, Permanent(link.Errorf("share target %q is a cloud metadata address and cannot be shared", c.Target))
		}
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !IsAllowedIP(ip) {
			return nil, nil, Permanent(link.Errorf("share target %q is not a local or private LAN address", c.Target))
		}
		if c.IdentityHeaders {
			tr.DialContext = LoopbackOnlyDialContext(nil, nil)
		} else {
			tr.DialContext = LocalOrLANDialContext(nil, nil)
		}
		targetURL = u
	}

	type shareIdentityCtxKey struct{}

	rp := &httputil.ReverseProxy{
		Transport: tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Opaque = ""
			pr.SetURL(targetURL)
			if rewriteHost != "" {
				pr.Out.Host = rewriteHost
			}
			// Never trust client-supplied forwarding or X-Hogman-* identity
			// headers: strip them unconditionally before setting fresh values
			// from the authenticated mesh connection.
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			StripHogmanHeaders(pr.Out.Header)
			StripHogmanHeaders(pr.Out.Trailer)
			if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil && clientIP != "" {
				pr.Out.Header.Set("X-Forwarded-For", clientIP)
			}
			pr.Out.Header.Set("X-Forwarded-Host", c.FQDN())
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			if c.IdentityHeaders {
				if id, ok := pr.In.Context().Value(shareIdentityCtxKey{}).(*PeerIdentity); ok && id != nil {
					if id.Handle != "" {
						pr.Out.Header.Set("X-Hogman-Handle", id.Handle)
					}
					if id.Node != "" {
						pr.Out.Header.Set("X-Hogman-Node", id.Node)
					}
					if id.IP != "" {
						pr.Out.Header.Set("X-Hogman-IP", id.IP)
					}
					if len(id.Tags) > 0 {
						pr.Out.Header.Set("X-Hogman-Tags", strings.Join(id.Tags, ","))
					}
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "%s is shared from a computer where the app isn't answering right now.\n", c.FQDN())
		},
		ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelError),
	}
	subpath := targetURL.Path != "" && targetURL.Path != "/"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Opaque != "" || (subpath && hasPathTraversal(r.URL)) {
			http.Error(w, "invalid path", http.StatusBadRequest)
			return
		}
		if c.IdentityHeaders {
			if resolve == nil {
				http.Error(w, "could not verify caller identity", http.StatusServiceUnavailable)
				return
			}
			whoCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			id, err := resolve(whoCtx, r.RemoteAddr)
			cancel()
			if err != nil || id == nil {
				http.Error(w, "could not verify caller identity", http.StatusServiceUnavailable)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), shareIdentityCtxKey{}, id))
		}
		rp.ServeHTTP(w, r)
	}), func() {}, nil
}
