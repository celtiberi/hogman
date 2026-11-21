// Command fake-challengedns is a self-contained test helper for offline ACME
// end-to-end verification in Docker Compose. It runs:
//   - HTTP challenge-dns stub (-api-addr) talking to pebble-challtestsrv
//   - UDP+TCP DNS proxy (-dns-addr) synthesizing SOA records for the pens zone
//     and forwarding remaining queries (TXT) to pebble-challtestsrv
//   - Lightweight Headscale API stub (-hs-addr) for device/node enrollment
//   - Optional mock ACME TLS server (-mock429-addr) returning HTTP 429 on /order
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxLivePerFQDN    = 2
	maxWeeklyDistinct = 10
	maxDailyEAB       = 5
)

var (
	txtValueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	dnsLabelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// challengeServer implements the Step 1 challenge-dns contract backed by pebble-challtestsrv.
type challengeServer struct {
	penName   string
	pensZone  string
	token     string
	mgmtURL   string
	eabKID    string
	eabHMAC   string
	httpCli   *http.Client

	mu         sync.Mutex
	live       map[string][]string
	seen       map[string]bool
	txtWrites  int
	txtDeletes int
	eabCount   int
	failTXT    bool
	corruptTXT bool
}

func newChallengeServer(penName, pensZone, token, mgmtURL, eabKID, eabHMAC string) *challengeServer {
	return &challengeServer{
		penName:  strings.TrimSuffix(strings.ToLower(strings.TrimSpace(penName)), "."),
		pensZone: strings.TrimSuffix(strings.ToLower(strings.TrimSpace(pensZone)), "."),
		token:    strings.TrimSpace(token),
		mgmtURL:  strings.TrimRight(strings.TrimSpace(mgmtURL), "/"),
		eabKID:   strings.TrimSpace(eabKID),
		eabHMAC:  strings.TrimSpace(eabHMAC),
		httpCli:  &http.Client{Timeout: 5 * time.Second},
		live:     map[string][]string{},
		seen:     map[string]bool{},
	}
}

func normalizeFQDN(raw string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
}

func (c *challengeServer) allowedFQDN(fqdn string) bool {
	if c.penName == "" || c.pensZone == "" {
		return false
	}
	suffix := "." + c.penName + "." + c.pensZone
	if !strings.HasSuffix(fqdn, suffix) {
		return false
	}
	rest := strings.TrimSuffix(fqdn, suffix)
	if !strings.HasPrefix(rest, "_acme-challenge.") {
		return false
	}
	sub := strings.TrimPrefix(rest, "_acme-challenge.")
	if sub == "" {
		return false
	}
	labels := strings.Split(sub, ".")
	if len(labels) < 1 || len(labels) > 4 {
		return false
	}
	for _, lbl := range labels {
		if !dnsLabelRE.MatchString(lbl) {
			return false
		}
	}
	return true
}

func (c *challengeServer) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+c.token {
		writeJSONErr(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func (c *challengeServer) syncChallTestSrv(ctx context.Context, fqdn string, vals []string) error {
	host := fqdn + "."
	if err := c.postMgmt(ctx, "/clear-txt", map[string]string{"host": host}); err != nil {
		return err
	}
	for _, v := range vals {
		if err := c.postMgmt(ctx, "/set-txt", map[string]string{"host": host, "value": v}); err != nil {
			return err
		}
	}
	return nil
}

func (c *challengeServer) postMgmt(ctx context.Context, path string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.mgmtURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpCli.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

func (c *challengeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/txt", c.handlePostTXT)
	mux.HandleFunc("DELETE /v1/txt", c.handleDeleteTXT)
	mux.HandleFunc("POST /v1/eab", c.handlePostEAB)
	mux.HandleFunc("GET /test/stats", c.handleStats)
	mux.HandleFunc("POST /test/mode", c.handleMode)
	mux.HandleFunc("POST /test/reset", c.handleReset)
	return mux
}

func (c *challengeServer) handlePostTXT(w http.ResponseWriter, r *http.Request) {
	if !c.checkAuth(w, r) {
		return
	}
	var req struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	fqdn := normalizeFQDN(req.FQDN)
	if !c.allowedFQDN(fqdn) {
		writeJSONErr(w, http.StatusForbidden, "fqdn outside pen scope")
		return
	}
	if !txtValueRE.MatchString(req.Value) {
		writeJSONErr(w, http.StatusBadRequest, "invalid TXT challenge value")
		return
	}

	c.mu.Lock()
	if c.failTXT {
		c.mu.Unlock()
		writeJSONErr(w, http.StatusInternalServerError, "simulated TXT write failure")
		return
	}
	actualVal := req.Value
	if c.corruptTXT {
		actualVal = "WRONGVALUE1234567890"
	}
	for _, existing := range c.live[fqdn] {
		if existing == actualVal || existing == req.Value {
			c.mu.Unlock()
			writeJSON(w, http.StatusCreated, map[string]string{"fqdn": fqdn})
			return
		}
	}
	if len(c.live[fqdn]) >= maxLivePerFQDN {
		c.mu.Unlock()
		writeJSONErr(w, http.StatusConflict, "too many live TXT values for fqdn")
		return
	}
	if !c.seen[fqdn] && len(c.seen) >= maxWeeklyDistinct {
		c.mu.Unlock()
		writeJSONErr(w, http.StatusTooManyRequests, "weekly distinct name cap reached")
		return
	}
	nextVals := append(append([]string(nil), c.live[fqdn]...), actualVal)
	c.mu.Unlock()

	if err := c.syncChallTestSrv(r.Context(), fqdn, nextVals); err != nil {
		writeJSONErr(w, http.StatusBadGateway, err.Error())
		return
	}

	c.mu.Lock()
	c.live[fqdn] = nextVals
	c.seen[fqdn] = true
	c.txtWrites++
	c.mu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]string{"fqdn": fqdn})
}

func (c *challengeServer) handleDeleteTXT(w http.ResponseWriter, r *http.Request) {
	if !c.checkAuth(w, r) {
		return
	}
	var req struct {
		FQDN  string `json:"fqdn"`
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	fqdn := normalizeFQDN(req.FQDN)
	if !c.allowedFQDN(fqdn) {
		writeJSONErr(w, http.StatusForbidden, "fqdn outside pen scope")
		return
	}

	c.mu.Lock()
	target := req.Value
	if c.corruptTXT {
		target = "WRONGVALUE1234567890"
	}
	cur := c.live[fqdn]
	kept := make([]string, 0, len(cur))
	found := false
	for _, v := range cur {
		if !found && (v == req.Value || v == target) {
			found = true
			continue
		}
		kept = append(kept, v)
	}
	c.mu.Unlock()

	if !found {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err := c.syncChallTestSrv(r.Context(), fqdn, kept); err != nil {
		writeJSONErr(w, http.StatusBadGateway, err.Error())
		return
	}

	c.mu.Lock()
	if len(kept) == 0 {
		delete(c.live, fqdn)
	} else {
		c.live[fqdn] = kept
	}
	c.txtDeletes++
	c.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (c *challengeServer) handlePostEAB(w http.ResponseWriter, r *http.Request) {
	if !c.checkAuth(w, r) {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.eabKID == "" || c.eabHMAC == "" {
		writeJSONErr(w, http.StatusServiceUnavailable, "EAB not configured")
		return
	}
	if c.eabCount >= maxDailyEAB {
		writeJSONErr(w, http.StatusTooManyRequests, "daily EAB cap reached")
		return
	}
	c.eabCount++
	writeJSON(w, http.StatusCreated, map[string]string{
		"kid":         c.eabKID,
		"hmac_b64url": c.eabHMAC,
	})
}

func (c *challengeServer) handleStats(w http.ResponseWriter, _ *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	liveCopy := make(map[string][]string, len(c.live))
	for k, v := range c.live {
		liveCopy[k] = append([]string(nil), v...)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"txt_writes":     c.txtWrites,
		"txt_deletes":    c.txtDeletes,
		"eab_count":      c.eabCount,
		"distinct_fqdns": len(c.seen),
		"live":           liveCopy,
		"fail_txt":       c.failTXT,
		"corrupt_txt":    c.corruptTXT,
	})
}

func (c *challengeServer) handleMode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FailTXT    *bool `json:"fail_txt"`
		CorruptTXT *bool `json:"corrupt_txt"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSONErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	c.mu.Lock()
	if req.FailTXT != nil {
		c.failTXT = *req.FailTXT
	}
	if req.CorruptTXT != nil {
		c.corruptTXT = *req.CorruptTXT
	}
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (c *challengeServer) handleReset(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	fqdns := make([]string, 0, len(c.live))
	for f := range c.live {
		fqdns = append(fqdns, f)
	}
	c.mu.Unlock()

	for _, f := range fqdns {
		_ = c.syncChallTestSrv(r.Context(), f, nil)
	}

	c.mu.Lock()
	c.live = map[string][]string{}
	c.seen = map[string]bool{}
	c.txtWrites = 0
	c.txtDeletes = 0
	c.eabCount = 0
	c.failTXT = false
	c.corruptTXT = false
	c.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]bool{"reset": true})
}

// ------------------------------------------------------------------- DNS ----

// dnsProxy synthesizes authoritative SOA responses for pensZone and subdomains
// (so certmagic's FindZoneByFQDN resolves the zone cleanly) and forwards all
// other DNS queries verbatim over UDP/TCP to upstream (pebble-challtestsrv).
type dnsProxy struct {
	pensZone string
	upstream string
}

func (d *dnsProxy) handlePacket(pkt []byte) ([]byte, error) {
	qname, qtype, _, qEnd, ok := parseDNSQuestion(pkt)
	if ok && qtype == 6 && d.pensZone != "" {
		normQ := normalizeFQDN(qname)
		if normQ == d.pensZone {
			return buildSOAResponse(pkt, qEnd, d.pensZone, true), nil
		}
		if strings.HasSuffix(normQ, "."+d.pensZone) {
			return buildSOAResponse(pkt, qEnd, d.pensZone, false), nil
		}
	}
	return nil, errForwardDNS
}

var errForwardDNS = errors.New("forward dns")

func parseDNSQuestion(pkt []byte) (name string, qtype, qclass uint16, end int, ok bool) {
	if len(pkt) < 12 {
		return "", 0, 0, 0, false
	}
	if binary.BigEndian.Uint16(pkt[4:6]) == 0 {
		return "", 0, 0, 0, false
	}
	idx := 12
	var labels []string
	for {
		if idx >= len(pkt) {
			return "", 0, 0, 0, false
		}
		l := int(pkt[idx])
		idx++
		if l == 0 {
			break
		}
		if l >= 64 || idx+l > len(pkt) {
			return "", 0, 0, 0, false
		}
		labels = append(labels, string(pkt[idx:idx+l]))
		idx += l
	}
	if idx+4 > len(pkt) {
		return "", 0, 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(pkt[idx : idx+2])
	qclass = binary.BigEndian.Uint16(pkt[idx+2 : idx+4])
	return strings.Join(labels, "."), qtype, qclass, idx + 4, true
}

func encodeDNSName(buf *bytes.Buffer, fqdn string) {
	fqdn = normalizeFQDN(fqdn)
	if fqdn != "" {
		for _, lbl := range strings.Split(fqdn, ".") {
			buf.WriteByte(byte(len(lbl)))
			buf.WriteString(lbl)
		}
	}
	buf.WriteByte(0)
}

func buildSOAResponse(req []byte, qEnd int, zone string, inAnswer bool) []byte {
	var out bytes.Buffer
	out.Grow(qEnd + 128)
	hdr := make([]byte, 12)
	copy(hdr[0:2], req[0:2])
	reqFlags := binary.BigEndian.Uint16(req[2:4])
	// QR=1, AA=1, preserve Opcode and RD bits, RCODE=0 (NOERROR).
	respFlags := uint16(0x8400) | (reqFlags & 0x7800) | (reqFlags & 0x0100)
	binary.BigEndian.PutUint16(hdr[2:4], respFlags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	if inAnswer {
		binary.BigEndian.PutUint16(hdr[6:8], 1)
	} else {
		binary.BigEndian.PutUint16(hdr[8:10], 1)
	}
	out.Write(hdr)
	out.Write(req[12:qEnd])

	var rdata bytes.Buffer
	encodeDNSName(&rdata, "ns1."+zone)
	encodeDNSName(&rdata, "hostmaster."+zone)
	var nums [20]byte
	binary.BigEndian.PutUint32(nums[0:4], 1)     // serial
	binary.BigEndian.PutUint32(nums[4:8], 3600)  // refresh
	binary.BigEndian.PutUint32(nums[8:12], 600)  // retry
	binary.BigEndian.PutUint32(nums[12:16], 86400) // expire
	binary.BigEndian.PutUint32(nums[16:20], 60)  // minimum
	rdata.Write(nums[:])

	encodeDNSName(&out, zone)
	var rrMeta [10]byte
	binary.BigEndian.PutUint16(rrMeta[0:2], 6)  // TYPE SOA
	binary.BigEndian.PutUint16(rrMeta[2:4], 1)  // CLASS IN
	binary.BigEndian.PutUint32(rrMeta[4:8], 60) // TTL
	binary.BigEndian.PutUint16(rrMeta[8:10], uint16(rdata.Len()))
	out.Write(rrMeta[:])
	out.Write(rdata.Bytes())
	return out.Bytes()
}

func (d *dnsProxy) forwardUDP(pkt []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", d.upstream, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write(pkt); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (d *dnsProxy) forwardTCP(pkt []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", d.upstream, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if err := writeTCPMsg(conn, pkt); err != nil {
		return nil, err
	}
	return readTCPMsg(conn)
}

func readTCPMsg(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	msg := make([]byte, n)
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func writeTCPMsg(w io.Writer, msg []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(msg)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func (d *dnsProxy) serve(ctx context.Context, addr string) error {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		_ = pc.Close()
		_ = ln.Close()
	}()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pkt := append([]byte(nil), buf[:n]...)
			go func() {
				resp, err := d.handlePacket(pkt)
				if errors.Is(err, errForwardDNS) {
					resp, err = d.forwardUDP(pkt)
				}
				if err == nil && len(resp) > 0 {
					_, _ = pc.WriteTo(resp, raddr)
				}
			}()
		}
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				pkt, err := readTCPMsg(conn)
				if err != nil {
					return
				}
				resp, err := d.handlePacket(pkt)
				if errors.Is(err, errForwardDNS) {
					resp, err = d.forwardTCP(pkt)
				}
				if err == nil && len(resp) > 0 {
					_ = writeTCPMsg(conn, resp)
				}
			}(c)
		}
	}()
	return nil
}

// ------------------------------------------------------------- Headscale ----

type hsUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type hsPreAuthKey struct {
	ID         string   `json:"id"`
	Key        string   `json:"key"`
	Used       bool     `json:"used"`
	Expiration string   `json:"expiration"`
	ACLTags    []string `json:"aclTags"`
	User       *hsUser  `json:"user,omitempty"`
}

type hsNode struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	GivenName   string        `json:"givenName"`
	IPAddresses []string      `json:"ipAddresses"`
	User        *hsUser       `json:"user"`
	PreAuthKey  *hsPreAuthKey `json:"preAuthKey"`
	Tags        []string      `json:"tags"`
	Online      bool          `json:"online"`
}

type fakeHeadscale struct {
	mu      sync.Mutex
	nextID  int
	users   map[string]hsUser
	keys    map[string]hsPreAuthKey
	nodes   []hsNode
	policy  string
}

func newFakeHeadscale() *fakeHeadscale {
	return &fakeHeadscale{
		users:  map[string]hsUser{},
		keys:   map[string]hsPreAuthKey{},
		policy: "{}",
	}
}

func (f *fakeHeadscale) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		f.mu.Lock()
		defer f.mu.Unlock()
		out := make([]hsUser, 0)
		for _, u := range f.users {
			if name == "" || u.Name == name {
				out = append(out, u)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	})
	mux.HandleFunc("POST /api/v1/user", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Name) == "" {
			writeJSONErr(w, http.StatusBadRequest, "missing user name")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if u, ok := f.users[in.Name]; ok {
			writeJSON(w, http.StatusOK, map[string]hsUser{"user": u})
			return
		}
		f.nextID++
		u := hsUser{ID: strconv.Itoa(f.nextID), Name: in.Name}
		f.users[in.Name] = u
		writeJSON(w, http.StatusOK, map[string]hsUser{"user": u})
	})
	mux.HandleFunc("DELETE /api/v1/user/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		defer f.mu.Unlock()
		for k, u := range f.users {
			if u.ID == id {
				delete(f.users, k)
				writeJSON(w, http.StatusOK, map[string]any{})
				return
			}
		}
		writeJSONErr(w, http.StatusNotFound, "user not found")
	})
	mux.HandleFunc("POST /api/v1/preauthkey", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			User       string   `json:"user"`
			Expiration string   `json:"expiration"`
			ACLTags    []string `json:"aclTags"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		var owner *hsUser
		for _, u := range f.users {
			if u.ID == in.User || u.Name == in.User {
				uc := u
				owner = &uc
				break
			}
		}
		f.nextID++
		id := strconv.Itoa(f.nextID)
		k := hsPreAuthKey{
			ID:         id,
			Key:        "hskey-" + id + "-" + randHex(6),
			Expiration: in.Expiration,
			ACLTags:    append([]string(nil), in.ACLTags...),
			User:       owner,
		}
		f.keys[k.Key] = k
		writeJSON(w, http.StatusOK, map[string]hsPreAuthKey{"preAuthKey": k})
	})
	mux.HandleFunc("POST /api/v1/preauthkey/expire", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("GET /api/v1/node", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		out := make([]hsNode, len(f.nodes))
		copy(out, f.nodes)
		writeJSON(w, http.StatusOK, map[string]any{"nodes": out})
	})
	mux.HandleFunc("DELETE /api/v1/node/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		f.mu.Lock()
		defer f.mu.Unlock()
		kept := f.nodes[:0]
		for _, n := range f.nodes {
			if n.ID != id {
				kept = append(kept, n)
			}
		}
		f.nodes = kept
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("GET /api/v1/policy", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{"policy": f.policy})
	})
	mux.HandleFunc("PUT /api/v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Policy string `json:"policy"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSONErr(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		f.mu.Lock()
		f.policy = in.Policy
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{})
	})
	mux.HandleFunc("POST /test/hs-node", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Key  string `json:"key"`
			IP   string `json:"ip"`
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Key == "" || in.IP == "" {
			writeJSONErr(w, http.StatusBadRequest, "key and ip required")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		pak, ok := f.keys[in.Key]
		if !ok {
			writeJSONErr(w, http.StatusNotFound, "unknown preauthkey")
			return
		}
		pak.Used = true
		f.keys[in.Key] = pak
		f.nextID++
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = "node-" + strconv.Itoa(f.nextID)
		}
		node := hsNode{
			ID:          strconv.Itoa(f.nextID),
			Name:        name,
			GivenName:   name,
			IPAddresses: []string{in.IP},
			User:        pak.User,
			PreAuthKey:  &pak,
			Tags:        append([]string(nil), pak.ACLTags...),
			Online:      true,
		}
		f.nodes = append(f.nodes, node)
		writeJSON(w, http.StatusCreated, node)
	})
	mux.HandleFunc("POST /test/hs-reset", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.users = map[string]hsUser{}
		f.keys = map[string]hsPreAuthKey{}
		f.nodes = nil
		f.policy = "{}"
		f.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]bool{"reset": true})
	})
	return mux
}

// ------------------------------------------------------------- mock429 CA ---

func mock429Handler() http.Handler {
	var nonceSeq atomic.Int64
	nextNonce := func(w http.ResponseWriter) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("mock429-%d", nonceSeq.Add(1)))
		w.Header().Set("Cache-Control", "no-store")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/dir", func(w http.ResponseWriter, r *http.Request) {
		base := "https://" + r.Host
		writeJSON(w, http.StatusOK, map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/acct",
			"newOrder":   base + "/order",
			"revokeCert": base + "/revoke",
			"keyChange":  base + "/key",
		})
	})
	mux.HandleFunc("/nonce", func(w http.ResponseWriter, _ *http.Request) {
		nextNonce(w)
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/acct", func(w http.ResponseWriter, r *http.Request) {
		nextNonce(w)
		w.Header().Set("Location", "https://"+r.Host+"/acct/1")
		writeJSON(w, http.StatusCreated, map[string]any{
			"status": "valid",
			"orders": "https://" + r.Host + "/acct/1/orders",
		})
	})
	mux.HandleFunc("/order", func(w http.ResponseWriter, _ *http.Request) {
		nextNonce(w)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, `{"type":"urn:ietf:params:acme:error:rateLimited","status":429,"detail":"simulated primary CA rate limit"}`)
	})
	return mux
}

// ------------------------------------------------------------------ util ----

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	penName := flag.String("pen-name", "bobo", "pen name under -pens-zone")
	pensZone := flag.String("pens-zone", "pens.hogman.network", "configurable pens zone")
	token := flag.String("token", "test-token", "bearer token for /v1/*")
	mgmtURL := flag.String("challtestsrv-mgmt", "http://challtestsrv:8055", "pebble-challtestsrv management URL")
	dnsUpstream := flag.String("challtestsrv-dns", "challtestsrv:8053", "pebble-challtestsrv DNS addr")
	eabKID := flag.String("eab-kid", "test-eab-kid", "fallback EAB key ID")
	eabHMAC := flag.String("eab-hmac", "", "fallback EAB base64url HMAC key")
	apiAddr := flag.String("api-addr", ":8080", "challenge-dns HTTP API listen address")
	dnsAddr := flag.String("dns-addr", ":8054", "DNS proxy listen address (empty to disable)")
	hsAddr := flag.String("hs-addr", ":8085", "Headscale mock listen address (empty to disable)")
	mock429Addr := flag.String("mock429-addr", "", "optional HTTPS mock 429 ACME listen address")
	tlsCert := flag.String("tls-cert", "", "TLS cert path for -mock429-addr")
	tlsKey := flag.String("tls-key", "", "TLS key path for -mock429-addr")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	chSrv := newChallengeServer(*penName, *pensZone, *token, *mgmtURL, *eabKID, *eabHMAC)
	apiHTTP := &http.Server{Addr: *apiAddr, Handler: chSrv.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("challenge-dns stub listening on %s (zone=%s.%s)", *apiAddr, *penName, *pensZone)
		if err := apiHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("api server: %v", err)
		}
	}()

	if *dnsAddr != "" {
		proxy := &dnsProxy{pensZone: normalizeFQDN(*pensZone), upstream: *dnsUpstream}
		if err := proxy.serve(ctx, *dnsAddr); err != nil {
			log.Fatalf("dns proxy: %v", err)
		}
		log.Printf("dns proxy listening on %s -> %s (SOA for %s)", *dnsAddr, *dnsUpstream, *pensZone)
	}

	var hsHTTP *http.Server
	if *hsAddr != "" {
		hs := newFakeHeadscale()
		hsHTTP = &http.Server{Addr: *hsAddr, Handler: hs.handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("fake headscale listening on %s", *hsAddr)
			if err := hsHTTP.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("headscale server: %v", err)
			}
		}()
	}

	var m429HTTP *http.Server
	if *mock429Addr != "" {
		if *tlsCert == "" || *tlsKey == "" {
			log.Fatal("-tls-cert and -tls-key are required with -mock429-addr")
		}
		m429HTTP = &http.Server{Addr: *mock429Addr, Handler: mock429Handler(), ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Printf("mock 429 ACME server listening on %s", *mock429Addr)
			if err := m429HTTP.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatalf("mock429 server: %v", err)
			}
		}()
	}

	<-ctx.Done()
	shut, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = apiHTTP.Shutdown(shut)
	if hsHTTP != nil {
		_ = hsHTTP.Shutdown(shut)
	}
	if m429HTTP != nil {
		_ = m429HTTP.Shutdown(shut)
	}
}
