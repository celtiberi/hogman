package dns

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type stubLookup struct {
	names map[string]string
	err   error
}

func (s *stubLookup) LookupNameIPv4(rel string) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	ip, ok := s.names[rel]
	return ip, ok, nil
}

func (s *stubLookup) HasResolvableChild(rel string) (bool, error) {
	if s.err != nil {
		return false, s.err
	}
	suffix := "." + rel
	for k := range s.names {
		if strings.HasSuffix(k, suffix) {
			return true, nil
		}
	}
	return false, nil
}

func queryPacket(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	qn, err := dnsmessage.NewName(name)
	if err != nil {
		t.Fatalf("NewName(%q): %v", name, err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x4242, RecursionDesired: true})
	_ = b.StartQuestions()
	_ = b.Question(dnsmessage.Question{Name: qn, Type: qtype, Class: dnsmessage.ClassINET})
	raw, err := b.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return raw
}

func TestServerIsolatedWithStubLookup(t *testing.T) {
	lookup := &stubLookup{names: map[string]string{
		"blog":       "100.64.0.10",
		"app.photos": "100.64.0.11",
	}}
	srv, err := NewServer("demo.pens.example", netip.MustParseAddr("100.64.0.1"), lookup)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := srv.SelfCheck(); err != nil {
		t.Fatalf("SelfCheck: %v", err)
	}

	// Active A lookup.
	resp, ok := srv.HandlePacket(queryPacket(t, "blog.demo.pens.example.", dnsmessage.TypeA), false)
	if !ok {
		t.Fatal("expected response for blog")
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeSuccess || !hdr.Authoritative {
		t.Fatalf("blog header = %+v, err=%v", hdr, err)
	}
	_ = p.SkipAllQuestions()
	ah, err := p.AnswerHeader()
	if err != nil || ah.Type != dnsmessage.TypeA {
		t.Fatalf("blog answer header = %+v, err=%v", ah, err)
	}
	a, err := p.AResource()
	if err != nil || netip.AddrFrom4(a.A) != netip.MustParseAddr("100.64.0.10") {
		t.Fatalf("blog A = %v, err=%v", netip.AddrFrom4(a.A), err)
	}

	// Empty non-terminal (photos has child app.photos): NOERROR + SOA authority, no answers.
	resp, ok = srv.HandlePacket(queryPacket(t, "photos.demo.pens.example.", dnsmessage.TypeA), false)
	if !ok {
		t.Fatal("expected response for ENT photos")
	}
	hdr, err = p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("ENT rcode = %v, want NOERROR", hdr.RCode)
	}

	// Unknown name: NXDOMAIN.
	resp, ok = srv.HandlePacket(queryPacket(t, "nope.demo.pens.example.", dnsmessage.TypeA), false)
	if !ok {
		t.Fatal("expected response for NXDOMAIN")
	}
	hdr, err = p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unknown rcode = %v, want NXDOMAIN", hdr.RCode)
	}

	// Out-of-zone query: REFUSED.
	resp, ok = srv.HandlePacket(queryPacket(t, "example.com.", dnsmessage.TypeA), false)
	if !ok {
		t.Fatal("expected response for out-of-zone")
	}
	hdr, err = p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("out-of-zone rcode = %v, want REFUSED", hdr.RCode)
	}

	// Backing lookup error: SERVFAIL.
	lookup.err = errors.New("db down")
	resp, ok = srv.HandlePacket(queryPacket(t, "blog.demo.pens.example.", dnsmessage.TypeA), false)
	if !ok {
		t.Fatal("expected response for lookup error")
	}
	hdr, err = p.Start(resp)
	if err != nil || hdr.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("lookup error rcode = %v, want SERVFAIL", hdr.RCode)
	}
}
