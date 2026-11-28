package mobile

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
)

func FuzzParseLinkJSON(f *testing.F) {
	f.Add("https://bobo.gate.example.com/join#t=abc")
	f.Add("https://bobo.gate.example.com/join#k=xyz&for=share")
	f.Add("hogman://join#t=abc")
	f.Add("")
	c := NewController()
	f.Fuzz(func(t *testing.T, raw string) {
		out := c.ParseLinkJSON(raw)
		var env jsonEnvelope
		if err := json.Unmarshal([]byte(out), &env); err != nil {
			t.Fatalf("ParseLinkJSON returned invalid JSON %q: %v", out, err)
		}
	})
}

func FuzzParseUpstreamDNSJSON(f *testing.F) {
	f.Add(`["1.1.1.1","8.8.8.8"]`)
	f.Add(`[]`)
	f.Add(`not-json`)
	f.Fuzz(func(t *testing.T, raw string) {
		_, _ = ParseUpstreamDNSJSON(raw)
	})
}

func FuzzSplitDNSResolveWire(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	stub := NewSplitDNSStub("bobo.pens.example.com", nil)
	stub.forwardPen = func(_ context.Context, raw []byte, _ netip.Addr) ([]byte, error) {
		return nil, nil
	}
	stub.forwardUpstream = func(_ context.Context, raw []byte, _ []netip.Addr) ([]byte, error) {
		return nil, nil
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = stub.ResolveWire(context.Background(), raw)
	})
}
