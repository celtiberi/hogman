package main

import (
	"strings"
	"testing"
)

func TestQRSVG(t *testing.T) {
	link := "https://bobo.gate.example.com/join#k=hskey-auth-abcdefghijklmnop-qrstuvwxyz0123456789"
	svg, err := qrSVG(link)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, "<svg ") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("not an SVG: %.60s", svg)
	}
	if strings.Count(svg, "h1v1h-1z") < 100 {
		t.Fatalf("too few modules for a %d-character link", len(link))
	}
	if strings.Contains(svg, "hskey") {
		t.Fatal("the secret must only be encoded, never written into the SVG as text")
	}
}
