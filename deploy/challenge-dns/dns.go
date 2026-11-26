package main

// Authoritative answers for the two delegated zones, and nothing else:
//   pens zone (e.g. pens.hogman.network): SOA, NS, CAA at the apex; TXT for
//     _acme-challenge names; NODATA for every other name and type.
//   gate challenge name (e.g. _acme-challenge.gate.hogman.network): SOA, NS,
//     and the front door's TXT.
// Never an address record. Names under a zone are never NXDOMAIN (RFC 8020:
// an NXDOMAIN would tell resolvers that nothing exists below that name,
// including the challenge records), so every miss is NOERROR with no answer
// and the SOA in the authority section. Outside the zones: REFUSED.

import (
	"net"
	"strings"

	"github.com/miekg/dns"
)

type DNS struct {
	store *Store
	zones Zones
	ns    string    // our nameserver's name, e.g. ns1.hogman.network
	mbox  string    // SOA contact, e.g. hostmaster.hogman.network
	caa   []dns.CAA // records at the pens apex
}

const (
	answerTTL = 60  // TXT and the like: short, they change
	apexTTL   = 300 // SOA, NS, CAA
	negTTL    = 60  // how long a "no such record" may be cached
)

func (d *DNS) zoneOf(name string) string {
	n := normalize(name)
	for _, z := range []string{d.zones.Pens, d.zones.Gate} {
		if n == z || strings.HasSuffix(n, "."+z) {
			return z
		}
	}
	return ""
}

func (d *DNS) soa(owner string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: dns.Fqdn(owner), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: apexTTL},
		Ns:      dns.Fqdn(d.ns),
		Mbox:    dns.Fqdn(d.mbox),
		Serial:  2026112101,
		Refresh: 3600, Retry: 600, Expire: 86400, Minttl: negTTL,
	}
}

func clampedEDNS0Size(opt *dns.OPT) uint16 {
	size := opt.UDPSize()
	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}
	if size > 1232 {
		return 1232
	}
	return size
}

func (d *DNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r) // copies the question exactly, keeping the asker's letter case (0x20)
	m.Compress = true
	if len(r.Question) != 1 || r.Opcode != dns.OpcodeQuery {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	q := r.Question[0]
	zone := d.zoneOf(q.Name)
	if zone == "" || q.Qclass != dns.ClassINET {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}
	m.Authoritative = true
	// The zone apex, written in the asker's own letter case when possible.
	zoneFQDN := dns.Fqdn(zone)
	qNameFQDN := dns.Fqdn(q.Name)
	m.Question[0].Name = qNameFQDN
	apexOwner := zoneFQDN
	if len(qNameFQDN) >= len(zoneFQDN) && strings.EqualFold(qNameFQDN[len(qNameFQDN)-len(zoneFQDN):], zoneFQDN) {
		apexOwner = qNameFQDN[len(qNameFQDN)-len(zoneFQDN):]
	}
	isApex := normalize(q.Name) == zone
	hdr := func(t uint16, ttl uint32) dns.RR_Header {
		return dns.RR_Header{Name: qNameFQDN, Rrtype: t, Class: dns.ClassINET, Ttl: ttl}
	}

	switch {
	case q.Qtype == dns.TypeTXT && (strings.HasPrefix(normalize(q.Name), acmePrefix) || normalize(q.Name) == d.zones.Gate):
		for _, v := range d.store.TXT(q.Name) {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr(dns.TypeTXT, answerTTL), Txt: []string{v}})
		}
	case isApex && q.Qtype == dns.TypeSOA:
		m.Answer = append(m.Answer, d.soa(q.Name))
	case isApex && q.Qtype == dns.TypeNS:
		m.Answer = append(m.Answer, &dns.NS{Hdr: hdr(dns.TypeNS, apexTTL), Ns: dns.Fqdn(d.ns)})
	case isApex && q.Qtype == dns.TypeCAA && zone == d.zones.Pens:
		for _, c := range d.caa {
			rr := c
			rr.Hdr = hdr(dns.TypeCAA, apexTTL)
			m.Answer = append(m.Answer, &rr)
		}
	}
	if len(m.Answer) == 0 {
		m.Ns = append(m.Ns, d.soa(apexOwner))
	}
	opt := r.IsEdns0()
	if opt != nil {
		m.SetEdns0(clampedEDNS0Size(opt), false)
	}
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if opt != nil {
			size = int(clampedEDNS0Size(opt))
		}
		m.Truncate(size)
	}
	_ = w.WriteMsg(m)
}

// defaultCAA: only Let's Encrypt and Google Trust Services, only by DNS-01,
// and no wildcards anywhere under the pens zone.
func defaultCAA() []dns.CAA {
	return []dns.CAA{
		{Flag: 0, Tag: "issue", Value: "letsencrypt.org; validationmethods=dns-01"},
		{Flag: 0, Tag: "issue", Value: "pki.goog; validationmethods=dns-01"},
		{Flag: 0, Tag: "issuewild", Value: ";"},
	}
}
