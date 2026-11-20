package main

// Proofs from the site itself: a Stateless DANE site (HIP-17) serves a
// certificate with two extra extensions holding its proofs. The extension
// IDs are the ones htools-org/stateless-dane and randomlogin/sane use (HIP-17
// still lists them as "TBD"); Castell embeds the same.
//
// The checker connects to the site like a browser would (the address comes
// from Dit's own hnsd, the certificate is not trusted by itself), takes the
// proofs from the certificate, and at the end checks that the certificate's
// key is the one the proven TLSA record pins.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var (
	oidUrkelProof  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1620}
	oidDNSSECChain = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 54392, 5, 1621}
)

type siteCert struct {
	Address string
	Chain   []*x509.Certificate
	Urkel   []byte // nil when the certificate has no Urkel proof extension
	DNSSEC  []byte // nil when it has no DNSSEC chain extension
}

func (s *siteCert) hasProofs() bool { return s != nil && s.Urkel != nil && s.DNSSEC != nil }

// proofExtensions returns the raw extension values (the HIP-17 blobs)
func proofExtensions(cert *x509.Certificate) (urkel, chain []byte) {
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidUrkelProof):
			urkel = ext.Value
		case ext.Id.Equal(oidDNSSECChain):
			chain = ext.Value
		}
	}
	return urkel, chain
}

// resolveAddress asks Dit's own resolver (hnsd) for the site's address
func resolveAddress(name, resolver string) (string, error) {
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qtype)
		m.RecursionDesired = true
		res, _, err := client.Exchange(m, resolver)
		if err != nil {
			return "", err
		}
		for _, rr := range res.Answer {
			switch a := rr.(type) {
			case *dns.A:
				return a.A.String(), nil
			case *dns.AAAA:
				return a.AAAA.String(), nil
			}
		}
	}
	return "", fmt.Errorf("%s has no address", name)
}

// fetchSiteCert connects to name:443 and returns what the server presents.
// A variable so tests can replace it.
var fetchSiteCert = func(name, resolver string) (*siteCert, error) {
	ip, err := resolveAddress(name, resolver)
	if err != nil {
		return nil, err
	}
	addr := net.JoinHostPort(ip, "443")
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		ServerName: name,
		// Not trusted by itself: the proofs and the TLSA record decide
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", addr, err)
	}
	defer conn.Close()
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return nil, errors.New("the site sent no certificate")
	}
	s := &siteCert{Address: ip, Chain: chain}
	s.Urkel, s.DNSSEC = proofExtensions(chain[0])
	return s, nil
}

// keyMatches: does the served certificate match a proven TLSA record?
// DANE-EE (usage 3) pins the site's own certificate or key; DANE-TA (usage 2)
// pins a certificate higher in the chain the site sends.
func keyMatches(chain []*x509.Certificate, records []*dns.TLSA) (bool, string) {
	var seen []string
	for _, t := range records {
		switch t.Usage {
		case 3:
			if t.Verify(chain[0]) == nil {
				return true, "its own key"
			}
		case 2:
			for _, c := range chain[1:] {
				if t.Verify(c) == nil {
					return true, "the authority that issued it"
				}
			}
		}
		seen = append(seen, fmt.Sprintf("%d %d %d", t.Usage, t.Selector, t.MatchingType))
	}
	return false, strings.Join(seen, ", ")
}
