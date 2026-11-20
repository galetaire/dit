package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"
)

// belikebill's certificate as Castell 0.4.0 served it on 21 Nov 2026, with
// both HIP-17 extensions (testdata/belikebill.crt)
var belikebillDay = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func loadCert(t *testing.T, file string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// Replace the network: the "site" serves this chain
func serveChain(t *testing.T, chain []*x509.Certificate, err error) {
	t.Helper()
	old := fetchSiteCert
	fetchSiteCert = func(name, resolver string) (*siteCert, error) {
		if err != nil {
			return nil, err
		}
		s := &siteCert{Address: "192.0.2.10", Chain: chain}
		s.Urkel, s.DNSSEC = proofExtensions(chain[0])
		return s, nil
	}
	t.Cleanup(func() { fetchSiteCert = old })
}

// Tree roots that include the one belikebill's proof is anchored to
func belikebillRoots(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	urkel, _ := proofExtensions(cert)
	proofs, err := decodeUrkelBlob(urkel)
	if err != nil {
		t.Fatal(err)
	}
	return writeRoots(t, []storedRoot{{Root: hex.EncodeToString(proofs[0].root), Height: 355465, Time: belikebillDay.Add(-8 * 24 * time.Hour).Unix()}})
}

func TestBelikebillCertificateCarriesProofs(t *testing.T) {
	cert := loadCert(t, "testdata/belikebill.crt")
	urkel, chain := proofExtensions(cert)
	if urkel == nil || chain == nil {
		t.Fatal("expected both HIP-17 extensions")
	}
	t.Logf("Urkel %d bytes, DNSSEC chain %d bytes", len(urkel), len(chain))
}

func TestCheckReadsProofsFromCertificate(t *testing.T) {
	cert := loadCert(t, "testdata/belikebill.crt")
	serveChain(t, []*x509.Certificate{cert}, nil)
	r := check("belikebill", belikebillRoots(t, cert), "", "", "", nil, belikebillDay)
	for _, s := range r.Steps {
		t.Logf("%-12s %v  %s", s.ID, s.OK, s.Detail)
	}
	if !r.OK || r.Source != "certificate" {
		t.Fatalf("ok=%v source=%s, want a verified check from the certificate", r.OK, r.Source)
	}
	if last := lastStep(r); last.ID != "key" || !last.OK {
		t.Fatalf("last step %s ok=%v, want key ok", last.ID, last.OK)
	}
}

// A server with belikebill's proofs but another key: the proofs verify, but
// the key step must fail (someone replaying the proofs on their own server)
func TestCheckRejectsCertificateWithOtherKey(t *testing.T) {
	real := loadCert(t, "testdata/belikebill.crt")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "belikebill"},
		DNSNames:     []string{"belikebill"},
		NotBefore:    belikebillDay.Add(-time.Hour),
		NotAfter:     belikebillDay.Add(time.Hour),
	}
	for _, ext := range real.Extensions {
		if ext.Id.Equal(oidUrkelProof) || ext.Id.Equal(oidDNSSECChain) {
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	fake, _ := x509.ParseCertificate(der)
	serveChain(t, []*x509.Certificate{fake}, nil)
	r := check("belikebill", belikebillRoots(t, real), "", "", "", nil, belikebillDay)
	if r.OK || lastStep(r).ID != "key" {
		t.Fatalf("ok=%v at %s, want failure at the key step", r.OK, lastStep(r).ID)
	}
}

// No connection and no proof service: a clear failure at the first step
func TestCheckWithoutSiteOrService(t *testing.T) {
	serveChain(t, nil, errors.New("connection refused"))
	r := check("belikebill", "", "", "", "", []string{"http://127.0.0.1:1/proofs/"}, belikebillDay)
	if r.OK || len(r.Steps) != 1 || r.Steps[0].ID != "proofs" {
		t.Fatalf("want one failed proofs step, got %+v", r.Steps)
	}
}
