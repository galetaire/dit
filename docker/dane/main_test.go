package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTLDs(t *testing.T, count int) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("# Version 2026111700, Last Updated Mon Nov 17 07:07:01 2026 UTC\n")
	b.WriteString("COM\nORG\n")
	for i := 0; i < count; i++ {
		b.WriteString("tld" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26)) + "\n")
	}
	file := filepath.Join(t.TempDir(), "tlds.txt")
	if err := os.WriteFile(file, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestLoadTLDs(t *testing.T) {
	tlds, err := loadTLDs(writeTLDs(t, 1200))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"com", "org", "local", "localhost", "onion"} {
		if _, ok := tlds[name]; !ok {
			t.Errorf("%q missing", name)
		}
	}
	if _, ok := tlds["# version 2026111700, last updated mon nov 17 07:07:01 2026 utc"]; ok {
		t.Error("header line read as a TLD")
	}
}

func TestLoadTLDsRejectsShortList(t *testing.T) {
	if _, err := loadTLDs(writeTLDs(t, 10)); err == nil {
		t.Fatal("a truncated list must be rejected")
	}
}

func TestAllowedClient(t *testing.T) {
	cases := map[string]bool{
		"192.168.1.40:5123":     true,
		"10.0.0.5:80":           true,
		"172.16.3.3:80":         true,
		"127.0.0.1:9":           true,
		"[::1]:9":               true,
		"[fd7a:115c:a1e0::1]:9": true, // Tailscale IPv6 (ULA)
		"100.93.247.127:9":      true, // Tailscale IPv4
		"[fe80::1]:9":           true,
		"8.8.8.8:53":            false,
		"100.128.0.1:9":         false, // just outside 100.64.0.0/10
		"[2001:db8::1]:9":       false,
		"garbage":               false,
	}
	for addr, want := range cases {
		if got := allowedClient(addr); got != want {
			t.Errorf("allowedClient(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestPACScript(t *testing.T) {
	pac := pacScript("192.168.1.27:9053", map[string]struct{}{"com": {}, "home.arpa": {}, "local": {}})
	if !strings.Contains(pac, `return "PROXY 192.168.1.27:9053";`) {
		t.Error("proxy address missing")
	}
	if !strings.Contains(pac, `var direct = {"com":1,"local":1};`) {
		t.Errorf("unexpected direct list in:\n%s", pac)
	}
}

func TestCAIsNameConstrained(t *testing.T) {
	tlds, err := loadTLDs(writeTLDs(t, 1200))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ca, err := loadOrCreateCA(dir, tlds)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.cert.IsCA || !ca.cert.PermittedDNSDomainsCritical {
		t.Error("CA must be a CA with critical name constraints")
	}
	excluded := map[string]bool{}
	for _, name := range ca.cert.ExcludedDNSDomains {
		excluded[name] = true
	}
	// letsdane writes ".com": every name under com
	if !excluded[".com"] || !excluded[".localhost"] {
		t.Errorf(".com and .localhost must be excluded, got %d names", len(excluded))
	}
	if info, err := os.Stat(filepath.Join(dir, "ca.key")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("key file must be 0600: %v %v", info, err)
	}

	// A second start loads the same CA instead of making a new one
	again, err := loadOrCreateCA(dir, tlds)
	if err != nil {
		t.Fatal(err)
	}
	if !again.cert.Equal(ca.cert) {
		t.Error("CA changed on restart")
	}

	// The point of the constraints: a certificate this CA signs verifies for
	// a Handshake name, and is rejected for a regular (ICANN) one
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	for name, wantOK := range map[string]bool{"nathan.woodburn": true, "mysite": true, "www.com": false, "mail.org": false} {
		leaf := signLeaf(t, ca, name)
		_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name})
		if (err == nil) != wantOK {
			t.Errorf("leaf for %q: verify error %v, want ok=%v", name, err, wantOK)
		}
	}
}

func signLeaf(t *testing.T, ca *authority, name string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestCAHalfMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateCA(dir, map[string]struct{}{"com": {}}); err == nil {
		t.Fatal("a certificate without its key must be an error")
	}
}
