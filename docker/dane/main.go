// dit-dane: Dit's DANE proxy, the "dane" service.
//
// Browsers do not check DANE (TLSA records), so a site secured only by its
// TLSA record shows a certificate warning. This proxy, built on letsdane
// (github.com/buffrr/letsdane, Apache-2.0, as in Fingertip), sits between
// the browser and Handshake sites: it checks the site's certificate against
// its DNSSEC-validated TLSA record and re-signs the connection with a local
// CA that each device installs once.
//
//   - Resolver: Dit's own dnsproxy on the Umbrel's loopback (port 5300, open in
//     every listening mode). letsdane trusts the AD flag of a loopback resolver;
//     hnsd validates and dnsproxy passes the flag through.
//   - CA: created on first start in /data/dane. Its name constraints exclude
//     every ICANN top-level domain (IANA's list, downloaded at image build), so
//     even a stolen key cannot sign certificates for gmail.com or a bank.
//   - The proxy also serves, to plain (non-proxy) requests:
//     /proxy.pac     the auto-config file: ICANN names and IPs go direct,
//     everything else (Handshake names) through this proxy
//     /dit-dane.crt  the CA certificate to install on each device
//     They need no Umbrel login, since devices fetch them by themselves.
//   - Only clients on private networks may use it (LAN, Tailscale, loopback).
//   - Writes /data/dane-state.json for the web page.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/buffrr/letsdane"
	rs "github.com/buffrr/letsdane/resolver"
)

// Names that are never Handshake names: special-use names (RFC 6761 and
// friends) besides the ICANN list. They go direct and the CA may not sign them.
var specialUse = []string{"local", "localhost", "onion", "test", "invalid", "example", "internal", "alt", "home.arpa"}

const (
	caName     = "Dit DANE (Umbrel)"
	caValidity = 5 * 365 * 24 * time.Hour
)

type settings struct {
	dataDir  string
	port     int
	resolver string
	tldFile  string
	verbose  bool
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func loadSettings() settings {
	port, err := strconv.Atoi(env("DIT_DANE_PORT", "9053"))
	if err != nil || port < 1 || port > 65535 {
		log.Fatalf("DIT_DANE_PORT must be a port number")
	}
	return settings{
		dataDir:  env("DIT_DATA", "/data"),
		port:     port,
		resolver: env("DIT_DANE_RESOLVER", "127.0.0.1:5300"),
		tldFile:  env("DIT_DANE_TLDS", "/opt/dit/icann-tlds.txt"),
		verbose:  os.Getenv("DIT_DANE_VERBOSE") == "true",
	}
}

// IANA's tlds-alpha-by-domain.txt: a "#" header line, then one TLD per line
func loadTLDs(file string) (map[string]struct{}, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tlds := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.ToLower(strings.TrimSpace(sc.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tlds[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	// A truncated download must not produce a CA that can sign ICANN names
	if len(tlds) < 1000 {
		return nil, fmt.Errorf("only %d TLDs in %s, expected over 1000", len(tlds), file)
	}
	for _, name := range specialUse {
		tlds[name] = struct{}{}
	}
	return tlds, nil
}

// ---------- CA ----------

type authority struct {
	cert     *x509.Certificate
	key      interface{}
	pem      []byte
	certFile string
}

func writeFile(file string, data []byte, mode os.FileMode) error {
	tmp := file + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

func loadOrCreateCA(dir string, constraints map[string]struct{}) (*authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certFile := filepath.Join(dir, "ca.crt")
	keyFile := filepath.Join(dir, "ca.key")

	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	switch {
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		log.Printf("creating a new CA in %s", dir)
		cert, key, err := letsdane.NewAuthority(caName, "Dit", caValidity, constraints)
		if err != nil {
			return nil, fmt.Errorf("could not create the CA: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		// Key first: a certificate without its key would block the next start
		if err := writeFile(keyFile, keyPEM, 0o600); err != nil {
			return nil, err
		}
		if err := writeFile(certFile, certPEM, 0o644); err != nil {
			return nil, err
		}
	case certErr != nil || keyErr != nil:
		return nil, fmt.Errorf("%s and %s must both exist or both be missing; delete the one left to create a new CA", certFile, keyFile)
	}

	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("could not load the CA: %w", err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	return &authority{cert: cert, key: pair.PrivateKey, pem: certPEM, certFile: certFile}, nil
}

func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	parts := make([]string, 0, len(sum))
	for i := 0; i < len(hexed); i += 2 {
		parts = append(parts, hexed[i:i+2])
	}
	return strings.Join(parts, ":")
}

// ---------- PAC file ----------

// The JavaScript that browsers run for every URL: ICANN and special-use names
// and IP addresses go direct, everything else (Handshake names) to the proxy.
func pacScript(proxy string, direct map[string]struct{}) string {
	names := make([]string, 0, len(direct))
	for name := range direct {
		// home.arpa and other multi-label names are covered by their TLD here
		if !strings.Contains(name, ".") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	var list strings.Builder
	for i, name := range names {
		if i > 0 {
			list.WriteString(",")
		}
		list.WriteString(strconv.Quote(name) + ":1")
	}
	return fmt.Sprintf(`// Dit: send Handshake names through the DANE proxy on your Umbrel
var direct = {%s};

function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  if (host.charAt(host.length - 1) == ".") host = host.substring(0, host.length - 1);

  // IPv4 and IPv6 addresses
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.indexOf(":") != -1) return "DIRECT";

  var tld = host.substring(host.lastIndexOf(".") + 1);
  if (direct.hasOwnProperty(tld)) return "DIRECT";

  return "PROXY %s";
}
`, list.String(), proxy)
}

// ---------- requests ----------

// Private, loopback, link-local and Tailscale (100.64.0.0/10) addresses
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func allowedClient(remote string) bool {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || cgnat.Contains(ip)
}

// The address devices should use for the proxy: the one they reached us on
func proxyAddress(r *http.Request, port int) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	if host == "" || net.ParseIP(strings.Trim(host, "[]")) == nil {
		// A name we cannot vouch for: fall back to the address the request arrived on
		if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
			if h, _, err := net.SplitHostPort(addr.String()); err == nil {
				host = h
			}
		}
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func contentHandler(ca *authority, direct map[string]struct{}, port int) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/proxy.pac", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprint(w, pacScript(proxyAddress(r, port), direct))
	})
	mux.HandleFunc("/dit-dane.crt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="dit-dane.crt"`)
		w.Write(ca.pem)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "Dit DANE proxy\n\nAuto-config (PAC) file: /proxy.pac\nCA certificate: /dit-dane.crt\nCA SHA-256 fingerprint: %s\n\nSet up your devices from Dit's page on your Umbrel.\n", fingerprint(ca.cert))
	})
	return mux
}

// ---------- state file for the web page ----------

type state struct {
	Running       bool      `json:"running"`
	Port          int       `json:"port"`
	Resolver      string    `json:"resolver"`
	CAFingerprint string    `json:"caFingerprint"`
	CANotAfter    time.Time `json:"caNotAfter"`
	DirectTLDs    int       `json:"directTlds"`
	StartedAt     time.Time `json:"startedAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
}

func writeState(file string, s state) {
	s.UpdatedAt = time.Now().UTC()
	data, _ := json.MarshalIndent(s, "", "  ")
	if err := writeFile(file, append(data, '\n'), 0o644); err != nil {
		log.Printf("could not write the state file: %v", err)
	}
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("[dit-dane] ")
	cfg := loadSettings()
	letsdane.Version = "0.6.1 (Dit)"

	direct, err := loadTLDs(cfg.tldFile)
	if err != nil {
		log.Fatalf("could not load the ICANN TLD list: %v", err)
	}
	ca, err := loadOrCreateCA(filepath.Join(cfg.dataDir, "dane"), direct)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("CA %q, SHA-256 %s, valid until %s", ca.cert.Subject.CommonName, fingerprint(ca.cert), ca.cert.NotAfter.Format("2006-01-02"))

	resolver, err := rs.NewStub(cfg.resolver)
	if err != nil {
		log.Fatalf("resolver %s: %v", cfg.resolver, err)
	}

	proxyConfig := &letsdane.Config{
		Certificate: ca.cert,
		PrivateKey:  ca.key,
		Validity:    time.Hour,
		Resolver:    resolver,
		// ICANN names are not looked up for TLSA: tunnelled as they are
		Constraints:    direct,
		SkipNameChecks: false,
		Verbose:        cfg.verbose,
		ContentHandler: contentHandler(ca, direct, cfg.port),
	}
	proxyHandler, err := proxyConfig.NewHandler()
	if err != nil {
		log.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowedClient(r.RemoteAddr) {
			http.Error(w, "Dit's DANE proxy only serves your local network.", http.StatusForbidden)
			return
		}
		proxyHandler.ServeHTTP(w, r)
	})

	addr := fmt.Sprintf(":%d", cfg.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("could not listen on port %d: %v", cfg.port, err)
	}
	log.Printf("listening on port %d, resolving through %s", cfg.port, cfg.resolver)

	stateFile := filepath.Join(cfg.dataDir, "dane-state.json")
	current := state{
		Running:       true,
		Port:          cfg.port,
		Resolver:      cfg.resolver,
		CAFingerprint: fingerprint(ca.cert),
		CANotAfter:    ca.cert.NotAfter.UTC(),
		DirectTLDs:    len(direct),
		StartedAt:     time.Now().UTC(),
	}
	writeState(stateFile, current)
	go func() {
		for range time.Tick(10 * time.Second) {
			writeState(stateFile, current)
		}
	}()

	// No write timeout: CONNECT tunnels stay open as long as the browser needs
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 15 * time.Second}
	log.Fatal(server.Serve(listener))
}
