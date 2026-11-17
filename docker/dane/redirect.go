// v0.3: DANE without proxy settings ("redirect mode").
//
// Switched on from Dit's page (settings.json "redirect": enabled + an extra
// LAN address, the "redirect address"). The listeners below always run;
// while the feature is off the rewriter only passes answers through and
// nothing sends traffic to the fronts.
//
//  1. DNS rewriter (DIT_REWRITE_LISTEN, default 127.0.0.1:15351): while the
//     feature is on, dnsproxy forwards here instead of straight to hnsd.
//     A and AAAA (and HTTPS/SVCB) questions for a Handshake name whose
//     _443._tcp TLSA record is DNSSEC-validated get the redirect address (A)
//     or no records; everything else is passed through from hnsd unchanged.
//  2. SNI front (DIT_REDIRECT_TLS_PORT, default 9443): the host's firewall
//     sends <redirect address>:443 here (netsetup.go). It reads which name
//     the browser asked for from the TLS ClientHello and hands the connection
//     to the DANE proxy as a CONNECT, so the same DANE check and the same
//     name-constrained CA are used.
//  3. HTTP front (DIT_REDIRECT_HTTP_PORT, default 9080): from
//     <redirect address>:80; sends the browser to https://.
//
// The extra address is needed because umbrelOS serves its own HTTPS on
// port 443 of every address it has, for every name.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type redirectSettings struct {
	target    *redirectTarget
	listen    string // DNS rewriter
	upstream  string // hnsd's recursive resolver, unrewritten
	tlsPort   int
	httpPort  int
	proxyPort int
}

func redirectPorts() (tlsPort, httpPort int, err error) {
	tlsPort, err1 := strconv.Atoi(env("DIT_REDIRECT_TLS_PORT", "9443"))
	httpPort, err2 := strconv.Atoi(env("DIT_REDIRECT_HTTP_PORT", "9080"))
	if err1 != nil || err2 != nil {
		return 0, 0, errors.New("DIT_REDIRECT_TLS_PORT and DIT_REDIRECT_HTTP_PORT must be port numbers")
	}
	return tlsPort, httpPort, nil
}

func loadRedirectSettings(dataDir string, proxyPort int) (*redirectSettings, error) {
	tlsPort, httpPort, err := redirectPorts()
	if err != nil {
		return nil, err
	}
	return &redirectSettings{
		target:    watchRedirectTarget(dataDir, 2*time.Second),
		listen:    env("DIT_REWRITE_LISTEN", "127.0.0.1:15351"),
		upstream:  env("DIT_REWRITE_UPSTREAM", "127.0.0.1:15350"),
		tlsPort:   tlsPort,
		httpPort:  httpPort,
		proxyPort: proxyPort,
	}, nil
}

// handshakeName: the name lowercased without its final dot, if it is not an
// ICANN or special-use name (those are never redirected)
func handshakeName(name string, direct map[string]struct{}) (string, bool) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" || net.ParseIP(name) != nil {
		return "", false
	}
	tld := name[strings.LastIndex(name, ".")+1:]
	if _, icann := direct[tld]; icann {
		return "", false
	}
	return name, true
}

// ---------- DNS rewriter ----------

type daneCacheEntry struct {
	dane    bool
	expires time.Time
}

type rewriter struct {
	cfg    *redirectSettings
	direct map[string]struct{}
	client *dns.Client

	mu    sync.Mutex
	cache map[string]daneCacheEntry
}

func newRewriter(cfg *redirectSettings, direct map[string]struct{}) *rewriter {
	return &rewriter{
		cfg:    cfg,
		direct: direct,
		client: &dns.Client{Net: "udp", Timeout: 5 * time.Second, UDPSize: 4096},
		cache:  map[string]daneCacheEntry{},
	}
}

func (rw *rewriter) exchange(m *dns.Msg) (*dns.Msg, error) {
	r, _, err := rw.client.Exchange(m, rw.cfg.upstream)
	return r, err
}

// Does the name publish a DNSSEC-validated TLSA record for HTTPS that the
// DANE proxy can check (usage 2 DANE-TA or 3 DANE-EE)?
func (rw *rewriter) hasDANE(name string) bool {
	rw.mu.Lock()
	entry, ok := rw.cache[name]
	rw.mu.Unlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.dane
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("_443._tcp."+name), dns.TypeTLSA)
	m.SetEdns0(4096, true)
	m.AuthenticatedData = true
	r, err := rw.exchange(m)
	if err != nil {
		// Not cached: try again on the next question
		return false
	}
	dane := false
	ttl := uint32(60)
	if r.Rcode == dns.RcodeSuccess && r.AuthenticatedData {
		for _, rr := range r.Answer {
			if t, ok := rr.(*dns.TLSA); ok && (t.Usage == 2 || t.Usage == 3) {
				dane = true
				ttl = rr.Header().Ttl
			}
		}
	}
	if ttl > 300 {
		ttl = 300
	} else if ttl < 30 {
		ttl = 30
	}
	rw.mu.Lock()
	if len(rw.cache) > 10000 {
		rw.cache = map[string]daneCacheEntry{}
	}
	rw.cache[name] = daneCacheEntry{dane: dane, expires: time.Now().Add(time.Duration(ttl) * time.Second)}
	rw.mu.Unlock()
	return dane
}

// The answer to send: the upstream's, or a rewritten one for DANE names
func (rw *rewriter) answer(req *dns.Msg) *dns.Msg {
	redirectIP := rw.cfg.target.IP()
	if redirectIP != nil && len(req.Question) == 1 {
		q := req.Question[0]
		switch q.Qtype {
		case dns.TypeA, dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB:
			if name, ok := handshakeName(q.Name, rw.direct); ok && q.Qclass == dns.ClassINET && rw.hasDANE(name) {
				reply := new(dns.Msg)
				reply.SetReply(req)
				reply.RecursionAvailable = true
				// A rewritten answer is not the signed one: never claim it was validated
				reply.AuthenticatedData = false
				if q.Qtype == dns.TypeA {
					reply.Answer = []dns.RR{&dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   redirectIP,
					}}
				}
				// AAAA, HTTPS, SVCB: no records, so browsers use the IPv4 address
				return reply
			}
		}
	}

	r, err := rw.exchange(req)
	if err == nil && r.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: 5 * time.Second}
		if r2, _, err2 := tcp.Exchange(req, rw.cfg.upstream); err2 == nil {
			r = r2
		}
	}
	if err != nil {
		fail := new(dns.Msg)
		fail.SetRcode(req, dns.RcodeServerFailure)
		return fail
	}
	r.Id = req.Id
	return r
}

func (rw *rewriter) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	reply := rw.answer(req)
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		size := 512
		if opt := req.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		reply.Truncate(size)
	}
	if err := w.WriteMsg(reply); err != nil && rw.cfg != nil {
		log.Printf("dns: could not answer: %v", err)
	}
}

// ---------- SNI front ----------

// A net.Conn that only reads, from r: lets crypto/tls parse the ClientHello
// without sending anything back to the browser
type readOnlyConn struct {
	net.Conn
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c readOnlyConn) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

var errHelloRead = errors.New("client hello read")

// The server name the browser asked for, and the bytes read to find it
func peekSNI(conn net.Conn) (string, []byte, error) {
	var seen bytes.Buffer
	var name string
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	err := tls.Server(readOnlyConn{Conn: conn, r: io.TeeReader(conn, &seen)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			name = hello.ServerName
			return nil, errHelloRead
		},
	}).Handshake()
	if name == "" {
		if err == nil {
			err = errors.New("no server name")
		}
		return "", nil, fmt.Errorf("no server name in the TLS handshake: %w", err)
	}
	return name, seen.Bytes(), nil
}

func (rs *redirectSettings) serveTLS(client net.Conn, direct map[string]struct{}) {
	defer client.Close()
	if !allowedClient(client.RemoteAddr().String()) {
		return
	}
	sni, hello, err := peekSNI(client)
	if err != nil {
		return
	}
	name, ok := handshakeName(sni, direct)
	if !ok {
		log.Printf("redirect: refusing %q from %s: not a Handshake name", sni, client.RemoteAddr())
		return
	}

	// Hand the connection to the DANE proxy, as a browser with proxy settings would
	proxy, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", rs.proxyPort), 5*time.Second)
	if err != nil {
		log.Printf("redirect: DANE proxy unreachable: %v", err)
		return
	}
	defer proxy.Close()
	target := net.JoinHostPort(name, "443")
	fmt.Fprintf(proxy, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(proxy)
	res, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		log.Printf("redirect: %s: %v", name, err)
		return
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("redirect: %s: proxy answered %s", name, res.Status)
		return
	}
	if _, err := proxy.Write(hello); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(proxy, client); done <- struct{}{} }()
	go func() { io.Copy(client, br); done <- struct{}{} }()
	<-done
}

// ---------- start ----------

func startRedirect(cfg *redirectSettings, direct map[string]struct{}) error {
	rw := newRewriter(cfg, direct)
	for _, network := range []string{"udp", "tcp"} {
		server := &dns.Server{Addr: cfg.listen, Net: network, Handler: rw}
		started := make(chan error, 1)
		server.NotifyStartedFunc = func() { started <- nil }
		go func() {
			if err := server.ListenAndServe(); err != nil {
				started <- err
			}
		}()
		if err := <-started; err != nil {
			return fmt.Errorf("DNS rewriter on %s/%s: %w", cfg.listen, network, err)
		}
	}

	tlsListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.tlsPort))
	if err != nil {
		return err
	}
	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				log.Printf("redirect: accept: %v", err)
				time.Sleep(time.Second)
				continue
			}
			go cfg.serveTLS(conn, direct)
		}
	}()

	httpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.httpPort))
	if err != nil {
		return err
	}
	go http.Serve(httpListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		name, ok := handshakeName(host, direct)
		if !ok || !allowedClient(r.RemoteAddr) {
			http.Error(w, "Not a Handshake name.", http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, "https://"+name+r.URL.RequestURI(), http.StatusMovedPermanently)
	}))

	log.Printf("DNS rewriter on %s (upstream %s), redirect fronts on TLS %d and HTTP %d",
		cfg.listen, cfg.upstream, cfg.tlsPort, cfg.httpPort)
	return nil
}
