package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

func TestHandshakeName(t *testing.T) {
	direct := map[string]struct{}{"com": {}, "local": {}}
	cases := map[string]string{
		"nathan.woodburn.": "nathan.woodburn",
		"MySite":           "mysite",
		"www.google.com.":  "",
		"umbrel.local":     "",
		"192.168.1.27":     "",
		"":                 "",
	}
	for in, want := range cases {
		got, ok := handshakeName(in, direct)
		if (want != "") != ok || got != want {
			t.Errorf("handshakeName(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestValidRedirectIP(t *testing.T) {
	for raw, ok := range map[string]bool{
		"192.168.1.200": true, "10.0.0.9": true,
		"8.8.8.8": false, "192.168.1.0": false, "192.168.1.255": false, "fd00::1": false, "nonsense": false,
	} {
		if (validRedirectIP(raw) != nil) != ok {
			t.Errorf("validRedirectIP(%q): want ok=%v", raw, ok)
		}
	}
}

func TestWantedRedirectIPFromSettings(t *testing.T) {
	t.Setenv("DIT_REDIRECT_IP", "")
	dir := t.TempDir()
	write := func(text string) {
		if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if wantedRedirectIP(dir) != nil {
		t.Error("no settings file: off")
	}
	write(`{"mode":"auto","redirect":{"enabled":false,"ip":"192.168.1.200"}}`)
	if wantedRedirectIP(dir) != nil {
		t.Error("disabled: off")
	}
	write(`{"mode":"auto","redirect":{"enabled":true,"ip":"192.168.1.200"}}`)
	if ip := wantedRedirectIP(dir); ip == nil || ip.String() != "192.168.1.200" {
		t.Errorf("enabled: got %v", ip)
	}
	write(`{"redirect":{"enabled":true,"ip":"8.8.8.8"}}`)
	if wantedRedirectIP(dir) != nil {
		t.Error("public address: off")
	}
}

// A fake hnsd: dane.test has a validated TLSA record, plain.test has none,
// both have an A record
func fakeUpstream(t *testing.T) string {
	t.Helper()
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		switch {
		case q.Qtype == dns.TypeTLSA && q.Name == "_443._tcp.dane.test.":
			m.AuthenticatedData = true
			rr, _ := dns.NewRR("_443._tcp.dane.test. 300 IN TLSA 3 1 1 d09b780f703ddf9f00a52dd6ded78f26d5c2f1a4f6e1e7e0c5ab1c7b9e4b1a20")
			m.Answer = append(m.Answer, rr)
		case q.Qtype == dns.TypeA:
			m.AuthenticatedData = true
			rr, _ := dns.NewRR(q.Name + " 300 IN A 203.0.113.7")
			m.Answer = append(m.Answer, rr)
		}
		w.WriteMsg(m)
	})
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: conn, Handler: mux}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return conn.LocalAddr().String()
}

func TestRewriter(t *testing.T) {
	target := &redirectTarget{}
	cfg := &redirectSettings{target: target, upstream: fakeUpstream(t)}
	rw := newRewriter(cfg, map[string]struct{}{"com": {}})
	ask := func(name string, qtype uint16) *dns.Msg {
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		return rw.answer(m)
	}
	firstA := func(m *dns.Msg) string {
		for _, rr := range m.Answer {
			if a, ok := rr.(*dns.A); ok {
				return a.A.String()
			}
		}
		return ""
	}

	// Off: everything passes through
	if got := firstA(ask("dane.test.", dns.TypeA)); got != "203.0.113.7" {
		t.Errorf("off: dane.test A = %q", got)
	}

	ip := net.ParseIP("192.168.1.200").To4()
	target.current.Store(&ip)
	rw.cache = map[string]daneCacheEntry{}

	if got := firstA(ask("dane.test.", dns.TypeA)); got != "192.168.1.200" {
		t.Errorf("on: dane.test A = %q, want the redirect address", got)
	}
	if m := ask("dane.test.", dns.TypeAAAA); len(m.Answer) != 0 || m.Rcode != dns.RcodeSuccess {
		t.Errorf("on: dane.test AAAA should be empty, got %v", m.Answer)
	}
	if m := ask("dane.test.", dns.TypeA); m.AuthenticatedData {
		t.Error("a rewritten answer must not claim DNSSEC validation")
	}
	if got := firstA(ask("plain.test.", dns.TypeA)); got != "203.0.113.7" {
		t.Errorf("on: plain.test (no TLSA) A = %q, want unchanged", got)
	}
	if got := firstA(ask("www.example.com.", dns.TypeA)); got != "203.0.113.7" {
		t.Errorf("on: ICANN name A = %q, want unchanged", got)
	}

	// Switched off again: no more rewriting, even with the DANE answer cached
	target.current.Store(nil)
	if got := firstA(ask("dane.test.", dns.TypeA)); got != "203.0.113.7" {
		t.Errorf("off again: dane.test A = %q", got)
	}
}
