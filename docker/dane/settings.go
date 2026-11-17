package main

// Dit's settings.json, written by the web server (docker/web/server.js).
// The Go side only reads the "redirect" part: whether DANE without proxy
// settings is on, and the extra LAN address it uses.

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type appSettings struct {
	Redirect struct {
		Enabled bool   `json:"enabled"`
		IP      string `json:"ip"`
	} `json:"redirect"`
}

func settingsFile(dataDir string) string { return filepath.Join(dataDir, "settings.json") }

// The redirect address wanted right now, or nil when the feature is off.
// DIT_REDIRECT_IP, when set, overrides the settings (for testing).
func wantedRedirectIP(dataDir string) net.IP {
	raw := strings.TrimSpace(os.Getenv("DIT_REDIRECT_IP"))
	if raw == "" {
		data, err := os.ReadFile(settingsFile(dataDir))
		if err != nil {
			return nil
		}
		var s appSettings
		if json.Unmarshal(data, &s) != nil || !s.Redirect.Enabled {
			return nil
		}
		raw = strings.TrimSpace(s.Redirect.IP)
	}
	return validRedirectIP(raw)
}

// A private IPv4 address, not a network or broadcast-looking .0/.255
func validRedirectIP(raw string) net.IP {
	ip := net.ParseIP(raw).To4()
	if ip == nil || !ip.IsPrivate() || ip[3] == 0 || ip[3] == 255 {
		return nil
	}
	return ip
}

// Keeps the wanted redirect address up to date, polling settings.json
type redirectTarget struct {
	current atomic.Pointer[net.IP]
}

func watchRedirectTarget(dataDir string, every time.Duration) *redirectTarget {
	t := &redirectTarget{}
	update := func() {
		ip := wantedRedirectIP(dataDir)
		if ip == nil {
			t.current.Store(nil)
		} else {
			t.current.Store(&ip)
		}
	}
	update()
	go func() {
		for range time.Tick(every) {
			update()
		}
	}()
	return t
}

// The address to answer with, or nil when DANE without proxy settings is off
func (t *redirectTarget) IP() net.IP {
	if p := t.current.Load(); p != nil {
		return *p
	}
	return nil
}
