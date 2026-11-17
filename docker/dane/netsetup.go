package main

// "dit-dane net": the network helper behind DANE without proxy settings.
//
// Run by the "net" service: host network, root with only NET_ADMIN and
// NET_RAW. Every few seconds it compares what settings.json asks for with
// what it has set up, and fixes the difference:
//
//   - on: adds the redirect address to the interface whose subnet contains
//     it (after checking no other device answers for it), and two nat
//     PREROUTING rules tagged "dit-redirect":
//     <address>:443 -> local port DIT_REDIRECT_TLS_PORT (SNI front)
//     <address>:80  -> local port DIT_REDIRECT_HTTP_PORT (to https)
//     If the rules disappear (a firewall reload), it adds them again.
//   - off, or another address: removes the rules and the address.
//   - stopped (SIGTERM): removes everything.
//
// What it set up is kept in /data/net-state.json, so after a crash the next
// start can remove an address that is no longer wanted. The web page reads
// the same file for its status.

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const ruleTag = "dit-redirect"

type netState struct {
	// What is set up now
	Active bool   `json:"active"`
	IP     string `json:"ip,omitempty"`
	Dev    string `json:"dev,omitempty"`
	Prefix int    `json:"prefix,omitempty"`
	// Why it could not be set up, in words for the page
	Error     string    `json:"error,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type netHelper struct {
	dataDir  string
	tlsPort  int
	httpPort int
	ipt      string
	state    netState
}

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text != "" {
			return text, fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, text)
		}
		return text, fmt.Errorf("%s %s: %v", name, strings.Join(args, " "), err)
	}
	return text, nil
}

// Use the same iptables backend as the host: Docker's rules show which one.
// The default (nft) is checked first: listing the legacy tables can create
// them, and then every iptables call on the host warns about them.
func iptablesCommand() string {
	if out, err := run("iptables", "-t", "nat", "-S"); err == nil && strings.Contains(out, "DOCKER") {
		return "iptables"
	}
	if out, err := run("iptables-legacy", "-t", "nat", "-S"); err == nil && strings.Contains(out, "DOCKER") {
		return "iptables-legacy"
	}
	return "iptables"
}

// One line of "ip -o -4 addr show": interface and address/prefix
type ifaceAddr struct {
	dev    string
	ip     string
	prefix int
}

func ipv4Addrs() ([]ifaceAddr, error) {
	out, err := run("ip", "-o", "-4", "addr", "show")
	if err != nil {
		return nil, err
	}
	var list []ifaceAddr
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				parts := strings.SplitN(f[i+1], "/", 2)
				prefix, _ := strconv.Atoi(parts[len(parts)-1])
				list = append(list, ifaceAddr{dev: f[1], ip: parts[0], prefix: prefix})
				break
			}
		}
	}
	return list, nil
}

// The interface for ip: the one already carrying it, else the one whose
// subnet contains it. Also the prefix of that interface's own address.
func interfaceFor(ip string) (dev string, prefix int, err error) {
	addrs, err := ipv4Addrs()
	if err != nil {
		return "", 0, err
	}
	target := net.ParseIP(ip)
	for _, a := range addrs {
		if a.ip == ip {
			dev = a.dev
		}
	}
	if dev == "" {
		for _, a := range addrs {
			_, subnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", a.ip, a.prefix))
			if err == nil && a.dev != "lo" && subnet.Contains(target) {
				dev = a.dev
				break
			}
		}
	}
	if dev == "" || dev == "lo" {
		return "", 0, fmt.Errorf("%s is not on any of the Umbrel's networks: choose an address in the same range as the Umbrel (for example 192.168.1.x)", ip)
	}
	for _, a := range addrs {
		if a.dev == dev && a.ip != ip {
			return dev, a.prefix, nil
		}
	}
	return "", 0, fmt.Errorf("%s has no address of its own", dev)
}

func (h *netHelper) rule(action, ip string, port, toPort int) error {
	_, err := run(h.ipt, "-t", "nat", action, "PREROUTING", "-d", ip, "-p", "tcp", "--dport", strconv.Itoa(port),
		"-m", "comment", "--comment", ruleTag, "-j", "REDIRECT", "--to-ports", strconv.Itoa(toPort))
	return err
}

func (h *netHelper) ensureRules(ip string) error {
	for _, r := range [][2]int{{443, h.tlsPort}, {80, h.httpPort}} {
		if h.rule("-C", ip, r[0], r[1]) != nil {
			if err := h.rule("-A", ip, r[0], r[1]); err != nil {
				return err
			}
			log.Printf("added rule %s:%d -> %d", ip, r[0], r[1])
		}
	}
	return nil
}

// Delete every rule tagged dit-redirect, whatever address it is for
func (h *netHelper) removeRules() {
	out, err := run(h.ipt, "-t", "nat", "-S", "PREROUTING")
	if err != nil {
		log.Printf("could not list rules: %v", err)
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A PREROUTING") || !strings.Contains(line, "--comment "+ruleTag) {
			continue
		}
		args := append([]string{"-t", "nat", "-D"}, strings.Fields(line)[1:]...)
		if _, err := run(h.ipt, args...); err != nil {
			log.Printf("could not remove a rule: %v", err)
		}
	}
}

func (h *netHelper) teardown() {
	h.removeRules()
	if h.state.IP != "" && h.state.Dev != "" {
		if _, err := run("ip", "addr", "del", fmt.Sprintf("%s/%d", h.state.IP, h.state.Prefix), "dev", h.state.Dev); err == nil {
			log.Printf("removed %s from %s", h.state.IP, h.state.Dev)
		}
	}
	h.state = netState{}
}

func (h *netHelper) addressPresent() bool {
	addrs, err := ipv4Addrs()
	if err != nil {
		return true // cannot tell: leave it
	}
	for _, a := range addrs {
		if a.ip == h.state.IP && a.dev == h.state.Dev {
			return true
		}
	}
	return false
}

func (h *netHelper) setup(ip string) error {
	dev, prefix, err := interfaceFor(ip)
	if err != nil {
		return err
	}
	addrs, err := ipv4Addrs()
	if err != nil {
		return err
	}
	present := false
	for _, a := range addrs {
		if a.ip == ip && a.dev == dev {
			present = true
		}
	}
	if !present {
		// Duplicate address detection: exit 0 means nobody answered
		if _, err := run("arping", "-D", "-q", "-c", "2", "-w", "3", "-I", dev, ip); err != nil {
			return fmt.Errorf("another device on your network already uses %s: choose a free address outside your router's DHCP range", ip)
		}
		if _, err := run("ip", "addr", "add", fmt.Sprintf("%s/%d", ip, prefix), "dev", dev); err != nil {
			return err
		}
		log.Printf("added %s/%d to %s", ip, prefix, dev)
	}
	h.state = netState{Active: true, IP: ip, Dev: dev, Prefix: prefix}
	return h.ensureRules(ip)
}

func (h *netHelper) stateFile() string { return filepath.Join(h.dataDir, "net-state.json") }

func (h *netHelper) save() {
	h.state.UpdatedAt = time.Now().UTC()
	data, _ := json.MarshalIndent(h.state, "", "  ")
	if err := writeFile(h.stateFile(), append(data, '\n'), 0o644); err != nil {
		log.Printf("could not write the state file: %v", err)
	}
}

// One pass: make the system match the settings
func (h *netHelper) reconcile() {
	want := ""
	if ip := wantedRedirectIP(h.dataDir); ip != nil {
		want = ip.String()
	}
	if h.state.Active && h.state.IP != want {
		h.teardown()
	}
	switch {
	case want == "":
		h.state.Error = ""
	case h.state.Active && !h.addressPresent():
		// Gone (a reboot, a network restart): set it up again
		log.Printf("%s is no longer on %s, adding it again", h.state.IP, h.state.Dev)
		h.state = netState{}
		h.reconcile()
		return
	case h.state.Active:
		if err := h.ensureRules(want); err != nil {
			h.state.Error = err.Error()
		} else {
			h.state.Error = ""
		}
	default:
		if err := h.setup(want); err != nil {
			log.Printf("could not set up %s: %v", want, err)
			// Keep what was done so far, so the next pass or a stop removes it
			h.state.Error = err.Error()
		} else {
			h.state.Error = ""
			log.Printf("%s on %s: 443 -> %d, 80 -> %d (%s)", want, h.state.Dev, h.tlsPort, h.httpPort, h.ipt)
		}
	}
	h.save()
}

func runNetHelper() {
	tlsPort, httpPort, err := redirectPorts()
	if err != nil {
		log.Fatal(err)
	}
	h := &netHelper{dataDir: env("DIT_DATA", "/data"), tlsPort: tlsPort, httpPort: httpPort, ipt: iptablesCommand()}

	// Left from a crash: the address that was set up last time
	if data, err := os.ReadFile(h.stateFile()); err == nil {
		var previous netState
		if json.Unmarshal(data, &previous) == nil && previous.IP != "" {
			h.state = previous
		}
	}
	log.Printf("watching settings (iptables backend: %s)", h.ipt)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	h.reconcile()
	for {
		select {
		case <-stop:
			h.teardown()
			h.save()
			log.Printf("stopped, everything removed")
			return
		case <-tick.C:
			h.reconcile()
		}
	}
}
