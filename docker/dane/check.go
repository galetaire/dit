package main

// "dit-dane check -name <name>": the Stateless DANE checker (beta).
//
// Takes a name's HIP-17 proofs (Urkel proof + DNSSEC chain) from the site's
// own certificate (sitecert.go), or from a public proof service when the
// certificate carries none, and verifies them offline against the tree roots
// that Dit's own hnsd synced. Neither source is trusted: every step is
// checked here.
// Prints one JSON object with the steps, for the web server (server.js),
// which runs this command in its own container (same image).
//
// Steps:
//  1. proofs  read from the site's certificate, else fetched from a service
//  2. urkel   the Urkel proof leads to the tree root it names, and proves the
//             on-chain state of the top-level name
//  3. root    that tree root is one Dit's hnsd synced, and recent enough
//  4. ds      the proven state has DS records (the name's DNSSEC anchor)
//  5. dnssec  the DNSSEC chain verifies from that DS, offline
//  6. tlsa    the chain proves TLSA records for HTTPS on the name
//  7. key     the certificate the site serves matches a proven TLSA record

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var defaultProofServices = []string{
	"https://sdaneproofs.htools.work/proofs/",
	"https://sdaneproofs.woodburn.au/proofs/",
}

// Proofs anchored to a tree root older than this are refused. HIP-17 lets
// certificates use a root about 8 days old (the 32nd most recent) and stay
// valid for a week; hnsd re-syncs about two weeks of headers on every start.
const maxRootAge = 15 * 24 * time.Hour

type checkStep struct {
	ID     string `json:"id"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type rootInfo struct {
	Root   string `json:"root"`
	Height int    `json:"height,omitempty"`
	Time   int64  `json:"time,omitempty"`
	Known  bool   `json:"known"`
}

type checkReport struct {
	Name    string `json:"name"`
	TLD     string `json:"tld"`
	OK      bool   `json:"ok"`
	Service string `json:"service,omitempty"`
	// Where the proofs came from: "certificate", "service" or "files"
	Source  string      `json:"source,omitempty"`
	Address string      `json:"address,omitempty"`
	Steps   []checkStep `json:"steps"`
	Root    *rootInfo   `json:"root,omitempty"`
	DS      []hnsDS     `json:"ds,omitempty"`
	Zones   []string    `json:"zones,omitempty"`
	TLSA    []string    `json:"tlsa,omitempty"`
	Roots   int         `json:"rootsKnown"`
	Checked time.Time   `json:"checkedAt"`
}

// The tree roots file written by the web server (lib/treeroots.js)
type storedRoot struct {
	Root   string `json:"root"`
	Height int    `json:"height"`
	Time   int64  `json:"time"`
}

func loadRoots(file string) ([]storedRoot, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Roots []storedRoot `json:"roots"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc.Roots, nil
}

var nameRE = regexp.MustCompile(`^([a-z0-9_]([a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func fetchProof(service, name, kind string) ([]byte, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	res, err := client.Get(service + name + "?" + kind)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if err != nil {
		return nil, err
	}
	var doc map[string]string
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("unexpected answer: %v", err)
	}
	text := strings.TrimSpace(doc[kind])
	if text == "" {
		return nil, errors.New("no proof for this name")
	}
	return hex.DecodeString(text)
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	name := fs.String("name", "", "name to check, like nathan.woodburn")
	rootsFile := fs.String("roots", env("DIT_DATA", "/data")+"/tree-roots.json", "tree roots synced by Dit's hnsd")
	urkelFile := fs.String("urkel-file", "", "read the Urkel proof (hex) from this file instead of a service")
	dnssecFile := fs.String("dnssec-file", "", "read the DNSSEC chain (hex) from this file instead of a service")
	at := fs.String("at", "", "check as of this time (RFC 3339), for tests")
	resolver := fs.String("resolver", "127.0.0.1:5350", "resolver for the site's address: Dit's hnsd")
	var services multiFlag
	fs.Var(&services, "service", "proof service base URL (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(services) == 0 {
		services = defaultProofServices
	}
	now := time.Now()
	if *at != "" {
		t, err := time.Parse(time.RFC3339, *at)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad -at:", err)
			return 2
		}
		now = t
	}

	report := check(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*name)), "."), *rootsFile, *urkelFile, *dnssecFile, *resolver, services, now)
	out, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(out))
	if !report.OK {
		return 1
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func check(name, rootsFile, urkelFile, dnssecFile, resolver string, services []string, now time.Time) *checkReport {
	r := &checkReport{Name: name, Checked: now.UTC(), Steps: []checkStep{}}
	step := func(id string, ok bool, format string, a ...any) bool {
		r.Steps = append(r.Steps, checkStep{ID: id, OK: ok, Detail: fmt.Sprintf(format, a...)})
		return ok
	}
	if !nameRE.MatchString(name) || len(name) > 253 {
		step("proofs", false, "That is not a valid name.")
		return r
	}
	labels := strings.Split(name, ".")
	r.TLD = labels[len(labels)-1]

	// 1. Proofs
	var urkelBlob, chainBlob []byte
	var err error
	var site *siteCert
	var siteErr error
	if urkelFile != "" || dnssecFile != "" {
		r.Source = "files"
		if urkelBlob, err = readHexFile(urkelFile); err == nil {
			chainBlob, err = readHexFile(dnssecFile)
		}
		if !step("proofs", err == nil, "Read from files%s", errSuffix(err)) {
			return r
		}
	} else if site, siteErr = fetchSiteCert(name, resolver); site.hasProofs() {
		// The site carries its own proofs (HIP-17)
		r.Source, r.Address = "certificate", site.Address
		urkelBlob, chainBlob = site.Urkel, site.DNSSEC
		step("proofs", true, "Read from the certificate %s serves (at %s): Urkel proof %d bytes, DNSSEC chain %d bytes. The certificate is not trusted by itself: everything below is checked here.", name, site.Address, len(urkelBlob), len(chainBlob))
	} else {
		r.Source = "service"
		if site != nil {
			r.Address = site.Address
		}
		var problems []string
		for _, service := range services {
			u, err1 := fetchProof(service, name, "urkel")
			d, err2 := fetchProof(service, name, "dnssec")
			if err1 == nil && err2 == nil {
				urkelBlob, chainBlob, r.Service = u, d, service
				break
			}
			problems = append(problems, fmt.Sprintf("%s: %v", hostOf(service), firstErr(err1, err2)))
		}
		why := "The site's certificate carries no proofs"
		if siteErr != nil {
			why = "Could not read the site's certificate (" + siteErr.Error() + ")"
		}
		if r.Service == "" {
			step("proofs", false, "%s, and no proof service had proofs for %s (%s).", why, name, strings.Join(problems, "; "))
			return r
		}
		step("proofs", true, "%s, so they were fetched from %s: Urkel proof %d bytes, DNSSEC chain %d bytes. The service is not trusted: everything below is checked here.", why, hostOf(r.Service), len(urkelBlob), len(chainBlob))
	}

	// 2. Urkel proof
	proofs, err := decodeUrkelBlob(urkelBlob)
	if !step("urkel-decode", err == nil, "%d proof(s) in the Urkel data%s", len(proofs), errSuffix(err)) {
		return r
	}
	roots, rootsErr := loadRoots(rootsFile)
	r.Roots = len(roots)
	known := map[string]storedRoot{}
	for _, sr := range roots {
		known[strings.ToLower(sr.Root)] = sr
	}

	// Use the first proof that verifies; prefer one whose root Dit knows
	var state *nameState
	var used rootedProof
	var verifyErr error
	for _, pass := range []bool{true, false} {
		for _, p := range proofs {
			if _, ok := known[hex.EncodeToString(p.root)]; pass && !ok {
				continue
			}
			value, err := p.proof.verify(p.root, nameKey(r.TLD))
			if err != nil {
				verifyErr = err
				continue
			}
			if value == nil {
				verifyErr = fmt.Errorf("the proof says %s does not exist", r.TLD)
				continue
			}
			ns, err := decodeNameState(value)
			if err != nil || ns.name != r.TLD {
				verifyErr = fmt.Errorf("the proven value is not the state of %s", r.TLD)
				continue
			}
			state, used = ns, p
			break
		}
		if state != nil {
			break
		}
	}
	if !step("urkel", state != nil, "%s", urkelDetail(state, used, verifyErr, r.TLD)) {
		return r
	}

	// 3. Tree root
	rootHex := hex.EncodeToString(used.root)
	r.Root = &rootInfo{Root: rootHex}
	sr, isKnown := known[rootHex]
	switch {
	case rootsErr != nil:
		step("root", false, "Dit has not collected tree roots from hnsd yet (%v). They appear after hnsd's next start or new blocks.", rootsErr)
		return r
	case !isKnown:
		step("root", false, "Tree root %s… is not one of the %d roots Dit's hnsd synced, so the proof cannot be trusted.", rootHex[:16], len(roots))
		return r
	}
	r.Root.Known, r.Root.Height, r.Root.Time = true, sr.Height, sr.Time
	age := now.Sub(time.Unix(sr.Time, 0))
	if !step("root", age <= maxRootAge, "Tree root %s… is from block %d, %s old, synced by Dit's own hnsd.%s",
		rootHex[:16], sr.Height, humanAge(age), map[bool]string{true: "", false: " Too old: proofs must use a root from the last 15 days."}[age <= maxRootAge]) {
		return r
	}

	// 4. DS records on chain
	ds, err := resourceDS(state.resource)
	r.DS = ds
	if !step("ds", err == nil && len(ds) > 0, "%s", dsDetail(ds, err, r.TLD)) {
		return r
	}

	// 5 + 6. DNSSEC chain and TLSA
	res, err := verifyChain(chainBlob, name, r.TLD, ds, now)
	if res != nil {
		r.Zones, r.TLSA = res.Zones, res.TLSA
	}
	zonesOK := res != nil && len(res.Zones) > 0
	if err != nil && !zonesOK {
		step("dnssec", false, "The DNSSEC chain does not verify from the on-chain DS: %v", err)
		return r
	}
	step("dnssec", true, "Verified offline from the on-chain DS: keys of %s (%d records in the chain).", strings.Join(res.Zones, ", "), res.Records)
	if !step("tlsa", err == nil && len(res.TLSA) > 0, "%s", tlsaDetail(res, err, name)) {
		return r
	}

	// 7. The certificate the site actually serves (not for proofs from files)
	if r.Source != "files" {
		if site == nil {
			step("key", false, "Could not reach %s to compare its certificate with the proven TLSA record: %v", name, siteErr)
			return r
		}
		ok, how := keyMatches(site.Chain, res.tlsa)
		if !step("key", ok, "%s", keyDetail(ok, how, name, site.Address)) {
			return r
		}
	}
	r.OK = true
	return r
}

func readHexFile(file string) ([]byte, error) {
	if file == "" {
		return nil, errors.New("both -urkel-file and -dnssec-file are needed")
	}
	text, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimSpace(string(text)))
}

func errSuffix(err error) string {
	if err == nil {
		return "."
	}
	return ": " + err.Error()
}

func firstErr(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func hostOf(url string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	return strings.SplitN(s, "/", 2)[0]
}

func humanAge(d time.Duration) string {
	switch {
	case d < 0:
		return "less than a minute"
	case d < 2*time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	}
}

func urkelDetail(state *nameState, p rootedProof, err error, tld string) string {
	if state == nil {
		return fmt.Sprintf("The Urkel proof does not verify for %s: %v", tld, err)
	}
	return fmt.Sprintf("The %s proof (%d steps) leads to tree root %x… and proves the on-chain state of %s.",
		proofTypeNames[p.proof.kind], len(p.proof.nodes), p.root[:8], tld)
}

func dsDetail(ds []hnsDS, err error, tld string) string {
	if err != nil {
		return fmt.Sprintf("Could not read the on-chain records of %s: %v", tld, err)
	}
	if len(ds) == 0 {
		return fmt.Sprintf("%s has no DS record on chain, so it has no DNSSEC to anchor DANE.", tld)
	}
	var parts []string
	for _, d := range ds {
		parts = append(parts, fmt.Sprintf("key %d (algorithm %d)", d.KeyTag, d.Algorithm))
	}
	return fmt.Sprintf("On-chain DS for %s: %s. This is the only trust anchor used.", tld, strings.Join(parts, ", "))
}

func tlsaDetail(res *chainResult, err error, name string) string {
	if err != nil {
		return fmt.Sprintf("No proven TLSA record for %s: %v", name, err)
	}
	return fmt.Sprintf("Proven TLSA for https://%s/: %s", name, strings.Join(res.TLSA, "; "))
}

func keyDetail(ok bool, how, name, address string) string {
	if ok {
		return fmt.Sprintf("The certificate %s serves (at %s) matches the proven TLSA record: it pins %s.", name, address, how)
	}
	return fmt.Sprintf("The certificate %s serves (at %s) does NOT match the proven TLSA record (%s). This server is not the one the blockchain and DNSSEC vouch for.", name, address, how)
}
