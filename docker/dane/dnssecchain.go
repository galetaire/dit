package main

// The DNSSEC part of a Stateless DANE proof (HIP-17): an RFC 9102 style
// authentication chain, here 4 bytes of header followed by DNS records in
// wire format (the layout htools-org/stateless-dane and randomlogin/sane
// use). It is verified offline, in pure Go:
//
//   - the only trust anchor is the DS set of the top-level name, taken from
//     the Urkel proof (so from the Handshake blockchain), never from the chain;
//   - a zone's DNSKEY set is trusted when one of its keys matches a trusted DS
//     and that key signs the set; then DS sets signed by a trusted zone
//     delegate to child zones the same way;
//   - the TLSA set is proven when a trusted key of an enclosing zone signs it,
//     within the signature's validity period.

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type chainResult struct {
	Records int      `json:"records"`
	Zones   []string `json:"zones"` // zones whose keys were verified, top first
	TLSA    []string `json:"tlsa"`  // proven TLSA records, as text
	tlsa    []*dns.TLSA
}

type rrsetKey struct {
	name  string
	rtype uint16
}

func parseChain(blob []byte) ([]dns.RR, error) {
	if len(blob) < 5 {
		return nil, errors.New("DNSSEC data too short")
	}
	var records []dns.RR
	off := 4
	for off < len(blob) {
		rr, next, err := dns.UnpackRR(blob, off)
		if err != nil {
			return nil, fmt.Errorf("cannot read DNSSEC record: %w", err)
		}
		if rr == nil || next <= off {
			return nil, errors.New("cannot read DNSSEC record")
		}
		records = append(records, rr)
		off = next
	}
	if deduped := dns.Dedup(append([]dns.RR{}, records...), nil); len(deduped) != len(records) {
		return nil, errors.New("DNSSEC data contains duplicate records")
	}
	return records, nil
}

// dsMatches: does key hash to this DS (key tag, algorithm and digest)?
func dsMatches(key *dns.DNSKEY, keyTag uint16, alg, digestType uint8, digest string) bool {
	if key.KeyTag() != keyTag || key.Algorithm != alg {
		return false
	}
	computed := key.ToDS(digestType)
	return computed != nil && strings.EqualFold(computed.Digest, digest)
}

// verifySet: is set signed, now, by one of keys belonging to signer?
func verifySet(set []dns.RR, sigs []*dns.RRSIG, signer string, keys []*dns.DNSKEY, now time.Time) error {
	if len(set) == 0 {
		return errors.New("empty record set")
	}
	var lastErr error = fmt.Errorf("no signature by %s", signer)
	for _, sig := range sigs {
		if !strings.EqualFold(dns.Fqdn(sig.SignerName), signer) {
			continue
		}
		for _, key := range keys {
			if key.KeyTag() != sig.KeyTag || key.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(key, set); err != nil {
				lastErr = fmt.Errorf("signature by %s (key %d) does not verify: %v", signer, key.KeyTag(), err)
				continue
			}
			if !sig.ValidityPeriod(now) {
				lastErr = fmt.Errorf("signature by %s (key %d) is outside its validity period", signer, key.KeyTag())
				continue
			}
			return nil
		}
	}
	return lastErr
}

// verifyChain checks the chain for the TLSA records of name, anchored only on
// the DS records proven on chain for tld
func verifyChain(blob []byte, name, tld string, anchors []hnsDS, now time.Time) (*chainResult, error) {
	records, err := parseChain(blob)
	if err != nil {
		return nil, err
	}
	res := &chainResult{Records: len(records)}

	sets := map[rrsetKey][]dns.RR{}
	sigs := map[rrsetKey][]*dns.RRSIG{}
	for _, rr := range records {
		owner := strings.ToLower(dns.Fqdn(rr.Header().Name))
		if sig, ok := rr.(*dns.RRSIG); ok {
			k := rrsetKey{owner, sig.TypeCovered}
			sigs[k] = append(sigs[k], sig)
			continue
		}
		k := rrsetKey{owner, rr.Header().Rrtype}
		sets[k] = append(sets[k], rr)
	}

	dnskeys := func(zone string) []*dns.DNSKEY {
		var keys []*dns.DNSKEY
		for _, rr := range sets[rrsetKey{zone, dns.TypeDNSKEY}] {
			keys = append(keys, rr.(*dns.DNSKEY))
		}
		return keys
	}

	// trustZone: given the DS records that delegate to zone, verify its keys
	trusted := map[string][]*dns.DNSKEY{}
	trustZone := func(zone string, match func(*dns.DNSKEY) bool) error {
		keys := dnskeys(zone)
		if len(keys) == 0 {
			return fmt.Errorf("no DNSKEY records for %s in the proof", zone)
		}
		var entry []*dns.DNSKEY
		for _, key := range keys {
			if match(key) {
				entry = append(entry, key)
			}
		}
		if len(entry) == 0 {
			return fmt.Errorf("no DNSKEY of %s matches its DS", zone)
		}
		set := sets[rrsetKey{zone, dns.TypeDNSKEY}]
		if err := verifySet(set, sigs[rrsetKey{zone, dns.TypeDNSKEY}], zone, entry, now); err != nil {
			return fmt.Errorf("DNSKEY set of %s: %w", zone, err)
		}
		trusted[zone] = keys
		res.Zones = append(res.Zones, strings.TrimSuffix(zone, "."))
		return nil
	}

	// 1. The top-level name, from the DS proven on the Handshake chain
	top := strings.ToLower(dns.Fqdn(tld))
	if len(anchors) == 0 {
		return res, fmt.Errorf("%s has no DS record on chain, so it has no DNSSEC to anchor", tld)
	}
	if err := trustZone(top, func(key *dns.DNSKEY) bool {
		for _, a := range anchors {
			if dsMatches(key, a.KeyTag, a.Algorithm, a.DigestType, fmt.Sprintf("%x", a.Digest)) {
				return true
			}
		}
		return false
	}); err != nil {
		return res, err
	}

	// 2. Delegations below it, as far as the proof goes
	for changed := true; changed; {
		changed = false
		for k, set := range sets {
			if k.rtype != dns.TypeDS {
				continue
			}
			if _, done := trusted[k.name]; done {
				continue
			}
			for parent, keys := range trusted {
				if !dns.IsSubDomain(parent, k.name) || parent == k.name {
					continue
				}
				if verifySet(set, sigs[k], parent, keys, now) != nil {
					continue
				}
				if err := trustZone(k.name, func(key *dns.DNSKEY) bool {
					for _, rr := range set {
						ds := rr.(*dns.DS)
						if dsMatches(key, ds.KeyTag, ds.Algorithm, ds.DigestType, ds.Digest) {
							return true
						}
					}
					return false
				}); err != nil {
					return res, err
				}
				changed = true
				break
			}
		}
	}

	// 3. The TLSA records for HTTPS, signed by the closest trusted zone
	owner := strings.ToLower(dns.Fqdn("_443._tcp." + name))
	set := sets[rrsetKey{owner, dns.TypeTLSA}]
	if len(set) == 0 {
		return res, fmt.Errorf("no TLSA record for %s in the proof", name)
	}
	signer := ""
	for zone := range trusted {
		if dns.IsSubDomain(zone, owner) && len(zone) > len(signer) {
			signer = zone
		}
	}
	if signer == "" {
		return res, errors.New("no verified zone encloses the TLSA record")
	}
	if err := verifySet(set, sigs[rrsetKey{owner, dns.TypeTLSA}], signer, trusted[signer], now); err != nil {
		return res, fmt.Errorf("TLSA record: %w", err)
	}
	for _, rr := range set {
		t := rr.(*dns.TLSA)
		res.tlsa = append(res.tlsa, t)
		res.TLSA = append(res.TLSA, fmt.Sprintf("%d %d %d %s", t.Usage, t.Selector, t.MatchingType, t.Certificate))
	}
	return res, nil
}
