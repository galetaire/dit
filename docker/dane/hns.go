package main

// Handshake name data, as proven by an Urkel proof: the key is the SHA3-256
// of the top-level name, the value is the name's on-chain state, which holds
// its DNS resource (hsd lib/covenants/namestate.js, lib/dns/resource.js,
// MIT License). Only the parts a DANE check needs are decoded: the name and
// the DS records that anchor the name's DNSSEC.

import (
	"crypto/sha3"
	"errors"
	"fmt"
	"strings"
)

func nameKey(tld string) []byte {
	sum := sha3.Sum256([]byte(strings.ToLower(tld)))
	return sum[:]
}

type nameState struct {
	name     string
	resource []byte
}

// NameState.read: name (1-byte length), data (2-byte little-endian length), ...
func decodeNameState(value []byte) (*nameState, error) {
	r := &reader{data: value}
	n, err := r.take(1)
	if err != nil {
		return nil, err
	}
	name, err := r.take(int(n[0]))
	if err != nil {
		return nil, err
	}
	size, err := r.u16le()
	if err != nil {
		return nil, err
	}
	data, err := r.take(size)
	if err != nil {
		return nil, err
	}
	return &nameState{name: string(name), resource: data}, nil
}

// A DS record from a Handshake resource
type hnsDS struct {
	KeyTag     uint16 `json:"keyTag"`
	Algorithm  uint8  `json:"algorithm"`
	DigestType uint8  `json:"digestType"`
	Digest     []byte `json:"-"`
}

// skipName passes over a DNS-style name: labels, ended by a zero byte or a
// two-byte compression pointer
func (r *reader) skipName() error {
	for i := 0; i < 128; i++ {
		b, err := r.take(1)
		if err != nil {
			return err
		}
		switch {
		case b[0] == 0:
			return nil
		case b[0]&0xc0 == 0xc0:
			_, err := r.take(1)
			return err
		case b[0]&0xc0 != 0:
			return errors.New("bad name label")
		default:
			if _, err := r.take(int(b[0])); err != nil {
				return err
			}
		}
	}
	return errors.New("name too long")
}

// resourceDS returns the DS records of a resource (Resource.read). Records:
// 0 DS, 1 NS, 2 GLUE4, 3 GLUE6, 4 SYNTH4, 5 SYNTH6, 6 TXT; decoding stops at
// an unknown type, as hsd does.
func resourceDS(resource []byte) ([]hnsDS, error) {
	if len(resource) == 0 {
		return nil, nil
	}
	r := &reader{data: resource}
	version, _ := r.take(1)
	if version[0] != 0 {
		return nil, fmt.Errorf("unknown resource version %d", version[0])
	}
	var out []hnsDS
	for r.pos < len(r.data) {
		t, _ := r.take(1)
		switch t[0] {
		case 0: // DS
			head, err := r.take(4)
			if err != nil {
				return nil, err
			}
			n, err := r.take(1)
			if err != nil {
				return nil, err
			}
			digest, err := r.take(int(n[0]))
			if err != nil {
				return nil, err
			}
			out = append(out, hnsDS{
				KeyTag:     uint16(head[0])<<8 | uint16(head[1]),
				Algorithm:  head[2],
				DigestType: head[3],
				Digest:     digest,
			})
		case 1: // NS
			if err := r.skipName(); err != nil {
				return nil, err
			}
		case 2, 3: // GLUE4, GLUE6
			if err := r.skipName(); err != nil {
				return nil, err
			}
			size := 4
			if t[0] == 3 {
				size = 16
			}
			if _, err := r.take(size); err != nil {
				return nil, err
			}
		case 4: // SYNTH4
			if _, err := r.take(4); err != nil {
				return nil, err
			}
		case 5: // SYNTH6
			if _, err := r.take(16); err != nil {
				return nil, err
			}
		case 6: // TXT: count, then length-prefixed strings
			c, err := r.take(1)
			if err != nil {
				return nil, err
			}
			for i := 0; i < int(c[0]); i++ {
				l, err := r.take(1)
				if err != nil {
					return nil, err
				}
				if _, err := r.take(int(l[0])); err != nil {
					return nil, err
				}
			}
		default:
			return out, nil
		}
	}
	return out, nil
}
