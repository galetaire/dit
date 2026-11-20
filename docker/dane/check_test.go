package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const woodburnRoot = "0e7787ce2235e52924af7b8236f2df19327a277289d75d45c062ccd139b122ec"

func writeRoots(t *testing.T, roots []storedRoot) string {
	t.Helper()
	data, _ := json.Marshal(map[string]any{"roots": roots})
	file := filepath.Join(t.TempDir(), "tree-roots.json")
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

func runFileCheck(rootsFile string, at time.Time) *checkReport {
	return check("nathan.woodburn", rootsFile,
		"testdata/nathan.woodburn.urkel.hex", "testdata/nathan.woodburn.dnssec.hex", nil, at)
}

func lastStep(r *checkReport) checkStep {
	return r.Steps[len(r.Steps)-1]
}

func TestCheckPassesWithKnownRoot(t *testing.T) {
	roots := writeRoots(t, []storedRoot{{Root: woodburnRoot, Height: 356300, Time: proofDay.Add(-3 * time.Hour).Unix()}})
	r := runFileCheck(roots, proofDay)
	for _, s := range r.Steps {
		t.Logf("%-12s %v  %s", s.ID, s.OK, s.Detail)
	}
	if !r.OK {
		t.Fatal("check failed")
	}
	want := []string{"proofs", "urkel-decode", "urkel", "root", "ds", "dnssec", "tlsa"}
	if len(r.Steps) != len(want) {
		t.Fatalf("%d steps, want %d", len(r.Steps), len(want))
	}
	for i, id := range want {
		if r.Steps[i].ID != id || !r.Steps[i].OK {
			t.Errorf("step %d = %s ok=%v, want %s ok", i, r.Steps[i].ID, r.Steps[i].OK, id)
		}
	}
}

func TestCheckFailsWithUnknownRoot(t *testing.T) {
	other := "1111111111111111111111111111111111111111111111111111111111111111"
	r := runFileCheck(writeRoots(t, []storedRoot{{Root: other, Height: 1, Time: proofDay.Unix()}}), proofDay)
	if r.OK || lastStep(r).ID != "root" {
		t.Fatalf("want failure at the root step, got ok=%v at %s", r.OK, lastStep(r).ID)
	}
}

func TestCheckFailsWithOldRoot(t *testing.T) {
	old := proofDay.Add(-20 * 24 * time.Hour).Unix()
	r := runFileCheck(writeRoots(t, []storedRoot{{Root: woodburnRoot, Height: 353000, Time: old}}), proofDay)
	if r.OK || lastStep(r).ID != "root" {
		t.Fatalf("want failure at the root step, got ok=%v at %s", r.OK, lastStep(r).ID)
	}
}

func TestCheckFailsWithoutRootsFile(t *testing.T) {
	r := runFileCheck(filepath.Join(t.TempDir(), "missing.json"), proofDay)
	if r.OK || lastStep(r).ID != "root" {
		t.Fatalf("want failure at the root step, got ok=%v at %s", r.OK, lastStep(r).ID)
	}
}

func TestCheckRejectsBadName(t *testing.T) {
	r := check("../etc/passwd", "", "", "", nil, proofDay)
	if r.OK || len(r.Steps) != 1 {
		t.Fatal("a bad name must stop the check")
	}
}
