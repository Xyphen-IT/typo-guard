package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func zstdBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(s))
	w.Close()
	return buf.Bytes()
}

func rec(typ, rcpt string, ts int64) string {
	return fmt.Sprintf(`{"type":%q,"id":"x","sender":"s@example.net","recipient":%q,"timestamp":%d,"response":{"code":250}}`+"\n", typ, rcpt, ts)
}

func TestHarvest(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Unix()
	old := now - 100*86400

	complete := rec("Delivery", "a@One.Example", now) +
		rec("Reception", "b@reception-only.example", now) +
		rec("TransientFailure", "c@transient.example", now) +
		rec("Delivery", "d@too-old.example", old) +
		`{"type":"Delivery","recipient":["e@array.example"],"timestamp":` + fmt.Sprint(now) + "}\n" +
		"not json but mentions \"Delivery\"\n"
	os.WriteFile(filepath.Join(dir, "20261101-000000"), zstdBytes(t, complete), 0o644)

	// Segment still being written: second frame cut in half, last line unterminated.
	first := zstdBytes(t, rec("Delivery", "f@two.example", now))
	second := zstdBytes(t, strings.Repeat(rec("Delivery", "g@lost.example", now), 50))
	partial := append(first, second[:len(second)/2]...)
	os.WriteFile(filepath.Join(dir, "20261108-000000"), partial, 0o644)

	unterminated := zstdBytes(t, rec("Delivery", "h@three.example", now)+`{"type":"Delivery","recipient":"i@cut.exa`)
	os.WriteFile(filepath.Join(dir, "20261108-010000"), unterminated, 0o644)

	stale := filepath.Join(dir, "20260101-000000")
	os.WriteFile(stale, zstdBytes(t, rec("Delivery", "j@stale-file.example", now)), 0o644)
	oldTime := time.Now().Add(-120 * 24 * time.Hour)
	os.Chtimes(stale, oldTime, oldTime)

	os.WriteFile(filepath.Join(dir, "plain.log"), []byte(rec("Delivery", "k@plain.example", now)), 0o644)

	st, err := Harvest(dir, time.Now().Add(-90*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := "array.example,one.example,plain.example,three.example,two.example"
	if got := strings.Join(st.Domains, ","); got != want {
		t.Errorf("domains = %s, want %s", got, want)
	}
	if st.Skipped != 1 || st.Files != 4 || st.Partial != 1 {
		t.Errorf("stats = %+v", st)
	}

	out := filepath.Join(t.TempDir(), "delivered.txt")
	var summary bytes.Buffer
	if err := runHarvest([]string{"--kumo-logs", dir, "--days", "90", "--out", out}, &summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "5 domains written") || strings.Count(summary.String(), "\n") != 1 {
		t.Errorf("summary = %q", summary.String())
	}
	set, err := readDomainFile(out)
	if err != nil || len(set) != 5 {
		t.Errorf("written list: %v %v", set, err)
	}
}
