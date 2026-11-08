package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeResolver answers from maps; missing names are NXDOMAIN.
type fakeResolver struct {
	ns    map[string]bool
	mx    map[string][]string
	hosts map[string][]string
	fail  map[string]error
	calls int
}

func nx(name string) error { return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true} }

func (f *fakeResolver) LookupNS(_ context.Context, name string) ([]*net.NS, error) {
	f.calls++
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	if f.ns[name] {
		return []*net.NS{{Host: "a.ns."}}, nil
	}
	return nil, nx(name)
}

func (f *fakeResolver) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	f.calls++
	if err := f.fail[name]; err != nil {
		return nil, err
	}
	hosts, ok := f.mx[name]
	if !ok {
		return nil, nx(name)
	}
	var out []*net.MX
	for _, h := range hosts {
		out = append(out, &net.MX{Host: h})
	}
	return out, nil
}

func (f *fakeResolver) LookupHost(_ context.Context, name string) ([]string, error) {
	f.calls++
	if a, ok := f.hosts[name]; ok {
		return a, nil
	}
	return nil, nx(name)
}

func newTestDetector(t *testing.T, cfgJSON string, res *fakeResolver, allow DomainSet) *Detector {
	t.Helper()
	cfg, err := parseConfig([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	return NewDetector(cfg, allow, NewDNSChecker(res, cfg.DNS, nil))
}

func defaultResolver() *fakeResolver {
	return &fakeResolver{
		ns: map[string]bool{"com.": true, "nl.": true, "co.": true, "org.": true},
		mx: map[string][]string{
			"gmaio.com.":   {"mx.gmaio.com."},
			"nullmx.org.":  {"."},
			"example.org.": {"mx.example.org."},
		},
		hosts: map[string][]string{"gmali.com.": {"192.0.2.1"}},
		fail:  map[string]error{},
	}
}

func TestOSADistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0}, {"abc", "", 3}, {"", "ab", 2},
		{"gmail.com", "gmail.com", 0},
		{"gmial.com", "gmail.com", 1}, // transposition
		{"gnail.com", "gmail.com", 1}, // substitution
		{"gmal.com", "gmail.com", 1},  // deletion
		{"gmaill.com", "gmail.com", 1},
		{"ca", "abc", 3}, // OSA, not full Damerau
		{"hotmail.com", "hotmail.nl", 3},
	}
	for _, c := range cases {
		if got := osaDistance(c.a, c.b); got != c.want {
			t.Errorf("osaDistance(%q,%q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

type staticSet map[string]bool

func (s staticSet) Contains(d string) bool { return s[d] }

func TestDetectorRules(t *testing.T) {
	allow := staticSet{"example.nl": true, "gmaij.com": true}
	cases := []struct {
		rcpt, verdict, suggestion, reason string
	}{
		{"", VerdictOK, "", "no domain"},
		{"postmaster", VerdictOK, "", "no domain"},
		{"a@[192.0.2.1]", VerdictOK, "", "address literal"},
		{"<A@GMail.COM.>", VerdictOK, "", "popular domain"},
		{"a@example.nl", VerdictOK, "", "allowlisted"},
		{"a@ghotmail.com", VerdictTypo, "hotmail.com", "known typo"},
		{"a@x@gmial.com", VerdictTypo, "gmail.com", "known typo"},
		{"a@zinlab", VerdictInvalid, "", "no dot in domain"},
		{"a@gmail", VerdictInvalid, "gmail.com", "no dot in domain"},
		{"a@hotmal", VerdictInvalid, "hotmail.com", "no dot in domain"},
		{"a@gmail.con", VerdictInvalid, "gmail.com", "tld does not exist"},
		{"a@example.nll", VerdictInvalid, "example.nl", "tld does not exist"},
		{"a@unknown.con", VerdictInvalid, "", "tld does not exist"},
		{"a@gmaio.com", VerdictOK, "", "near miss with mail route"},
		{"a@gmali.com", VerdictOK, "", "near miss with mail route"}, // A record only
		{"a@gmaik.com", VerdictTypo, "gmail.com", "near miss, no mail route"},
		{"a@gmaij.com", VerdictOK, "", "allowlisted"},
		{"a@gmail.co", VerdictTypo, "gmail.com", "near miss, no mail route"},
		{"a@gmail.org", VerdictTypo, "gmail.com", "tld swap, no mail route"},
		{"a@hotmail.org", VerdictOK, "", "no match"}, // not in tld_swap_domains
		{"a@protonmial.com", VerdictTypo, "protonmail.com", "near miss, no mail route"},
		{"a@protonmeil.cmo", VerdictInvalid, "", "tld does not exist"},
		{"a@prtonmial.com", VerdictTypo, "protonmail.com", "near miss, no mail route"}, // distance 2, len >= 12
		{"a@gmxil.de", VerdictOK, "", "no match"},                                      // distance 2, short
		{"a@example.org", VerdictOK, "", "no match"},
	}
	det := newTestDetector(t, `{}`, defaultResolver(), allow)
	for _, c := range cases {
		v := det.Check(context.Background(), c.rcpt)
		if v.Verdict != c.verdict || v.Suggestion != c.suggestion || v.Reason != c.reason {
			t.Errorf("%q: got %+v, want %s/%s/%s", c.rcpt, v, c.verdict, c.suggestion, c.reason)
		}
	}
}

func TestDetectorNullMXAndAlwaysPolicy(t *testing.T) {
	cfg := `{"extra_popular_domains":["nullmy.org"]}`
	det := newTestDetector(t, cfg, defaultResolver(), nil)
	if v := det.Check(context.Background(), "a@nullmx.org"); v.Verdict != VerdictTypo || v.Suggestion != "nullmy.org" {
		t.Errorf("null MX: %+v", v)
	}
	det = newTestDetector(t, `{"near_miss_policy":"always"}`, defaultResolver(), nil)
	if v := det.Check(context.Background(), "a@gmaio.com"); v.Verdict != VerdictTypo || v.Reason != "near miss" {
		t.Errorf("always: %+v", v)
	}
}

func TestDetectorFailOpen(t *testing.T) {
	res := defaultResolver()
	res.fail["con."] = &net.DNSError{Err: "timeout", IsTimeout: true}
	res.fail["gmail.con."] = context.DeadlineExceeded
	res.fail["gmaik.com."] = errors.New("server misbehaving")
	cfg, _ := parseConfig([]byte(`{}`))
	var kinds []string
	det := NewDetector(cfg, nil, NewDNSChecker(res, cfg.DNS, func(k string) { kinds = append(kinds, k) }))
	if v := det.Check(context.Background(), "a@gmail.con"); v.Verdict != VerdictOK {
		t.Errorf("tld timeout should fail open: %+v", v)
	}
	if v := det.Check(context.Background(), "a@gmaik.com"); v.Verdict != VerdictOK || v.Reason != "dns error, fail open" {
		t.Errorf("mx error should fail open: %+v", v)
	}
	if len(kinds) != 3 || kinds[0] != "timeout" || kinds[1] != "timeout" || kinds[2] != "error" {
		t.Errorf("dns error kinds = %v", kinds)
	}
}

func TestDNSCache(t *testing.T) {
	res := defaultResolver()
	cfg, _ := parseConfig([]byte(`{}`))
	c := NewDNSChecker(res, cfg.DNS, nil)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if ok, _ := c.TLDExists(context.Background(), "con"); ok {
			t.Fatal("con should not exist")
		}
	}
	if res.calls != 1 {
		t.Errorf("expected 1 lookup, got %d", res.calls)
	}
	now = now.Add(11 * time.Minute) // past negative TTL
	c.TLDExists(context.Background(), "con")
	if res.calls != 2 {
		t.Errorf("expected re-lookup after negative TTL, got %d", res.calls)
	}
}

func TestConfigErrors(t *testing.T) {
	bad := []string{
		`{"mode":"block"}`,
		`{"near_miss_policy":"sometimes"}`,
		`{"policy_listen":"","http_listen":""}`,
		`{"policy_listen":"localhost"}`,
		`{"reject_message":"Domain {domain} is wrong"}`,
		`{"dns":{"lookup_timeout":"0s"}}`,
		`{"dns":{"lookup_timeout":5}}`,
		`{"unknown_field":true}`,
		`{"tld_swap_domains":["example.com"]}`,
		`{"http_allow":["10.0.0.0/33"]}`,
		`{"delivered_sync_url":"ftp://x/y"}`,
		`{"log_level":"loud"}`,
		`{"popular_domains":["nodot"]}`,
	}
	for _, b := range bad {
		if _, err := parseConfig([]byte(b)); err == nil {
			t.Errorf("config %s: expected error", b)
		}
	}
	cfg, err := parseConfig([]byte(`{"policy_listen":"172.22.1.1:10041","http_allow":["127.0.0.1","10.0.0.0/8"],"popular_domains":["Example.COM."]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PopularDomains) != 1 || cfg.PopularDomains[0] != "example.com" || len(cfg.httpAllow) != 2 {
		t.Errorf("unexpected config %+v", cfg)
	}
}

func TestShippedConfigParses(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("packaging", "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(data); err != nil {
		t.Fatal(err)
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	if !testing.Verbose() {
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	}
	os.Exit(m.Run())
}
