package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestService(t *testing.T, cfgJSON string) *Service {
	t.Helper()
	cfg, err := parseConfig([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	metrics := NewMetrics()
	allow := NewAllowlists(cfg)
	allow.ReloadAll()
	return &Service{
		cfg:      cfg,
		det:      NewDetector(cfg, allow, NewDNSChecker(defaultResolver(), cfg.DNS, metrics.IncDNSError)),
		allow:    allow,
		metrics:  metrics,
		syncStat: &SyncStatus{},
	}
}

func noFiles(dir string) string {
	return `"allowlist_file":"` + filepath.Join(dir, "allow.txt") + `","hosted_domains_file":"","delivered_domains_file":"` + filepath.Join(dir, "delivered.txt") + `"`
}

func TestAllowlistReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.txt")
	l := NewFileList("static", path)
	a := &Allowlists{Lists: []*FileList{l}}
	a.ReloadAll() // missing file is fine
	if a.Contains("example.org") {
		t.Fatal("empty list matched")
	}
	os.WriteFile(path, []byte("# comment\nExample.ORG.  # trailing\n\n other.net\n"), 0o644)
	a.ReloadAll()
	for _, d := range []string{"example.org", "mail.example.org", "other.net"} {
		if !a.Contains(d) {
			t.Errorf("%s should match", d)
		}
	}
	if a.Contains("notexample.org") || a.Contains("org") {
		t.Error("parent matching too broad")
	}
	os.WriteFile(path, []byte("new.example\n"), 0o644)
	future := time.Now().Add(time.Minute)
	os.Chtimes(path, future, future)
	a.ReloadAll()
	if a.Contains("example.org") || !a.Contains("new.example") || l.Len() != 1 {
		t.Error("reload after mtime change did not apply")
	}
	os.Remove(path)
	a.ReloadAll()
	if l.Len() != 0 {
		t.Error("removed file should empty the list")
	}
}

func TestPolicyActions(t *testing.T) {
	typo := Verdict{VerdictTypo, "ghotmail.com", "hotmail.com", "known typo"}
	invalid := Verdict{VerdictInvalid, "zinlab", "", "no dot in domain"}
	ok := Verdict{Verdict: VerdictOK}
	for mode, want := range map[string][3]string{
		"log":  {"DUNNO", "DUNNO", "DUNNO"},
		"warn": {"DUNNO", "WARN typo-guard: ghotmail.com -> hotmail.com", "WARN typo-guard: zinlab invalid"},
		"reject": {"DUNNO",
			"REJECT 5.1.2 Het domein ghotmail.com bestaat waarschijnlijk niet, bedoelde u hotmail.com? / The domain ghotmail.com probably does not exist, did you mean hotmail.com?",
			"REJECT 5.1.2 Het domein zinlab bestaat niet of is ongeldig / The domain zinlab does not exist or is invalid"},
	} {
		s := newTestService(t, `{"mode":"`+mode+`",`+noFiles(t.TempDir())+`}`)
		for i, v := range []Verdict{ok, typo, invalid} {
			if got := s.PolicyAction(v); got != want[i] {
				t.Errorf("mode %s verdict %s: got %q want %q", mode, v.Verdict, got, want[i])
			}
		}
	}
}

func TestMaskAddress(t *testing.T) {
	for in, want := range map[string]string{"john@example.com": "j…@example.com", "@x.nl": "…@x.nl", "nobody": "…"} {
		if got := maskAddress(in); got != want {
			t.Errorf("maskAddress(%q) = %q", in, got)
		}
	}
}

func TestPolicyServerKeepAlive(t *testing.T) {
	s := newTestService(t, `{"mode":"reject",`+noFiles(t.TempDir())+`}`)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- NewPolicyServer(s, 5*time.Second, 10).Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	req := func(state, rcpt string) string {
		return "request=smtpd_access_policy\nprotocol_state=" + state + "\nprotocol_name=ESMTP\n" +
			"client_address=192.0.2.10\nsasl_username=user@example.org\nrecipient=" + rcpt + "\nunknown_attr=x=y\n\n"
	}
	// Three requests written at once, then a fourth after the replies.
	io.WriteString(conn, req("RCPT", "a@ghotmail.com")+req("RCPT", "b@gmail.com")+req("DATA", "a@ghotmail.com"))
	r := bufio.NewReader(conn)
	read := func() string {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if blank, _ := r.ReadString('\n'); blank != "\n" {
			t.Fatalf("reply not terminated by empty line: %q", blank)
		}
		return strings.TrimSuffix(line, "\n")
	}
	if got := read(); !strings.HasPrefix(got, "action=REJECT 5.1.2 ") || !strings.Contains(got, "hotmail.com?") {
		t.Errorf("reply 1: %q", got)
	}
	if got := read(); got != "action=DUNNO" {
		t.Errorf("reply 2: %q", got)
	}
	if got := read(); got != "action=DUNNO" {
		t.Errorf("reply 3 (non-RCPT): %q", got)
	}
	io.WriteString(conn, req("RCPT", "c@zinlab"))
	if got := read(); !strings.HasPrefix(got, "action=REJECT 5.1.2 Het domein zinlab") {
		t.Errorf("reply 4: %q", got)
	}

	// Over-long line closes the connection.
	c2, _ := net.Dial("tcp", ln.Addr().String())
	io.WriteString(c2, "recipient="+strings.Repeat("a", policyMaxLine+10)+"\n\n")
	c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if n, err := c2.Read(make([]byte, 10)); err == nil || n > 0 {
		t.Errorf("expected close on long line, got n=%d err=%v", n, err)
	}
	c2.Close()

	s.metrics.mu.Lock()
	typos := s.metrics.checks[[2]string{"policy", VerdictTypo}]
	s.metrics.mu.Unlock()
	if typos != 1 {
		t.Errorf("policy typo counter = %d", typos)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not stop")
	}
}

func TestReadPolicyRequest(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("\nrecipient=a@b.c\r\nprotocol_state=RCPT\n\nrecipient=x"))
	attrs, err := readPolicyRequest(r)
	if err != nil || attrs["recipient"] != "a@b.c" || attrs["protocol_state"] != "RCPT" {
		t.Fatalf("got %v %v", attrs, err)
	}
	if _, err := readPolicyRequest(r); err == nil {
		t.Error("truncated request should fail")
	}
}

func TestHTTPHandler(t *testing.T) {
	dir := t.TempDir()
	s := newTestService(t, `{"mode":"warn",`+noFiles(dir)+`}`)
	h := s.Handler()
	get := func(path, remote string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if remote != "" {
			req.RemoteAddr = remote
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := get("/v1/check?rcpt=a%40gmail.con", "")
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 {
		t.Fatalf("check: %d %s", w.Code, w.Body)
	}
	if resp["verdict"] != "invalid" || resp["suggestion"] != "gmail.com" || resp["mode"] != "warn" || !strings.HasPrefix(resp["message"], "5.1.2 ") {
		t.Errorf("check response: %v", resp)
	}
	w = get("/v1/check?domain=hotmail.nl", "")
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["verdict"] != "ok" || resp["message"] != "" || resp["domain"] != "hotmail.nl" {
		t.Errorf("domain check: %v", resp)
	}
	if w = get("/v1/check", ""); w.Code != 400 {
		t.Errorf("missing param: %d", w.Code)
	}
	if w = get("/healthz", ""); w.Code != 200 || w.Body.String() != "ok\n" {
		t.Errorf("healthz: %d %q", w.Code, w.Body)
	}
	if w = get("/v1/delivered", ""); w.Code != 404 {
		t.Errorf("delivered missing: %d", w.Code)
	}
	os.WriteFile(filepath.Join(dir, "delivered.txt"), []byte("example.org\n"), 0o644)
	if w = get("/v1/delivered", ""); w.Code != 200 || w.Body.String() != "example.org\n" || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("delivered: %d %q", w.Code, w.Body)
	}
	w = get("/metrics", "")
	body := w.Body.String()
	for _, want := range []string{
		`typo_guard_checks_total{listener="http",verdict="invalid"} 1`,
		`typo_guard_checks_total{listener="http",verdict="ok"} 1`,
		`typo_guard_checks_total{listener="policy",verdict="typo"} 0`,
		`typo_guard_dns_errors_total{kind="timeout"} 0`,
		`typo_guard_allowlist_domains{list="static"} 0`,
		`# TYPE typo_guard_allowlist_last_reload_timestamp_seconds gauge`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}

	// Access control.
	s = newTestService(t, `{"http_allow":["10.0.0.0/8","::1"],`+noFiles(dir)+`}`)
	h = s.Handler()
	for _, c := range []struct {
		path, remote string
		code         int
	}{
		{"/v1/check?domain=gmail.com", "192.0.2.1:1234", 403},
		{"/metrics", "192.0.2.1:1234", 403},
		{"/v1/delivered", "192.0.2.1:1234", 403},
		{"/healthz", "192.0.2.1:1234", 200},
		{"/v1/check?domain=gmail.com", "10.1.2.3:1234", 200},
		{"/v1/delivered", "[::1]:1234", 200},
		{"/metrics", "[::ffff:10.0.0.1]:1234", 200},
	} {
		if w := get(c.path, c.remote); w.Code != c.code {
			t.Errorf("%s from %s: %d, want %d", c.path, c.remote, w.Code, c.code)
		}
	}
}

func TestDeliveredSync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "delivered.txt")
	body := "a.example\nb.example\nc.example\nd.example\n"
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	defer srv.Close()
	updates := 0
	ds := &DeliveredSync{URL: srv.URL, Path: path, Client: &http.Client{Timeout: time.Second},
		Metrics: NewMetrics(), Status: &SyncStatus{}, OnUpdate: func() { updates++ }}
	ctx := context.Background()

	if r := ds.RunOnce(ctx); r != "updated" || updates != 1 {
		t.Fatalf("first sync: %s", r)
	}
	if r := ds.RunOnce(ctx); r != "unchanged" {
		t.Errorf("second sync: %s", r)
	}
	body = "a.example\n" // shrinks by 75%
	if r := ds.RunOnce(ctx); r != "rejected" {
		t.Errorf("shrink: %s", r)
	}
	body = ""
	if r := ds.RunOnce(ctx); r != "rejected" {
		t.Errorf("empty: %s", r)
	}
	body = "<html>error page</html>\n"
	if r := ds.RunOnce(ctx); r != "rejected" {
		t.Errorf("html: %s", r)
	}
	status, body = 500, "a.example\nb.example\nc.example\n"
	if r := ds.RunOnce(ctx); r != "error" {
		t.Errorf("500: %s", r)
	}
	status = 200
	if r := ds.RunOnce(ctx); r != "updated" {
		t.Errorf("small shrink: %s", r)
	}
	got, _ := os.ReadFile(path)
	if string(got) != body || updates != 2 {
		t.Errorf("file = %q, updates = %d", got, updates)
	}
	if ds.Status.lastSuccess.Load() == 0 {
		t.Error("last success not recorded")
	}
}
