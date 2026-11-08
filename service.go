package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Service ties the detector to config-dependent output, logging and metrics.
type Service struct {
	cfg      *Config
	det      *Detector
	allow    *Allowlists
	metrics  *Metrics
	syncStat *SyncStatus
}

type CheckInfo struct {
	Listener string
	Rcpt     string
	SASL     string
	Client   string
}

func (s *Service) Check(ctx context.Context, info CheckInfo) Verdict {
	v := s.det.Check(ctx, info.Rcpt)
	s.metrics.IncCheck(info.Listener, v.Verdict)
	if v.Verdict != VerdictOK {
		slog.Warn("suspicious recipient domain",
			"listener", info.Listener, "verdict", v.Verdict, "rcpt", maskAddress(info.Rcpt),
			"domain", v.Domain, "suggestion", v.Suggestion, "reason", v.Reason,
			"sasl_username", info.SASL, "client_address", info.Client, "mode", s.cfg.Mode)
	} else {
		slog.Debug("recipient ok", "listener", info.Listener, "domain", v.Domain, "reason", v.Reason)
	}
	return v
}

// Message renders the reject text for a non-ok verdict.
func (s *Service) Message(v Verdict) string {
	if v.Verdict == VerdictOK {
		return ""
	}
	tpl := s.cfg.RejectMessageNoSuggestion
	if v.Suggestion != "" {
		tpl = s.cfg.RejectMessage
	}
	r := strings.NewReplacer("{domain}", safeText(v.Domain), "{suggestion}", safeText(v.Suggestion))
	return r.Replace(tpl)
}

// PolicyAction is the Postfix policy reply for a verdict.
func (s *Service) PolicyAction(v Verdict) string {
	if v.Verdict == VerdictOK || s.cfg.Mode == ModeLog {
		return "DUNNO"
	}
	if s.cfg.Mode == ModeWarn {
		if v.Suggestion != "" {
			return fmt.Sprintf("WARN typo-guard: %s -> %s", safeText(v.Domain), safeText(v.Suggestion))
		}
		return fmt.Sprintf("WARN typo-guard: %s %s", safeText(v.Domain), v.Verdict)
	}
	return "REJECT " + s.Message(v)
}

// safeText keeps reply lines single-line and bounded.
func safeText(s string) string {
	if len(s) > 255 {
		s = s[:255]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

// maskAddress turns "john@example.com" into "j…@example.com".
func maskAddress(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return "…"
	}
	local := []rune(addr[:i])
	first := ""
	if len(local) > 0 {
		first = string(local[0])
	}
	return safeText(first + "…" + addr[i:])
}

// Metrics is a tiny Prometheus text-format registry.
type Metrics struct {
	mu        sync.Mutex
	checks    map[[2]string]uint64
	dnsErrors map[string]uint64
	syncRuns  map[string]uint64
	policyCon atomic.Int64
	started   time.Time
}

func NewMetrics() *Metrics {
	m := &Metrics{
		checks:    map[[2]string]uint64{},
		dnsErrors: map[string]uint64{"error": 0, "timeout": 0},
		syncRuns:  map[string]uint64{},
		started:   time.Now(),
	}
	for _, l := range []string{"policy", "http"} {
		for _, v := range []string{VerdictOK, VerdictTypo, VerdictInvalid} {
			m.checks[[2]string{l, v}] = 0
		}
	}
	return m
}

func (m *Metrics) IncCheck(listener, verdict string) {
	m.mu.Lock()
	m.checks[[2]string{listener, verdict}]++
	m.mu.Unlock()
}

func (m *Metrics) IncDNSError(kind string) {
	m.mu.Lock()
	m.dnsErrors[kind]++
	m.mu.Unlock()
}

func (m *Metrics) IncSync(result string) {
	m.mu.Lock()
	m.syncRuns[result]++
	m.mu.Unlock()
}

func (m *Metrics) Write(w io.Writer, allow *Allowlists, sync *SyncStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Fprintln(w, "# HELP typo_guard_checks_total Recipient checks by listener and verdict.")
	fmt.Fprintln(w, "# TYPE typo_guard_checks_total counter")
	keys := make([][2]string, 0, len(m.checks))
	for k := range m.checks {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	for _, k := range keys {
		fmt.Fprintf(w, "typo_guard_checks_total{listener=%q,verdict=%q} %d\n", k[0], k[1], m.checks[k])
	}

	fmt.Fprintln(w, "# HELP typo_guard_dns_errors_total DNS lookups that failed (treated as ok).")
	fmt.Fprintln(w, "# TYPE typo_guard_dns_errors_total counter")
	writeSorted(w, "typo_guard_dns_errors_total", "kind", m.dnsErrors)

	fmt.Fprintln(w, "# HELP typo_guard_policy_connections Open policy connections.")
	fmt.Fprintln(w, "# TYPE typo_guard_policy_connections gauge")
	fmt.Fprintf(w, "typo_guard_policy_connections %d\n", m.policyCon.Load())

	if allow != nil {
		fmt.Fprintln(w, "# HELP typo_guard_allowlist_domains Domains per allowlist.")
		fmt.Fprintln(w, "# TYPE typo_guard_allowlist_domains gauge")
		for _, l := range allow.Lists {
			fmt.Fprintf(w, "typo_guard_allowlist_domains{list=%q} %d\n", l.Name, l.Len())
		}
		fmt.Fprintln(w, "# HELP typo_guard_allowlist_last_reload_timestamp_seconds Last successful reload per allowlist.")
		fmt.Fprintln(w, "# TYPE typo_guard_allowlist_last_reload_timestamp_seconds gauge")
		for _, l := range allow.Lists {
			fmt.Fprintf(w, "typo_guard_allowlist_last_reload_timestamp_seconds{list=%q} %d\n", l.Name, l.lastReload.Load())
		}
		fmt.Fprintln(w, "# HELP typo_guard_allowlist_file_mtime_seconds Allowlist file mtime (delivered = last harvest or sync).")
		fmt.Fprintln(w, "# TYPE typo_guard_allowlist_file_mtime_seconds gauge")
		for _, l := range allow.Lists {
			var ts int64
			if mt := l.MTime(); !mt.IsZero() {
				ts = mt.Unix()
			}
			fmt.Fprintf(w, "typo_guard_allowlist_file_mtime_seconds{list=%q} %d\n", l.Name, ts)
		}
	}

	fmt.Fprintln(w, "# HELP typo_guard_delivered_sync_total Delivered-domains sync attempts by result.")
	fmt.Fprintln(w, "# TYPE typo_guard_delivered_sync_total counter")
	writeSorted(w, "typo_guard_delivered_sync_total", "result", m.syncRuns)
	if sync != nil {
		fmt.Fprintln(w, "# HELP typo_guard_delivered_sync_last_success_timestamp_seconds Last successful delivered-domains sync.")
		fmt.Fprintln(w, "# TYPE typo_guard_delivered_sync_last_success_timestamp_seconds gauge")
		fmt.Fprintf(w, "typo_guard_delivered_sync_last_success_timestamp_seconds %d\n", sync.lastSuccess.Load())
	}

	fmt.Fprintln(w, "# HELP typo_guard_start_time_seconds Process start time.")
	fmt.Fprintln(w, "# TYPE typo_guard_start_time_seconds gauge")
	fmt.Fprintf(w, "typo_guard_start_time_seconds %d\n", m.started.Unix())
	fmt.Fprintln(w, "# HELP typo_guard_build_info Build version.")
	fmt.Fprintln(w, "# TYPE typo_guard_build_info gauge")
	fmt.Fprintf(w, "typo_guard_build_info{version=%q} 1\n", version)
}

func writeSorted(w io.Writer, name, label string, m map[string]uint64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", name, label, k, m[k])
	}
}
