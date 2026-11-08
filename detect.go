package main

import (
	"context"
	"strings"
	"time"
)

const (
	VerdictOK      = "ok"
	VerdictTypo    = "typo"
	VerdictInvalid = "invalid"
)

type Verdict struct {
	Verdict    string `json:"verdict"`
	Domain     string `json:"domain"`
	Suggestion string `json:"suggestion"`
	Reason     string `json:"reason"`
}

// DomainSet reports whether a domain (or a parent of it) is allowlisted.
type DomainSet interface {
	Contains(domain string) bool
}

type Detector struct {
	popular     []string
	popularSet  map[string]bool
	popularTLDs map[string]bool
	knownTypos  map[string]string
	tldTypos    map[string]string
	tldSwap     []string
	alwaysNear  bool
	allow       DomainSet
	dns         *DNSChecker
	reqTimeout  time.Duration
}

func NewDetector(cfg *Config, allow DomainSet, dns *DNSChecker) *Detector {
	d := &Detector{
		popular:     cfg.PopularDomains,
		popularSet:  map[string]bool{},
		popularTLDs: map[string]bool{},
		knownTypos:  cfg.KnownTypos,
		tldTypos:    cfg.TLDTypos,
		tldSwap:     cfg.TLDSwapDomains,
		alwaysNear:  cfg.NearMissPolicy == NearMissAlways,
		allow:       allow,
		dns:         dns,
		reqTimeout:  cfg.DNS.RequestTimeout.Duration,
	}
	for _, p := range d.popular {
		d.popularSet[p] = true
		_, tld := splitTLD(p)
		d.popularTLDs[tld] = true
	}
	return d
}

func normalizeDomain(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// recipientDomain returns the normalised part after the last '@', or "".
func recipientDomain(rcpt string) string {
	rcpt = strings.Trim(strings.TrimSpace(rcpt), "<>")
	i := strings.LastIndexByte(rcpt, '@')
	if i < 0 {
		return ""
	}
	return normalizeDomain(rcpt[i+1:])
}

// splitTLD splits "a.b.com" into "a.b" and "com".
func splitTLD(domain string) (string, string) {
	i := strings.LastIndexByte(domain, '.')
	if i < 0 {
		return "", domain
	}
	return domain[:i], domain[i+1:]
}

func (d *Detector) allowed(domain string) bool {
	return d.popularSet[domain] || (d.allow != nil && d.allow.Contains(domain))
}

// Check judges a recipient address. It fails open: DNS problems yield ok.
func (d *Detector) Check(ctx context.Context, rcpt string) Verdict {
	domain := recipientDomain(rcpt)
	v := Verdict{Verdict: VerdictOK, Domain: domain}
	switch {
	case domain == "":
		v.Reason = "no domain"
		return v
	case strings.HasPrefix(domain, "["):
		v.Reason = "address literal"
		return v
	case d.popularSet[domain]:
		v.Reason = "popular domain"
		return v
	case d.allow != nil && d.allow.Contains(domain):
		v.Reason = "allowlisted"
		return v
	}

	if s, ok := d.knownTypos[domain]; ok {
		return Verdict{VerdictTypo, domain, s, "known typo"}
	}

	if !strings.Contains(domain, ".") {
		v = Verdict{Verdict: VerdictInvalid, Domain: domain, Reason: "no dot in domain"}
		best := 2
		for _, p := range d.popular {
			label, _ := splitTLD(p)
			if dist := osaDistance(domain, label); dist < best {
				best, v.Suggestion = dist, p
			}
		}
		return v
	}

	ctx, cancel := context.WithTimeout(ctx, d.reqTimeout)
	defer cancel()

	base, tld := splitTLD(domain)
	if !d.popularTLDs[tld] {
		exists, err := d.dns.TLDExists(ctx, tld)
		if err == nil && !exists {
			v = Verdict{Verdict: VerdictInvalid, Domain: domain, Reason: "tld does not exist"}
			if t, ok := d.tldTypos[tld]; ok && d.allowed(base+"."+t) {
				v.Suggestion = base + "." + t
			}
			return v
		}
	}

	suggestion, reason := d.nearMiss(domain)
	if suggestion == "" {
		v.Reason = "no match"
		return v
	}
	if !d.alwaysNear {
		route, err := d.dns.HasMailRoute(ctx, domain)
		if err != nil {
			v.Reason = "dns error, fail open"
			return v
		}
		if route {
			v.Reason = "near miss with mail route"
			return v
		}
		reason += ", no mail route"
	}
	return Verdict{VerdictTypo, domain, suggestion, reason}
}

// nearMiss returns the closest popular domain within the allowed distance.
func (d *Detector) nearMiss(domain string) (string, string) {
	limit := 1
	if len(domain) >= 12 {
		limit = 2
	}
	best, bestDist := "", limit+1
	for _, p := range d.popular {
		if dist := osaDistance(domain, p); dist < bestDist {
			best, bestDist = p, dist
		}
	}
	if best != "" {
		return best, "near miss"
	}
	base, tld := splitTLD(domain)
	for _, p := range d.tldSwap {
		pb, ptld := splitTLD(p)
		if pb == base && ptld != tld {
			return p, "tld swap"
		}
	}
	return "", ""
}

// osaDistance is the optimal string alignment (restricted Damerau-Levenshtein) distance.
func osaDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	n, m := len(ra), len(rb)
	if n == 0 {
		return m
	}
	if m == 0 {
		return n
	}
	// Three rolling rows: two back, previous, current.
	prev2 := make([]int, m+1)
	prev := make([]int, m+1)
	cur := make([]int, m+1)
	for j := 0; j <= m; j++ {
		prev[j] = j
	}
	for i := 1; i <= n; i++ {
		cur[0] = i
		for j := 1; j <= m; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				cur[j] = min(cur[j], prev2[j-2]+1)
			}
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return prev[m]
}
