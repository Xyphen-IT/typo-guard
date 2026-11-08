package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	ModeLog    = "log"
	ModeWarn   = "warn"
	ModeReject = "reject"

	NearMissNoMX   = "no-mx"
	NearMissAlways = "always"
)

// Duration accepts Go duration strings ("1s", "10m") in JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("duration must be a string such as \"1s\", got %s", b)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

type DNSConfig struct {
	LookupTimeout  Duration `json:"lookup_timeout"`
	RequestTimeout Duration `json:"request_timeout"`
	PositiveTTL    Duration `json:"positive_ttl"`
	NegativeTTL    Duration `json:"negative_ttl"`
}

type Config struct {
	PolicyListen         string   `json:"policy_listen"`
	PolicyIdleTimeout    Duration `json:"policy_idle_timeout"`
	PolicyMaxConnections int      `json:"policy_max_connections"`
	HTTPListen           string   `json:"http_listen"`
	HTTPAllow            []string `json:"http_allow"`

	Mode           string `json:"mode"`
	NearMissPolicy string `json:"near_miss_policy"`

	PopularDomains      []string          `json:"popular_domains"`
	ExtraPopularDomains []string          `json:"extra_popular_domains"`
	KnownTypos          map[string]string `json:"known_typos"`
	TLDTypos            map[string]string `json:"tld_typos"`
	TLDSwapDomains      []string          `json:"tld_swap_domains"`

	AllowlistFile         string   `json:"allowlist_file"`
	HostedDomainsFile     string   `json:"hosted_domains_file"`
	DeliveredDomainsFile  string   `json:"delivered_domains_file"`
	AllowlistReload       Duration `json:"allowlist_reload_interval"`
	DeliveredSyncURL      string   `json:"delivered_sync_url"`
	DeliveredSyncInterval Duration `json:"delivered_sync_interval"`
	DeliveredSyncTimeout  Duration `json:"delivered_sync_timeout"`

	DNS DNSConfig `json:"dns"`

	RejectMessage             string `json:"reject_message"`
	RejectMessageNoSuggestion string `json:"reject_message_no_suggestion"`

	LogLevel string `json:"log_level"`

	httpAllow []netip.Prefix
}

var defaultPopular = []string{
	"gmail.com", "googlemail.com", "hotmail.com", "hotmail.nl", "outlook.com", "live.nl", "live.com",
	"msn.com", "icloud.com", "me.com", "yahoo.com", "ziggo.nl", "kpnmail.nl", "kpnplanet.nl", "planet.nl",
	"home.nl", "xs4all.nl", "hetnet.nl", "casema.nl", "upcmail.nl", "telfort.nl", "chello.nl", "quicknet.nl",
	"online.nl", "tele2.nl", "zeelandnet.nl", "solcon.nl", "gmx.de", "gmx.net", "web.de", "t-online.de",
	"proton.me", "protonmail.com",
}

var defaultKnownTypos = map[string]string{
	"ghotmail.com": "hotmail.com", "hotmial.com": "hotmail.com", "hotmal.com": "hotmail.com",
	"hotmai.com": "hotmail.com", "homail.com": "hotmail.com", "hotamil.com": "hotmail.com",
	"gmial.com": "gmail.com", "gnail.com": "gmail.com", "gmal.com": "gmail.com",
	"gamil.com": "gmail.com", "gmaill.com": "gmail.com",
	"outlok.com": "outlook.com", "outllok.com": "outlook.com",
	"iclod.com": "icloud.com", "icoud.com": "icloud.com",
}

var defaultTLDSwap = []string{"gmail.com", "googlemail.com", "icloud.com"}

var defaultTLDTypos = map[string]string{
	"con": "com", "cmo": "com", "cpm": "com", "vom": "com", "xom": "com", "ocm": "com", "comm": "com",
	"nll": "nl", "nk": "nl", "bl": "nl", "ln": "nl",
	"nte": "net", "ner": "net",
	"dee": "de",
}

func defaultConfig() Config {
	return Config{
		PolicyListen:          "127.0.0.1:10041",
		PolicyIdleTimeout:     Duration{300 * time.Second},
		PolicyMaxConnections:  1024,
		HTTPListen:            "127.0.0.1:10042",
		Mode:                  ModeLog,
		NearMissPolicy:        NearMissNoMX,
		AllowlistFile:         "/etc/typo-guard/allowlist.txt",
		HostedDomainsFile:     "/etc/typo-guard/hosted-domains.txt",
		DeliveredDomainsFile:  "/var/lib/typo-guard/delivered.txt",
		AllowlistReload:       Duration{10 * time.Second},
		DeliveredSyncInterval: Duration{time.Hour},
		DeliveredSyncTimeout:  Duration{30 * time.Second},
		DNS: DNSConfig{
			LookupTimeout:  Duration{time.Second},
			RequestTimeout: Duration{2 * time.Second},
			PositiveTTL:    Duration{time.Hour},
			NegativeTTL:    Duration{10 * time.Minute},
		},
		RejectMessage:             "5.1.2 Het domein {domain} bestaat waarschijnlijk niet, bedoelde u {suggestion}? / The domain {domain} probably does not exist, did you mean {suggestion}?",
		RejectMessageNoSuggestion: "5.1.2 Het domein {domain} bestaat niet of is ongeldig / The domain {domain} does not exist or is invalid",
		LogLevel:                  "info",
	}
}

// LoadConfig reads a JSON config; absent fields keep their defaults.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return parseConfig(data)
}

func parseConfig(data []byte) (*Config, error) {
	cfg := defaultConfig()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if err := cfg.finish(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &cfg, nil
}

var enhancedCodeRe = regexp.MustCompile(`^5\.\d{1,3}\.\d{1,3} `)

func (c *Config) finish() error {
	if c.PopularDomains == nil {
		c.PopularDomains = defaultPopular
	}
	if c.KnownTypos == nil {
		c.KnownTypos = defaultKnownTypos
	}
	if c.TLDTypos == nil {
		c.TLDTypos = defaultTLDTypos
	}

	var popular []string
	seen := map[string]bool{}
	for _, d := range append(append([]string{}, c.PopularDomains...), c.ExtraPopularDomains...) {
		n := normalizeDomain(d)
		if n == "" || !strings.Contains(n, ".") {
			return fmt.Errorf("popular domain %q is not a valid domain", d)
		}
		if !seen[n] {
			seen[n] = true
			popular = append(popular, n)
		}
	}
	c.PopularDomains, c.ExtraPopularDomains = popular, nil

	typos := map[string]string{}
	for k, v := range c.KnownTypos {
		nk, nv := normalizeDomain(k), normalizeDomain(v)
		if nk == "" || nv == "" || nk == nv {
			return fmt.Errorf("known_typos entry %q: %q is invalid", k, v)
		}
		typos[nk] = nv
	}
	c.KnownTypos = typos

	tlds := map[string]string{}
	for k, v := range c.TLDTypos {
		nk, nv := normalizeDomain(k), normalizeDomain(v)
		if nk == "" || nv == "" || strings.Contains(nk, ".") || strings.Contains(nv, ".") {
			return fmt.Errorf("tld_typos entry %q: %q must map a single label to a single label", k, v)
		}
		tlds[nk] = nv
	}
	c.TLDTypos = tlds

	if c.TLDSwapDomains == nil {
		for _, d := range defaultTLDSwap {
			if seen[d] {
				c.TLDSwapDomains = append(c.TLDSwapDomains, d)
			}
		}
	}
	for i, d := range c.TLDSwapDomains {
		n := normalizeDomain(d)
		if !seen[n] {
			return fmt.Errorf("tld_swap_domains entry %q is not in the popular list", d)
		}
		c.TLDSwapDomains[i] = n
	}

	switch c.Mode {
	case ModeLog, ModeWarn, ModeReject:
	default:
		return fmt.Errorf("mode %q must be log, warn or reject", c.Mode)
	}
	switch c.NearMissPolicy {
	case NearMissNoMX, NearMissAlways:
	default:
		return fmt.Errorf("near_miss_policy %q must be no-mx or always", c.NearMissPolicy)
	}
	if c.PolicyListen == "" && c.HTTPListen == "" {
		return fmt.Errorf("policy_listen and http_listen are both empty")
	}
	for name, addr := range map[string]string{"policy_listen": c.PolicyListen, "http_listen": c.HTTPListen} {
		if addr == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return fmt.Errorf("%s %q: %v", name, addr, err)
		}
	}
	for _, s := range c.HTTPAllow {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return fmt.Errorf("http_allow entry %q is not a CIDR or address", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		c.httpAllow = append(c.httpAllow, p.Masked())
	}
	if c.PolicyMaxConnections <= 0 {
		return fmt.Errorf("policy_max_connections must be > 0")
	}
	durations := map[string]Duration{
		"policy_idle_timeout": c.PolicyIdleTimeout, "allowlist_reload_interval": c.AllowlistReload,
		"delivered_sync_interval": c.DeliveredSyncInterval, "delivered_sync_timeout": c.DeliveredSyncTimeout,
		"dns.lookup_timeout": c.DNS.LookupTimeout, "dns.request_timeout": c.DNS.RequestTimeout,
		"dns.positive_ttl": c.DNS.PositiveTTL, "dns.negative_ttl": c.DNS.NegativeTTL,
	}
	for name, d := range durations {
		if d.Duration <= 0 {
			return fmt.Errorf("%s must be > 0", name)
		}
	}
	if c.DeliveredSyncURL != "" {
		if !strings.HasPrefix(c.DeliveredSyncURL, "http://") && !strings.HasPrefix(c.DeliveredSyncURL, "https://") {
			return fmt.Errorf("delivered_sync_url %q must be http(s)", c.DeliveredSyncURL)
		}
		if c.DeliveredDomainsFile == "" {
			return fmt.Errorf("delivered_sync_url needs delivered_domains_file")
		}
	}
	for name, m := range map[string]string{"reject_message": c.RejectMessage, "reject_message_no_suggestion": c.RejectMessageNoSuggestion} {
		if !enhancedCodeRe.MatchString(m) {
			return fmt.Errorf("%s must start with a 5.x.x enhanced status code followed by a space", name)
		}
		if strings.ContainsAny(m, "\r\n") {
			return fmt.Errorf("%s must be a single line", name)
		}
	}
	if _, err := parseLevel(c.LogLevel); err != nil {
		return err
	}
	return nil
}
