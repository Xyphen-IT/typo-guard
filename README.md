# typo-guard

Detects mistyped recipient domains in outgoing e-mail (`ghotmail.com` → `hotmail.com`,
`name@zinlab` without a TLD) and tells Postfix what to do about it.

* **Postfix policy delegation server** (default `127.0.0.1:10041`)
* **HTTP API** (default `127.0.0.1:10042`): `/v1/check`, `/v1/delivered`, `/healthz`, `/metrics`
* **`harvest`** subcommand that learns delivered domains from KumoMTA logs

## Detection

Recipient domains are lowercased, trimmed and stripped of a trailing dot (part after the
last `@`). Rules, first match wins:

| # | Rule | Verdict | DNS |
|---|------|---------|-----|
| 1 | empty / no `@` / address literal | ok | no |
| 2 | domain is popular, or it (or a parent) is in an allowlist file | ok | no |
| 3 | listed in `known_typos` | typo, mapped suggestion | no |
| 4 | no dot | invalid; suggestion if within distance 1 of a popular domain's first label (`gmail` → `gmail.com`) | no |
| 5 | TLD has no NS records | invalid; suggestion if `tld_typos` maps it to a popular/allowlisted domain (`gmail.con` → `gmail.com`) | NS of the TLD (skipped for TLDs of popular domains) |
| 6 | OSA distance 1 to a popular domain (2 when the domain is ≥ 12 chars), or same first label with another TLD for `tld_swap_domains` | typo when `near_miss_policy` is `always`, or `no-mx` and the domain has no mail route (NXDOMAIN, null MX, or no MX and no A/AAAA) | MX, then A/AAAA |
| 7 | otherwise | ok | – |

Known typos are flagged even when they have MX records: typo-squatting domains often accept mail.

DNS uses the system resolver with a per-lookup timeout and a per-request deadline, and caches
answers (positive and negative TTLs). Any DNS error or timeout yields `ok` (fail open).

## Postfix

```
smtpd_recipient_restrictions =
    ...
    check_policy_service { inet:127.0.0.1:10041, timeout=5s, default_action=DUNNO }
```

Only requests with `protocol_state=RCPT` are judged; everything else gets `DUNNO`. Replies:

| mode | ok | typo / invalid |
|------|----|----------------|
| `log` | `DUNNO` | `DUNNO` (log and metrics only) |
| `warn` | `DUNNO` | `WARN typo-guard: <domain> -> <suggestion>` |
| `reject` | `DUNNO` | `REJECT 5.1.2 …` (from `reject_message` / `reject_message_no_suggestion`) |

For a Postfix in a container (mailcow), bind `policy_listen` to the Docker bridge gateway, e.g.
`172.22.1.1:10041`. The unit restarts every 5 s until that address exists.

## HTTP API

```
GET /v1/check?rcpt=user@gmail.con     (or ?domain=gmail.con)
{"verdict":"invalid","domain":"gmail.con","suggestion":"gmail.com","reason":"tld does not exist",
 "message":"5.1.2 Het domein gmail.con …","mode":"log"}
GET /v1/delivered   current delivered-domains file (text/plain, 404 if absent)
GET /healthz        200 ok
GET /metrics        Prometheus text format
```

`http_allow` (CIDRs or addresses) restricts every endpoint except `/healthz`; others get 403.

Metrics: `typo_guard_checks_total{listener,verdict}`, `typo_guard_dns_errors_total{kind}`,
`typo_guard_allowlist_domains{list}`, `typo_guard_allowlist_last_reload_timestamp_seconds{list}`,
`typo_guard_allowlist_file_mtime_seconds{list}` (for `delivered`: last harvest/sync),
`typo_guard_delivered_sync_total{result}`, `typo_guard_delivered_sync_last_success_timestamp_seconds`,
`typo_guard_policy_connections`, `typo_guard_start_time_seconds`, `typo_guard_build_info`.

## Delivered domains

On the host with KumoMTA logs, `typo-guard-harvest.timer` runs hourly:

```
typo-guard harvest --kumo-logs /var/log/kumomta --days 90 --out /var/lib/typo-guard/delivered.txt
```

It reads every segment (zstd JSON lines; a truncated segment that is still being written is fine)
whose mtime is in the window, collects recipient domains of `Delivery` records and writes the
sorted list atomically. If nothing is found the existing file is left alone. The running server
picks the file up by mtime. Start `typo-guard.service` once before the timer: it creates
`/var/lib/typo-guard`.

Other hosts fetch that list with `delivered_sync_url` (e.g.
`http://10.0.0.5:10042/v1/delivered`, with `http_allow` on the source). A download replaces the
local file atomically only when it is non-empty, looks like a domain list, and does not shrink by
more than 50 %; otherwise the last good copy stays.

## Configuration

`/etc/typo-guard/config.json` (flag `-config`). Absent fields use the defaults below; unknown
fields and invalid values stop the service at start. Comments are not valid JSON; they are
annotations only.

```jsonc
{
  "policy_listen": "127.0.0.1:10041",      // "" disables
  "policy_idle_timeout": "300s",           // read deadline per request on a keep-alive connection
  "policy_max_connections": 1024,
  "http_listen": "127.0.0.1:10042",        // "" disables
  "http_allow": [],                        // e.g. ["127.0.0.1", "10.0.0.0/8"]; empty = all
  "mode": "log",                           // log | warn | reject
  "near_miss_policy": "no-mx",             // no-mx | always
  "popular_domains": ["gmail.com", "..."], // replaces the built-in list
  "extra_popular_domains": [],             // extends it
  "known_typos": {"ghotmail.com": "hotmail.com", "gmial.com": "gmail.com"}, // replaces built-in map
  "tld_typos": {"con": "com", "nll": "nl"},                                 // replaces built-in map
  "tld_swap_domains": ["gmail.com", "googlemail.com", "icloud.com"],        // must be popular
  "allowlist_file": "/etc/typo-guard/allowlist.txt",          // one domain per line, # comments
  "hosted_domains_file": "/etc/typo-guard/hosted-domains.txt",
  "delivered_domains_file": "/var/lib/typo-guard/delivered.txt",
  "allowlist_reload_interval": "10s",      // mtime/size check interval
  "delivered_sync_url": "",                // "" disables
  "delivered_sync_interval": "1h",
  "delivered_sync_timeout": "30s",
  "dns": {
    "lookup_timeout": "1s",
    "request_timeout": "2s",
    "positive_ttl": "1h",
    "negative_ttl": "10m"
  },
  "reject_message": "5.1.2 Het domein {domain} bestaat waarschijnlijk niet, bedoelde u {suggestion}? / The domain {domain} probably does not exist, did you mean {suggestion}?",
  "reject_message_no_suggestion": "5.1.2 Het domein {domain} bestaat niet of is ongeldig / The domain {domain} does not exist or is invalid",
  "log_level": "info"                      // debug | info | warn | error
}
```

Built-in popular domains: gmail.com, googlemail.com, hotmail.com, hotmail.nl, outlook.com,
live.nl, live.com, msn.com, icloud.com, me.com, yahoo.com, ziggo.nl, kpnmail.nl, kpnplanet.nl,
planet.nl, home.nl, xs4all.nl, hetnet.nl, casema.nl, upcmail.nl, telfort.nl, chello.nl,
quicknet.nl, online.nl, tele2.nl, zeelandnet.nl, solcon.nl, gmx.de, gmx.net, web.de,
t-online.de, proton.me, protonmail.com.

Test a config by hand: `typo-guard check -config /etc/typo-guard/config.json user@gmail.con`.

## Logging

One logfmt line per event on stderr (journald). Every non-ok verdict is logged with listener,
verdict, masked recipient (`j…@example.com`), domain, suggestion, reason, `sasl_username` and
`client_address`.

## Package

`make test` runs vet and tests; `make deb` builds `dist/typo-guard_0.1.0_amd64.deb` (static
linux/amd64 binary, nfpm via `go run`). The package installs the binary, the config (conffile)
and the units, runs `daemon-reload`, and on upgrade restarts `typo-guard.service` only if it is
running. It never enables or starts units.
