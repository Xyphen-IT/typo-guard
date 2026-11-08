// Command typo-guard flags mistyped recipient domains in outgoing mail.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

const defaultConfigPath = "/etc/typo-guard/config.json"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = runServe(args)
	case "harvest":
		err = runHarvest(args, os.Stdout)
	case "check":
		err = runCheck(args)
	case "version":
		fmt.Println(version)
	default:
		fmt.Fprintf(os.Stderr, "usage: typo-guard [serve|harvest|check|version] [flags]\n")
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "typo-guard: %v\n", err)
		os.Exit(1)
	}
}

func parseLevel(s string) (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(s)); err != nil {
		return l, fmt.Errorf("log_level %q must be debug, info, warn or error", s)
	}
	return l, nil
}

func setupLogging(level string) {
	l, _ := parseLevel(level)
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: l,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{} // journald adds timestamps
			}
			return a
		},
	})
	slog.SetDefault(slog.New(h))
}

func buildService(cfg *Config) *Service {
	metrics := NewMetrics()
	allow := NewAllowlists(cfg)
	dns := NewDNSChecker(net.DefaultResolver, cfg.DNS, metrics.IncDNSError)
	return &Service{
		cfg:      cfg,
		det:      NewDetector(cfg, allow, dns),
		allow:    allow,
		metrics:  metrics,
		syncStat: &SyncStatus{},
	}
}

func runServe(args []string) error {
	fl := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fl.String("config", defaultConfigPath, "config file")
	if err := fl.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*path)
	if err != nil {
		return err
	}
	setupLogging(cfg.LogLevel)
	svc := buildService(cfg)
	slog.Info("starting typo-guard", "version", version, "config", *path,
		"policy_listen", cfg.PolicyListen, "http_listen", cfg.HTTPListen, "mode", cfg.Mode,
		"near_miss_policy", cfg.NearMissPolicy, "popular", len(cfg.PopularDomains),
		"known_typos", len(cfg.KnownTypos), "tld_typos", len(cfg.TLDTypos),
		"http_allow", strings.Join(cfg.HTTPAllow, ","), "delivered_sync_url", cfg.DeliveredSyncURL,
		"dns_lookup_timeout", cfg.DNS.LookupTimeout.String(), "dns_request_timeout", cfg.DNS.RequestTimeout.String())
	svc.allow.ReloadAll()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go svc.allow.Watch(ctx, cfg.AllowlistReload.Duration)

	if cfg.DeliveredSyncURL != "" {
		ds := &DeliveredSync{
			URL: cfg.DeliveredSyncURL, Path: cfg.DeliveredDomainsFile, Interval: cfg.DeliveredSyncInterval.Duration,
			Client:  &http.Client{Timeout: cfg.DeliveredSyncTimeout.Duration},
			Metrics: svc.metrics, Status: svc.syncStat,
			OnUpdate: func() {
				if l := svc.allow.Get("delivered"); l != nil {
					l.CheckReload()
				}
			},
		}
		go ds.Run(ctx)
	}

	errc := make(chan error, 2)
	if cfg.PolicyListen != "" {
		ln, err := net.Listen("tcp", cfg.PolicyListen)
		if err != nil {
			return fmt.Errorf("policy listener: %w", err)
		}
		ps := NewPolicyServer(svc, cfg.PolicyIdleTimeout.Duration, cfg.PolicyMaxConnections)
		go func() { errc <- ps.Serve(ctx, ln) }()
	}
	var hs *http.Server
	if cfg.HTTPListen != "" {
		ln, err := net.Listen("tcp", cfg.HTTPListen)
		if err != nil {
			return fmt.Errorf("http listener: %w", err)
		}
		hs = &http.Server{
			Handler:           svc.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			if err := hs.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	slog.Info("listening")

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
	case err = <-errc:
		if err != nil {
			slog.Error("listener failed", "err", err)
		}
	}
	stop()
	if hs != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}
	return err
}

// runCheck evaluates addresses once, for manual testing.
func runCheck(args []string) error {
	fl := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fl.String("config", defaultConfigPath, "config file (built-in defaults if it does not exist)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*path)
	if errors.Is(err, os.ErrNotExist) {
		cfg, err = parseConfig([]byte("{}"))
	}
	if err != nil {
		return err
	}
	setupLogging("error")
	svc := buildService(cfg)
	svc.allow.ReloadAll()
	enc := json.NewEncoder(os.Stdout)
	for _, a := range fl.Args() {
		v := svc.det.Check(context.Background(), a)
		enc.Encode(checkResponse{Verdict: v, Message: svc.Message(v), Mode: cfg.Mode})
	}
	return nil
}
