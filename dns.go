package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// Resolver is the subset of *net.Resolver we use; tests supply a fake.
type Resolver interface {
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type cacheEntry struct {
	value   bool
	expires time.Time
}

// DNSChecker answers the two questions the detector asks, with caching.
// Errors are returned uncached so callers can fail open.
type DNSChecker struct {
	res           Resolver
	lookupTimeout time.Duration
	posTTL        time.Duration
	negTTL        time.Duration
	maxEntries    int
	onError       func(kind string)
	now           func() time.Time

	mu    sync.Mutex
	cache map[string]cacheEntry
}

func NewDNSChecker(res Resolver, cfg DNSConfig, onError func(kind string)) *DNSChecker {
	if onError == nil {
		onError = func(string) {}
	}
	return &DNSChecker{
		res:           res,
		lookupTimeout: cfg.LookupTimeout.Duration,
		posTTL:        cfg.PositiveTTL.Duration,
		negTTL:        cfg.NegativeTTL.Duration,
		maxEntries:    100000,
		onError:       onError,
		now:           time.Now,
		cache:         map[string]cacheEntry{},
	}
}

func (c *DNSChecker) get(key string) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[key]
	if !ok || c.now().After(e.expires) {
		return false, false
	}
	return e.value, true
}

func (c *DNSChecker) put(key string, v bool) {
	ttl := c.negTTL
	if v {
		ttl = c.posTTL
	}
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.maxEntries {
		for k, e := range c.cache {
			if now.After(e.expires) {
				delete(c.cache, k)
			}
		}
		if len(c.cache) >= c.maxEntries {
			c.cache = map[string]cacheEntry{}
		}
	}
	c.cache[key] = cacheEntry{v, now.Add(ttl)}
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func (c *DNSChecker) classify(err error) error {
	var de *net.DNSError
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &de) && de.IsTimeout) {
		c.onError("timeout")
	} else {
		c.onError("error")
	}
	return err
}

// TLDExists looks up NS records for the TLD. Unknown answers return an error.
func (c *DNSChecker) TLDExists(ctx context.Context, tld string) (bool, error) {
	key := "tld:" + tld
	if v, ok := c.get(key); ok {
		return v, nil
	}
	lctx, cancel := context.WithTimeout(ctx, c.lookupTimeout)
	defer cancel()
	ns, err := c.res.LookupNS(lctx, tld+".")
	switch {
	case err == nil:
		c.put(key, len(ns) > 0)
		return len(ns) > 0, nil
	case isNotFound(err):
		c.put(key, false)
		return false, nil
	default:
		return false, c.classify(err)
	}
}

// HasMailRoute reports false for NXDOMAIN, null MX, or no MX and no address records.
func (c *DNSChecker) HasMailRoute(ctx context.Context, domain string) (bool, error) {
	key := "route:" + domain
	if v, ok := c.get(key); ok {
		return v, nil
	}
	lctx, cancel := context.WithTimeout(ctx, c.lookupTimeout)
	mx, err := c.res.LookupMX(lctx, domain+".")
	cancel()
	if err == nil && len(mx) > 0 {
		route := false
		for _, r := range mx {
			if r.Host != "." && r.Host != "" {
				route = true
			}
		}
		c.put(key, route)
		return route, nil
	}
	if err != nil && !isNotFound(err) {
		return false, c.classify(err)
	}
	lctx, cancel = context.WithTimeout(ctx, c.lookupTimeout)
	defer cancel()
	addrs, err := c.res.LookupHost(lctx, domain+".")
	switch {
	case err == nil:
		c.put(key, len(addrs) > 0)
		return len(addrs) > 0, nil
	case isNotFound(err):
		c.put(key, false)
		return false, nil
	default:
		return false, c.classify(err)
	}
}
