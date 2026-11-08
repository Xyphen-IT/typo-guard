package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

const syncMaxBody = 64 << 20

// SyncStatus tracks the delivered-domains download.
type SyncStatus struct {
	lastSuccess atomic.Int64
}

// DeliveredSync periodically fetches the delivered-domains list from another host.
type DeliveredSync struct {
	URL      string
	Path     string
	Interval time.Duration
	Client   *http.Client
	Metrics  *Metrics
	Status   *SyncStatus
	OnUpdate func()
}

func (s *DeliveredSync) Run(ctx context.Context) {
	for {
		s.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(s.Interval):
		}
	}
}

// RunOnce downloads and installs the list; on any problem the current file stays.
func (s *DeliveredSync) RunOnce(ctx context.Context) string {
	result, n, err := s.fetch(ctx)
	s.Metrics.IncSync(result)
	switch {
	case err != nil:
		slog.Warn("delivered sync failed, keeping current file", "url", s.URL, "result", result, "err", err)
	case result == "unchanged":
		s.Status.lastSuccess.Store(time.Now().Unix())
		slog.Debug("delivered sync unchanged", "url", s.URL, "domains", n)
	default:
		s.Status.lastSuccess.Store(time.Now().Unix())
		slog.Info("delivered sync updated", "url", s.URL, "path", s.Path, "domains", n)
		if s.OnUpdate != nil {
			s.OnUpdate()
		}
	}
	return result
}

func (s *DeliveredSync) fetch(ctx context.Context) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.URL, nil)
	if err != nil {
		return "error", 0, err
	}
	req.Header.Set("User-Agent", "typo-guard/"+version)
	resp, err := s.Client.Do(req)
	if err != nil {
		return "error", 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "error", 0, fmt.Errorf("http status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, syncMaxBody+1))
	if err != nil {
		return "error", 0, err
	}
	if len(body) > syncMaxBody {
		return "rejected", 0, errors.New("body too large")
	}
	n, err := countDomains(body)
	if err != nil {
		return "rejected", 0, err
	}
	if n == 0 {
		return "rejected", 0, errors.New("empty list")
	}
	current, err := os.ReadFile(s.Path)
	if err == nil {
		if bytes.Equal(current, body) {
			return "unchanged", n, nil
		}
		if cur, _ := countDomains(current); n*2 < cur {
			return "rejected", n, fmt.Errorf("list shrank from %d to %d domains", cur, n)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "error", n, err
	}
	if err := writeFileAtomic(s.Path, body); err != nil {
		return "error", n, err
	}
	return "updated", n, nil
}

// countDomains validates a list body and counts its entries.
func countDomains(body []byte) (int, error) {
	n := 0
	for i, line := range strings.Split(string(body), "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t<>@/\x00") {
			return 0, fmt.Errorf("line %d does not look like a domain", i+1)
		}
		n++
	}
	return n, nil
}

// writeFileAtomic writes via a temp file in the same directory and renames it.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
