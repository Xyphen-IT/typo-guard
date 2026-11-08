package main

import (
	"bufio"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FileList is a domain list file that is reloaded when its mtime or size changes.
type FileList struct {
	Name string
	Path string

	set        atomic.Pointer[map[string]struct{}]
	mu         sync.Mutex
	mtime      time.Time
	size       int64
	missing    bool
	lastReload atomic.Int64 // unix seconds
}

func NewFileList(name, path string) *FileList {
	l := &FileList{Name: name, Path: path}
	empty := map[string]struct{}{}
	l.set.Store(&empty)
	return l
}

func (l *FileList) Len() int { return len(*l.set.Load()) }

func (l *FileList) Has(domain string) bool {
	_, ok := (*l.set.Load())[domain]
	return ok
}

func (l *FileList) MTime() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.mtime
}

// CheckReload reloads the file if it changed; a vanished file empties the list.
func (l *FileList) CheckReload() {
	l.mu.Lock()
	defer l.mu.Unlock()
	st, err := os.Stat(l.Path)
	if err != nil {
		if !l.missing {
			if errors.Is(err, fs.ErrNotExist) {
				slog.Info("allowlist file not present", "list", l.Name, "path", l.Path)
			} else {
				slog.Warn("allowlist file unreadable", "list", l.Name, "path", l.Path, "err", err)
			}
			if l.Len() > 0 && errors.Is(err, fs.ErrNotExist) {
				empty := map[string]struct{}{}
				l.set.Store(&empty)
			}
			l.missing, l.mtime, l.size = true, time.Time{}, 0
		}
		return
	}
	if !l.missing && st.ModTime().Equal(l.mtime) && st.Size() == l.size {
		return
	}
	set, err := readDomainFile(l.Path)
	if err != nil {
		slog.Warn("allowlist reload failed, keeping previous", "list", l.Name, "path", l.Path, "err", err)
		return
	}
	l.set.Store(&set)
	l.missing, l.mtime, l.size = false, st.ModTime(), st.Size()
	l.lastReload.Store(time.Now().Unix())
	slog.Info("allowlist loaded", "list", l.Name, "path", l.Path, "domains", len(set))
}

func readDomainFile(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if d := normalizeDomain(line); d != "" {
			set[d] = struct{}{}
		}
	}
	return set, sc.Err()
}

// Allowlists combines several lists; a domain matches itself or any parent.
type Allowlists struct {
	Lists []*FileList
}

func NewAllowlists(cfg *Config) *Allowlists {
	a := &Allowlists{}
	for _, e := range []struct{ name, path string }{
		{"static", cfg.AllowlistFile},
		{"hosted", cfg.HostedDomainsFile},
		{"delivered", cfg.DeliveredDomainsFile},
	} {
		if e.path != "" {
			a.Lists = append(a.Lists, NewFileList(e.name, e.path))
		}
	}
	return a
}

func (a *Allowlists) Get(name string) *FileList {
	for _, l := range a.Lists {
		if l.Name == name {
			return l
		}
	}
	return nil
}

func (a *Allowlists) Contains(domain string) bool {
	for d := domain; d != ""; {
		for _, l := range a.Lists {
			if l.Has(d) {
				return true
			}
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

func (a *Allowlists) ReloadAll() {
	for _, l := range a.Lists {
		l.CheckReload()
	}
}

func (a *Allowlists) Watch(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.ReloadAll()
		}
	}
}
