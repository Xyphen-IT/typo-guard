package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"os"
)

type checkResponse struct {
	Verdict
	Message string `json:"message"`
	Mode    string `json:"mode"`
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /v1/check", s.restricted(http.HandlerFunc(s.handleCheck)))
	mux.Handle("GET /v1/delivered", s.restricted(http.HandlerFunc(s.handleDelivered)))
	mux.Handle("GET /metrics", s.restricted(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.metrics.Write(w, s.allow, s.syncStat)
	})))
	return mux
}

// restricted enforces http_allow; an empty list allows everyone.
func (s *Service) restricted(h http.Handler) http.Handler {
	if len(s.cfg.httpAllow) == 0 {
		return h
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		addr, perr := netip.ParseAddr(host)
		if err != nil || perr != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		addr = addr.Unmap()
		for _, p := range s.cfg.httpAllow {
			if p.Contains(addr) {
				h.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}

func (s *Service) handleCheck(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rcpt := q.Get("rcpt")
	if rcpt == "" && q.Get("domain") != "" {
		rcpt = "x@" + q.Get("domain")
	}
	w.Header().Set("Content-Type", "application/json")
	if rcpt == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "rcpt or domain parameter required"})
		return
	}
	v := s.Check(r.Context(), CheckInfo{Listener: "http", Rcpt: rcpt, Client: r.RemoteAddr})
	json.NewEncoder(w).Encode(checkResponse{Verdict: v, Message: s.Message(v), Mode: s.cfg.Mode})
}

func (s *Service) handleDelivered(w http.ResponseWriter, r *http.Request) {
	path := s.cfg.DeliveredDomainsFile
	f, err := os.Open(path)
	if path == "" || errors.Is(err, fs.ErrNotExist) {
		http.Error(w, "no delivered-domains file", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "cannot read delivered-domains file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.Error(w, "cannot read delivered-domains file", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeContent(w, r, "", st.ModTime(), f)
}
