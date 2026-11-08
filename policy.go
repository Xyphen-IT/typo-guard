package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

const (
	policyMaxLine  = 8192
	policyMaxAttrs = 256
	policyWriteTO  = 10 * time.Second
)

var errLineTooLong = errors.New("policy line too long")

// PolicyServer implements the Postfix SMTP access policy delegation protocol.
type PolicyServer struct {
	svc         *Service
	idleTimeout time.Duration
	sem         chan struct{}
	wg          sync.WaitGroup
}

func NewPolicyServer(svc *Service, idle time.Duration, maxConns int) *PolicyServer {
	return &PolicyServer{svc: svc, idleTimeout: idle, sem: make(chan struct{}, maxConns)}
}

func (p *PolicyServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				p.wg.Wait()
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		select {
		case p.sem <- struct{}{}:
		default:
			slog.Warn("policy connection limit reached, closing", "remote", conn.RemoteAddr().String())
			conn.Close()
			continue
		}
		p.wg.Add(1)
		go func() {
			defer func() { <-p.sem; p.wg.Done() }()
			p.handle(ctx, conn)
		}()
	}
}

func (p *PolicyServer) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	p.svc.metrics.policyCon.Add(1)
	defer p.svc.metrics.policyCon.Add(-1)
	stop := context.AfterFunc(ctx, func() { conn.SetReadDeadline(time.Now()) })
	defer stop()

	r := bufio.NewReaderSize(conn, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(p.idleTimeout))
		attrs, err := readPolicyRequest(r)
		if err != nil {
			if !errors.Is(err, io.EOF) && !isTimeout(err) && ctx.Err() == nil {
				slog.Warn("policy request error", "remote", conn.RemoteAddr().String(), "err", err)
			}
			return
		}
		action := p.decide(ctx, attrs)
		conn.SetWriteDeadline(time.Now().Add(policyWriteTO))
		if _, err := fmt.Fprintf(conn, "action=%s\n\n", action); err != nil {
			return
		}
	}
}

func (p *PolicyServer) decide(ctx context.Context, attrs map[string]string) string {
	if attrs["protocol_state"] != "RCPT" {
		return "DUNNO"
	}
	v := p.svc.Check(ctx, CheckInfo{
		Listener: "policy",
		Rcpt:     attrs["recipient"],
		SASL:     attrs["sasl_username"],
		Client:   attrs["client_address"],
	})
	return p.svc.PolicyAction(v)
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readPolicyRequest reads name=value lines up to an empty line.
func readPolicyRequest(r *bufio.Reader) (map[string]string, error) {
	attrs := map[string]string{}
	lines := 0
	for {
		line, err := readLine(r)
		if err != nil {
			if errors.Is(err, io.EOF) && lines > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if len(line) == 0 {
			if lines == 0 {
				continue // tolerate stray empty lines between requests
			}
			return attrs, nil
		}
		lines++
		if lines > policyMaxAttrs {
			return nil, errors.New("too many policy attributes")
		}
		if k, v, ok := bytes.Cut(line, []byte("=")); ok {
			attrs[string(k)] = string(v)
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > policyMaxLine {
			return nil, errLineTooLong
		}
		buf = append(buf, chunk...)
		if err == nil {
			return bytes.TrimRight(buf, "\r\n"), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}
