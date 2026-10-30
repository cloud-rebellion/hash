//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
)

// Finite local transport fixture. Forward genuine PostgreSQL protocol bytes;
// after the explicitly armed Admission PID receives a real Q commit, consume
// but withhold its genuine completion/error and idle response, then close the
// connection. No transaction, SQL result, backend identity or outcome is
// supplied to production code. It never logs authentication frames.
type packageCommitWireProxy236 struct {
	dialCtx    context.Context
	cancelDial context.CancelFunc
	closing    atomic.Bool
	listener   *net.UnixListener
	upstream   string
	deadline   time.Time
	mode       string
	mu         sync.Mutex
	pairs      []*packageCommitWirePair236
	workers    sync.WaitGroup
	acceptDone chan struct{}
	target     atomic.Int32
	// Test-only automatic arming observes the actual fixed sqlc statement on
	// its actual PostgreSQL connection; it supplies no PID or result to the app.
	armQuery         atomic.Pointer[string]
	accepted         atomic.Int32
	bad              atomic.Bool
	fault            chan struct{}
	faultOnce        sync.Once
	observedCommit   atomic.Bool
	observedRollback atomic.Bool
}
type packageCommitWirePair236 struct {
	client     *net.UnixConn
	server     net.Conn
	pid        atomic.Int32
	commitSeen atomic.Bool
	once       sync.Once
}

func (p *packageCommitWirePair236) close236() {
	p.once.Do(func() { _ = p.client.Close(); _ = p.server.Close() })
}

var errCommitWireBound236 = errors.New("bounded local commit frame refused")

func commitWireWrite236(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, e := w.Write(b)
		if e != nil {
			return e
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}
func commitWireFrame236(r io.Reader, used, frames *int) (byte, []byte, error) {
	var head [5]byte
	if _, e := io.ReadFull(r, head[:]); e != nil {
		return 0, nil, e
	}
	n := int(binary.BigEndian.Uint32(head[1:]))
	*frames++
	if n < 4 || n > 65536 || *frames > 8192 || *used+n+1 > 16<<20 {
		return 0, nil, errCommitWireBound236
	}
	raw := make([]byte, n+1)
	copy(raw, head[:])
	*used += len(raw)
	_, e := io.ReadFull(r, raw[5:])
	return head[0], raw, e
}
func (p *packageCommitWireProxy236) client236(pair *packageCommitWirePair236) {
	defer p.workers.Done()
	defer pair.close236()
	var head [4]byte
	if _, e := io.ReadFull(pair.client, head[:]); e != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(head[:]))
	if n < 8 || n > 65536 {
		p.bad.Store(true)
		return
	}
	raw := make([]byte, n)
	copy(raw, head[:])
	if _, e := io.ReadFull(pair.client, raw[4:]); e != nil {
		return
	}
	if binary.BigEndian.Uint32(raw[4:8]) != 196608 {
		p.bad.Store(true)
		return
	}
	if commitWireWrite236(pair.server, raw) != nil {
		return
	}
	used, frames := len(raw), 0
	for {
		kind, raw, e := commitWireFrame236(pair.client, &used, &frames)
		if e != nil {
			if errors.Is(e, errCommitWireBound236) {
				p.bad.Store(true)
			}
			return
		}
		if expected := p.armQuery.Load(); expected != nil {
			var query string
			switch kind {
			case 'Q':
				if len(raw) >= 6 && raw[len(raw)-1] == 0 {
					query = string(raw[5 : len(raw)-1])
				}
			case 'P':
				// Parse: statement name, SQL string, then parameter OIDs.
				body := raw[5:]
				if end := bytes.IndexByte(body, 0); end >= 0 {
					body = body[end+1:]
					if end = bytes.IndexByte(body, 0); end >= 0 {
						query = string(body[:end])
					}
				}
			}
			if strings.HasPrefix(query, "-- name: "+*expected+" ") && p.armQuery.CompareAndSwap(expected, nil) {
				if p.arm236(pair.pid.Load()) != nil {
					p.bad.Store(true)
					return
				}
			}
		}
		if kind == 'Q' && p.target.Load() != 0 && pair.pid.Load() == p.target.Load() {
			if len(raw) < 6 || raw[len(raw)-1] != 0 {
				p.bad.Store(true)
				return
			}
			if strings.EqualFold(strings.TrimSpace(string(raw[5:len(raw)-1])), "commit") {
				pair.commitSeen.Store(true)
			}
		}
		if commitWireWrite236(pair.server, raw) != nil {
			return
		}
	}
}
func commitWireSQLState236(raw []byte) string {
	if len(raw) < 7 {
		return ""
	}
	body := raw[5:]
	for len(body) > 1 && body[0] != 0 {
		kind := body[0]
		body = body[1:]
		i := strings.IndexByte(string(body), 0)
		if i < 0 {
			return ""
		}
		if kind == 'C' {
			return string(body[:i])
		}
		body = body[i+1:]
	}
	return ""
}
func (p *packageCommitWireProxy236) server236(pair *packageCommitWirePair236) {
	defer p.workers.Done()
	defer pair.close236()
	used, frames := 0, 0
	suppressed := false
	for {
		kind, raw, e := commitWireFrame236(pair.server, &used, &frames)
		if e != nil {
			if errors.Is(e, errCommitWireBound236) {
				p.bad.Store(true)
			}
			return
		}
		if kind == 'K' {
			if len(raw) != 13 {
				p.bad.Store(true)
				return
			}
			pair.pid.Store(int32(binary.BigEndian.Uint32(raw[5:9])))
		}
		target := p.target.Load() != 0 && pair.pid.Load() == p.target.Load() && pair.commitSeen.Load()
		if target && !suppressed {
			if kind == 'C' {
				if p.mode != "applied" || string(raw[5:]) != "COMMIT\x00" {
					p.bad.Store(true)
					return
				}
				p.observedCommit.Store(true)
				suppressed = true
			}
			if kind == 'E' {
				if p.mode != "rejected" || commitWireSQLState236(raw) != "23514" {
					p.bad.Store(true)
					return
				}
				p.observedRollback.Store(true)
				suppressed = true
			}
		}
		if suppressed {
			if kind == 'Z' {
				if len(raw) != 6 || raw[5] != 'I' {
					p.bad.Store(true)
					return
				}
				p.faultOnce.Do(func() { close(p.fault) })
				return
			}
			continue
		}
		if commitWireWrite236(pair.client, raw) != nil {
			return
		}
	}
}
func (p *packageCommitWireProxy236) arm236(pid int32) error {
	if pid <= 0 {
		return errors.New("invalid actual Admission backend")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	matches := 0
	for _, pair := range p.pairs {
		if pair.pid.Load() == pid {
			matches++
		}
	}
	if matches != 1 || !p.target.CompareAndSwap(0, pid) {
		return errors.New("cannot arm exact unique original Admission")
	}
	return nil
}
func commitWireProxy236(t *testing.T, mode string) *packageCommitWireProxy236 {
	t.Helper()
	if mode != "applied" && mode != "rejected" {
		t.Fatal("invalid finite transport mode")
	}
	dsn := os.Getenv("HASH_E2E_DB_URL")
	cfg, e := pgx.ParseConfig(dsn)
	if e != nil {
		t.Fatal(e)
	}
	ip := net.ParseIP(cfg.Host)
	if ip == nil || !ip.IsLoopback() || cfg.TLSConfig != nil {
		t.Fatal("transport fixture requires actual local plaintext PG fixture")
	}
	// Keep this socket under the caller's bounded TMPDIR without Go's long
	// test/subtest-derived directory name exceeding sockaddr_un's path limit.
	dir, e := os.MkdirTemp("", "hcw-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error("remove exact owned transport socket directory", err)
		}
	})
	if e = os.Chmod(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	sock := filepath.Join(dir, ".s.PGSQL."+strconv.Itoa(int(cfg.Port)))
	if len(sock) > 100 {
		t.Fatal("bounded caller TMPDIR leaves no portable Unix socket path")
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	listener.SetUnlinkOnClose(true)
	if e = os.Chmod(sock, 0o600); e != nil {
		_ = listener.Close()
		t.Fatal(e)
	}
	deadline := time.Now().Add(40 * time.Second)
	dialCtx, cancelDial := context.WithDeadline(context.Background(), deadline)
	p := &packageCommitWireProxy236{dialCtx: dialCtx, cancelDial: cancelDial, listener: listener, upstream: net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))), deadline: deadline, mode: mode, acceptDone: make(chan struct{}), fault: make(chan struct{})}
	go func() {
		defer close(p.acceptDone)
		for {
			client, e := p.listener.AcceptUnix()
			if e != nil {
				return
			}
			if p.accepted.Add(1) > 32 {
				p.bad.Store(true)
				_ = client.Close()
				return
			}
			server, e := (&net.Dialer{}).DialContext(p.dialCtx, "tcp", p.upstream)
			if e != nil {
				if !p.closing.Load() {
					p.bad.Store(true)
				}
				_ = client.Close()
				return
			}
			_ = client.SetDeadline(p.deadline)
			_ = server.SetDeadline(p.deadline)
			pair := &packageCommitWirePair236{client: client, server: server}
			p.mu.Lock()
			if p.closing.Load() {
				p.mu.Unlock()
				pair.close236()
				return
			}
			p.pairs = append(p.pairs, pair)
			p.workers.Add(2)
			p.mu.Unlock()
			go p.client236(pair)
			go p.server236(pair)
		}
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closing.Store(true)
		for _, pair := range p.pairs {
			pair.close236()
		}
		p.mu.Unlock()
		p.cancelDial()
		_ = p.listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		select {
		case <-p.acceptDone:
		case <-ctx.Done():
			t.Error("local transport accept activity unjoined")
		}
		p.mu.Lock()
		for _, pair := range p.pairs {
			pair.close236()
		}
		p.mu.Unlock()
		joined := make(chan struct{})
		go func() { p.workers.Wait(); close(joined) }()
		select {
		case <-joined:
		case <-ctx.Done():
			t.Error("local transport pumps unjoined")
		}
		if p.bad.Load() {
			t.Error("local protocol fixture exceeded bounds or saw unexpected state")
		}
	})
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	params := u.Query()
	params.Set("host", dir)
	u.RawQuery = params.Encode()
	t.Setenv("HASH_E2E_DB_URL", u.String())
	return p
}
func TestDocumentPackageSendCommitResponseLossV1E2E(t *testing.T) {
	for _, mode := range []string{"applied", "rejected"} {
		t.Run(mode+" genuine commit response lost", func(t *testing.T) {
			proxy := commitWireProxy236(t, mode)
			q := inspectionFixturePG236(t)
			root := packageImported220(t, q, "Real commit response-loss contract")
			p := packageCreate223(t, q, root)
			root = packageLatest223(t, q, root.ID)
			beforeBirth := packageMeasurementState232(t, q)
			e := withPackageAttempt236(t, q, root, p, packageBirthPlan236{seal: mode == "applied", unknown: true, arm: proxy.arm236}, func(op *pdfadmission.ApplicationHTMLSendOperationV1, birth *pdfadmission.ApplicationSessionV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, actor authoring.Actor) error {
				select {
				case <-proxy.fault:
				default:
					t.Fatal("native result did not follow genuine suppressed idle response")
				}
				if proxy.bad.Load() || !birth.CommitUnknownV1() {
					t.Fatal("transport fault or uncertainty disappeared")
				}
				if mode == "applied" && !proxy.observedCommit.Load() {
					t.Fatal("server COMMIT was not observed")
				}
				if mode == "rejected" && !proxy.observedRollback.Load() {
					t.Fatal("real rejected COMMIT was not observed")
				}
				if mode == "rejected" && packageMeasurementState232(t, q) != beforeBirth {
					t.Fatal("rejected commit retained tentative birth")
				}
				before := packageMeasurementState232(t, q)
				got, e := inspectPackageAttempt236(t, q, op, actor)
				if e != nil {
					return e
				}
				want := pdfadmission.HTMLSendPackageAttemptActiveV1
				if mode == "rejected" {
					want = pdfadmission.HTMLSendPackageAttemptMissingV1
				}
				if got.AttemptID != m.AttemptID || got.Outcome != want {
					t.Fatal("uncertain commit inferred the wrong exact attempt", got)
				}
				if mode == "applied" && got.Capture != m.Capture {
					t.Fatal("persisted private capture changed")
				}
				if !birth.CommitUnknownV1() {
					t.Fatal("inspection rewrote original commit uncertainty")
				}
				if packageMeasurementState232(t, q) != before {
					t.Fatal("inspection retried or mutated uncertain send")
				}
				t.Logf("genuine local PostgreSQL commit response withheld: mode=%s; birth backend retired; exact outcome=%d; original uncertainty retained", mode, got.Outcome)
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}
