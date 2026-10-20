//go:build owned_app_session_pg

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This finite proxy forwards only genuine disposable PostgreSQL bytes. The
// observer's first connection is untouched. The second connection forwards a
// complete real identity DataRow, then holds completion so the test can close
// the transport or cancel the real caller. No row, identity, fence, callback,
// transaction or retirement decision is injected into the application.
var errIdentityWireBoundV1 = errors.New("bounded protocol frame refused")

type identityWireProxyV1 struct {
	dialCtx       context.Context
	cancelDial    context.CancelFunc
	listener      *net.UnixListener
	upstream      string
	deadline      time.Time
	mu            sync.Mutex
	pairs         []*identityWirePairV1
	acceptDone    chan struct{}
	workers       sync.WaitGroup
	rowForwarded  chan struct{}
	fault         chan struct{}
	faultOnce     sync.Once
	closing       atomic.Bool
	accepted      atomic.Int32
	workPID       atomic.Int32
	identityParse atomic.Bool
	beginSeen     atomic.Bool
	bad           atomic.Bool
}
type identityWirePairV1 struct {
	client *net.UnixConn
	server net.Conn
	done   chan struct{}
	once   sync.Once
}

func (p *identityWirePairV1) closeV1() {
	p.once.Do(func() { _ = p.client.Close(); _ = p.server.Close(); close(p.done) })
}
func identityWireWriteV1(w io.Writer, raw []byte) error {
	for len(raw) > 0 {
		n, err := w.Write(raw)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		raw = raw[n:]
	}
	return nil
}
func identityWireFrameV1(r io.Reader, used *int, frames *int) (byte, []byte, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(head[1:]))
	*frames++
	if n < 4 || n > 65536 || *frames > 256 || *used+n+1 > 1<<20 {
		return 0, nil, errIdentityWireBoundV1
	}
	raw := make([]byte, n+1)
	copy(raw, head[:])
	*used += len(raw)
	_, err := io.ReadFull(r, raw[5:])
	return head[0], raw, err
}
func (p *identityWireProxyV1) clientV1(pair *identityWirePairV1, index int32) {
	defer p.workers.Done()
	defer pair.closeV1()
	var head [4]byte
	if _, err := io.ReadFull(pair.client, head[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint32(head[:]))
	if n < 8 || n > 65536 {
		p.bad.Store(true)
		return
	}
	startup := make([]byte, n)
	copy(startup, head[:])
	if _, err := io.ReadFull(pair.client, startup[4:]); err != nil {
		return
	}
	if binary.BigEndian.Uint32(startup[4:8]) != 196608 {
		p.bad.Store(true)
		return
	}
	if identityWireWriteV1(pair.server, startup) != nil {
		return
	}
	used, frames := len(startup), 0
	for {
		kind, raw, err := identityWireFrameV1(pair.client, &used, &frames)
		if err != nil {
			if errors.Is(err, errIdentityWireBoundV1) {
				p.bad.Store(true)
			}
			return
		}
		if index == 2 && (kind == 'P' || kind == 'Q') {
			query := raw[5:]
			if kind == 'P' {
				z := strings.IndexByte(string(query), 0)
				if z < 0 {
					p.bad.Store(true)
					return
				}
				query = query[z+1:]
			}
			z := strings.IndexByte(string(query), 0)
			if z < 0 {
				p.bad.Store(true)
				return
			}
			text := strings.TrimSpace(string(query[:z]))
			if text == strings.TrimSpace(applicationBackendIdentitySQLV1) {
				p.identityParse.Store(true)
			}
			tokens := strings.Fields(strings.ToLower(text))
			if len(tokens) > 0 && (tokens[0] == "begin" || (len(tokens) > 1 && tokens[0] == "start" && tokens[1] == "transaction")) {
				p.beginSeen.Store(true)
			}
		}
		if identityWireWriteV1(pair.server, raw) != nil {
			return
		}
	}
}
func (p *identityWireProxyV1) serverV1(pair *identityWirePairV1, index int32) {
	defer p.workers.Done()
	used, frames := 0, 0
	for {
		kind, raw, err := identityWireFrameV1(pair.server, &used, &frames)
		if err != nil {
			if errors.Is(err, errIdentityWireBoundV1) {
				p.bad.Store(true)
			}
			_ = pair.client.CloseWrite()
			return
		}
		if index == 2 && kind == 'K' {
			if len(raw) != 13 {
				p.bad.Store(true)
				pair.closeV1()
				return
			}
			p.workPID.Store(int32(binary.BigEndian.Uint32(raw[5:9])))
		}
		if identityWireWriteV1(pair.client, raw) != nil {
			return
		}
		if index == 2 && kind == 'D' {
			if !p.identityParse.Load() || len(raw) < 7 || binary.BigEndian.Uint16(raw[5:7]) != 7 {
				p.bad.Store(true)
				pair.closeV1()
				return
			}
			close(p.rowForwarded)
			select {
			case <-p.fault:
				_ = pair.client.CloseWrite()
				_ = pair.server.Close()
				return
			case <-pair.done:
				return
			}
		}
	}
}
func newIdentityWireProxyV1(t *testing.T, upstream string, deadline time.Time) *identityWireProxyV1 {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "hiw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(dir); err != nil {
			t.Error("owned proxy directory cleanup", err)
		}
	})
	socket := filepath.Join(dir, ".s.PGSQL.5432")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal("listen finite owned identity proxy", err)
	}
	dialCtx, cancelDial := context.WithDeadline(context.Background(), deadline)
	p := &identityWireProxyV1{dialCtx: dialCtx, cancelDial: cancelDial, listener: listener, upstream: upstream, deadline: deadline, acceptDone: make(chan struct{}), rowForwarded: make(chan struct{}), fault: make(chan struct{})}
	go func() {
		defer close(p.acceptDone)
		for {
			client, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			index := p.accepted.Add(1)
			if index > 2 || p.closing.Load() {
				if !p.closing.Load() {
					p.bad.Store(true)
				}
				_ = client.Close()
				return
			}
			server, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(p.dialCtx, "unix", upstream)
			if err != nil {
				if !p.closing.Load() {
					p.bad.Store(true)
				}
				_ = client.Close()
				return
			}
			_ = client.SetDeadline(deadline)
			_ = server.SetDeadline(deadline)
			pair := &identityWirePairV1{client: client, server: server, done: make(chan struct{})}
			p.mu.Lock()
			if p.closing.Load() {
				p.mu.Unlock()
				pair.closeV1()
				return
			}
			p.pairs = append(p.pairs, pair)
			p.workers.Add(2)
			p.mu.Unlock()
			go p.clientV1(pair, index)
			go p.serverV1(pair, index)
		}
	}()
	return p
}
func (p *identityWireProxyV1) closeV1(ctx context.Context) error {
	p.closing.Store(true)
	_ = p.listener.Close()
	p.cancelDial()
	p.faultOnce.Do(func() { close(p.fault) })
	// The same lock closes registration before Wait: a late dial cannot install
	// sockets or Add workers after this snapshot, even if accept joining fails.
	p.mu.Lock()
	pairs := append([]*identityWirePairV1(nil), p.pairs...)
	p.mu.Unlock()
	for _, pair := range pairs {
		pair.closeV1()
	}
	var out error
	select {
	case <-p.acceptDone:
	case <-ctx.Done():
		out = errors.New("proxy accept did not join")
	}
	done := make(chan struct{})
	go func() { p.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		out = errors.Join(out, errors.New("proxy pumps did not join"))
	}
	return out
}
func identityWireFencePresentV1(f *ApplicationSessionFactoryV1) bool {
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	for s := range f.state.sessions {
		s.mu.Lock()
		present := !s.observer && s.creating && s.active == 1 && s.fence != nil && applicationIdentityValidV1(s.fence.identity)
		s.mu.Unlock()
		if present {
			return true
		}
	}
	return false
}

func TestOwnedApplicationSessionIdentityWireRetirementV1(t *testing.T) {
	for _, mode := range []string{"identity_then_eof", "identity_then_cancel"} {
		t.Run(mode, func(t *testing.T) {
			dsn := os.Getenv("HASH_OWNED_SESSION_PG_DSN")
			if dsn == "" {
				t.Fatal("owned disposable Unix PG DSN required")
			}
			cfg, err := pgx.ParseConfig(dsn)
			if err != nil || !filepath.IsAbs(cfg.Host) || cfg.TLSConfig != nil || len(cfg.Fallbacks) != 0 || cfg.Password != "" {
				t.Fatal("explicit owned Unix/trust fixture required")
			}
			cfg.ConnectTimeout = 2 * time.Second
			if cfg.RuntimeParams == nil {
				cfg.RuntimeParams = make(map[string]string)
			}
			tag := "hash_identity_wire_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			cfg.RuntimeParams["application_name"] = tag
			cfg.RuntimeParams["statement_timeout"] = "3000"
			cfg.RuntimeParams["lock_timeout"] = "1000"
			cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "10000"
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			deadline, _ := ctx.Deadline()
			proxy := newIdentityWireProxyV1(t, filepath.Join(cfg.Host, ".s.PGSQL."+strconv.Itoa(int(cfg.Port))), deadline)
			var factory *ApplicationSessionFactoryV1
			var raw *pgx.Conn
			var rawStarted bool
			var grant func()
			stopOpen := func() {}
			var joined chan struct{}
			t.Cleanup(func() {
				stopOpen()
				proxy.faultOnce.Do(func() { close(proxy.fault) })
				joinCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
				if joined != nil {
					select {
					case <-joined:
					case <-joinCtx.Done():
						t.Error("actual Open call did not join")
					}
				}
				stop()
				if factory != nil {
					cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
					_ = factory.CloseV1(cleanup)
					stop()
				}
				cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
				if err := proxy.closeV1(cleanup); err != nil {
					t.Error(err)
				}
				stop()
				if joined != nil {
					cleanup, stop := context.WithTimeout(context.Background(), time.Second)
					select {
					case <-joined:
					case <-cleanup.Done():
						t.Error("actual Open call survived physical proxy cleanup")
					}
					stop()
				}
				if raw != nil {
					cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
					defer stop()
					tick := time.NewTicker(20 * time.Millisecond)
					defer tick.Stop()
					for {
						var count int
						err := raw.QueryRow(cleanup, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE application_name=$1", tag).Scan(&count)
						if err != nil {
							t.Error("owned backend observation failed", err)
							break
						}
						if count == 0 {
							break
						}
						select {
						case <-tick.C:
						case <-cleanup.Done():
							t.Error("owned real backends remain after physical fixture cleanup")
							goto observed
						}
					}
				observed:
					done := raw.PgConn().CleanupDone()
					if err := raw.Close(cleanup); err != nil {
						t.Error("witness close", err)
					}
					select {
					case <-done:
						if grant != nil {
							grant()
						}
					case <-cleanup.Done():
						t.Error("witness client did not join")
					}
				} else if grant != nil && !rawStarted {
					grant()
				}
			})
			limits := workguard.VectorV1{ParentBytes: 32 << 20, DBStagingBytes: 32 << 20, SQLSessions: 4}
			coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 32, MaxOrganisationGrants: 32})
			if err != nil {
				t.Fatal(err)
			}
			work, err := NewWorkAdmissionV1(coordinator)
			if err != nil {
				t.Fatal(err)
			}
			org := uuid.New()
			grant, err = work.SQLSessionV1(ctx, org)
			if err != nil {
				t.Fatal(err)
			}
			rawCfg := cfg.Copy()
			rawCfg.RuntimeParams["application_name"] = tag + "_raw"
			rawStarted = true
			raw, err = pgx.ConnectConfig(ctx, rawCfg)
			if err != nil {
				t.Fatal("connect owned witness", err)
			}
			proxied := cfg.Copy()
			proxied.Host = filepath.Dir(proxy.listener.Addr().String())
			proxied.Port = 5432
			factory, err = NewApplicationSessionFactoryV1(proxied, work, ApplicationSessionDirectProfileV1)
			if err != nil {
				t.Fatal(err)
			}
			openCtx, cancelOpen := context.WithCancel(ctx)
			stopOpen = cancelOpen
			type opened struct {
				h   *ApplicationSessionV1
				err error
			}
			result := make(chan opened, 1)
			joined = make(chan struct{})
			go func() { defer close(joined); h, e := factory.OpenV1(openCtx, org, uuid.New()); result <- opened{h, e} }()
			select {
			case <-proxy.rowForwarded:
			case <-ctx.Done():
				t.Fatal("actual full identity row was not forwarded")
			}
			var backendStart time.Time
			if pid := proxy.workPID.Load(); pid <= 0 {
				t.Fatal("real BackendKeyData PID missing")
			} else if err := raw.QueryRow(ctx, "SELECT backend_start FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND application_name=$2", pid, tag).Scan(&backendStart); err != nil {
				t.Fatal("genuine work backend was not independently observed", err)
			}
			before := coordinator.SnapshotV1(org)
			if before.Global != (workguard.VectorV1{SQLSessions: 3}) || before.Organisation != before.Global || before.GlobalGrants != 3 || before.OrganisationGrants != 3 {
				t.Fatal("work/control/witness debt not funded before fault")
			}
			if mode == "identity_then_eof" {
				proxy.faultOnce.Do(func() { close(proxy.fault) })
			} else {
				barrier, stop := context.WithTimeout(ctx, time.Second)
				tick := time.NewTicker(time.Millisecond)
				for !identityWireFencePresentV1(factory) && barrier.Err() == nil {
					select {
					case <-tick.C:
					case <-barrier.Done():
					}
				}
				present := identityWireFencePresentV1(factory)
				tick.Stop()
				stop()
				if !present {
					t.Error("genuine decoded identity fence was discarded until protocol completion")
				}
				stopOpen()
			}
			var got opened
			select {
			case got = <-result:
			case <-ctx.Done():
				t.Fatal("failed real startup did not return")
			}
			if got.err == nil || got.h == nil || !got.h.WorkStartedV1() || got.h.RetiredV1() {
				t.Fatal("fault must refuse Open while retaining actual work owner")
			}
			if mode == "identity_then_cancel" && !errors.Is(got.err, context.Canceled) {
				t.Error("startup cancellation decision lost")
			}
			observed, captured := ApplicationSessionStartObservationForV1(got.err)
			if !captured || observed.Phase != 6 {
				t.Fatal("actual trailing identity failure observation missing")
			}
			wantContext := uint8(2)
			if mode == "identity_then_cancel" {
				wantContext = 3
				if observed.ErrorClass != 2 {
					t.Fatal("actual cancellation classification changed")
				}
			}
			if observed.ContextState != wantContext {
				t.Fatal("startup context sampled after cancellation or cleanup")
			}
			pending := factory.PendingV1()
			if pending.WorkSessions != 1 || pending.ObserverSessions != 1 || pending.UnknownStarts != 0 || coordinator.SnapshotV1(org) != before {
				t.Errorf("decoded identity lost or work credited before physical close: %+v", pending)
			}
			cleanup, stop := context.WithTimeout(ctx, 2*time.Second)
			defer stop()
			if err := got.h.CloseV1(cleanup); err != nil || !got.h.RetiredV1() {
				t.Error("authentic client/observer retirement did not join", err)
			}
			if after, ok := ApplicationSessionStartObservationForV1(got.err); !ok || after != observed {
				t.Error("physical cleanup rewrote original startup observation")
			}
			pending = factory.PendingV1()
			after := coordinator.SnapshotV1(org)
			if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 1 || after.Global != (workguard.VectorV1{SQLSessions: 2}) || after.Organisation != after.Global || after.GlobalGrants != 2 || after.OrganisationGrants != 2 {
				t.Errorf("real work debt did not drain to original observer plus witness: %+v %+v", pending, after)
			}
			var exists bool
			if err := raw.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE pid=$1 AND backend_start=$2)", proxy.workPID.Load(), backendStart).Scan(&exists); err != nil || exists {
				t.Error("actual retired work backend remains", err)
			}
			if proxy.accepted.Load() != 2 || proxy.beginSeen.Load() || !proxy.identityParse.Load() || proxy.bad.Load() {
				t.Error("fault opened replacement work, dispatched BEGIN or violated fixed wire contract")
			}
		})
	}
}
