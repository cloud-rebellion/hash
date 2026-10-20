// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Original SQL effects use independent physical READ COMMITTED sessions, never
// caller transactions or borrowed idle sessions. A pending CleanupDone keeps all
// resource permits and owned bodies quarantined; no new original read/capture
// may interpret absence while that physical outcome is still live.
type originalResourceLeaseV1 struct {
	mu                 sync.Mutex
	holds              int
	returned, released bool
	releases           []func()
	bodies             [][]byte
}
type originalResourceContextKeyV1 struct{}

func (l *originalResourceLeaseV1) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, originalResourceContextKeyV1{}, l)
}
func (l *originalResourceLeaseV1) hold() { l.mu.Lock(); l.holds++; l.mu.Unlock() }
func (l *originalResourceLeaseV1) addRelease(release func()) {
	l.mu.Lock()
	l.releases = append(l.releases, release)
	l.mu.Unlock()
}
func (l *originalResourceLeaseV1) ownBody(body []byte) {
	l.mu.Lock()
	l.bodies = append(l.bodies, body)
	l.mu.Unlock()
}
func (l *originalResourceLeaseV1) releaseOwner() {
	l.mu.Lock()
	l.returned = true
	l.mu.Unlock()
	l.maybeRelease()
}
func (l *originalResourceLeaseV1) releasePhysical() {
	l.mu.Lock()
	if l.holds > 0 {
		l.holds--
	}
	l.mu.Unlock()
	l.maybeRelease()
}
func (l *originalResourceLeaseV1) maybeRelease() {
	l.mu.Lock()
	if l.released || !l.returned || l.holds != 0 {
		l.mu.Unlock()
		return
	}
	l.released = true
	bodies, releases := l.bodies, l.releases
	l.bodies = nil
	l.releases = nil
	l.mu.Unlock()
	for _, body := range bodies {
		clear(body)
	}
	for _, release := range releases {
		release()
	}
}

var (
	ErrOriginalJournalV1    = errors.New("fit preparation original journal unavailable")
	ErrOriginalSQLUnknownV1 = errors.New("fit preparation original SQL outcome or physical cleanup unresolved")
	ErrOriginalResourcesV1  = errors.New("fit preparation original resources not admitted")
)

func originalErrorV1(ctx context.Context, phase error) error {
	return errors.Join(phase, safeErrorV1(ctx, phase))
}

type originalPostgresV1 struct {
	pool           *pgxpool.Pool
	slots, reapers chan struct{}
	mu             sync.Mutex
	pending        map[*pgx.Conn]*originalSessionPermitV1
	changed        chan struct{}
	closing        bool
}
type originalSessionPermitV1 struct {
	owner     *originalPostgresV1
	resources *originalResourceLeaseV1
	once      sync.Once
}

func newOriginalPostgresV1(pool *pgxpool.Pool) *originalPostgresV1 {
	n := int(pool.Config().MaxConns)
	return &originalPostgresV1{pool: pool, slots: make(chan struct{}, n), reapers: make(chan struct{}, n), pending: map[*pgx.Conn]*originalSessionPermitV1{}, changed: make(chan struct{})}
}
func (p *originalSessionPermitV1) release(closed bool) {
	if p == nil || !closed {
		return
	}
	p.once.Do(func() { <-p.owner.slots; p.resources.releasePhysical(); p.owner.signal() })
}
func (p *originalPostgresV1) signal() {
	p.mu.Lock()
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}
func (p *originalPostgresV1) acquire(ctx context.Context) (*originalSessionPermitV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
	resources, _ := ctx.Value(originalResourceContextKeyV1{}).(*originalResourceLeaseV1)
	if resources == nil {
		return nil, ErrOriginalResourcesV1
	}
	p.reconcileReady()
	p.mu.Lock()
	refuse := p.closing || len(p.pending) != 0
	p.mu.Unlock()
	if refuse {
		return nil, ErrOriginalSQLUnknownV1
	}
	select {
	case p.slots <- struct{}{}:
		p.mu.Lock()
		refuse = p.closing || len(p.pending) != 0
		p.mu.Unlock()
		if ctx.Err() != nil || refuse {
			<-p.slots
			return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
		}
		resources.hold()
		return &originalSessionPermitV1{owner: p, resources: resources}, nil
	case <-ctx.Done():
		return nil, originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
	}
}
func (p *originalPostgresV1) Begin(ctx context.Context) (*originalPostgresTransactionV1, error) {
	if p == nil || p.pool == nil {
		return nil, ErrOriginalJournalV1
	}
	permit, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig.Copy())
	if err != nil {
		if conn == nil {
			permit.release(true)
		} else {
			_ = p.closeOwned(conn, permit)
		}
		return nil, ErrOriginalSQLUnknownV1
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		_ = p.closeOwned(conn, permit)
		return nil, ErrOriginalSQLUnknownV1
	}
	return &originalPostgresTransactionV1{owner: p, permit: permit, conn: conn, tx: tx, q: generated.New(tx)}, nil
}

type originalPhysicalCloserV1 interface {
	Close(context.Context) error
	IsClosed() bool
	CleanupDone() <-chan struct{}
}
type originalPGXCloserV1 struct{ *pgx.Conn }

func (c originalPGXCloserV1) CleanupDone() <-chan struct{} { return c.PgConn().CleanupDone() }
func originalClosePhysicalV1(ctx context.Context, c originalPhysicalCloserV1) (bool, error) {
	if c == nil {
		return true, nil
	}
	err := c.Close(ctx)
	if !c.IsClosed() {
		return false, ErrOriginalSQLUnknownV1
	}
	select {
	case <-c.CleanupDone():
		if err != nil {
			return true, ErrOriginalSQLUnknownV1
		}
		return true, nil
	case <-ctx.Done():
		return false, ErrOriginalSQLUnknownV1
	}
}
func (p *originalPostgresV1) closeOwned(conn *pgx.Conn, permit *originalSessionPermitV1) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	closed, err := originalClosePhysicalV1(ctx, originalPGXCloserV1{conn})
	if closed {
		permit.release(true)
		return err
	}
	p.mu.Lock()
	p.pending[conn] = permit
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
	select {
	case p.reapers <- struct{}{}:
		go func() {
			defer func() { <-p.reapers; p.signal() }()
			timer := time.NewTimer(20 * time.Second)
			defer timer.Stop()
			select {
			case <-conn.PgConn().CleanupDone():
				p.reconcileReady()
			case <-timer.C:
				p.signal()
			}
		}()
	default:
	}
	return ErrOriginalSQLUnknownV1
}
func (p *originalPostgresV1) reconcileReady() {
	p.mu.Lock()
	var permits []*originalSessionPermitV1
	for conn, permit := range p.pending {
		select {
		case <-conn.PgConn().CleanupDone():
			delete(p.pending, conn)
			permits = append(permits, permit)
		default:
		}
	}
	p.mu.Unlock()
	for _, permit := range permits {
		permit.release(true)
	}
}
func (p *originalPostgresV1) Drain(ctx context.Context, closeNew bool) error {
	if p == nil || ctx == nil {
		return ErrOriginalJournalV1
	}
	if closeNew {
		p.mu.Lock()
		p.closing = true
		close(p.changed)
		p.changed = make(chan struct{})
		p.mu.Unlock()
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		p.reconcileReady()
		p.mu.Lock()
		pending, changed := len(p.pending), p.changed
		p.mu.Unlock()
		if pending == 0 && (!closeNew || (len(p.slots) == 0 && len(p.reapers) == 0)) {
			return nil
		}
		if _, bounded := ctx.Deadline(); !bounded {
			return ErrOriginalResourcesV1
		}
		select {
		case <-ctx.Done():
			return originalErrorV1(ctx, ErrOriginalSQLUnknownV1)
		case <-changed:
		case <-tick.C:
		}
	}
}

type originalPostgresTransactionV1 struct {
	owner  *originalPostgresV1
	permit *originalSessionPermitV1
	conn   *pgx.Conn
	tx     pgx.Tx
	q      *generated.Queries
	done   bool
}

func (t *originalPostgresTransactionV1) Commit(ctx context.Context) error {
	if t.done {
		return pgx.ErrTxClosed
	}
	t.done = true
	err := t.tx.Commit(ctx)
	closeErr := t.owner.closeOwned(t.conn, t.permit)
	if err != nil || closeErr != nil {
		return ErrOriginalSQLUnknownV1
	}
	return nil
}
func (t *originalPostgresTransactionV1) Rollback(ctx context.Context) error {
	if t.done {
		return nil
	}
	t.done = true
	err := t.tx.Rollback(ctx)
	closeErr := t.owner.closeOwned(t.conn, t.permit)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) || closeErr != nil {
		return ErrOriginalSQLUnknownV1
	}
	return nil
}
