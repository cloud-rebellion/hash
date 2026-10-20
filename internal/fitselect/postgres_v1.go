// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgreSQLV1 opens independent physical connections using the existing pool's
// saved config. No credential is logged, exposed, replaced or expanded. This
// deliberately avoids consulting a transaction or cached snapshot whose COMMIT
// outcome is unknown. Connections are bounded by the caller's live deadline.
type PostgreSQLV1 struct {
	pool    *pgxpool.Pool
	slots   chan struct{}
	reapers chan struct{}
	mu      sync.Mutex
	pending map[*pgx.Conn]*sessionPermitV1
	changed chan struct{}
	closing bool
}

func NewPostgreSQLV1(pool *pgxpool.Pool) (*PostgreSQLV1, error) {
	if pool == nil {
		return nil, ErrInvalidV1
	}
	n := pool.Config().MaxConns
	if n < 1 {
		return nil, ErrInvalidV1
	}
	return &PostgreSQLV1{pool: pool, slots: make(chan struct{}, int(n)), reapers: make(chan struct{}, int(n)), pending: make(map[*pgx.Conn]*sessionPermitV1), changed: make(chan struct{})}, nil
}

// A permit is released exactly once and only after the corresponding physical
// connection is verified closed. An error from Close alone proves neither
// continued liveness nor closure.
type sessionPermitV1 struct {
	slots        chan struct{}
	once         sync.Once
	afterRelease func()
}

func acquireSessionV1(ctx context.Context, slots chan struct{}) (*sessionPermitV1, error) {
	if ctx == nil || slots == nil {
		return nil, ErrInvalidV1
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case slots <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-slots
			return nil, err
		}
		return &sessionPermitV1{slots: slots}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (p *sessionPermitV1) releaseAfterClose(closed bool) {
	if p == nil || !closed {
		return
	}
	p.once.Do(func() {
		<-p.slots
		if p.afterRelease != nil {
			p.afterRelease()
		}
	})
}
func (p *PostgreSQLV1) Begin(ctx context.Context) (TransactionV1, error) {
	if ctx == nil || p == nil || p.pool == nil {
		return nil, ErrInvalidV1
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	permit, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn, err := pgx.ConnectConfig(ctx, p.pool.Config().ConnConfig.Copy())
	if err != nil {
		if conn == nil {
			permit.releaseAfterClose(true)
		} else {
			_ = p.closeOwned(conn, permit)
		}
		return nil, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		closeErr := p.closeOwned(conn, permit)
		return nil, errors.Join(err, closeErr)
	}
	return &postgresTransactionV1{conn: conn, tx: tx, q: generated.New(tx), permit: permit, owner: p}, nil
}

type postgresTransactionV1 struct {
	conn   *pgx.Conn
	tx     pgx.Tx
	q      *generated.Queries
	done   bool
	permit *sessionPermitV1
	owner  *PostgreSQLV1
}

func (t *postgresTransactionV1) Lock(ctx context.Context, b manualfit.BindingV1) (LockedStateV1, error) {
	if !validBinding(b) {
		return LockedStateV1{}, ErrInvalidV1
	}
	d, err := t.q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: b.DocumentID, OrgID: b.OrgID})
	if err != nil {
		return LockedStateV1{}, err
	}
	// The schema85 trigger uses this same document -> recipient lock order.
	// Existing GetRecipient is generated but has no exclusive-lock variant.
	var id uuid.UUID
	err = t.tx.QueryRow(ctx, "SELECT id FROM recipients WHERE id=$1 AND document_id=$2 FOR UPDATE", b.RecipientID, b.DocumentID).Scan(&id) //nolint:rawsql
	if err != nil {
		return LockedStateV1{}, err
	}
	r, err := t.q.GetRecipient(ctx, generated.GetRecipientParams{ID: id, OrgID: b.OrgID})
	if err != nil {
		return LockedStateV1{}, err
	}
	p, err := t.q.GetSignatureFitPreparationForUpdate(ctx, generated.GetSignatureFitPreparationForUpdateParams{ID: b.OperationID, OrgID: b.OrgID})
	if err != nil {
		return LockedStateV1{}, err
	}
	fields, err := t.q.ListFieldsByDocument(ctx, b.DocumentID)
	if err != nil {
		return LockedStateV1{}, err
	}
	objects, err := t.q.ListSignatureFitObjects(ctx, generated.ListSignatureFitObjectsParams{ID: b.OperationID, OrgID: b.OrgID})
	if err != nil {
		return LockedStateV1{}, err
	}
	inventory, err := t.q.ListSignatureFitInventory(ctx, generated.ListSignatureFitInventoryParams{DocumentID: b.DocumentID, OrgID: b.OrgID})
	if err != nil {
		return LockedStateV1{}, err
	}
	if len(inventory) > 8192 {
		return LockedStateV1{}, ErrAdmissionV1
	}
	return LockedStateV1{Document: d, Recipient: r, Preparation: p, Objects: objects, AllFields: fields, Inventory: inventory, Queries: t.q}, nil
}
func (t *postgresTransactionV1) FindSelection(ctx context.Context, b manualfit.BindingV1) (*generated.SignatureFitSelection, error) {
	return t.q.GetSignatureFitSelectionForUpdate(ctx, generated.GetSignatureFitSelectionForUpdateParams{DocumentID: b.DocumentID, RecipientID: b.RecipientID, CeremonyEpoch: timestamp(b.CeremonyEpoch), OrgID: b.OrgID})
}
func (t *postgresTransactionV1) MarkAttempt(ctx context.Context, r RequestV1) (*generated.SignatureFitPreparation, error) {
	return t.q.MarkSignatureFitSelectionCommitAttempted(ctx, generated.MarkSignatureFitSelectionCommitAttemptedParams{ID: r.Binding.OperationID, OrgID: r.Binding.OrgID, OwnerID: r.OwnerID})
}
func (t *postgresTransactionV1) Select(ctx context.Context, r RequestV1, id uuid.UUID) (*generated.SignatureFitSelection, error) {
	digest, err := decodeDigest(r.Binding.AuthoritySHA256)
	if err != nil {
		return nil, err
	}
	return t.q.SelectSignatureFitPreparation(ctx, generated.SelectSignatureFitPreparationParams{ID: id, DocumentID: r.Binding.DocumentID, OrgID: r.Binding.OrgID, CeremonyEpoch: timestamp(r.Binding.CeremonyEpoch), RecipientID: r.Binding.RecipientID, PreparationID: r.Binding.OperationID, AuthoritySha256: digest})
}
func (t *postgresTransactionV1) MarkNotCommitted(ctx context.Context, r RequestV1) (*generated.SignatureFitPreparation, error) {
	return t.q.MarkSignatureFitSelectionNotCommitted(ctx, generated.MarkSignatureFitSelectionNotCommittedParams{ID: r.Binding.OperationID, OrgID: r.Binding.OrgID, OwnerID: r.OwnerID})
}
func (t *postgresTransactionV1) MarkRetentionStarted(ctx context.Context, r *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error) {
	return t.q.MarkSignatureFitRetentionStarted(ctx, generated.MarkSignatureFitRetentionStartedParams{ID: r.ID, OrgID: r.OrgID})
}
func (t *postgresTransactionV1) MarkRetentionComplete(ctx context.Context, r *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error) {
	return t.q.MarkSignatureFitRetentionComplete(ctx, generated.MarkSignatureFitRetentionCompleteParams{ID: r.ID, OrgID: r.OrgID})
}
func (t *postgresTransactionV1) Commit(ctx context.Context) error {
	if t.done {
		return pgx.ErrTxClosed
	}
	t.done = true
	err := t.tx.Commit(ctx)
	closeErr := t.owner.closeOwned(t.conn, t.permit)
	return errors.Join(err, closeErr)
}
func (t *postgresTransactionV1) Rollback(ctx context.Context) error {
	if t.done {
		return pgx.ErrTxClosed
	}
	t.done = true
	err := t.tx.Rollback(ctx)
	closeErr := t.owner.closeOwned(t.conn, t.permit)
	return errors.Join(err, closeErr)
}

type physicalCloserV1 interface {
	Close(context.Context) error
	IsClosed() bool
	CleanupDone() <-chan struct{}
}
type pgxLifecycleV1 struct{ *pgx.Conn }

func (c pgxLifecycleV1) CleanupDone() <-chan struct{} { return c.PgConn().CleanupDone() }
func closeConnection(c physicalCloserV1) (error, bool) {
	if c == nil {
		return nil, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := c.Close(ctx)
	if !c.IsClosed() {
		return errors.Join(ErrOutcomeUnknownV1, err), false
	}
	select {
	case <-c.CleanupDone():
		return err, true
	case <-ctx.Done():
		return errors.Join(ErrOutcomeUnknownV1, err), false
	}
}
func timestamp(v time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: v.UTC(), Valid: true} }
func objectIdentity(kind string, page int32) string {
	return kind + ":" + strconv.FormatInt(int64(page), 10)
}
func inventoryJSON(r *generated.ListSignatureFitInventoryRow) ([]byte, error) { return json.Marshal(r) }

// InventoryV1 returns every scoped durable preparation/object checkpoint,
// including unknown uploads and selections without a signature. It does not
// authorize deletion, infer object absence, or anonymize retained original names.
// Rights/retention/legal-hold policy remains the controller's explicit gate.
// More than8192 rows refuses with no partial result. Larger retained histories
// need a separately authorized paginated inventory/disposition workflow.
func (p *PostgreSQLV1) InventoryV1(ctx context.Context, orgID, documentID uuid.UUID) ([]*generated.ListSignatureFitInventoryRow, error) {
	if orgID == uuid.Nil || documentID == uuid.Nil {
		return nil, ErrInvalidV1
	}
	raw, err := p.Begin(ctx)
	if err != nil {
		return nil, publicError(ctx, err)
	}
	defer rollback(raw)
	tx := raw.(*postgresTransactionV1)
	_, err = tx.q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: documentID, OrgID: orgID})
	if err != nil {
		return nil, publicError(ctx, err)
	}
	rows, err := tx.q.ListSignatureFitInventory(ctx, generated.ListSignatureFitInventoryParams{DocumentID: documentID, OrgID: orgID})
	if err != nil {
		return nil, publicError(ctx, err)
	}
	if len(rows) > 8192 {
		return nil, ErrAdmissionV1
	}
	return rows, nil
}

// FinalAdmissionV1 runs in the ACTUAL signature transaction. The caller passes
// its transaction, not pool-scoped Queries. It locks/rebinds the stable retained
// selection and returns a deterministic field for the existing one-row signature
// model. It publishes nothing: original credential must remain current at the
// final commit boundary, and fitted signature+companion/status/audit must commit
// atomically. No legacy/delegated signature can reuse this admission.
func FinalAdmissionV1(ctx context.Context, tx pgx.Tx, selected *SelectedV1, admit AdmissionFuncV1) (*generated.DocumentField, error) {
	if ctx == nil || tx == nil || selected == nil || selected.row == nil || selected.retained == nil || !selected.row.RetentionStartedAt.Valid || !selected.row.RetentionCompletedAt.Valid || admit == nil {
		return nil, ErrInvalidV1
	}
	adapter := &postgresTransactionV1{tx: tx, q: generated.New(tx)}
	state, err := adapter.Lock(ctx, selected.Binding())
	if err != nil {
		return nil, publicError(ctx, err)
	}
	row, err := adapter.FindSelection(ctx, selected.Binding())
	if err != nil || !sameSelection(row, selected.row) || !row.RetentionStartedAt.Valid || !row.RetentionCompletedAt.Valid {
		return nil, ErrAuthorityChangedV1
	}
	service := ServiceV1{Admit: admit}
	if err = service.admit(ctx, state, selected.retained, row); err != nil {
		return nil, err
	}
	targets := selected.retained.Manifest().Authority().Input().ExpectedTargetIDs
	if len(targets) == 0 {
		return nil, ErrAuthorityChangedV1
	}
	for _, f := range state.AllFields {
		if f.ID == targets[0] {
			copy := *f
			return &copy, nil
		}
	}
	return nil, ErrAuthorityChangedV1
}

var _ StoreV1 = (*PostgreSQLV1)(nil)
var _ TransactionV1 = (*postgresTransactionV1)(nil)

// A timed-out physical close remains owned and quarantined. At most MaxConns
// reapers can exist, each for at most 20 seconds. If even that expires, the
// exact connection+permit remain in pending for explicit reconciliation; no
// fresh capacity is guessed from logical pgx.IsClosed.
func (p *PostgreSQLV1) signal() {
	p.mu.Lock()
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}
func (p *PostgreSQLV1) acquire(ctx context.Context) (*sessionPermitV1, error) {
	if ctx == nil {
		return nil, ErrInvalidV1
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		p.reconcileReady()
		p.mu.Lock()
		closing := p.closing
		p.mu.Unlock()
		if closing {
			return nil, ErrOutcomeUnknownV1
		}
		if ctx.Err() != nil {
			return nil, contextualV1(ErrAdmissionV1, ctx)
		}
		select {
		case p.slots <- struct{}{}:
			permit := &sessionPermitV1{slots: p.slots, afterRelease: p.signal}
			p.mu.Lock()
			closing = p.closing
			p.mu.Unlock()
			if ctx.Err() != nil || closing {
				permit.releaseAfterClose(true)
				if ctx.Err() != nil {
					return nil, contextualV1(ErrAdmissionV1, ctx)
				}
				return nil, ErrOutcomeUnknownV1
			}
			return permit, nil
		case <-ctx.Done():
			return nil, contextualV1(ErrAdmissionV1, ctx)
		case <-tick.C:
		}
	}
}
func (p *PostgreSQLV1) closeOwned(c *pgx.Conn, permit *sessionPermitV1) error {
	err, closed := closeConnection(pgxLifecycleV1{c})
	if closed {
		permit.releaseAfterClose(true)
		return err
	}
	p.mu.Lock()
	p.pending[c] = permit
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
			case <-c.PgConn().CleanupDone():
				p.reconcileReady()
			case <-timer.C:
				p.signal()
			}
		}()
	default:
	}
	// If a completing reaper still owns its worker slot, quarantine remains
	// fully owned and the explicit/Begin reconciliation paths observe completion.
	return errors.Join(ErrOutcomeUnknownV1, err)
}
func (p *PostgreSQLV1) reconcileReady() {
	p.mu.Lock()
	var permits []*sessionPermitV1
	for c, permit := range p.pending {
		select {
		case <-c.PgConn().CleanupDone():
			delete(p.pending, c)
			permits = append(permits, permit)
		default:
		}
	}
	p.mu.Unlock()
	for _, permit := range permits {
		permit.releaseAfterClose(true)
	}
}

// PendingCleanupV1 observes actual completion before reporting owned quarantine.
func (p *PostgreSQLV1) PendingCleanupV1() int {
	if p == nil {
		return 0
	}
	p.reconcileReady()
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.pending)
}

// ReconcileCleanupV1 owns a bounded join; expiry reports pending work and keeps
// the exact connections/permits quarantined. It opens no SQL sessions.
func (p *PostgreSQLV1) ReconcileCleanupV1(ctx context.Context) error { return p.drain(ctx, false) }

// CloseV1 disables new independent sessions and joins all active/quarantined
// permits within the supplied deadline. It does not close the caller-owned pool
// or silently terminate active signing transactions. The application shutdown
// path must call it and report a timed-out join as incomplete cleanup.
func (p *PostgreSQLV1) CloseV1(ctx context.Context) error { return p.drain(ctx, true) }
func (p *PostgreSQLV1) drain(ctx context.Context, closeNew bool) error {
	if p == nil || ctx == nil {
		return ErrInvalidV1
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
		pending := len(p.pending)
		changed := p.changed
		p.mu.Unlock()
		if pending == 0 && (!closeNew || (len(p.slots) == 0 && len(p.reapers) == 0)) {
			return nil
		}
		if _, ok := ctx.Deadline(); !ok {
			return ErrInvalidV1
		}
		select {
		case <-ctx.Done():
			return contextualV1(ErrOutcomeUnknownV1, ctx)
		case <-changed:
		case <-tick.C:
		}
	}
}
