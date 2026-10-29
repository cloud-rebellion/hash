//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// This executes the real service/generated SQL/physical-session paths against
// the caller-pinned current embedded release, including the migration85 protocol.
// Object bytes are explicitly INTEGRITY-ONLY metadata-rebound archive fixtures;
// retention is a test provider, not Object Lock or accepted legal policy.
type postgresSelectionFixtureV1 struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	observer *pgx.Conn
	service  *ServiceV1
	request  RequestV1
	objects  *objectStoreV1
	database string
}

func actualSelectionFixtureV1(t *testing.T) *postgresSelectionFixtureV1 {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("HASH_E2E_DB_URL required for actual owned PostgreSQL")
	}
	got, versions, err := db.EmbeddedMigrationsIdentity()
	want := os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256")
	if err != nil || want == "" || got != want || len(versions) < 85 {
		t.Fatal("root must pin the exact current embedded release including migration85")
	}
	for i, v := range versions {
		if v != int64(i+1) {
			t.Fatal("compiled release migrations are not contiguous")
		}
	}
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("parse private owned PostgreSQL configuration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	adminCfg := config.Copy()
	adminCfg.Tracer = nil
	adminCfg.RuntimeParams["application_name"] = "hash-fitselect-owned-admin"
	adminCfg.RuntimeParams["statement_timeout"] = "10000"
	adminCfg.RuntimeParams["lock_timeout"] = "5000"
	admin, err := pgx.ConnectConfig(ctx, adminCfg)
	if err != nil {
		cancel()
		t.Fatal("connect private owned parent database")
	}
	name := "hash_fitselect_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(ctx)
		cancel()
		t.Fatal("create uniquely owned fitselect database")
	}
	f := &postgresSelectionFixtureV1{ctx: ctx, database: name}
	var migrationPool interface{ Close() error }
	t.Cleanup(func() {
		if f.pool != nil {
			f.pool.Close()
		}
		if migrationPool != nil {
			if e := migrationPool.Close(); e != nil {
				t.Error("close exact owned migration pool")
			}
		}
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if f.observer != nil {
			if e := f.observer.Close(cleanup); e != nil {
				t.Error("close exact owned observer")
			}
		}
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); e != nil {
			t.Error("drop uniquely owned fitselect database")
		}
		if e := admin.Close(cleanup); e != nil {
			t.Error("close exact owned parent")
		}
		cancel()
	})
	own := config.Copy()
	own.Database = name
	own.Tracer = nil
	own.RuntimeParams["statement_timeout"] = "10000"
	own.RuntimeParams["lock_timeout"] = "5000"
	own.RuntimeParams["application_name"] = "hash-fitselect-owned-client"
	migration := stdlib.OpenDB(*own)
	migration.SetMaxOpenConns(4)
	migration.SetMaxIdleConns(4)
	migrationPool = migration
	if err = db.RunMigrations(migration); err != nil {
		t.Fatal("apply exact embedded migrations through normal runner")
	}
	if err = migration.Close(); err != nil {
		t.Fatal("close exact owned migration pool before actual service sessions")
	}
	migrationPool = nil
	observerCfg := own.Copy()
	observerCfg.RuntimeParams["application_name"] = "hash-fitselect-owned-observer"
	f.observer, err = pgx.ConnectConfig(ctx, observerCfg)
	if err != nil {
		t.Fatal("connect independent owned observer")
	}
	var count, distinct, latest int64
	var applied bool
	wantHistoryRows := int64(len(versions) + 1) // Goose's initial version0 plus this exact release.
	if err = f.observer.QueryRow(ctx, "SELECT count(*),count(DISTINCT version_id),max(version_id),bool_and(is_applied) FROM goose_db_version").Scan(&count, &distinct, &latest, &applied); err != nil || count != wantHistoryRows || distinct != wantHistoryRows || latest != versions[len(versions)-1] || !applied {
		t.Fatal("normal migration history differs from the exact compiled release")
	}
	poolConfig, err := pgxpool.ParseConfig(own.ConnString())
	if err != nil {
		t.Fatal("parse private owned pool")
	}
	poolConfig.ConnConfig = own.Copy()
	poolConfig.MaxConns = 2
	f.pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal("connect bounded owned pool")
	}
	base, request, memory, objects := setupSelectionV1(t)
	f.request = request
	f.objects = objects
	state := memory.state
	d, r, p := state.Document, state.Recipient, state.Preparation
	sender := uuid.New()
	seed, err := f.observer.Begin(ctx)
	if err != nil {
		t.Fatal("begin normal owned fixture")
	}
	defer seed.Rollback(ctx)
	for _, statement := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO orgs(id,name) VALUES($1,'synthetic fit selection')", []any{d.OrgID}},
		{"INSERT INTO users(id,org_id,email,name,role) VALUES($1,$2,$3,'Synthetic Owner','owner')", []any{sender, d.OrgID, sender.String() + "@invalid.example"}},
		{"INSERT INTO documents(id,org_id,name,status,source_kind,sender_id,pdf_storage_key,pdf_sha256,pdf_storage_version_id) VALUES($1,$2,'synthetic fit source','draft','pdf',$3,$4,$5,$6)", []any{d.ID, d.OrgID, sender, d.PdfStorageKey.String, d.PdfSha256, d.PdfStorageVersionID.String}},
		{"INSERT INTO document_branding_override(document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color) VALUES($1,'#334455','#556677','#ffffff','#111111','#777777','','','Inter, sans-serif','Inter, sans-serif','#222222')", []any{d.ID}},
		// This raw initial intent is synthetic metadata authority, not an invocation
		// of the production Send allocator or a storage/provider acceptance proof.
		// Its fixed epoch is already bound into the archive fixture; no committed
		// document epoch is rewritten and every ordinary database guard stays active.
		{"INSERT INTO send_sealing_intents(document_id,org_id,actor_user_id,actor_email,via,tool,article13_notice_epoch_at,retain_until) VALUES($1,$2,$3,$4,'worker','metadata-only-fitselect-fixture',$5,hash_evidence_retain_until($5::timestamptz,7))", []any{d.ID, d.OrgID, sender, sender.String() + "@invalid.example", p.CeremonyEpoch.Time}},
		{"INSERT INTO recipients(id,document_id,email,name,magic_token_hash) VALUES($1,$2,'synthetic.signer@invalid.example','Synthetic Signer',$3)", []any{r.ID, d.ID, d.PdfSha256}},
	} {
		if _, err = seed.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatal("seed normal fixture without disabling guards")
		}
	}
	for _, field := range state.AllFields {
		if _, err = seed.Exec(ctx, "INSERT INTO document_fields(id,document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required) VALUES($1,$2,$3,'signature',$4,$5,$6,$7,$8,true)", field.ID, d.ID, r.ID, field.Page, field.XPct, field.YPct, field.WPct, field.HPct); err != nil {
			t.Fatal("seed exact assigned target rows")
		}
	}
	// Exercise the normal generated sealing checkpoints to leave draft.
	// Only the initial synthetic intent allocation above fixes fixture identity;
	// these metadata checkpoints do not assert actual external retention.
	sealing := generated.New(seed)
	if _, err = sealing.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: d.ID, OrgID: d.OrgID}); err != nil {
		t.Fatalf("begin guarded synthetic send sealing: %v", err)
	}
	if _, err = sealing.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{ID: d.ID, OrgID: d.OrgID, PdfStorageVersionID: d.PdfStorageVersionID}); err != nil {
		t.Fatalf("pin exact synthetic source version: %v", err)
	}
	if affected, e := sealing.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: d.ID, OrgID: d.OrgID}); e != nil || affected != 1 {
		t.Fatalf("start synthetic send retention checkpoint: %v", e)
	}
	if affected, e := sealing.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: d.ID, OrgID: d.OrgID}); e != nil || affected != 1 {
		t.Fatalf("complete synthetic send retention checkpoint: %v", e)
	}
	sent, err := sealing.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: d.ID, OrgID: d.OrgID})
	if err != nil || sent == nil || sent.Status != "sent" || !sent.SentAt.Valid || !sent.SentAt.Time.Equal(p.CeremonyEpoch.Time) || !sent.Article13NoticeEpochAt.Valid || !sent.Article13NoticeEpochAt.Time.Equal(p.CeremonyEpoch.Time) || !sent.Article13NoticeEpochV61Committed {
		t.Fatalf("complete guarded fixture-bound ceremony epoch: %v", err)
	}
	// Commit the canonical marker with the generated sent transition, before
	// the deferred Article13 guard examines the final transaction snapshot.
	if _, err = seed.Exec(ctx, "INSERT INTO events(org_id,document_id,kind,payload_json,payload_hashed,row_hash) VALUES($1,$2,'document.sent',jsonb_build_object('required_notice_schema','hash-a13-2026-08-31','required_notice_sent_at',hash_article13_canonical_sent_at($3::timestamptz)),convert_to(jsonb_build_object('required_notice_schema','hash-a13-2026-08-31','required_notice_sent_at',hash_article13_canonical_sent_at($3::timestamptz))::text,'UTF8'),$4)", d.OrgID, d.ID, p.CeremonyEpoch.Time, d.PdfSha256); err != nil {
		t.Fatalf("bind exact synthetic send marker: %v", err)
	}
	if affected, e := sealing.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: d.ID, OrgID: d.OrgID}); e != nil || affected != 1 {
		t.Fatalf("delete consumed synthetic send intent: %v", e)
	}
	if err = seed.Commit(ctx); err != nil {
		t.Fatal("commit normal guarded fixture")
	}
	q := generated.New(f.observer)
	_, err = q.ReserveSignatureFitPreparation(ctx, generated.ReserveSignatureFitPreparationParams{
		ID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, RecipientID: p.RecipientID, CeremonyEpoch: p.CeremonyEpoch, AuthoritySha256: p.AuthoritySha256,
		SourceStorageKey: p.SourceStorageKey, SourceVersionID: p.SourceVersionID, SourceSha256: p.SourceSha256, SourceBytes: p.SourceBytes,
		GeometrySha256: p.GeometrySha256, SpanSha256: p.SpanSha256, ReservedBytes: p.ReservedBytes, ExpectedObjects: p.ExpectedObjects, OwnerID: p.OwnerID, LeaseUntil: p.LeaseUntil,
	})
	if err != nil {
		t.Fatal("reserve real guarded preparation")
	}
	for _, o := range state.Objects {
		_, err = q.ReserveSignatureFitObject(ctx, generated.ReserveSignatureFitObjectParams{PreparationID: p.ID, OrgID: p.OrgID, OwnerID: p.OwnerID, Kind: o.Kind, Page: o.Page, StorageKey: o.StorageKey, Sha256: o.Sha256, Bytes: o.Bytes, ContentType: o.ContentType})
		if err != nil {
			t.Fatal("reserve actual generated object metadata")
		}
		_, err = q.MarkSignatureFitUploadAttempted(ctx, generated.MarkSignatureFitUploadAttemptedParams{PreparationID: p.ID, OrgID: p.OrgID, OwnerID: p.OwnerID, Kind: o.Kind, Page: o.Page})
		if err != nil {
			t.Fatal("commit original upload attempt")
		}
		_, err = q.PinSignatureFitObjectVersion(ctx, generated.PinSignatureFitObjectVersionParams{PreparationID: p.ID, OrgID: p.OrgID, OwnerID: p.OwnerID, Kind: o.Kind, Page: o.Page, VersionID: o.VersionID.String})
		if err != nil {
			t.Fatal("commit positive exact version pin")
		}
		_, err = q.MarkSignatureFitObjectReadbackVerified(ctx, generated.MarkSignatureFitObjectReadbackVerifiedParams{PreparationID: p.ID, OrgID: p.OrgID, OwnerID: p.OwnerID, Kind: o.Kind, Page: o.Page, VersionID: o.VersionID.String, Sha256: o.Sha256, Bytes: o.Bytes})
		if err != nil {
			t.Fatal("commit fixture exact-version readback")
		}
	}
	_, err = q.MarkSignatureFitPreparationPrepared(ctx, generated.MarkSignatureFitPreparationPreparedParams{ID: p.ID, OrgID: p.OrgID, OwnerID: p.OwnerID})
	if err != nil {
		t.Fatal("mark complete guarded preparation")
	}
	adapter, err := NewPostgreSQLV1(f.pool)
	if err != nil {
		t.Fatal("construct bounded fresh-session adapter")
	}
	base.Store = adapter
	f.service = base
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		if e := adapter.CloseV1(cleanup); e != nil {
			t.Error("join exact owned selection adapter cleanup")
		}
	})
	return f
}

type actualCommitWitnessV1 struct {
	store     *PostgreSQLV1
	mu        sync.Mutex
	pids      []uint32
	commits   int
	unknownAt int
}
type actualWitnessTransactionV1 struct {
	TransactionV1
	spy *actualCommitWitnessV1
}

func (s *actualCommitWitnessV1) Begin(ctx context.Context) (TransactionV1, error) {
	raw, e := s.store.Begin(ctx)
	if e != nil {
		return nil, e
	}
	tx := raw.(*postgresTransactionV1)
	pid := tx.conn.PgConn().PID()
	s.mu.Lock()
	s.pids = append(s.pids, pid)
	s.mu.Unlock()
	return &actualWitnessTransactionV1{raw, s}, nil
}
func (t *actualWitnessTransactionV1) Commit(ctx context.Context) error {
	t.spy.mu.Lock()
	t.spy.commits++
	n := t.spy.commits
	t.spy.mu.Unlock()
	if e := t.TransactionV1.Commit(ctx); e != nil {
		return e
	}
	if t.spy.unknownAt == n {
		return errors.New("synthetic response loss after real COMMIT")
	}
	return nil
}
func TestHashFitSelectionRealSQLUnknownCommitE2E(t *testing.T) {
	f := actualSelectionFixtureV1(t)
	adapter := f.service.Store.(*PostgreSQLV1)
	spy := &actualCommitWitnessV1{store: adapter, unknownAt: 2}
	f.service.Store = spy
	f.objects.beforeRetain = func(n int) {
		var started, complete bool
		if e := f.observer.QueryRow(f.ctx, "SELECT retention_started_at IS NOT NULL,retention_completed_at IS NOT NULL FROM signature_fit_selections WHERE preparation_id=$1", f.request.Binding.OperationID).Scan(&started, &complete); e != nil || !started || complete {
			t.Error("committed start checkpoint missing before retention")
		}
	}
	selected, err := f.service.SelectV1(f.ctx, f.request)
	if err != nil || selected == nil {
		t.Fatalf("real SQL lost-ACK reconciliation: %v", err)
	}
	if len(f.objects.retained) != 3 {
		t.Fatal("selected set retained incomplete or substituted objects")
	}
	unique := map[uint32]bool{}
	for _, pid := range spy.pids {
		if pid == 0 || unique[pid] {
			t.Fatal("fresh reconciliation reused physical session")
		}
		unique[pid] = true
	}
	if len(unique) < 6 {
		t.Fatal("insufficient distinct observed physical sessions")
	}
	var complete bool
	var picked uuid.UUID
	if err = f.observer.QueryRow(f.ctx, "SELECT id,retention_completed_at IS NOT NULL FROM signature_fit_selections WHERE preparation_id=$1", f.request.Binding.OperationID).Scan(&picked, &complete); err != nil || picked != selected.ID() || !complete {
		t.Fatal("independent observer did not see stable retained winner")
	}
	if len(adapter.slots) != 0 {
		t.Fatal("actual COMMIT/rollback leaked bounded session permit")
	}
	finalTx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin actual signature admission transaction")
	}
	field, err := FinalAdmissionV1(f.ctx, finalTx, selected, testAdmissionV1)
	if err != nil || field == nil {
		_ = finalTx.Rollback(f.ctx)
		t.Fatalf("actual retained final admission: %v", err)
	}
	if err = finalTx.Rollback(f.ctx); err != nil {
		t.Fatal("rollback read-only actual final admission")
	}
	var signatures, events int64
	if err = f.observer.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.signed')", f.request.Binding.DocumentID).Scan(&signatures, &events); err != nil || signatures != 0 || events != 0 {
		t.Fatal("dependency published an early Sign or audit event")
	}
	rows, err := adapter.InventoryV1(f.ctx, f.request.Binding.OrgID, f.request.Binding.DocumentID)
	if err != nil || len(rows) != 3 {
		t.Fatal("SQL inventory omitted selected versions")
	}
	for _, r := range rows {
		if !r.SelectionID.Valid || !r.RetentionCompletedAt.Valid || !r.UploadAttemptedAt.Valid || !r.VersionID.Valid {
			t.Fatal("inventory omitted original/selected checkpoints")
		}
	}
	witness, _ := json.Marshal(map[string]any{"schema": 1, "database": f.database, "physical_pids": spy.pids, "unknown_actual_committed": true, "stable_selection": selected.ID(), "no_early_sign": true})
	t.Logf("HASH_FIT_SELECTION_SQL_WITNESS %s", witness)
}
func TestHashFitSelectionRealSQLPartialRetentionAndDriftE2E(t *testing.T) {
	f := actualSelectionFixtureV1(t)
	f.objects.failAt = 2
	selected, err := f.service.SelectV1(f.ctx, f.request)
	if selected != nil || !errors.Is(err, ErrRetentionPendingV1) {
		t.Fatalf("partial provider retention claimed success: %v", err)
	}
	var started, complete bool
	if err = f.observer.QueryRow(f.ctx, "SELECT retention_started_at IS NOT NULL,retention_completed_at IS NOT NULL FROM signature_fit_selections WHERE preparation_id=$1", f.request.Binding.OperationID).Scan(&started, &complete); err != nil || !started || complete {
		t.Fatal("actual partial checkpoint state differs")
	}
	f.objects.failAt = 0
	selected, err = f.service.ResumeV1(f.ctx, f.request.Binding)
	if err != nil || selected == nil || len(f.objects.retained) != 5 {
		t.Fatalf("renderer-independent actual SQL resume: %v", err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin owned target drift")
	}
	defer tx.Rollback(f.ctx)
	q := generated.New(tx)
	if _, err = q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.request.Binding.DocumentID, OrgID: f.request.Binding.OrgID}); err != nil {
		t.Fatal("lock exact parent for target drift")
	}
	if _, err = tx.Exec(f.ctx, "UPDATE document_fields SET x_pct=x_pct+0.0001 WHERE document_id=$1 AND id=(SELECT id FROM document_fields WHERE document_id=$1 ORDER BY id DESC LIMIT 1)", f.request.Binding.DocumentID); err != nil {
		t.Fatal("normal guarded second-target drift")
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("commit parent-locked target drift")
	}
	finalTx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin actual final admission")
	}
	_, err = FinalAdmissionV1(f.ctx, finalTx, selected, testAdmissionV1)
	_ = finalTx.Rollback(f.ctx)
	if !errors.Is(err, ErrAuthorityChangedV1) {
		t.Fatalf("final admission consumed changed second target: %v", err)
	}
	pin := selected.Retained().Manifest().Span()
	if !bytes.Equal(selected.Retained().SpanBytes(), f.objects.blobs[blobIDV1(pin.Key, pin.VersionID)].raw) {
		t.Fatal("live drift replaced original archived signer bytes")
	}
}

func TestHashFitSelectionRealSQLCancellationCleanupE2E(t *testing.T) {
	f := actualSelectionFixtureV1(t)
	adapter := f.service.Store.(*PostgreSQLV1)
	raw, err := adapter.Begin(f.ctx)
	if err != nil {
		t.Fatal("begin actual cancelable fresh session")
	}
	tx := raw.(*postgresTransactionV1)
	pid := tx.conn.PgConn().PID()
	cancelCtx, cancel := context.WithTimeout(f.ctx, 20*time.Millisecond)
	defer cancel()
	var ignored any
	err = tx.tx.QueryRow(cancelCtx, "SELECT pg_sleep(10)").Scan(&ignored)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		_ = raw.Rollback(f.ctx)
		t.Fatal("actual PostgreSQL query did not cancel")
	}
	if len(adapter.slots) != 1 {
		t.Fatal("canceled query released permit before owner cleanup")
	}
	rollbackErr := raw.Rollback(f.ctx)
	// Cancellation may mark pgx logically closed and start asynchronous cleanup.
	// Neither that status nor Rollback errors are physical completion proof.
	if len(adapter.slots) == 0 {
		select {
		case <-tx.conn.PgConn().CleanupDone():
		default:
			t.Fatal("permit released before physicalCleanupDone")
		}
	}
	cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	if e := adapter.ReconcileCleanupV1(cleanup); e != nil {
		t.Fatalf("bounded owned cancellation cleanup: %v", e)
	}
	if len(adapter.slots) != 0 || adapter.PendingCleanupV1() != 0 {
		t.Fatal("actual canceled connection/permit leaked")
	}
	select {
	case <-tx.conn.PgConn().CleanupDone():
	default:
		t.Fatal("reconciliation inferred physical cleanup")
	}
	// Confirm the original scoped backend disappears; never terminate another
	// session or replace credentials as a cancellation workaround.
	gone := false
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		var exists bool
		if e := f.observer.QueryRow(cleanup, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND datname=$2 AND application_name='hash-fitselect-owned-client')", int64(pid), f.database).Scan(&exists); e != nil {
			t.Fatal("observe exact canceled backend")
		}
		if !exists {
			gone = true
			break
		}
		select {
		case <-cleanup.Done():
			t.Fatal("owned disappearance deadline")
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !gone {
		t.Fatal("owned canceled backend remained after physical cleanup")
	}
	next, err := adapter.Begin(f.ctx)
	if err != nil {
		t.Fatal("fresh bounded session did not recover after actual cancellation")
	}
	if err = next.Rollback(f.ctx); err != nil {
		t.Fatal("close exact recovered session")
	}
	witness, _ := json.Marshal(map[string]any{
		"schema": 1, "original_pid": pid, "logical_closed": tx.conn.IsClosed(),
		"physical_cleanup_done": true, "original_backend_gone": gone,
		"rollback_returned_error": rollbackErr != nil,
		"quarantined_connections": adapter.PendingCleanupV1(),
		"capacity_recovered":      len(adapter.slots) == 0,
	})
	t.Logf("HASH_FIT_SELECTION_CANCEL_WITNESS %s", witness)
}

type actualDuplicateBarrierV1 struct {
	firstNoWinner  chan struct{}
	secondNoWinner chan struct{}
	releaseSecond  chan struct{}
}
type actualDuplicateStoreV1 struct {
	StoreV1
	mu      sync.Mutex
	begins  int
	first   bool
	barrier *actualDuplicateBarrierV1
}
type actualDuplicateTransactionV1 struct {
	TransactionV1
	owner   *actualDuplicateStoreV1
	initial bool
}

func (s *actualDuplicateStoreV1) Begin(ctx context.Context) (TransactionV1, error) {
	tx, err := s.StoreV1.Begin(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.begins++
	initial := s.begins == 1
	s.mu.Unlock()
	return &actualDuplicateTransactionV1{tx, s, initial}, nil
}
func (t *actualDuplicateTransactionV1) FindSelection(ctx context.Context, b manualfit.BindingV1) (*generated.SignatureFitSelection, error) {
	row, err := t.TransactionV1.FindSelection(ctx, b)
	if t.initial && errors.Is(err, pgx.ErrNoRows) {
		t.initial = false
		if t.owner.first {
			close(t.owner.barrier.firstNoWinner)
			select {
			case <-t.owner.barrier.secondNoWinner:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			close(t.owner.barrier.secondNoWinner)
			select {
			case <-t.owner.barrier.releaseSecond:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return row, err
}
func TestHashFitSelectionRealSQLConcurrentDuplicateE2E(t *testing.T) {
	f := actualSelectionFixtureV1(t)
	adapter := f.service.Store.(*PostgreSQLV1)
	barrier := &actualDuplicateBarrierV1{firstNoWinner: make(chan struct{}), secondNoWinner: make(chan struct{}), releaseSecond: make(chan struct{})}
	var once sync.Once
	workerCtx, cancelWorkers := context.WithCancel(f.ctx)
	var workers sync.WaitGroup
	defer func() { cancelWorkers(); once.Do(func() { close(barrier.releaseSecond) }); workers.Wait() }()
	first := *f.service
	second := *f.service
	first.Store = &actualDuplicateStoreV1{StoreV1: adapter, first: true, barrier: barrier}
	second.Store = &actualDuplicateStoreV1{StoreV1: adapter, first: false, barrier: barrier}
	type result struct {
		selected *SelectedV1
		err      error
	}
	firstResults := make(chan result, 1)
	secondResults := make(chan result, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		s, e := first.SelectV1(workerCtx, f.request)
		firstResults <- result{s, e}
	}()
	select {
	case <-barrier.firstNoWinner:
	case <-f.ctx.Done():
		t.Fatal("actual first initial-read barrier deadline")
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		s, e := second.SelectV1(workerCtx, f.request)
		secondResults <- result{s, e}
	}()
	// Both actual SQL sessions observed no winner. Caller two retains that
	// observation while caller one completes selection/retention; caller two is
	// then released before its stage1 document lock. The old code deterministically
	// failed its MarkAttempt NOT EXISTS predicate instead of returning the winner.
	var winner result
	select {
	case winner = <-firstResults:
	case <-f.ctx.Done():
		t.Fatal("actual first completion deadline")
	}
	if winner.err != nil || winner.selected == nil {
		t.Fatalf("actual first selection: %v", winner.err)
	}
	once.Do(func() { close(barrier.releaseSecond) })
	var got result
	select {
	case got = <-secondResults:
	case <-f.ctx.Done():
		t.Fatal("actual duplicate result deadline")
	}
	if got.err != nil || got.selected == nil {
		t.Fatalf("actual duplicate selection denied: %v", got.err)
	}
	if got.selected.ID() != winner.selected.ID() || got.selected.ManifestObject() != f.request.Manifest || got.selected.Binding() != f.request.Binding {
		t.Fatal("actual duplicate chose different retained set")
	}
	var selections, signatures, events int64
	if e := f.observer.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM signature_fit_selections WHERE document_id=$1),(SELECT count(*) FROM signatures WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.signed')", f.request.Binding.DocumentID).Scan(&selections, &signatures, &events); e != nil || selections != 1 || signatures != 0 || events != 0 {
		t.Fatal("actual duplicate replaced winner or published early Sign")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 20*time.Second)
	defer stop()
	if e := adapter.ReconcileCleanupV1(cleanup); e != nil || len(adapter.slots) != 0 {
		t.Fatal("actual duplicate leaked SQL ownership")
	}
}
