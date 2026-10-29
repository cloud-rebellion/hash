//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Real public constructor, caller-pinned current embedded migrations and actual
// guarded preparation/original protocols introduced in85/87. Synthetic
// source/geometry/packages/storage isolate the original
// capture and recovery protocol; this is not renderer, provider or live Sign
// acceptance and does not simulate a successful COMMIT with a lost ACK.
type originalPGFixtureV1 struct {
	f          *preparationFixtureV1
	ctx        context.Context
	pool       *pgxpool.Pool
	observer   *pgx.Conn
	q          *generated.Queries
	j          *SQLOriginalJournalV1
	resources  atomic.Int32
	denyBodies atomic.Bool
	bodyReads  atomic.Int32
}
type originalPGTracerV1 struct{ v *originalPGFixtureV1 }

func (v originalPGTracerV1) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "-- name: GetSignatureFitOriginalPayloadBody") {
		v.v.bodyReads.Add(1)
	}
	return ctx
}
func (v originalPGTracerV1) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func originalPGMustV1(t *testing.T, phase string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(phase)
	}
}
func originalPGSetupV1(t *testing.T) *originalPGFixtureV1 {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Skip("HASH_E2E_DB_URL required for owned PostgreSQL")
	}
	if os.Getenv("HASH_E2E_ORIGINALS_OWNED_PG") != "1" {
		t.Fatal("root-owned original capture fixture required")
	}
	digest, versions, err := db.EmbeddedMigrationsIdentity()
	originalPGMustV1(t, "embedded original capture identity", err)
	want := os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256")
	if want == "" || digest != want || len(versions) < 87 {
		t.Fatal("root must pin the exact current embedded release including migration87")
	}
	for i, n := range versions {
		if n != int64(i+1) {
			t.Fatal("noncontiguous original migration tree")
		}
	}
	v := &originalPGFixtureV1{f: protocolFixtureV1(t, "v1-case-1.fit", 1)}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	t.Cleanup(cancel)
	v.ctx = ctx
	config, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	originalPGMustV1(t, "parse private owned database configuration", err)
	admin, err := pgx.ConnectConfig(ctx, config.Copy())
	originalPGMustV1(t, "connect owned synthetic parent", err)
	database := "hash_fit_original_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	created := false
	var migration interface{ Close() error }
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if v.j != nil && v.j.CloseV1(cleanup) != nil {
			t.Error("join original adapter shutdown")
		}
		if v.pool != nil {
			v.pool.Close()
		}
		if migration != nil && migration.Close() != nil {
			t.Error("close original fixture migrator")
		}
		if v.observer != nil && v.observer.Close(cleanup) != nil {
			t.Error("close original observer")
		}
		if created {
			if _, e := admin.Exec(cleanup, "DROP DATABASE "+pgx.Identifier{database}.Sanitize()+" WITH (FORCE)"); e != nil {
				t.Error("drop exact owned original database")
			}
		}
		if admin.Close(cleanup) != nil {
			t.Error("close original fixture admin")
		}
	})
	_, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{database}.Sanitize())
	originalPGMustV1(t, "create exact owned original database", err)
	created = true
	config.Database = database
	migrator := stdlib.OpenDB(*config.Copy())
	migration = migrator
	originalPGMustV1(t, "apply exact current embedded migrations", db.RunMigrationsContext(ctx, migrator))
	originalPGMustV1(t, "close owned migrator", migrator.Close())
	migration = nil
	observerConfig := config.Copy()
	observerConfig.RuntimeParams["application_name"] = "hash-fit-original-observer"
	v.observer, err = pgx.ConnectConfig(ctx, observerConfig)
	originalPGMustV1(t, "connect independent observer", err)
	var count, distinct, latest int64
	var applied bool
	wantHistoryRows := int64(len(versions) + 1)
	err = v.observer.QueryRow(ctx, "SELECT count(*),count(DISTINCT version_id),max(version_id),bool_and(is_applied) FROM goose_db_version").Scan(&count, &distinct, &latest, &applied)
	originalPGMustV1(t, "read exact current migration history", err)
	if count != wantHistoryRows || distinct != wantHistoryRows || latest != versions[len(versions)-1] || !applied {
		t.Fatal("normal original fixture history differs from the exact compiled release")
	}
	v.q = generated.New(v.observer)
	poolConfig, err := pgxpool.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	originalPGMustV1(t, "parse owned writer pool", err)
	poolConfig.ConnConfig = config.Copy()
	poolConfig.ConnConfig.RuntimeParams["application_name"] = "hash-fit-original-writer"
	poolConfig.ConnConfig.Tracer = originalPGTracerV1{v}
	poolConfig.MaxConns = 2
	poolConfig.MinConns = 0
	poolConfig.MinIdleConns = 0
	v.pool, err = pgxpool.NewWithConfig(ctx, poolConfig)
	originalPGMustV1(t, "create owned writer pool", err)
	in := v.f.request.Authority.Input()
	user := uuid.New()
	source := v.f.objects.source
	tx, err := v.observer.Begin(ctx)
	originalPGMustV1(t, "begin normal original draft", err)
	defer tx.Rollback(ctx)
	for _, s := range []struct {
		sql  string
		args []any
	}{
		{"INSERT INTO orgs(id,name) VALUES($1,'synthetic current original')", []any{in.OrgID}},
		{"INSERT INTO users(id,org_id,email,name,role) VALUES($1,$2,$3,'Synthetic Owner','owner')", []any{user, in.OrgID, user.String() + "@invalid.example"}},
		{"INSERT INTO documents(id,org_id,name,status,source_kind,sender_id,pdf_storage_key,pdf_sha256,pdf_storage_version_id,evidence_version_pins_required) VALUES($1,$2,'current original protocol source','draft','pdf',$3,$4,$5,$6,true)", []any{in.DocumentID, in.OrgID, user, source.Key, digestBytesV1(source.SHA256), source.VersionID}},
		{"INSERT INTO document_branding_override(document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color) VALUES($1,'#0F172A','#3B82F6','#FFFFFF','#0F172A','#64748B','','','Inter','Inter','#0F172A')", []any{in.DocumentID}},
		{"INSERT INTO recipients(id,document_id,email,name,role,magic_token_hash) VALUES($1,$2,'synthetic.original@invalid.example','Synthetic Customer','customer',$3)", []any{in.RecipientID, in.DocumentID, digestBytesV1(digestV1([]byte("synthetic original credential")))}},
	} {
		_, err = tx.Exec(ctx, s.sql, s.args...)
		originalPGMustV1(t, "seed normal original draft", err)
	}
	for _, target := range in.Targets {
		_, err = tx.Exec(ctx, "INSERT INTO document_fields(id,document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct) VALUES($1,$2,$3,'signature',$4,$5::numeric,$6::numeric,$7::numeric,$8::numeric)", target.ID, in.DocumentID, in.RecipientID, target.Page, target.X, target.Y, target.W, target.H)
		originalPGMustV1(t, "seed exact synthetic original target", err)
	}
	_, err = tx.Exec(ctx, "INSERT INTO send_sealing_intents(document_id,org_id,actor_user_id,actor_email,actor_ip,via,tool,article13_notice_epoch_at,retain_until) VALUES($1,$2,$3,'synthetic.owner@invalid.example','127.0.0.1','e2e','current-original-fixture',$4,hash_evidence_retain_until($4,7))", in.DocumentID, in.OrgID, user, in.CeremonyEpoch)
	originalPGMustV1(t, "allocate guarded original ceremony", err)
	q := generated.New(tx)
	_, err = q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: in.DocumentID, OrgID: in.OrgID})
	originalPGMustV1(t, "begin guarded source sealing", err)
	n, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: in.DocumentID, OrgID: in.OrgID})
	if err != nil || n != 1 {
		t.Fatal("synthetic retention start")
	}
	n, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: in.DocumentID, OrgID: in.OrgID})
	if err != nil || n != 1 {
		t.Fatal("synthetic retention completion")
	}
	_, err = q.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: in.DocumentID, OrgID: in.OrgID})
	originalPGMustV1(t, "complete real guarded SQL source send", err)
	_, err = tx.Exec(ctx, "INSERT INTO events(org_id,document_id,kind,payload_json,payload_hashed,row_hash) VALUES($1,$2,'document.sent',jsonb_build_object('required_notice_schema','hash-a13-2026-08-31','required_notice_sent_at',hash_article13_canonical_sent_at($3::timestamptz)),convert_to(jsonb_build_object('required_notice_schema','hash-a13-2026-08-31','required_notice_sent_at',hash_article13_canonical_sent_at($3::timestamptz))::text,'UTF8'),$4)", in.OrgID, in.DocumentID, in.CeremonyEpoch, digestBytesV1(digestV1([]byte("synthetic original notice row"))))
	originalPGMustV1(t, "commit original notice event", err)
	n, err = q.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: in.DocumentID, OrgID: in.OrgID})
	if err != nil || n != 1 {
		t.Fatal("consume original send intent")
	}
	originalPGMustV1(t, "commit normal original fixture without disabling guards", tx.Commit(ctx))
	v.j = v.newJournal(t)
	v.f.preparer.Journal = NewSQLJournalV1(v.pool)
	v.f.preparer.Originals = v.j
	v.f.preparer.Objects = &originalPGObjectsV1{v: v, base: v.f.objects}
	return v
}
func (v *originalPGFixtureV1) newJournal(t *testing.T) *SQLOriginalJournalV1 {
	t.Helper()
	j, err := NewSQLOriginalJournalV1(v.pool, func(ctx context.Context, r OriginalResourceRequestV1) (func(), error) {
		if ctx.Err() != nil || (r.Kind != "metadata" && v.denyBodies.Load()) {
			return nil, ErrOriginalResourcesV1
		}
		if r.WorkingBytes < 1 || r.WorkingBytes > 80<<20 || r.StagingBytes < 0 {
			return nil, ErrOriginalResourcesV1
		}
		v.resources.Add(1)
		var closed atomic.Bool
		return func() {
			if !closed.CompareAndSwap(false, true) {
				t.Error("duplicate original admission release")
			}
			v.resources.Add(-1)
		}, nil
	})
	originalPGMustV1(t, "construct public original journal", err)
	return j
}
func (v *originalPGFixtureV1) row(t *testing.T) *generated.SignatureFitPreparation {
	t.Helper()
	row, err := v.q.GetSignatureFitPreparation(v.ctx, generated.GetSignatureFitPreparationParams{ID: v.f.request.OperationID, OrgID: v.f.request.Authority.Input().OrgID})
	originalPGMustV1(t, "read independent actual original operation", err)
	return row
}

type originalPGObjectsV1 struct {
	v    *originalPGFixtureV1
	base *objectsFixtureV1
}

func (o *originalPGObjectsV1) sync(ctx context.Context) error {
	in := o.v.f.request.Authority.Input()
	p, err := o.v.q.GetSignatureFitPreparation(ctx, generated.GetSignatureFitPreparationParams{ID: o.v.f.request.OperationID, OrgID: in.OrgID})
	if err != nil {
		return ErrIdentityV1
	}
	rows, err := o.v.q.ListSignatureFitObjects(ctx, generated.ListSignatureFitObjectsParams{ID: p.ID, OrgID: p.OrgID})
	if err != nil {
		return ErrIdentityV1
	}
	o.base.journal.operation = p
	for _, r := range rows {
		o.base.journal.objects[ObjectIDV1{r.Kind, r.Page}] = r
	}
	return nil
}
func (o *originalPGObjectsV1) GetVerifiedVersionBounded(ctx context.Context, key, version string, sha []byte, max int64) ([]byte, error) {
	if err := o.sync(ctx); err != nil {
		return nil, err
	}
	return o.base.GetVerifiedVersionBounded(ctx, key, version, sha, max)
}
func (o *originalPGObjectsV1) ResolveFitTransientVersion(ctx context.Context, r storage.FitTransientReservation) (storage.StoredObject, bool, error) {
	if err := o.sync(ctx); err != nil {
		return storage.StoredObject{}, false, err
	}
	return o.base.ResolveFitTransientVersion(ctx, r)
}
func (o *originalPGObjectsV1) PutFitTransientReserved(ctx context.Context, r storage.FitTransientReservation, raw []byte) (storage.StoredObject, error) {
	if err := o.sync(ctx); err != nil {
		return storage.StoredObject{}, err
	}
	for _, item := range o.base.journal.objects {
		if item.StorageKey == r.Key {
			m, err := o.v.q.GetSignatureFitOriginalPayloadMetadata(ctx, generated.GetSignatureFitOriginalPayloadMetadataParams{PreparationID: item.PreparationID, OrgID: o.base.journal.operation.OrgID, DocumentID: o.base.journal.operation.DocumentID, Kind: item.Kind, Page: item.Page})
			if err != nil || m.Bytes != int64(len(raw)) || !bytes.Equal(m.Sha256, digestBytesV1(digestV1(raw))) {
				return storage.StoredObject{}, ErrOriginalPayloadV1
			}
		}
	}
	return o.base.PutFitTransientReserved(ctx, r, raw)
}

type originalPGFailureJournalV1 struct {
	JournalV1
	mode   string
	failed bool
}

func (j *originalPGFailureJournalV1) ReserveObject(ctx context.Context, p generated.ReserveSignatureFitObjectParams) (*generated.SignatureFitObject, error) {
	if p.Kind == "page" && !j.failed && j.mode == "before_reserve" {
		j.failed = true
		return nil, errors.New("synthetic interruption after original capture")
	}
	o, err := j.JournalV1.ReserveObject(ctx, p)
	if err == nil && p.Kind == "page" && !j.failed && j.mode == "after_reserve" {
		j.failed = true
		return nil, errors.New("synthetic missing reservation acknowledgement")
	}
	return o, err
}
func (j *originalPGFailureJournalV1) Attempt(ctx context.Context, p generated.MarkSignatureFitUploadAttemptedParams) (*generated.SignatureFitObject, error) {
	o, err := j.JournalV1.Attempt(ctx, p)
	if err == nil && p.Kind == "page" && !j.failed && j.mode == "after_attempt" {
		j.failed = true
		return nil, errors.New("synthetic missing attempt acknowledgement")
	}
	return o, err
}

func TestOriginalJournalColdPreparedRecoveryE2E(t *testing.T) {
	for _, mode := range []string{"before_reserve", "after_reserve"} {
		t.Run(mode, func(t *testing.T) {
			v := originalPGSetupV1(t)
			v.f.preparer.Journal = &originalPGFailureJournalV1{JournalV1: v.f.preparer.Journal, mode: mode}
			_, err := v.f.preparer.Prepare(v.ctx, v.f.request)
			if !errors.Is(err, ErrUncertainIOV1) {
				t.Fatal("interruption did not stop after original capture")
			}
			if len(v.f.renderer.calls) != 1 {
				t.Fatal("original page must render once before interruption")
			}
			p := v.row(t)
			m, err := v.q.GetSignatureFitOriginalPayloadMetadata(v.ctx, generated.GetSignatureFitOriginalPayloadMetadataParams{PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, Kind: "page", Page: 1})
			originalPGMustV1(t, "observe committed original before object/upload", err)
			if m.Bytes < 1 || v.resources.Load() != 0 {
				t.Fatal("original capture or resource retirement missing")
			}
			originalPGMustV1(t, "join old original adapter", v.j.CloseV1(v.ctx))
			v.j = v.newJournal(t)
			v.f.preparer.Originals = v.j
			v.f.preparer.Journal = NewSQLJournalV1(v.pool)
			v.f.preparer.Renderer = nil
			v.f.request.Span = nil
			v.f.request.OriginalPayloads = nil
			ready, err := v.f.preparer.Prepare(v.ctx, v.f.request)
			originalPGMustV1(t, "fresh cold preparation from durable original bytes", err)
			if ready == nil || v.row(t).Status != "prepared" || len(v.f.renderer.calls) != 1 || v.resources.Load() != 0 {
				t.Fatal("cold preparation rerendered, leaked resources or failed to acknowledge prepared")
			}
			for _, n := range v.f.objects.puts {
				if n != 1 {
					t.Fatal("original SDK request repeated")
				}
			}
			p = v.row(t)
			lease, err := v.j.Load(v.ctx, p, ObjectIDV1{"page", 1})
			originalPGMustV1(t, "read original consumer lease", err)
			if v.resources.Load() != 2 || !bytes.Equal(lease.Bytes(), v.f.renderer.packages[1].Bytes()) {
				t.Fatal("body lease did not hold exact original and shared admission")
			}
			borrowed := lease.Bytes()
			lease.Close()
			lease.Close()
			if v.resources.Load() != 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("original consumer lease did not clear once and release")
			}
		})
	}
}
func TestOriginalJournalUnknownAttemptNeverReuploadsE2E(t *testing.T) {
	v := originalPGSetupV1(t)
	v.f.preparer.Journal = &originalPGFailureJournalV1{JournalV1: v.f.preparer.Journal, mode: "after_attempt"}
	_, err := v.f.preparer.Prepare(v.ctx, v.f.request)
	if !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal("unknown original attempt did not stop")
	}
	beforeReads := v.bodyReads.Load()
	v.f.preparer.Journal = NewSQLJournalV1(v.pool)
	v.f.preparer.Renderer = nil
	v.f.request.Span = nil
	_, err = v.f.preparer.Prepare(v.ctx, v.f.request)
	if !errors.Is(err, ErrUncertainIOV1) || v.bodyReads.Load() != beforeReads {
		t.Fatal("unknown attempt loaded/replayed original body")
	}
	for key, n := range v.f.objects.puts {
		if strings.HasSuffix(key, "page-1.fit") || n != 1 {
			t.Fatal("unknown attempt replayed SDK PUT")
		}
	}
	if v.resources.Load() != 0 {
		t.Fatal("unknown attempt retained returned body resources")
	}
}
func TestOriginalJournalBodyAdmissionAndScopeE2E(t *testing.T) {
	v := originalPGSetupV1(t)
	v.f.preparer.Journal = &originalPGFailureJournalV1{JournalV1: v.f.preparer.Journal, mode: "before_reserve"}
	_, err := v.f.preparer.Prepare(v.ctx, v.f.request)
	if !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal("prepare capture barrier")
	}
	p := v.row(t)
	before := v.bodyReads.Load()
	v.denyBodies.Store(true)
	lease, err := v.j.Load(v.ctx, p, ObjectIDV1{"page", 1})
	if lease != nil || !errors.Is(err, ErrOriginalResourcesV1) || v.bodyReads.Load() != before || v.resources.Load() != 0 {
		t.Fatal("original BYTEA retrieval preceded admission")
	}
	v.denyBodies.Store(false)
	foreign := *p
	foreign.OrgID = uuid.New()
	lease, err = v.j.Load(v.ctx, &foreign, ObjectIDV1{"page", 1})
	if err == nil || lease != nil || v.bodyReads.Load() != before || v.resources.Load() != 0 {
		t.Fatal("cross-tenant original body read")
	}
	changed := v.f.renderer.packages[1].Bytes()
	changed[len(changed)-1] ^= 1
	key, mime, _, _ := objectLayoutV1(ObjectIDV1{"page", 1}, manualfit.ObjectPrefixV1(p.ID, p.OrgID, p.DocumentID))
	err = v.j.Capture(v.ctx, p, ObjectIDV1{"page", 1}, key, mime, changed)
	if !errors.Is(err, ErrOriginalPayloadV1) || v.resources.Load() != 0 {
		t.Fatal("conflicting original accepted")
	}
	clear(changed)
}
func TestOriginalJournalBlockedCancellationJoinsPhysicalE2E(t *testing.T) {
	v := originalPGSetupV1(t)
	v.f.preparer.Journal = &originalPGFailureJournalV1{JournalV1: v.f.preparer.Journal, mode: "before_reserve"}
	_, err := v.f.preparer.Prepare(v.ctx, v.f.request)
	if !errors.Is(err, ErrUncertainIOV1) {
		t.Fatal("capture barrier")
	}
	p := v.row(t)
	barrierConfig := v.pool.Config().ConnConfig.Copy()
	barrierConfig.Tracer = nil
	barrierConfig.RuntimeParams["application_name"] = "hash-fit-original-barrier"
	barrierConn, err := pgx.ConnectConfig(v.ctx, barrierConfig)
	originalPGMustV1(t, "connect independent document barrier", err)
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if barrierConn.Close(closeCtx) != nil {
			t.Error("close exact original barrier backend")
		}
	}()
	barrier, err := barrierConn.Begin(v.ctx)
	originalPGMustV1(t, "begin actual document barrier", err)
	defer barrier.Rollback(v.ctx)
	_, err = barrier.Exec(v.ctx, "SELECT id FROM documents WHERE id=$1 FOR UPDATE", p.DocumentID)
	originalPGMustV1(t, "hold exact document barrier", err)
	ctx, cancel := context.WithTimeout(v.ctx, 5*time.Second)
	defer cancel()
	type result struct {
		body *OriginalPayloadV1
		err  error
	}
	done := make(chan result, 1)
	go func() { body, e := v.j.Load(ctx, p, ObjectIDV1{"page", 1}); done <- result{body, e} }()
	var pid int32
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case r := <-done:
			if r.body != nil {
				r.body.Close()
			}
			t.Fatal("original loader returned before the expected document lock wait")
		default:
		}
		err = v.observer.QueryRow(v.ctx, "SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name='hash-fit-original-writer' AND cardinality(pg_blocking_pids(pid))>0 LIMIT 1").Scan(&pid)
		if err == nil {
			break
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("observe real blocked original backend")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("no actual original document-lock wait")
	}
	before := v.bodyReads.Load()
	cancel()
	select {
	case r := <-done:
		if r.body != nil || !errors.Is(r.err, context.Canceled) {
			t.Fatal("blocked original cancellation returned body or hid cancellation")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("physical original cancellation failed to join")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	originalPGMustV1(t, "join actual original cleanup", v.j.ReconcileCleanupV1(cleanup))
	var present bool
	err = v.observer.QueryRow(v.ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", pid).Scan(&present)
	originalPGMustV1(t, "observe original backend retired", err)
	if present || v.resources.Load() != 0 || v.bodyReads.Load() != before {
		t.Fatal("original backend/resources/body work survived cancellation")
	}
	originalPGMustV1(t, "retire actual barrier after physical join", barrier.Rollback(v.ctx))
	t.Log("current-release original cancellation: actual lock wait, backend absent, CleanupDone joined, no body retrieval; no lost-commit-ack claim")
}
