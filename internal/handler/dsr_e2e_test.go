// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
)

func TestDSRErasureRollsBackEverySideEffectWhenSignatureScrubFailsE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID, doc, recipient := setupCompletedDSREvidenceE2E(t)
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
		SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	suffix := strings.ReplaceAll(recipient.ID.String(), "-", "")
	functionName := "hash_test_fail_signature_scrub_" + suffix
	triggerName := "hash_test_fail_signature_scrub_trg_" + suffix
	createFunction := fmt.Sprintf(`
CREATE FUNCTION "%s"() RETURNS trigger LANGUAGE plpgsql AS $body$
BEGIN
  IF OLD.recipient_id = '%s'::uuid THEN
    RAISE EXCEPTION 'forced signature scrub failure';
  END IF;
  RETURN NEW;
END
$body$`, functionName, recipient.ID) //nolint:gosec -- identifier and literal derive from a parsed UUID
	if _, err := pool.Exec(ctx, createFunction); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE TRIGGER "%s" BEFORE UPDATE ON signatures FOR EACH ROW EXECUTE FUNCTION "%s"()`, triggerName, functionName)); err != nil { //nolint:rawsql,gosec
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP TRIGGER IF EXISTS "%s" ON signatures`, triggerName)) //nolint:rawsql,gosec
		_, _ = pool.Exec(context.Background(), fmt.Sprintf(`DROP FUNCTION IF EXISTS "%s"()`, functionName))           //nolint:rawsql,gosec
	}()

	recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
	if recorder.Code < 500 {
		t.Fatalf("forced signature scrub failure status = %d, want 5xx; body=%s", recorder.Code, recorder.Body.String())
	}
	freshDSR, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if freshDSR.Status != "open" || freshDSR.SubjectEmail != recipient.Email || freshDSR.SubjectName != recipient.Name {
		t.Fatalf("DSR escaped rollback: status/email/name = %q/%q/%q", freshDSR.Status, freshDSR.SubjectEmail, freshDSR.SubjectName)
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if freshRecipient.Email != recipient.Email || freshRecipient.Name != recipient.Name {
		t.Fatalf("recipient escaped rollback: email/name = %q/%q", freshRecipient.Email, freshRecipient.Name)
	}
	signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil || len(signatures) != 1 {
		t.Fatalf("signatures after rollback = %d, err=%v", len(signatures), err)
	}
	if signatures[0].TypedName != "Original Legal Name" || !signatures[0].SignerUa.Valid {
		t.Fatalf("signature escaped rollback: %#v", signatures[0])
	}
	var terminalEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1 AND kind IN ('data_subject.anonymized','data_subject.fulfilled')`, orgID).Scan(&terminalEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if terminalEvents != 0 {
		t.Fatalf("terminal DSR audit events after rollback = %d, want 0", terminalEvents)
	}
}

func TestDSRConcurrentTerminalTransitionsHaveOneWinnerE2E(t *testing.T) {
	ctx, _, q, server, orgID, userID := setupDSRE2E(t)
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, SubjectEmail: "subject@example.test", SubjectName: "Subject", Kind: "access", RequestedVia: "sender",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	statuses := []string{"fulfilled", "denied"}
	results := make(chan int, len(statuses))
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(len(statuses))
	for _, status := range statuses {
		status := status
		go func() {
			ready.Done()
			<-start
			results <- transitionDSRE2E(server, orgID, userID, dsr.ID, status).Code
		}()
	}
	ready.Wait()
	close(start)
	counts := map[int]int{}
	for range statuses {
		counts[<-results]++
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent transition statuses = %#v, want one 200 and one 409", counts)
	}
	fresh, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Status != "fulfilled" && fresh.Status != "denied" {
		t.Fatalf("terminal status = %q", fresh.Status)
	}
}

func setupDSRE2E(t *testing.T, queryTracers ...pgx.QueryTracer) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
	return setupDSRPoolBirth315E2E(t, 0, queryTracers...)
}

// The optional test allocation is fixed before the original application pool exists.
// Zero preserves every existing default caller and its original parsed config.
func setupDSRPoolBirth315E2E(t *testing.T, maximum int32, queryTracers ...pgx.QueryTracer) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
	return setupDSRPoolBirthContext368E2E(t, maximum, nil, queryTracers...)
}

// The browser's existing four-minute root must own migration, pool and all
// native work from birth. Its migration phase still has the original90s bound.
// Other callers retain their original migrationFixtureContext242 parent.
func setupDSRBrowserBirth368E2E(t *testing.T, birth context.Context) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
	if birth == nil || birth.Err() != nil {
		t.Fatal("browser fixture requires its original live birth owner")
	}
	if _, ok := birth.Deadline(); !ok {
		t.Fatal("browser fixture requires its original finite birth owner")
	}
	return setupDSRPoolBirthContext368E2E(t, 0, birth)
}

func setupDSRPoolBirthContext368E2E(t *testing.T, maximum int32, birth context.Context, queryTracers ...pgx.QueryTracer) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID) {
	t.Helper()
	if len(queryTracers) > 1 {
		t.Fatal("fixture accepts at most one pool-scoped query tracer")
	}
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := birth
	if ctx == nil {
		ctx = migrationFixtureContext242(t)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Attribute lock-wait evidence to this fixture, even when independent
	// package test processes share the same disposable database.
	config.ConnConfig.RuntimeParams["application_name"] = "hash-auth-e2e-" + uuid.NewString()
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	migrationDB.SetMaxOpenConns(1)
	migrationDB.SetMaxIdleConns(1)
	// Registered before migration so a fatal setup error still closes its pool.
	t.Cleanup(func() {
		if err := migrationDB.Close(); err != nil {
			t.Error("close fixture migration database", err)
		}
	})
	migrationErr := func() error {
		if birth == nil {
			return mdb.RunMigrationsContext(ctx, migrationDB)
		}
		phase, cancel := browserMigrationPhaseContext368(ctx)
		defer cancel()
		return mdb.RunMigrationsContext(phase, migrationDB)
	}()
	if migrationErr != nil {
		t.Fatalf("migrate: %v", migrationErr)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatal("close fixture migration database", err)
	}
	// Fixture-local refusal observation is installed before this actual pool,
	// runtime or document exists. Migration work retains its original config.
	if len(queryTracers) == 1 {
		config.ConnConfig.Tracer = queryTracers[0]
	}
	if maximum != 0 && maximum != 1 {
		t.Fatal("explicit native fixture pool birth supports only original default or one connection")
	}
	if maximum == 1 {
		config.MaxConns, config.MinConns = 1, 0
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	cookies, err := auth.NewSignedCookie(strings.Repeat("4b", 32))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Pool: pool, Queries: q, Audit: audit.New(q, pool), Cookies: cookies, PublicURL: "https://hash.example.test"}
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "DSR atomicity " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uuid.NewString() + "@dsr.test", Name: "DPO", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, pool, q, server, org.ID, user.ID
}

func seedDSRRecipientE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, orgID, userID uuid.UUID, completed bool) (*generated.Document, *generated.Recipient) {
	t.Helper()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: orgID, Name: "DSR evidence", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`),
		VariablesJson: json.RawMessage(`{}`), SenderID: userID,
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: "original@example.test", Name: "Original Name", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fieldID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO document_fields (document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct, required, options_json)
VALUES ($1,$2,'signature',1,0,0,10,5,true,'[]'::jsonb) RETURNING id`, doc.ID, recipient.ID).Scan(&fieldID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	txq := q.WithTx(tx)
	if _, err := txq.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: orgID}); err != nil {
		t.Fatal(err)
	}
	if _, err := txq.InsertSignature(ctx, generated.InsertSignatureParams{
		DocumentID: doc.ID, RecipientID: recipient.ID, FieldID: fieldID, Font: "serif", TypedName: "Original Legal Name",
		ImageStorageKey: "org/" + orgID.String() + "/documents/" + doc.ID.String() + "/signatures/" + recipient.ID.String() + ".png",
		ImageSha256:     make([]byte, 32),
		ImageVersionID:  pgtype.Text{String: "test-image-version-1", Valid: true}, SignerUa: pgtype.Text{String: "test-agent", Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := txq.SetRecipientStatus(ctx, generated.SetRecipientStatusParams{
		ID: recipient.ID, DocumentID: doc.ID, Status: "signed", DeclinedReason: pgtype.Text{},
	}); err != nil {
		t.Fatal(err)
	}
	doc, err = txq.SetDocumentStatus(ctx, generated.SetDocumentStatusParams{ID: doc.ID, OrgID: orgID, Status: "in_progress"})
	if err != nil {
		t.Fatal(err)
	}
	pendingSigned, err := audit.New(q, pool).LogTx(ctx, tx, audit.Entry{
		OrgID: orgID, DocumentID: &doc.ID, RecipientID: &recipient.ID,
		Kind: audit.KindDocumentSigned, Payload: map[string]any{"fixture": "dsr-e2e"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pendingSigned)
	if completed {
		doc = completeDSRDocumentE2E(t, ctx, pool, q, doc)
	}
	return doc, recipient
}

func sendDSRDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
	recipient *generated.Recipient,
) *generated.Document {
	t.Helper()
	seedCompleteFrozenBrandingHandlerE2E(t, ctx, pool, doc.ID)
	sealingTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealingTx.Rollback(ctx) }()
	sealingQ := q.WithTx(sealingTx)
	if _, err := sealingQ.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
		ActorUserID: pgtype.UUID{Bytes: doc.SenderID, Valid: true},
		ActorEmail:  "dpo@dsr.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "dsr-fixture",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := sealingQ.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		t.Fatal(err)
	}
	if err := sealingTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture send retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture send retention complete: rows=%d err=%v", rows, err)
	}

	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	publishQ := q.WithTx(publishTx)
	sent, err := publishQ.CompleteDocumentSendSealing(ctx, generated.CompleteDocumentSendSealingParams{ID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.MarkRecipientSent(ctx, generated.MarkRecipientSentParams{ID: recipient.ID, DocumentID: doc.ID})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture recipient sent: rows=%d err=%v", rows, err)
	}
	canonicalEpoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, publishTx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentSent,
		Payload: map[string]any{
			article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1,
			article13.AuditRequiredNoticeSentAtKey: canonicalEpoch,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.DeleteSendSealingIntent(ctx, generated.DeleteSendSealingIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || rows != 1 {
		t.Fatalf("delete DSR fixture send intent: rows=%d err=%v", rows, err)
	}
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return sent
}

func seedCompleteFrozenBrandingHandlerE2E(t *testing.T, ctx context.Context, db generated.DBTX, documentID uuid.UUID) {
	t.Helper()
	_, err := db.Exec(ctx, `INSERT INTO document_branding_override (
		document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
		logo_url, logo_alt, font_heading, font_body, signature_color
	) VALUES ($1, '#0F172A', '#3B82F6', '#FFFFFF', '#0F172A', '#64748B',
	          '', '', 'Inter', 'Inter', '#0F172A')
	ON CONFLICT (document_id) DO UPDATE SET
		primary_hex=EXCLUDED.primary_hex, accent_hex=EXCLUDED.accent_hex,
		surface_hex=EXCLUDED.surface_hex, text_hex=EXCLUDED.text_hex,
		muted_hex=EXCLUDED.muted_hex, logo_url=EXCLUDED.logo_url,
		logo_alt=EXCLUDED.logo_alt, font_heading=EXCLUDED.font_heading,
		font_body=EXCLUDED.font_body, signature_color=EXCLUDED.signature_color`, documentID) //nolint:rawsql
	if err != nil {
		t.Fatalf("seed complete canonical frozen branding: %v", err)
	}
}

func completeDSRDocumentE2E(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	q *generated.Queries,
	doc *generated.Document,
) *generated.Document {
	t.Helper()
	claimed, err := q.BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
		RetentionYears: int32(article13.RetentionYearsV1), ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !claimed.CompletionEffectiveAtBound || !claimed.CompletionEffectiveAt.Valid || !claimed.FinalizationRetainUntil.Valid {
		t.Fatalf("DSR fixture finalization lacks durable commitments: %+v", claimed)
	}
	digest := make([]byte, 32)
	digest[0] = 3
	digestHex := hex.EncodeToString(digest)
	artifactDir := "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/"
	intent, err := q.CreateDocumentFinalizationIntent(ctx, generated.CreateDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Mode: "signature",
		CompletionEffectiveAt: claimed.CompletionEffectiveAt, RetainUntil: claimed.FinalizationRetainUntil,
		FinalPdfKey: artifactDir + "final-" + digestHex + ".pdf", FinalPdfSha256: digest,
		FinalPdfVersionID: pgtype.Text{String: "dsr-final-version-1", Valid: true},
		AuditCertKey:      artifactDir + "audit-" + digestHex + ".pdf", AuditCertSha256: digest,
		AuditCertVersionID: pgtype.Text{String: "dsr-cert-version-1", Valid: true},
		AuditPayloadKey:    artifactDir + "audit-payload-" + digestHex + ".txt", AuditPayloadSha256: digest,
		AuditPayloadVersionID: pgtype.Text{String: "dsr-payload-version-1", Valid: true},
		AuditSignatureKey:     artifactDir + "audit-signature-" + digestHex + ".txt", AuditSignatureSha256: digest,
		AuditSignatureVersionID: pgtype.Text{String: "dsr-audit-signature-version-1", Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := q.MarkDocumentFinalizationRetentionStarted(ctx, generated.MarkDocumentFinalizationRetentionStartedParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture finalization retention started: rows=%d err=%v", rows, err)
	}
	rows, err = q.MarkDocumentFinalizationRetentionComplete(ctx, generated.MarkDocumentFinalizationRetentionCompleteParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("mark DSR fixture finalization retention complete: rows=%d err=%v", rows, err)
	}

	publishTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publishTx.Rollback(ctx) }()
	publishQ := q.WithTx(publishTx)
	if _, err := publishQ.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: doc.OrgID}); err != nil {
		t.Fatal(err)
	}
	if _, err := publishQ.GetDocumentFinalizationIntentForUpdate(ctx, generated.GetDocumentFinalizationIntentForUpdateParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	}); err != nil {
		t.Fatal(err)
	}
	completed, err := publishQ.CompleteDocumentFinalization(ctx, generated.CompleteDocumentFinalizationParams{
		FinalPdfKey: pgtype.Text{String: intent.FinalPdfKey, Valid: true}, FinalPdfSha256: intent.FinalPdfSha256,
		FinalPdfVersionID: intent.FinalPdfVersionID,
		AuditCertKey:      pgtype.Text{String: intent.AuditCertKey, Valid: true}, AuditCertSha256: intent.AuditCertSha256,
		AuditCertVersionID: intent.AuditCertVersionID,
		AuditPayloadKey:    pgtype.Text{String: intent.AuditPayloadKey, Valid: true}, AuditPayloadSha256: intent.AuditPayloadSha256,
		AuditPayloadVersionID: intent.AuditPayloadVersionID,
		AuditSignatureKey:     pgtype.Text{String: intent.AuditSignatureKey, Valid: true}, AuditSignatureSha256: intent.AuditSignatureSha256,
		AuditSignatureVersionID: intent.AuditSignatureVersionID,
		ID:                      doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := audit.New(q, pool).LogTx(ctx, publishTx, audit.Entry{
		OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentCompleted,
		Payload: map[string]any{"fixture": "dsr-e2e"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err = publishQ.DeleteDocumentFinalizationIntent(ctx, generated.DeleteDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil || rows != 1 {
		t.Fatalf("delete DSR fixture finalization intent: rows=%d err=%v", rows, err)
	}
	if err := publishTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	audit.New(q, pool).Publish(pending)
	return completed
}

func transitionDSRE2E(server *Server, orgID, userID, requestID uuid.UUID, status string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), auth.UserIDKey, userID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, orgID)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	routeContext := chi.NewRouteContext()
	routeContext.URLParams.Add("id", requestID.String())
	ctx = context.WithValue(ctx, chi.RouteCtxKey, routeContext)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/dsr/"+requestID.String(), strings.NewReader(`{"status":"`+status+`"}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	payload, _ := json.Marshal(auth.SessionPayload{UserID: userID})
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: server.Cookies.Mint(payload, time.Hour)})
	recorder := httptest.NewRecorder()
	server.handleTransitionDSR(recorder, req)
	return recorder
}

func TestDSRErasureSoftDeletedDraftRequiresArchiveReviewAndCanCompleteE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID := setupDSRE2E(t)
	var err error
	server.Cookies, err = auth.NewSignedCookie(strings.Repeat("4b", 32))
	if err != nil {
		t.Fatal(err)
	}
	server.PublicURL = "https://hash.example.test"
	server.Collab = collab.NewHub(q)
	defer server.Collab.Shutdown(ctx)
	payload, _ := json.Marshal(auth.SessionPayload{UserID: userID})
	cookie := server.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: orgID, SenderID: userID, Name: "soft-deleted privacy grace draft",
		BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: "original@example.test", Name: "Original Name", OrderIndex: 0,
		MagicTokenHash: []byte(uuid.NewString()), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = q.DeleteDraftDocument(ctx, generated.DeleteDraftDocumentParams{ID: doc.ID, OrgID: orgID}); err != nil {
		t.Fatal(err)
	}
	deleted, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || !deleted.DeletedAt.Valid {
		t.Fatal("fixture was not soft deleted", err)
	}
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
		SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	var archiveID uuid.UUID
	archivedReplay := []byte("opaque legacy replay: Original Name original@example.test")
	if err = pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives(document_id,observed_canonical_generation,origin,ydoc_state,recovered_by)
SELECT document_id,generation,'persisted',$2,$3 FROM collab_document_generations WHERE document_id=$1 RETURNING id`, doc.ID, archivedReplay, userID).Scan(&archiveID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	routes := server.Routes()
	submit := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, server.PublicURL+"/api/v1/"+path, strings.NewReader(body))
		req.Header.Set("Origin", server.PublicURL)
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		res := httptest.NewRecorder()
		routes.ServeHTTP(res, req)
		return res
	}
	transition := func(status string) *httptest.ResponseRecorder {
		return submit(http.MethodPatch, "dsr/"+dsr.ID.String(), `{"status":"`+status+`","resolution_note":"fixture privacy review"}`)
	}
	if res := transition("fulfilled"); res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "separate privacy review") {
		t.Fatalf("soft-deleted archive erasure status=%d body=%s", res.Code, res.Body.String())
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: orgID})
	if err != nil || freshRecipient.Email != recipient.Email || freshRecipient.Name != recipient.Name {
		t.Fatal("blocked soft-deleted erasure changed recipient identifiers", err)
	}
	freshRequest, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil || freshRequest.Status != "open" || freshRequest.SubjectEmail != recipient.Email {
		t.Fatal("blocked soft-deleted erasure changed the request", err)
	}
	// Complete archive handling as a separate owner review. Temporarily close
	// the request, remove the reviewed operational replay with acknowledgement,
	// and reopen it before targeted erasure. This does not relax evidence checks.
	if res := transition("denied"); res.Code != http.StatusOK {
		t.Fatalf("archive review transition status=%d body=%s", res.Code, res.Body.String())
	}
	archivePath := "documents/" + doc.ID.String() + "/collab/recovery/archives/" + archiveID.String()
	if res := submit(http.MethodDelete, archivePath, `{"acknowledged":true}`); res.Code != http.StatusNoContent {
		t.Fatalf("reviewed soft-deleted archive removal status=%d body=%s", res.Code, res.Body.String())
	}
	if res := transition("in_progress"); res.Code != http.StatusOK {
		t.Fatalf("reopen soft-deleted erasure status=%d body=%s", res.Code, res.Body.String())
	}
	if res := transition("fulfilled"); res.Code != http.StatusOK {
		t.Fatalf("reviewed soft-deleted erasure status=%d body=%s", res.Code, res.Body.String())
	}
	freshRecipient, err = q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: orgID})
	if err != nil || freshRecipient.Email != AnonymizedEmail(dsr.ID) || freshRecipient.Name != AnonymizationMarker {
		t.Fatalf("targeted erasure did not anonymize recipient=%+v err=%v", freshRecipient, err)
	}
	freshRequest, err = q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil || freshRequest.Status != "fulfilled" || freshRequest.SubjectEmail != AnonymizedEmail(dsr.ID) || freshRequest.SubjectName != AnonymizationMarker {
		t.Fatalf("targeted erasure did not fulfill/redact request=%+v err=%v", freshRequest, err)
	}
	retained, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || !retained.DeletedAt.Time.Equal(deleted.DeletedAt.Time) || retained.Status != "draft" {
		t.Fatal("targeted erasure changed the retained draft/grace timestamp", err)
	}
	var archives, terminalEvents int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&archives); err != nil || archives != 0 {
		t.Fatalf("reviewed archives=%d err=%v", archives, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('data_subject.anonymized','data_subject.fulfilled')`, orgID).Scan(&terminalEvents); err != nil || terminalEvents != 2 {
		t.Fatalf("targeted erasure audit count=%d err=%v", terminalEvents, err)
	}
}

// Keep the existing90-second fixture budget while reserving cleanup before the
// actual enclosing test-process deadline. Cancellation is registered first, so
// pool/backend cleanup runs before this fixture parent is explicitly cancelled.
func migrationFixtureContext242(t *testing.T) context.Context {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Add(-5*time.Second).Before(deadline) {
		deadline = testDeadline.Add(-5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	t.Cleanup(cancel)
	return ctx
}

// This fixed test-fixture root restores the declared240s browser contract. It
// never extends an existing context, test-process deadline or cleanup reserve.
func browserFixtureContext368(t *testing.T) context.Context {
	t.Helper()
	deadline := time.Now().Add(4 * time.Minute)
	if testDeadline, ok := t.Deadline(); ok && testDeadline.Add(-5*time.Second).Before(deadline) {
		deadline = testDeadline.Add(-5 * time.Second)
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	// Register before DB/pool creation, so actual child/SQL cleanup precedes
	// cancellation of the browser root just as in the original fixture owner.
	t.Cleanup(cancel)
	return ctx
}

func browserMigrationPhaseContext368(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 90*time.Second)
}

// Completed DSR evidence comes from the genuine single-party ordinary creator,
// Send, notice-bound Sign, original-output staging and versioned provider path.
// The protocol peers are synthetic; no current intent/preparation is fabricated.
// Pure DSR/component fixtures keep setupDSRE2E and its original pool unchanged.
func setupCompletedDSREvidenceE2E(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID, *generated.Document, *generated.Recipient) {
	t.Helper()
	n := nativeNegotiationStart262(t, false, false)
	f := n.q.f
	rc := n.q.lookupV1(t, n.token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(n.token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: "Original Legal Name", Font: "Caveat", Notice: proof, IP: "127.0.0.1", UserAgent: "test-agent"})
	closeErr := rc.CloseReadV1()
	if err != nil || closeErr != nil || result == nil || !result.Completed {
		t.Fatal("genuine completed DSR signature/evidence", err, closeErr)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: n.document.ID, OrgID: f.org})
	if err != nil || doc.Status != "completed" || !doc.CompletedAt.Valid {
		t.Fatal("genuine completed DSR document", err)
	}
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: n.recipient, OrgID: f.org})
	if err != nil || recipient.Status != "signed" {
		t.Fatal("genuine DSR signed subject", err)
	}
	for _, artifact := range []struct {
		key     pgtype.Text
		sum     []byte
		version pgtype.Text
	}{
		{doc.FinalPdfKey, doc.FinalPdfSha, doc.FinalPdfVersionID},
		{doc.AuditCertKey, doc.AuditCertSha256, doc.AuditCertVersionID},
		{doc.AuditPayloadKey, doc.AuditPayloadSha256, doc.AuditPayloadVersionID},
		{doc.AuditSignatureKey, doc.AuditSignatureSha256, doc.AuditSignatureVersionID},
	} {
		if !artifact.key.Valid || !artifact.version.Valid || artifact.version.String == "" || len(artifact.sum) != 32 {
			t.Fatal("completed DSR evidence lacks exact four-artifact pins")
		}
		if body, readErr := readDocumentArtifact(f.ctx, f.s.Storage, doc, artifact.key.String, artifact.sum, artifact.version); readErr != nil || len(body) == 0 {
			t.Fatal("completed DSR artifact bytes do not match actual retained output", readErr)
		}
	}
	n.q.assertObserversOnlyV1(t)
	return f.ctx, f.pool, f.q, f.s, f.org, f.user.ID, doc, recipient
}
