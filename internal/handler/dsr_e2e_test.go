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
	"net/url"
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
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/config"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
)

func TestDSRErasureRollsBackEverySideEffectWhenSignatureScrubFailsE2E(t *testing.T) {
	t.Run("current-completed-evidence-requires-separate-review", func(t *testing.T) {
		ctx, pool, q, server, orgID, userID, doc, recipient := setupCompletedDSREvidenceE2E(t)
		dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
			OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
			SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender",
			PayloadJson: json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		// Modern completion retains mandatory participant/preparation evidence.
		// Its real API must refuse automated recipient-only fulfillment/export,
		// even though the original four signed artifacts are all verified above.
		before := snapshotDSRScopeE2E(t, ctx, pool, orgID)
		recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
		if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "separate privacy and retention review") {
			t.Fatalf("retained completion fulfillment=%d %s", recorder.Code, recorder.Body.String())
		}
		cookie := dsrSessionCookieE2E(t, server, userID, 0, time.Hour)
		export := submitSessionOperationContextE2E(ctx, server, http.MethodGet, "/api/v1/data-subject/export?email="+url.QueryEscape(recipient.Email), "", cookie)
		if export.Code != http.StatusConflict || !strings.Contains(export.Body.String(), "separate privacy export review") {
			t.Fatalf("retained completion export=%d %s", export.Code, export.Body.String())
		}
		if snapshotDSRScopeE2E(t, ctx, pool, orgID) != before {
			t.Fatal("retained evidence review refusal changed request, subject, evidence or audit")
		}
	})
	t.Run("synthetic-legacy-shaped-component-uses-real-handler-rollback", func(t *testing.T) {
		ctx, pool, q, server, orgID, userID, doc, recipient := setupSyntheticLegacyDSRComponentE2E(t)
		dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
			OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
			SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatal(err)
		}
		before := snapshotDSRScopeE2E(t, ctx, pool, orgID)
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

		// Invoke the authoritative application transaction. These input rows are
		// explicitly synthetic legacy-shaped components, not a verified signature
		// journey or current/legacy legal artifact acceptance claim.
		recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
		if recorder.Code != http.StatusInternalServerError || !strings.Contains(recorder.Body.String(), "anonymize signatures") {
			t.Fatalf("actual component handler scrub failure=%d %s", recorder.Code, recorder.Body.String())
		}
		if snapshotDSRScopeE2E(t, ctx, pool, orgID) != before {
			t.Fatal("actual application signature-scrub fault escaped complete rollback")
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
	})
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

// Explicit synthetic legacy-shaped COMPONENT rows, seeded at the historical
// schema boundary and migrated normally. Placeholders are only inputs for the
// DSR handler's redaction transaction: no storage body, valid certificate,
// cryptographic signature or genuine historical signing journey is asserted.
func setupSyntheticLegacyDSRComponentE2E(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID, *generated.Document, *generated.Recipient) {
	t.Helper()
	isolateEmptyHTMLTemplateDatabaseE2E(t)
	birth := migrationFixtureContext242(t)
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*cfg)
	t.Cleanup(func() {
		if err := migrationDB.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := mdb.RunMigrationsUpToContext(birth, migrationDB, 64); err != nil {
		t.Fatal("component historical prefix migration", err)
	}
	org, user, docID, recipientID, fieldID := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	sent := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	completed := sent.Add(time.Minute)
	digest := make([]byte, 32)
	digest[0] = 7
	prefix := "org/" + org.String() + "/documents/" + docID.String() + "/"
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO orgs(id,name,plan) VALUES($1,'Synthetic DSR component organization','pro')`, []any{org}},
		{`INSERT INTO users(id,org_id,email,name,role) VALUES($1,$2,$3,'Synthetic DSR component owner','owner')`, []any{user, org, uuid.NewString() + "@dsr-component.test"}},
		{`INSERT INTO documents(id,org_id,sender_id,name,status,source_kind,blocks_json,variables_json,sent_at,completed_at,completion_effective_at,finalization_retain_until,
 final_pdf_key,final_pdf_sha,final_pdf_version_id,audit_cert_key,audit_cert_sha256,audit_cert_version_id,audit_payload_key,audit_payload_sha256,audit_payload_version_id,audit_signature_key,audit_signature_sha256,audit_signature_version_id)
 VALUES($1,$2,$3,'Synthetic legacy-shaped DSR component','completed','blocks','[]','{}',$4,$5,$5,hash_evidence_retain_until($5,7),$6,$7,'component-only-final-version',$8,$7,'component-only-cert-version',$9,$7,'component-only-payload-version',$10,$7,'component-only-signature-version')`, []any{docID, org, user, sent, completed, prefix + "component-final.pdf", digest, prefix + "component-cert.pdf", prefix + "component-payload.txt", prefix + "component-signature.txt"}},
		{`INSERT INTO document_branding_override(document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color)
 VALUES($1,'#111111','#222222','#ffffff','#111111','#666666','','','Inter','Inter','#111111')`, []any{docID}},
		{`INSERT INTO recipients(id,document_id,email,name,role,status,magic_token_hash,sent_at,signed_at) VALUES($1,$2,'component-subject@dsr.test','Original Name','signer','signed',$3,$4,$5)`, []any{recipientID, docID, make([]byte, 32), sent, completed}},
		{`INSERT INTO document_fields(id,document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json) VALUES($1,$2,$3,'signature',1,0,0,10,5,true,'[]')`, []any{fieldID, docID, recipientID}},
		{`INSERT INTO signatures(document_id,recipient_id,field_id,font,typed_name,image_storage_key,image_sha256,image_version_id,signer_ip,signer_ua,signed_at)
 VALUES($1,$2,$3,'Caveat','Original Legal Name',$4,$5,'component-only-image-version','127.0.0.1','test-agent',$6)`, []any{docID, recipientID, fieldID, prefix + "component-signature.png", digest, completed}},
	}
	for _, statement := range statements {
		if _, err := migrationDB.ExecContext(birth, statement.sql, statement.args...); err != nil {
			t.Fatal("seed explicit synthetic DSR component", err)
		}
	} //nolint:rawsql -- historical scalar component inputs, never serving proofs/guard changes
	if err := mdb.RunMigrationsContext(birth, migrationDB); err != nil {
		t.Fatal("forward migrate DSR component to exact current source", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatal("close component migration connection", err)
	}
	ctx, pool, q, server, _, _ := setupDSRE2E(t)
	assertCurrentHandlerMigrationHistoryE2E(t, ctx, pool)
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: org})
	if err != nil || doc.Status != "completed" || !documentAllowsDestructiveErasure(doc, true) {
		t.Fatal("migrated synthetic component shape differs", err)
	}
	recipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipientID, OrgID: org})
	if err != nil || recipient.Status != "signed" {
		t.Fatal("migrated synthetic component recipient differs", err)
	}
	if present, err := q.HasHTMLAuthoringDataForDSR(ctx, org); err != nil || present {
		t.Fatal("synthetic component unexpectedly has actual retained report/history inventory", err)
	}
	return ctx, pool, q, server, org, user, doc, recipient
}

// This shared setup selects a fresh actual tenant on the same isolated native
// runtime without deleting the unrelated template tenant's retained history.
func newPlainDSRNativeFixtureE2E(t *testing.T) (*ownedPublicReadFixtureV1, uuid.UUID) {
	t.Helper()
	native := newOwnedAutomationAuthorizationFixtureV1(t)
	f := native.f
	originalOrg := f.org
	// Catalog preparation starts the process observer while the original
	// template tenant is still selected. The new DSR tenant has not performed
	// any native operation yet and must not claim that tenant's observer debt.
	ownedCreationPrepareProPlanV1(t, native)
	// The shared provider fixture has an unrelated HTML template. DSR's
	// tenant-wide separate-review guard must remain intact: this ordinary
	// blocks journey belongs to a fresh tenant in the SAME owned database and
	// runtime. Its records retire with that existing exact database owner.
	org, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Plain DSR evidence tenant", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@dsr-owner.test", Name: "DSR owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	// This fixture owns the server exclusively; keep its mutexes and runtime
	// identity intact while selecting the new plain-evidence tenant.
	f.org, f.user = org.ID, user
	f.s.Billing = billing.NewOperator(f.q, []config.OperatorEntitlement{{OrgID: f.org, PlanSlug: "pro", ReviewRef: "synthetic plain DSR evidence fixture"}})
	native.f = f
	native.cookie = dsrSessionCookieE2E(t, f.s, user.ID, user.SessionGeneration, time.Hour)
	return native, originalOrg
}

// Eligible unsigned draft coverage keeps the original current API privacy,
// authorization, archive and audit checks reachable without retained completion
// evidence. Both document and recipient are actual public native producers.
func setupEligibleDSRDraftE2E(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID, *generated.Document, *generated.Recipient) {
	t.Helper()
	native, originalOrg := newPlainDSRNativeFixtureE2E(t)
	f := native.f
	doc, err := nativeRevisionCreateE2E(t, f, "Eligible unsigned DSR draft", json.RawMessage(`{"version":1,"blocks":[]}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/recipients", `{"name":"Original subject","email":"subject@plain-dsr.test","role":"signer","locale":"en"}`, native.cookie)
	var created recipientResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		t.Fatal("actual eligible DSR recipient", w.Code, w.Body.String())
	}
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var signatures int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*) FROM signatures WHERE document_id=$1", doc.ID).Scan(&signatures); err != nil || signatures != 0 {
		t.Fatal("unsigned DSR fixture captured signature evidence", signatures, err)
	}
	if present, err := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org); err != nil || present || !documentAllowsDestructiveErasure(doc, false) {
		t.Fatal("actual unsigned DSR draft is not eligible", err)
	}
	assertPlainDSRObserverScopesE2E(t, native, originalOrg, f.org)
	return f.ctx, f.pool, f.q, f.s, f.org, f.user.ID, doc, recipient
}

// Completed DSR evidence comes from the genuine single-party ordinary creator,
// Send, notice-bound Sign, original-output staging and versioned provider path.
// The protocol peers are synthetic; no current intent/preparation is fabricated.
// Pure DSR/component fixtures keep setupDSRE2E and its original pool unchanged.
func setupCompletedDSREvidenceE2E(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID, *generated.Document, *generated.Recipient) {
	t.Helper()
	native, originalOrg := newPlainDSRNativeFixtureE2E(t)
	f := native.f
	draft, err := nativeRevisionCreateE2E(t, f, "Plain completed DSR evidence", json.RawMessage(`{"version":1,"blocks":[{"id":"terms","type":"paragraph","text":"Original agreed terms"},{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`), json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/documents/" + draft.ID.String()
	w := submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/recipients", `{"name":"Original subject","email":"subject@plain-dsr.test","role":"signer","locale":"en"}`, native.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("genuine plain DSR recipient=%d %s", w.Code, w.Body.String())
	}
	w = submitSessionOperationContextE2E(f.ctx, f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, native.cookie)
	var sent sendDocumentResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
		t.Fatalf("genuine plain DSR Send=%d %s", w.Code, w.Body.String())
	}
	link, err := url.Parse(sent.Links[0].URL)
	if err != nil || !strings.HasPrefix(link.Path, "/sign/") {
		t.Fatal("genuine plain DSR invitation missing", err)
	}
	token := strings.TrimPrefix(link.Path, "/sign/")
	rc := native.lookupV1(t, token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
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
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: draft.ID, OrgID: f.org})
	if err != nil || doc.Status != "completed" || !doc.CompletedAt.Valid || len(doc.HtmlSourceJson) != 0 {
		t.Fatal("genuine completed DSR document", err)
	}
	recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: sent.Links[0].RecipientID, OrgID: f.org})
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
	// Mandatory completion preparations/reports retain personal evidence even
	// for a blocks-only source. This real current API requires separate review.
	if present, checkErr := f.q.HasHTMLAuthoringDataForDSR(f.ctx, f.org); checkErr != nil || !present {
		t.Fatal("completed DSR evidence lost its mandatory retention-review fence", checkErr)
	}
	var preparations, reports int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*) FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1 AND org_id=$2 AND retain_until>=clock_timestamp()),
 (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2)`, doc.ID, f.org).Scan(&preparations, &reports); err != nil || preparations != 1 || reports != 1 {
		t.Fatal("completed DSR evidence lacks actual retained preparation/report", preparations, reports, err)
	} //nolint:rawsql -- exact native completion provenance scalars only
	assertPlainDSRObserverScopesE2E(t, native, originalOrg, f.org)
	return f.ctx, f.pool, f.q, f.s, f.org, f.user.ID, doc, recipient
}

// This one two-tenant fixture genuinely starts three observers: the retained
// original HTML-template tenant, the plain DSR tenant and process catalog.
// Compare every pending class and all three explicit coordinator scopes; no
// returned consumer, physical debt or additional grant is treated as retired.
func assertPlainDSRObserverScopesE2E(t *testing.T, native *ownedPublicReadFixtureV1, originalOrg, dsrOrg uuid.UUID) {
	t.Helper()
	if originalOrg == uuid.Nil || dsrOrg == uuid.Nil || originalOrg == dsrOrg || native.f.org != dsrOrg {
		t.Fatal("completed DSR observer recipe requires its two actual distinct tenants")
	}
	native.reconcileV1(t)
	pending := native.runtime.SessionsV1().PendingV1()
	if pending != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 3}) {
		t.Fatal("completed DSR work remains or exact three-observer recipe differs", pending)
	}
	for _, org := range []uuid.UUID{originalOrg, dsrOrg, uuid.Nil} {
		want := workguard.SnapshotV1{Global: workguard.VectorV1{SQLSessions: 3}, GlobalGrants: 3, ActiveOrganisations: 2}
		if org != uuid.Nil {
			want.Organisation, want.OrganisationGrants = workguard.VectorV1{SQLSessions: 1}, 1
		}
		actual, err := native.runtime.SnapshotV1(org)
		if err != nil || actual != want {
			t.Fatal("completed DSR observer scope differs from actual producer recipe", actual, err)
		}
	}
}

// A read-only complete synthetic scope snapshot. Comparing its value never
// authorizes fulfillment or redacts/retires any retained evidence.
func snapshotDSRScopeE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, org uuid.UUID) string {
	t.Helper()
	var state string
	if err := pool.QueryRow(ctx, `WITH owned AS(SELECT id FROM documents WHERE org_id=$1)
 SELECT jsonb_build_object(
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
 'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN(SELECT id FROM owned)),
 'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN(SELECT id FROM owned)),
 'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1),
 'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE org_id=$1),
 'preparations',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY document_id),'[]'::jsonb) FROM document_ordinary_finalization_preparations_v1 p WHERE org_id=$1),
 'outputs',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY document_id,kind),'[]'::jsonb) FROM document_ordinary_finalization_outputs_v1 o WHERE org_id=$1),
 'reports',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id,completion_effective_at),'[]'::jsonb) FROM document_participant_reports_v1 r WHERE org_id=$1),
 'deliveries',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY document_id,audience,recipient_id),'[]'::jsonb) FROM document_participant_report_deliveries_v1 d WHERE org_id=$1),
 'archives',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM collab_recovery_archives a WHERE document_id IN(SELECT id FROM owned)),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM email_deliveries e WHERE to_email IN(SELECT email FROM recipients WHERE document_id IN(SELECT id FROM owned))))::text`, org).Scan(&state); err != nil {
		t.Fatal("read exact DSR scope", err)
	} //nolint:rawsql -- read-only exact isolated synthetic tenant
	return state
}
