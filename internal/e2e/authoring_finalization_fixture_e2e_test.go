//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This SQL authoring fixture measures synthetic bodies and follows the actual
// immutable preparation/output/report protocol. It proves database lifecycle
// guards, not PDF rendering, provider retention, report content or delivery.
func stageAuthoringFinalizationE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, doc *generated.Document) *generated.DocumentFinalizationIntent {
	t.Helper()
	tx, err := pool.Begin(ctx)
	must(t, err, "begin measured authoring finalization fixture")
	defer func() { _ = tx.Rollback(ctx) }()
	qt := q.WithTx(tx)
	type output struct {
		kind, media, prefix, suffix, version, key string
		body                                      []byte
		sum                                       [sha256.Size]byte
	}
	outputs := []output{
		{kind: "final_pdf", media: "application/pdf", prefix: "final-", suffix: ".pdf", body: []byte("%PDF synthetic authoring final")},
		{kind: "certificate_pdf", media: "application/pdf", prefix: "audit-", suffix: ".pdf", body: []byte("%PDF synthetic authoring certificate")},
		{kind: "certificate_payload", media: "text/html; charset=utf-8", prefix: "audit-payload-", suffix: ".txt", body: []byte("<html>synthetic authoring certificate payload</html>")},
		{kind: "certificate_signature", media: "text/plain; charset=utf-8", prefix: "audit-signature-", suffix: ".txt", body: []byte("synthetic authoring detached signature")},
	}
	for i := range outputs {
		o := &outputs[i]
		o.sum = sha256.Sum256(o.body)
		o.version = "synthetic-authoring-" + o.kind
		o.key = "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/" + o.prefix + hex.EncodeToString(o.sum[:]) + o.suffix
	}
	rows, err := qt.CaptureOrdinaryFinalizationPreparationV1(ctx, generated.CaptureOrdinaryFinalizationPreparationV1Params{
		Mode: "signature", FinalPdfSha256: outputs[0].sum[:], DocumentID: doc.ID, OrgID: doc.OrgID, CompletionEffectiveAt: doc.CompletionEffectiveAt, Cutoff: doc.UpdatedAt,
	})
	authoringFixtureRows(t, "capture original final PDF commitment", rows, 1, err)
	report := sha256.Sum256([]byte("synthetic authoring participant report"))
	rows, err = qt.FreezeOrdinaryFinalizationCertificateInputV1(ctx, generated.FreezeOrdinaryFinalizationCertificateInputV1Params{
		DocumentID: doc.ID, OrgID: doc.OrgID, RenderHtml: outputs[2].body, ReportCutoff: doc.UpdatedAt, HistoryRows: 0, ReportSha256: report[:], ReportSchema: doc.ParticipantReportSchema,
	})
	authoringFixtureRows(t, "freeze original synthetic certificate input", rows, 1, err)
	for _, o := range outputs {
		rows, err = qt.CaptureOrdinaryFinalizationOutputV1(ctx, generated.CaptureOrdinaryFinalizationOutputV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, Kind: o.kind, StorageKey: o.key, Payload: o.body, ContentType: o.media})
		authoringFixtureRows(t, "capture measured synthetic "+o.kind, rows, 1, err)
		rows, err = qt.PinOrdinaryFinalizationOutputVersionV1(ctx, generated.PinOrdinaryFinalizationOutputVersionV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, Kind: o.kind, VersionID: o.version, ExpectedSha256: o.sum[:]})
		authoringFixtureRows(t, "pin synthetic "+o.kind, rows, 1, err)
		rows, err = qt.VerifyOrdinaryFinalizationOutputVersionV1(ctx, generated.VerifyOrdinaryFinalizationOutputVersionV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, Kind: o.kind, VersionID: o.version, ExpectedSha256: o.sum[:]})
		authoringFixtureRows(t, "record synthetic version verification "+o.kind, rows, 1, err)
	}
	pin := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	intent, err := qt.CreateDocumentFinalizationIntent(ctx, generated.CreateDocumentFinalizationIntentParams{
		DocumentID: doc.ID, OrgID: doc.OrgID, Mode: "signature", CompletionEffectiveAt: doc.CompletionEffectiveAt, RetainUntil: doc.FinalizationRetainUntil,
		FinalPdfKey: outputs[0].key, FinalPdfSha256: outputs[0].sum[:], FinalPdfVersionID: pin(outputs[0].version),
		AuditCertKey: outputs[1].key, AuditCertSha256: outputs[1].sum[:], AuditCertVersionID: pin(outputs[1].version),
		AuditPayloadKey: outputs[2].key, AuditPayloadSha256: outputs[2].sum[:], AuditPayloadVersionID: pin(outputs[2].version),
		AuditSignatureKey: outputs[3].key, AuditSignatureSha256: outputs[3].sum[:], AuditSignatureVersionID: pin(outputs[3].version),
	})
	must(t, err, "bind intent to measured synthetic originals")
	rows, err = qt.InsertParticipantReportReceiptV1(ctx, generated.InsertParticipantReportReceiptV1Params{
		DocumentID: doc.ID, OrgID: doc.OrgID, CompletionEffectiveAt: doc.CompletionEffectiveAt, ReportSchema: doc.ParticipantReportSchema,
		Cutoff: doc.UpdatedAt, HistoryRows: 0, ReportSha256: report[:], FinalPdfSha256: outputs[0].sum[:], AuditCertSha256: outputs[1].sum[:], AuditPayloadSha256: outputs[2].sum[:], AuditSignatureSha256: outputs[3].sum[:],
	})
	authoringFixtureRows(t, "bind exact synthetic participant receipt", rows, 1, err)
	rows, err = qt.MarkOrdinaryFinalizationPreparationStagedV1(ctx, generated.MarkOrdinaryFinalizationPreparationStagedV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	authoringFixtureRows(t, "stage four measured original outputs", rows, 1, err)
	must(t, tx.Commit(ctx), "commit original preparation and report through deferred guards")
	return intent
}

func finishAuthoringFinalizationE2E(t *testing.T, ctx context.Context, q *generated.Queries, doc *generated.Document) {
	t.Helper()
	owner, err := q.GetUser(ctx, doc.SenderID)
	must(t, err, "read authoring completion sender")
	type audience struct {
		kind, email string
		recipient   uuid.UUID
	}
	audiences := []audience{{kind: "sender", email: owner.Email}}
	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	must(t, err, "read authoring completion recipients")
	for _, r := range recipients {
		if r.Role != "cc" && r.Status == "signed" {
			audiences = append(audiences, audience{kind: "recipient", email: r.Email, recipient: r.ID})
		}
	}
	for _, a := range audiences {
		mail, err := q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{ToEmail: a.email, Subject: "Synthetic authoring report", HtmlBody: "<p>Synthetic report fixture</p>", TextBody: "Synthetic report fixture", HeadersJson: []byte(`{}`)})
		must(t, err, "queue synthetic completion report reference")
		rows, err := q.InsertParticipantReportDeliveryV1(ctx, generated.InsertParticipantReportDeliveryV1Params{Audience: a.kind, RecipientID: a.recipient, EmailDeliveryID: mail.ID, DocumentID: doc.ID, OrgID: doc.OrgID})
		authoringFixtureRows(t, "bind actual synthetic outbox message", rows, 1, err)
	}
	rows, err := q.MarkOrdinaryFinalizationPreparationPublishedV1(ctx, generated.MarkOrdinaryFinalizationPreparationPublishedV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	authoringFixtureRows(t, "publish original preparation", rows, 1, err)
	rows, err = q.RetirePublishedOrdinaryFinalizationRenderHTMLV1(ctx, generated.RetirePublishedOrdinaryFinalizationRenderHTMLV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	authoringFixtureRows(t, "retire published certificate input", rows, 1, err)
	rows, err = q.RetirePublishedOrdinaryFinalizationBodiesV1(ctx, generated.RetirePublishedOrdinaryFinalizationBodiesV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	authoringFixtureRows(t, "retire four published original bodies", rows, 4, err)
}

func authoringFixtureRows(t *testing.T, phase string, rows, want int64, err error) {
	t.Helper()
	if err != nil || rows != want {
		t.Fatalf("%s: rows=%d want=%d error=%v", phase, rows, want, err)
	}
}

// A nullable-pin legacy intent must actually predate the report/original
// cutovers. Current callers cannot manufacture their migration-time exemptions.
// This separate metadata fixture preserves that provenance and then exercises
// the current one-way pin query without rewriting any historical artifact.
func historicalAuthoringIntentE2E(t *testing.T) (*generated.Queries, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	pool, cleanup := scratchDatabase(t, ctx, os.Getenv("HASH_E2E_DB_URL"))
	t.Cleanup(cleanup)
	migration := stdlibConn(t, pool)
	t.Cleanup(func() { must(t, migration.Close(), "close historical authoring migrator") })
	must(t, mdb.RunMigrationsUpToContext(ctx, migration, 107), "migrate isolated historical intent fixture before report/original cutovers")
	id := seedDocument(t, ctx, pool, "Synthetic historical authoring intent")
	org := documentOrgID(t, ctx, pool, id)
	seedCompleteFrozenBrandingFixture(t, ctx, pool, id)
	beginArticle13SendSealing(t, ctx, pool, id, false)
	completeArticle13SendSealing(t, ctx, pool, id, false)
	_, err := pool.Exec(ctx, "UPDATE documents SET status='in_progress' WHERE id=$1 AND org_id=$2 AND status='sent'", id, org)
	must(t, err, "advance historical intent metadata fixture")
	var completion, retain pgtype.Timestamptz
	err = pool.QueryRow(ctx, `UPDATE documents SET status='finalizing',
 completion_effective_at=statement_timestamp(),finalization_retain_until=hash_evidence_retain_until(statement_timestamp(),7)
 WHERE id=$1 AND org_id=$2 AND status='in_progress'
 RETURNING completion_effective_at,finalization_retain_until`, id, org).Scan(&completion, &retain)
	must(t, err, "freeze actual pre-cutover historical intent clock")
	digest := sha256.Sum256([]byte("synthetic historical authoring artifact"))
	base := "org/" + org.String() + "/documents/" + id.String() + "/"
	hexDigest := hex.EncodeToString(digest[:])
	_, err = pool.Exec(ctx, `INSERT INTO document_finalization_intents (
 document_id,org_id,mode,completion_effective_at,retain_until,
 final_pdf_key,final_pdf_sha256,audit_cert_key,audit_cert_sha256,
 audit_payload_key,audit_payload_sha256,audit_signature_key,audit_signature_sha256,evidence_version_pins_required
 ) VALUES($1,$2,'signature',$3,$4,$5,$6,$7,$6,$8,$6,$9,$6,false)`, id, org, completion, retain,
		base+"final-"+hexDigest+".pdf", digest[:], base+"audit-"+hexDigest+".pdf", base+"audit-payload-"+hexDigest+".txt", base+"audit-signature-"+hexDigest+".txt")
	must(t, err, "retain genuine pre108/109 nullable-pin intent metadata")
	must(t, mdb.RunMigrationsContext(ctx, migration), "upgrade genuine retained intent through current embedded cutovers")
	must(t, migration.Close(), "close historical migrator before current pin query")
	return generated.New(pool), id, org
}
