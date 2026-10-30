//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are actual PostgreSQL source/history tests. Their PDF digest/version
// tuples are synthetic: no renderer, storage provider or signing acceptance is
// asserted. Approval is established directly through its owner-scoped query so
// this foundation test does not repeat the separately tested preview protocol.
func htmlMaterializationFixtureE2E(t *testing.T) (lifecycleAuthorizationFixture, *generated.Document) {
	t.Helper()
	return htmlMaterializationFixtureDatabaseE2E(t, isolateHTMLTemplateDatabaseE2E(t))
}

func htmlMaterializationFixtureDatabaseE2E(t *testing.T, database string) (lifecycleAuthorizationFixture, *generated.Document) {
	t.Helper()
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	approved, err := f.q.ApproveHTMLTemplateRevision(f.ctx, generated.ApproveHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, ExpectedVersion: template.Version, ExpectedContentSha256: template.HtmlContentSha256, ApprovedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic unchanged PDF bytes for materialization identity regression"))
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, TemplateID: pgtype.UUID{Bytes: template.ID, Valid: true}, SenderID: f.user.ID, Name: "Same-document materialization fixture", PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: digest[:], PdfStorageVersionID: pgtype.Text{String: "synthetic-old-version", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	doc, err = f.q.FreezeDocumentVariables(f.ctx, generated.FreezeDocumentVariablesParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, VariablesJson: template.VariablesJson})
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]string
	if err = json.Unmarshal(template.VariablesJson, &values); err != nil {
		t.Fatal(err)
	}
	raw, err := htmlsource.New(htmlsource.Input{TemplateID: template.ID, TemplateVersion: template.Version, TemplateContentSHA256: hex.EncodeToString(template.HtmlContentSha256), MasterJSON: template.HtmlMasterJson, DefaultVarsJSON: template.VariablesJson, Values: values, Sections: map[string]string{}, TemplateApprovedBy: f.user.ID, TemplateApprovedAt: approved.ApprovedAt.Time}, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, HtmlSourceJson: raw})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := f.q.WithTx(tx)
	doc, err = q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err = htmlmaterialization.RegisterOrigin(f.ctx, q, doc, 1, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	return f, doc
}

func htmlMaterializationCandidateE2E(t *testing.T, doc *generated.Document, value string) (*generated.Document, json.RawMessage) {
	t.Helper()
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	in.Values["customer"] = value
	candidate := *doc
	candidate.PdfStorageKey = pgtype.Text{String: "org/" + doc.OrgID.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}
	candidate.PdfStorageVersionID = pgtype.Text{String: "synthetic-new-" + uuid.NewString(), Valid: true}
	candidate.VariablesJson, err = json.Marshal(in.Values)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	return &candidate, raw
}

func htmlMaterializationNumericE2E(t *testing.T, value string) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(value); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHTMLMaterializationAppendOnlyCurrentPinsAndHistoryE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureE2E(t)
	reviewed, err := f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, ExpectedPdfSha256: doc.PdfSha256, ReviewedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "customer", Name: "Synthetic customer", Email: "materialization@synthetic.test", MagicTokenHash: bytes.Repeat([]byte{1}, 32), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	field, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Type: "signature", Page: 1, XPct: htmlMaterializationNumericE2E(t, "10"), YPct: htmlMaterializationNumericE2E(t, "20"), WPct: htmlMaterializationNumericE2E(t, "30"), HPct: htmlMaterializationNumericE2E(t, "10"), Required: true, Label: pgtype.Text{String: "Customer signature", Valid: true}, OptionsJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	candidate, raw := htmlMaterializationCandidateE2E(t, reviewed, "Negotiated customer AB")
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := f.q.WithTx(tx)
	previous, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	updated, row, err := htmlmaterialization.Append(f.ctx, q, previous, candidate, htmlmaterialization.AppendInput{SourceJSON: raw, PageCount: 2, ActorID: f.user.ID, Summary: "Negotiated declared customer"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if row.Sequence != 2 || !bytes.Equal(updated.HtmlSourceJson, doc.HtmlSourceJson) || updated.PdfStorageKey == doc.PdfStorageKey || !bytes.Equal(updated.PdfSha256, doc.PdfSha256) || updated.HtmlReviewedBy.Valid || updated.HtmlReviewedMaterializationID.Valid {
		t.Fatal("fresh same-byte artifact changed origin or inherited review")
	}
	if !errors.Is(htmlsource.Validate(updated, true), htmlsource.ErrReviewRequired) {
		t.Fatal("same-digest review bypass")
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil || len(fields) != 0 {
		t.Fatal("old pagination geometry remained current")
	}
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(recipients) != 1 || recipients[0].ID != recipient.ID || recipients[0].Role != "customer" {
		t.Fatal("named recipient identity changed")
	}
	var oldPDF, oldVersion string
	var oldSHA, oldReview []byte
	var capturedFields, capturedRecipients json.RawMessage
	err = f.pool.QueryRow(f.ctx, `SELECT pdf_key,pdf_version_id,pdf_sha256,reviewed_pdf_sha256,fields_json,recipients_json FROM html_document_materialization_snapshots WHERE document_id=$1 AND kind='draft_superseded'`, doc.ID).Scan(&oldPDF, &oldVersion, &oldSHA, &oldReview, &capturedFields, &capturedRecipients) //nolint:rawsql -- inspect exact owned historical tuple
	if err != nil || oldPDF != doc.PdfStorageKey.String || oldVersion != doc.PdfStorageVersionID.String || !bytes.Equal(oldSHA, doc.PdfSha256) || !bytes.Equal(oldReview, doc.PdfSha256) || !bytes.Contains(capturedFields, []byte(field.ID.String())) || !bytes.Contains(capturedRecipients, []byte(recipient.ID.String())) {
		t.Fatal("old exact PDF/review/layout/party history lost", err)
	}
	old, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	view, err := htmlmaterialization.HistoricalDocument(updated, old)
	if err != nil || view.PdfStorageKey != doc.PdfStorageKey || view.PdfStorageVersionID != doc.PdfStorageVersionID {
		t.Fatal("historical source resolves current artifact", err)
	}
	for _, statement := range []string{`UPDATE html_document_materializations SET pdf_version_id='rewritten' WHERE id=$1`, `DELETE FROM html_document_materializations WHERE id=$1`} {
		assertHTMLSchemaRefusalE2E(t, f, statement, row.ID)
	}
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE html_document_materialization_snapshots SET reviewed_at=now() WHERE document_id=$1`, doc.ID)
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE documents SET html_current_materialization_id=NULL,html_current_source_json=NULL,html_current_page_count=NULL,html_current_materialization_sequence=NULL WHERE id=$1`, doc.ID)
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE documents SET html_source_json=NULL WHERE id=$1`, doc.ID)
	purge, err := f.q.HasRetainedDraftEvidenceForPurge(f.ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || !purge {
		t.Fatal("history admitted destructive purge", err)
	}
	signing, err := f.q.HasRetainedDraftSigningEvidence(f.ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || signing {
		t.Fatal("history incorrectly forbids reversible draft mutation", err)
	}
	listed, err := f.q.ListDocumentsForMCP(f.ctx, generated.ListDocumentsForMCPParams{OrgID: f.org, Column2: []string{"draft"}, Limit: 50})
	if err != nil || len(listed) == 0 {
		t.Fatal("bounded MCP document list", err)
	}
	var listedDocument *generated.Document
	for _, entry := range listed {
		if entry.ID == updated.ID {
			listedDocument = (*generated.Document)(entry)
		}
	}
	if listedDocument == nil {
		t.Fatal("bounded MCP list omitted current HTML document")
	}
	searched, err := f.q.SearchDocumentsByNameForMCP(f.ctx, generated.SearchDocumentsByNameForMCPParams{OrgID: f.org, Column2: pgtype.Text{String: "Same-document materialization", Valid: true}, Limit: 50})
	if err != nil || len(searched) != 1 {
		t.Fatal("bounded MCP document search", err)
	}
	for _, thin := range []*generated.Document{listedDocument, (*generated.Document)(searched[0])} {
		if thin.HtmlSourceJson != nil || thin.HtmlCurrentSourceJson != nil || thin.ID != updated.ID || thin.OrgID != updated.OrgID ||
			thin.HtmlEffectiveSourceCommitment != updated.HtmlEffectiveSourceCommitment || thin.HtmlCurrentMaterializationID != updated.HtmlCurrentMaterializationID ||
			thin.PdfStorageKey != updated.PdfStorageKey || thin.PdfStorageVersionID != updated.PdfStorageVersionID || !bytes.Equal(thin.PdfSha256, updated.PdfSha256) ||
			thin.HtmlCurrentMaterializationSequence != updated.HtmlCurrentMaterializationSequence || !bytes.Equal(thin.VariablesJson, updated.VariablesJson) {
			t.Fatal("MCP projection transferred inline designs or lost ordinary current document pins")
		}
	}
	htmlMaterializationInventoryE2E(t, f, []*generated.HtmlDocumentMaterialization{old, row})
}

func htmlMaterializationInventoryE2E(t *testing.T, f lifecycleAuthorizationFixture, records []*generated.HtmlDocumentMaterialization) {
	t.Helper()
	inventory, err := os.ReadFile("../../ops/recovery-object-inventory.sql")
	if err != nil {
		t.Fatal(err)
	}
	inventoryTx, err := recoveryinventory.Begin(f.ctx, f.pool)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := recoveryinventory.Rollback(inventoryTx); err != nil {
			t.Error("close canonical inventory snapshot", err)
		}
	}()
	rows, err := inventoryTx.Query(f.ctx, string(inventory))
	if err != nil {
		t.Fatal("canonical inventory", err)
	} //nolint:rawsql -- exact operator inventory, not copied fixture SQL
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var key64, keyJSON, classes, owners, orgs, sha, version, retainedUntil string
		var hashConflict, legal, versionConflict, legacy bool
		var refs int64
		if err := rows.Scan(&key64, &keyJSON, &classes, &owners, &orgs, &sha, &hashConflict, &legal, &refs, &version, &versionConflict, &legacy, &retainedUntil); err != nil {
			t.Fatal(err)
		}
		decoded, err := base64.StdEncoding.DecodeString(key64)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range records {
			if string(decoded) == r.PdfKey {
				if sha != hex.EncodeToString(r.PdfSha256) || version != r.PdfVersionID || hashConflict || versionConflict || legacy || legal || retainedUntil != "-" || !strings.Contains(classes, "html_materialization_pdf") {
					t.Fatal("history inventory lost exact pins")
				}
				found[r.PdfKey] = true
			}
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(found) != len(records) {
		t.Fatal("canonical recovery inventory omitted historical PDF")
	}
}

func TestHTMLMaterializationRefusesFilledFieldsAndRetainedRollbackE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureDatabaseE2E(t, isolateEmptyHTMLTemplateDatabaseE2E(t))
	field, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: f.org, Type: "text", Page: 1, XPct: htmlMaterializationNumericE2E(t, "10"), YPct: htmlMaterializationNumericE2E(t, "20"), WPct: htmlMaterializationNumericE2E(t, "30"), HPct: htmlMaterializationNumericE2E(t, "10"), Label: pgtype.Text{String: "Synthetic captured field", Valid: true}, OptionsJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE document_fields SET value='captured fixture' WHERE id=$1`, field.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- synthetic anomalous draft proves DB captured-data defense
	candidate, raw := htmlMaterializationCandidateE2E(t, doc, "Must refuse")
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := f.q.WithTx(tx)
	previous, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = htmlmaterialization.Append(f.ctx, q, previous, candidate, htmlmaterialization.AppendInput{SourceJSON: raw, PageCount: 1, ActorID: f.user.ID})
	if err == nil {
		t.Fatal("captured field permitted revision")
	}
	_ = tx.Rollback(context.Background())
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.HtmlCurrentMaterializationID != doc.HtmlCurrentMaterializationID || current.PdfStorageKey != doc.PdfStorageKey {
		t.Fatal("refusal changed current artifact")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM html_document_materializations WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("refusal committed history", err)
	} //nolint:rawsql -- owned rollback inspection
	fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil || len(fields) != 1 || !fields[0].Value.Valid {
		t.Fatal("refusal erased captured field")
	}
	migration, err := os.ReadFile("../db/migrations/00074_html_document_materializations.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(migration), "-- +goose Down", 2)
	assertHTMLSchemaRefusalE2E(t, f, parts[1])
}

// Direct generated-query callers must retain the same archive/layout boundary
// as Append. Deliberate raw fixture mutations below model incomplete future
// callers, with every refusal transaction rolled back before the next case.
func TestHTMLMaterializationProjectionRequiresExactArchiveAndFreshLayoutE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureE2E(t)
	recipient, err := f.q.CreateRecipient(f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "customer", Name: "Archive party", Email: "archive@synthetic.test", MagicTokenHash: bytes.Repeat([]byte{5}, 32), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Type: "signature", Page: 1, XPct: htmlMaterializationNumericE2E(t, "10"), YPct: htmlMaterializationNumericE2E(t, "20"), WPct: htmlMaterializationNumericE2E(t, "30"), HPct: htmlMaterializationNumericE2E(t, "10"), Required: true, Label: pgtype.Text{String: "Archived signature", Valid: true}, OptionsJson: json.RawMessage(`{}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.Audit.Log(f.ctx, audit.Entry{OrgID: f.org, DocumentID: &doc.ID, ActorUserID: &f.user.ID, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"fixture": "canonical archive evidence"}}); err != nil {
		t.Fatal(err)
	}
	for _, reason := range []string{"missing archive", "uncleared unsigned fields", "stale captured revision", "party changed after archive"} {
		t.Run(reason, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			q := f.q.WithTx(tx)
			locked, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			row := htmlMaterializationStageRowE2E(t, f, q, locked)
			if reason != "missing archive" {
				htmlMaterializationCaptureDraftE2E(t, f, q, locked)
			}
			if reason == "party changed after archive" {
				if _, err = tx.Exec(f.ctx, `UPDATE recipients SET name='Changed after archived context' WHERE id=$1`, recipient.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- deliberate synthetic caller drift; real parent remains locked
			}
			if reason == "missing archive" || reason == "party changed after archive" {
				removed, err := q.ClearUnsignedHTMLMaterializationFields(f.ctx, generated.ClearUnsignedHTMLMaterializationFieldsParams{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: locked.UpdatedAt})
				if err != nil || removed != 0 {
					t.Fatal("field clear bypassed exact archived layout/context", err)
				}
			}
			if reason == "stale captured revision" {
				if _, err = tx.Exec(f.ctx, `UPDATE documents SET updated_at=updated_at+interval '1 second' WHERE id=$1`, doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- deterministic synthetic CAS drift after snapshot
				locked, err = q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
			}
			if reason != "uncleared unsigned fields" {
				if _, err = tx.Exec(f.ctx, `DELETE FROM document_fields WHERE document_id=$1`, doc.ID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- isolate the projection archive check from its separate no-fields guard
			}
			_, err = q.ProjectHTMLDocumentMaterialization(f.ctx, generated.ProjectHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: locked.UpdatedAt, MaterializationID: row.ID})
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
				t.Fatalf("projection refusal=%v, want check-violation", err)
			}
		})
	}
	for _, name := range []string{"fields_json", "recipients_json", "notice_context_json", "ceremony_events_json", "captured_updated_at"} {
		t.Run("substituted "+name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			q := f.q.WithTx(tx)
			locked, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			captured := htmlMaterializationCaptureDraftE2E(t, f, q, locked)
			var substitute any = []any{}
			if name == "notice_context_json" {
				substitute = map[string]any{}
			} else if name == "captured_updated_at" {
				substitute = locked.UpdatedAt.Time.Add(-time.Second).UTC().Format(time.RFC3339Nano)
			}
			patch, err := json.Marshal(map[string]any{"id": uuid.NewString(), name: substitute})
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, `INSERT INTO html_document_materialization_snapshots SELECT (jsonb_populate_record(NULL::html_document_materialization_snapshots,to_jsonb(s)||$2::jsonb)).* FROM html_document_materialization_snapshots s WHERE s.id=$1`, captured.ID, patch) //nolint:rawsql -- exact valid snapshot clone with one deliberately substituted historical commitment
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
				t.Fatalf("substituted snapshot refusal=%v, want check-violation", err)
			}
		})
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, doc.ID)
	if err != nil || len(fields) != 1 {
		t.Fatal("refused projection erased original layout", err)
	}
	var materializations, snapshots int
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_materializations WHERE document_id=$1),(SELECT count(*) FROM html_document_materialization_snapshots WHERE document_id=$1)`, doc.ID).Scan(&materializations, &snapshots); err != nil || materializations != 1 || snapshots != 0 {
		t.Fatal("refused direct caller committed history", err)
	} //nolint:rawsql -- bounded owned rollback inventory
}

func htmlMaterializationCaptureDraftE2E(t *testing.T, f lifecycleAuthorizationFixture, q *generated.Queries, doc *generated.Document) *generated.HtmlDocumentMaterializationSnapshot {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(commitment)
	row, err := q.CaptureHTMLMaterializationSnapshot(f.ctx, generated.CaptureHTMLMaterializationSnapshotParams{DocumentID: doc.ID, OrgID: f.org, Kind: "draft_superseded", SourceCommitment: digest, ExpectedUpdatedAt: doc.UpdatedAt, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func htmlMaterializationStageRowE2E(t *testing.T, f lifecycleAuthorizationFixture, q *generated.Queries, doc *generated.Document) *generated.HtmlDocumentMaterialization {
	t.Helper()
	parent, err := q.GetCurrentHTMLDocumentMaterialization(f.ctx, generated.GetCurrentHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	candidate, raw := htmlMaterializationCandidateE2E(t, doc, "Direct synthetic caller AB")
	var committed struct {
		Commitment string `json:"commitment"`
	}
	if err = json.Unmarshal(raw, &committed); err != nil {
		t.Fatal(err)
	}
	digest, _ := hex.DecodeString(committed.Commitment)
	row, err := q.InsertHTMLDocumentMaterialization(f.ctx, generated.InsertHTMLDocumentMaterializationParams{DocumentID: doc.ID, OrgID: f.org, Sequence: parent.Sequence + 1, ParentID: pgtype.UUID{Bytes: parent.ID, Valid: true}, ParentCommitment: parent.SourceCommitment, OriginCommitment: parent.OriginCommitment, SourceJson: raw, SourceCommitment: digest, PdfKey: candidate.PdfStorageKey.String, PdfSha256: candidate.PdfSha256, PdfVersionID: candidate.PdfStorageVersionID.String, PageCount: 2, Summary: "Direct projection boundary", ChangedSections: []string{}, CreatedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	return row
}

// The original native Send receipt is captured before negotiation or retirement.
// Its canonical payload commits to the persisted sealing-intent deadline; this
// read neither reconstructs that deadline from an archive nor manufactures a
// provider acknowledgement. A row hash checks this one receipt, not org-chain
// completeness or provider conformance.
func htmlMaterializationOriginalSendDeadlineE2E(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) time.Time {
	t.Helper()
	f := q.f
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID != f.org || doc.Status != "sent" || !doc.SentAt.Valid || doc.SentAt.InfinityModifier != pgtype.Finite || !doc.Article13NoticeEpochAt.Valid || !doc.Article13NoticeEpochAt.Time.Equal(doc.SentAt.Time) || !doc.Article13NoticeEpochV61Committed {
		t.Fatal("original native Send result lacks its committed ceremony")
	}
	var eventIDText string
	err := f.pool.QueryRow(f.ctx, `SELECT min(id::text) FROM events WHERE org_id=$1 AND document_id=$2 AND kind='document.sent' HAVING count(*)=1`, f.org, doc.ID).Scan(&eventIDText) //nolint:rawsql -- unique actual native Send receipt, no rows or measurements are written
	if err != nil {
		t.Fatal("unique original native Send receipt unavailable", err)
	}
	eventID, err := uuid.Parse(eventIDText)
	if err != nil {
		t.Fatal("invalid original native Send receipt identity", err)
	}
	event, err := f.q.GetEventByID(f.ctx, eventID)
	if err != nil || event == nil || event.ID != eventID || event.OrgID != f.org || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != doc.ID || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID || event.RecipientID.Valid || event.Kind != audit.KindDocumentSent || !event.CreatedAt.Valid || event.CreatedAt.InfinityModifier != pgtype.Finite || len(event.RowHash) != sha256.Size || len(event.PayloadHashed) == 0 {
		t.Fatal("original native Send receipt scope/actor/hash unavailable", err)
	}
	recomputed, err := audit.RecomputeEventRowHash(event)
	if err != nil || !bytes.Equal(recomputed, event.RowHash) {
		t.Fatal("original native Send receipt row hash differs", err)
	}
	// payload_json is a reserialized JSONB UI copy. The exact hash preimage is
	// payload_hashed, so derive the independent deadline from those bound bytes.
	var receipt struct {
		RetainUntil  string `json:"retain_until"`
		Retained     bool   `json:"evidence_retained"`
		NoticeSchema string `json:"required_notice_schema"`
		NoticeSentAt string `json:"required_notice_sent_at"`
	}
	if err := json.Unmarshal(event.PayloadHashed, &receipt); err != nil {
		t.Fatal("original native Send receipt payload unavailable", err)
	}
	epoch, err := article13.CanonicalSentAt(doc.SentAt.Time)
	if err != nil || !receipt.Retained || receipt.NoticeSchema != doc.Article13NoticeSchema || receipt.NoticeSentAt != epoch {
		t.Fatal("original native Send receipt lost its Article 13 commitment", err)
	}
	deadline, err := time.Parse(time.RFC3339, receipt.RetainUntil)
	if err != nil || deadline.Nanosecond() != 0 || deadline.UTC().Format(time.RFC3339) != receipt.RetainUntil || !deadline.After(doc.SentAt.Time) {
		t.Fatal("original native Send receipt deadline unavailable", err)
	}
	return deadline.UTC()
}

func TestHTMLMaterializationReviseArchivesOriginalCeremonyDeadlineE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	sent, originalParties := q.createSentV1(t)
	f, doc := q.f, sent
	originalDeadline := htmlMaterializationOriginalSendDeadlineE2E(t, q, sent)
	// Real creation, Send and negotiation own their original measurement rows.
	// The fixture retains its bounded synthetic renderer/storage peers; this is
	// not a provider, renderer-conformance or combined-capacity claim.
	bootstrap := q.requestV1(originalParties[0].Token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.DocumentID != doc.ID || page.Privacy.NoticeDigest == "" || page.PDFObservation == nil {
		t.Fatal("genuine public context/notice unavailable")
	}
	requestBody, err := json.Marshal(signerRequestChangesInput{Message: "Please revise the declared service scope", Proposed: "Human-approved revised synthetic service scope"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/sign/"+originalParties[0].Token+"/request-changes", bytes.NewReader(requestBody)).WithContext(f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", f.s.PublicURL)
	request.Header.Set(signerNoticeDigestHeader, page.Privacy.NoticeDigest)
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	var changed map[string]string
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &changed) != nil || changed["status"] != "changes_requested" {
		t.Fatalf("genuine notice-bound public change request=%d", response.Code)
	}
	var noticeEvents int
	var noticeBound bool
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::integer,coalesce(bool_and(payload_json->>$4=$5),false) FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND kind='document.changes_requested'", f.org, doc.ID, originalParties[0].RecipientID, article13.AuditNoticeDigestKey, page.Privacy.NoticeDigest).Scan(&noticeEvents, &noticeBound); err != nil || noticeEvents != 1 || !noticeBound {
		t.Fatal("actual change response did not bind original server notice", err)
	} //nolint:rawsql -- exact fresh response evidence, never insertion or repair
	ownedRevisionConsumedV1(t, q)
	requests, err := f.q.ListChangeRequests(f.ctx, doc.ID)
	if err != nil || len(requests) != 1 {
		t.Fatal("actual change request missing", err)
	}
	base := "/api/v1/documents/" + doc.ID.String()
	if w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/change-requests/"+requests[0].ID.String()+"/approve", "", q.cookie); w.Code != http.StatusOK {
		t.Fatalf("genuine sender approval=%d", w.Code)
	}
	paused, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || paused.Status != "changes_requested" || !sameSignerDocumentSource(doc, paused) {
		t.Fatal("HTML approval auto-applied unreviewed prose or lost paused state", err)
	}
	w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/revise", "", q.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("revise source history status=%d", w.Code)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.Status != "draft" || current.SentAt.Valid || !current.Article13NoticeEpochAt.Time.Equal(sent.SentAt.Time) {
		t.Fatal("revision lost epoch high-water mark", err)
	}
	var deadline, oldEpoch time.Time
	var notice, events, parties json.RawMessage
	var retainedVersion string
	err = f.pool.QueryRow(f.ctx, `SELECT retain_until,notice_epoch_at,notice_context_json,ceremony_events_json,recipients_json,pdf_version_id FROM html_document_materialization_snapshots WHERE document_id=$1 AND kind='ceremony_retired'`, doc.ID).Scan(&deadline, &oldEpoch, &notice, &events, &parties, &retainedVersion) //nolint:rawsql -- inspect committed historical ceremony after real REST Revise
	var retainedNotice struct {
		SentAt  time.Time `json:"sent_at"`
		EpochAt time.Time `json:"epoch_at"`
		Schema  string    `json:"schema"`
	}
	decodeErr := json.Unmarshal(notice, &retainedNotice)
	if err != nil || decodeErr != nil || !retainedNotice.SentAt.Equal(sent.SentAt.Time) || !retainedNotice.EpochAt.Equal(sent.SentAt.Time) || retainedNotice.Schema != sent.Article13NoticeSchema || !deadline.Equal(originalDeadline) || !oldEpoch.Equal(sent.SentAt.Time) || retainedVersion != doc.PdfStorageVersionID.String || !bytes.Contains(events, []byte(article13.AuditRequiredNoticeSchemaKey)) {
		t.Fatal("retired ceremony deadline/notice/evidence/parties lost", err)
	}
	if bytes.Contains(parties, []byte("magic_token")) {
		t.Fatal("history stored recipient credentials")
	}
	for _, originalParty := range originalParties {
		if !bytes.Contains(parties, []byte(originalParty.RecipientID.String())) {
			t.Fatal("retired ceremony deadline/notice/evidence/parties lost")
		}
		freshRecipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: originalParty.RecipientID, OrgID: f.org})
		if err != nil || !freshRecipient.MagicTokenExpiresAt.Valid || freshRecipient.MagicTokenExpiresAt.InfinityModifier != pgtype.Finite || freshRecipient.MagicTokenExpiresAt.Time.After(time.Now()) {
			t.Fatal("old ceremony credential remains unexpired in editable draft", err)
		}
	}
	retained, err := f.q.HasRetainedDraftEvidenceForPurge(f.ctx, generated.HasRetainedDraftEvidenceForPurgeParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || !retained {
		t.Fatal("retired legal history admitted purge", err)
	}
	signing, err := f.q.HasRetainedDraftSigningEvidence(f.ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || signing {
		t.Fatal("retired history prevented next editable materialization", err)
	}
	ownedRevisionConsumedV1(t, q)
}
