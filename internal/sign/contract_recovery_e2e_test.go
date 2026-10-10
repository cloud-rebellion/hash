//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var reviewedContractRecoveryCorruptions = []string{
	"mode_downgrade", "missing_party", "different_name", "different_email", "different_role",
	"replacement_party", "extra_recipient", "missing_signature", "misbound_signature", "missing_field",
}

func TestReviewedContractFinalizingRebuildRejectsDriftBeforeEvidenceE2E(t *testing.T) {
	for _, corruption := range reviewedContractRecoveryCorruptions {
		t.Run(corruption, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, false)
			corruptReviewedContractRecoveryE2E(t, f, corruption)
			assertReviewedContractRecoveryRefusedE2E(t, f, false)
		})
	}
}

func TestReviewedContractFinalizingResumeRejectsDriftBeforeEvidenceE2E(t *testing.T) {
	for _, corruption := range reviewedContractRecoveryCorruptions {
		t.Run(corruption, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, true)
			corruptReviewedContractRecoveryE2E(t, f, corruption)
			assertReviewedContractRecoveryRefusedE2E(t, f, true)
		})
	}
}

func TestReviewedContractFinalizationRecoveryCompletesBoundPartiesE2E(t *testing.T) {
	for _, withIntent := range []bool{false, true} {
		label := "rebuild"
		if withIntent {
			label = "resume"
		}
		t.Run(label, func(t *testing.T) {
			f := newReviewedContractRecoveryE2E(t, withIntent)
			before := reviewedContractHistoryE2E(t, f)
			rows, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
				t.Fatal(err)
			}
			f.assertCompleted(t, "reviewed_contract_"+label)
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
			if err != nil {
				t.Fatal(err)
			}
			current, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
			if err != nil || htmlsource.ValidateContractParties(doc, current) != nil {
				t.Fatalf("completed source lost its named recipients: %v", err)
			}
			if len(rows) != len(current) || rows[0].ID != current[0].ID || rows[1].ID != current[1].ID || before != reviewedContractHistoryE2E(t, f) {
				t.Fatal("recovery changed recipient bindings or immutable HTML history")
			}
			spy := &reviewedContractEvidenceSpy{EvidenceStorage: f.store}
			f.engine.Storage = spy
			snapshot := reviewedContractRecoverySnapshotE2E(t, f)
			if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
				t.Fatal(err)
			}
			if spy.calls.Load() != 0 || snapshot != reviewedContractRecoverySnapshotE2E(t, f) {
				t.Fatal("completed reviewed-contract retry changed evidence or publication state")
			}
		})
	}
}

// This fixture uses real PostgreSQL, durable Send, both typed Sign calls and
// finalization. Its exact-version object store and PDF renderer remain synthetic;
// the source PDF does not establish real Chromium or legal acceptance.
func newReviewedContractRecoveryE2E(t *testing.T, withIntent bool) *multipartyPDFFixture {
	t.Helper()
	f := newMultipartyPDFE2EWithDraft(t, false, func(f *multipartyPDFFixture, doc *generated.Document) *generated.Document {
		input, _, _ := testfixture.HTMLContract(t)
		sha, err := hex.DecodeString(input.TemplateContentSHA256)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		q := f.q.WithTx(tx)
		template, err := q.CreateHTMLTemplate(f.ctx, generated.CreateHTMLTemplateParams{OrgID: doc.OrgID, Name: "Synthetic reviewed recovery profile",
			HtmlMasterJson: input.MasterJSON, VariablesJson: input.DefaultVarsJSON, CreatedBy: doc.SenderID, HtmlContentSha256: sha})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.InsertHTMLTemplateRevision(f.ctx, generated.InsertHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: doc.OrgID,
			ExpectedVersion: template.Version, HtmlMasterJson: input.MasterJSON, VariablesJson: input.DefaultVarsJSON, ContentSha256: sha, CreatedBy: doc.SenderID}); err != nil {
			t.Fatal(err)
		}
		approved, err := q.ApproveHTMLTemplateRevision(f.ctx, generated.ApproveHTMLTemplateRevisionParams{ApprovedBy: doc.SenderID,
			TemplateID: template.ID, OrgID: doc.OrgID, ExpectedVersion: template.Version, ExpectedContentSha256: sha})
		if err != nil {
			t.Fatal(err)
		}
		rows, err := q.ListRecipientsByDocument(f.ctx, doc.ID)
		if err != nil || len(rows) != 2 {
			t.Fatalf("source fixture recipients=%d error=%v", len(rows), err)
		}
		input.PartyBindings = nil
		for _, row := range rows {
			input.Values[row.Role+"_name"], input.Values[row.Role+"_email"] = row.Name, row.Email
			input.PartyBindings = append(input.PartyBindings, htmlsource.PartyBinding{Slot: row.Role, RecipientID: row.ID})
		}
		input.TemplateID, input.TemplateVersion = template.ID, approved.Version
		input.TemplateApprovedBy, input.TemplateApprovedAt = doc.SenderID, approved.ApprovedAt.Time
		// Only attach the approved template to this synthetic unsigned draft.
		// Ordinary production creation owns this association transactionally.
		if _, err := tx.Exec(f.ctx, `UPDATE documents SET template_id=$2 WHERE id=$1 AND status='draft'`, doc.ID, template.ID); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		doc, err = q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: doc.OrgID})
		if err != nil {
			t.Fatal(err)
		}
		variables, err := json.Marshal(input.Values)
		if err != nil {
			t.Fatal(err)
		}
		doc, err = q.FreezeDocumentVariables(f.ctx, generated.FreezeDocumentVariablesParams{ID: doc.ID, OrgID: doc.OrgID, VariablesJson: variables, ExpectedUpdatedAt: doc.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		source, err := htmlsource.New(input, doc)
		if err != nil {
			t.Fatal(err)
		}
		doc, err = q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: doc.OrgID, HtmlSourceJson: source, ExpectedUpdatedAt: doc.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		doc, _, err = htmlmaterialization.RegisterOrigin(f.ctx, q, doc, 1, doc.SenderID)
		if err != nil {
			t.Fatal(err)
		}
		doc, err = q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: doc.OrgID,
			ReviewedBy: doc.SenderID, ExpectedPdfSha256: doc.PdfSha256, ExpectedUpdatedAt: doc.UpdatedAt})
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		return doc
	})
	first, second := f.context(t, 0), f.context(t, 1)
	if result, err := f.engine.Sign(f.ctx, first, f.input(t, first, 0)); err != nil || result.Completed {
		t.Fatalf("first reviewed party result=%+v error=%v", result, err)
	}
	if withIntent {
		f.store.failFinalRetention.Store(true)
	} else {
		f.rendererFail.Store(true)
	}
	if result, err := f.engine.Sign(f.ctx, second, f.input(t, second, 1)); err != nil || result.Completed {
		t.Fatalf("staged reviewed contract result=%+v error=%v", result, err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
	if err != nil || doc.Status != "finalizing" {
		t.Fatalf("reviewed fixture did not reach finalizing: status=%v error=%v", doc, err)
	}
	_, err = f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: f.docID, OrgID: f.orgID})
	if (withIntent && err != nil) || (!withIntent && !errors.Is(err, pgx.ErrNoRows)) {
		t.Fatalf("fixture intent boundary mismatch: withIntent=%v error=%v", withIntent, err)
	}
	f.store.failFinalRetention.Store(false)
	f.rendererFail.Store(false)
	return f
}

func corruptReviewedContractRecoveryE2E(t *testing.T, f *multipartyPDFFixture, corruption string) {
	t.Helper()
	rows, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("corruption fixture recipients=%d error=%v", len(rows), err)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, f.docID)
	if err != nil || len(fields) != 2 {
		t.Fatalf("corruption fixture fields=%d error=%v", len(fields), err)
	}
	// These deliberate database corruptions represent damaged recovery state;
	// ordinary API mutations already reject them under the shared parent lock.
	switch corruption {
	case "mode_downgrade":
		_, err = f.pool.Exec(f.ctx, `UPDATE documents SET requires_signature=false WHERE id=$1`, f.docID) //nolint:rawsql
	case "missing_party", "replacement_party":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM recipients WHERE id=$1`, rows[1].ID) //nolint:rawsql
		if err == nil && corruption == "replacement_party" {
			_, hash, mintErr := auth.MintMagicToken()
			if mintErr != nil {
				t.Fatal(mintErr)
			}
			// The production query correctly refuses creation after draft. Seed
			// a fresh UUID directly to simulate only this damaged recovery row.
			tag, insertErr := f.pool.Exec(f.ctx, `INSERT INTO recipients
				(document_id,role,email,name,order_index,magic_token_hash,magic_token_expires_at,locale)
				SELECT id,$3,$4,$5,$6,$7,$8,$9 FROM documents WHERE id=$1 AND org_id=$2 AND status='finalizing'`,
				f.docID, f.orgID, rows[1].Role, rows[1].Email, rows[1].Name, rows[1].OrderIndex, hash,
				time.Now().Add(time.Hour), rows[1].Locale) //nolint:rawsql -- deliberate isolated recovery corruption
			err = insertErr
			if err == nil && tag.RowsAffected() != 1 {
				err = errors.New("replacement recovery recipient was not inserted")
			}
		}
	case "different_name":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET name='Different recovery representative' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "different_email":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET email='different-recovery@example.test' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "different_role":
		_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET role='signer' WHERE id=$1`, rows[1].ID) //nolint:rawsql
	case "extra_recipient":
		_, hash, mintErr := auth.MintMagicToken()
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		// Bypass only fixture seeding; production recipient creation remains
		// draft-only and must never admit this extra finalizing participant.
		tag, insertErr := f.pool.Exec(f.ctx, `INSERT INTO recipients
			(document_id,role,email,name,order_index,magic_token_hash,magic_token_expires_at,locale)
			SELECT id,$3,$4,$5,$6,$7,$8,$9 FROM documents WHERE id=$1 AND org_id=$2 AND status='finalizing'`,
			f.docID, f.orgID, "approver", "extra-recovery@example.test", "Unexpected recovery person", int32(2), hash,
			time.Now().Add(time.Hour), "en") //nolint:rawsql -- deliberate isolated recovery corruption
		err = insertErr
		if err == nil && tag.RowsAffected() != 1 {
			err = errors.New("extra recovery recipient was not inserted")
		}
	case "missing_signature":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM signatures WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID) //nolint:rawsql
	case "misbound_signature":
		var other uuid.UUID
		for _, field := range fields {
			if uuid.UUID(field.RecipientID.Bytes) != rows[1].ID {
				other = field.ID
			}
		}
		_, err = f.pool.Exec(f.ctx, `UPDATE signatures SET field_id=$3 WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID, other) //nolint:rawsql
	case "missing_field":
		_, err = f.pool.Exec(f.ctx, `DELETE FROM document_fields WHERE document_id=$1 AND recipient_id=$2`, f.docID, rows[1].ID) //nolint:rawsql
	default:
		t.Fatalf("unknown fixture corruption %q", corruption)
	}
	if err != nil {
		t.Fatalf("seed corruption %s: %v", corruption, err)
	}
}

func assertReviewedContractRecoveryRefusedE2E(t *testing.T, f *multipartyPDFFixture, directResume bool) {
	t.Helper()
	spy := &reviewedContractEvidenceSpy{EvidenceStorage: f.store}
	f.engine.Storage = spy
	before := reviewedContractRecoverySnapshotE2E(t, f)
	renders := f.rendererRequests.Load()
	if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err == nil {
		t.Fatal("damaged reviewed contract finalized")
	}
	if directResume {
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
		if err != nil {
			t.Fatal(err)
		}
		conn, err := f.pool.Acquire(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		completed, did, err := f.engine.resumeDocumentFinalization(f.ctx, conn, doc, nil)
		conn.Release()
		if err == nil || did || completed != nil {
			t.Fatalf("direct recovery accepted damaged contract: completed=%t did=%t error=%v", completed != nil, did, err)
		}
	}
	newRenders := f.rendererRequests.Load()
	if spy.calls.Load() != 0 || renders != newRenders || before != reviewedContractRecoverySnapshotE2E(t, f) {
		t.Fatalf("rejected recovery touched evidence, renderer or database: storageCalls=%d rendererCalls=%d", spy.calls.Load(), newRenders-renders)
	}
}

func reviewedContractHistoryE2E(t *testing.T, f *multipartyPDFFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'materializations',(SELECT jsonb_agg(to_jsonb(m) ORDER BY sequence) FROM html_document_materializations m WHERE document_id=$1),
		'snapshots',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM html_document_materialization_snapshots s WHERE document_id=$1))::text`, f.docID).Scan(&state); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return state
}

func reviewedContractRecoverySnapshotE2E(t *testing.T, f *multipartyPDFFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'intent',(SELECT to_jsonb(i) FROM document_finalization_intents i WHERE document_id=$1),
		'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM document_versions v WHERE document_id=$1),
		'reminders',(SELECT to_jsonb(r) FROM reminders r WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed
			WHERE position($1::text in html_body)>0 OR to_email=(SELECT email FROM users WHERE id=(SELECT sender_id FROM documents WHERE id=$1))))::text`, f.docID).Scan(&state); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return strings.Join([]string{f.snapshot(t), reviewedContractHistoryE2E(t, f), state}, "\n")
}

type reviewedContractEvidenceSpy struct {
	EvidenceStorage
	calls atomic.Int64
}

func (s *reviewedContractEvidenceSpy) GetVerifiedVersion(ctx context.Context, key, version string, digest []byte) ([]byte, error) {
	s.calls.Add(1)
	return s.EvidenceStorage.GetVerifiedVersion(ctx, key, version, digest)
}

func (s *reviewedContractEvidenceSpy) ResolveVerifiedLegacy(ctx context.Context, key string, digest []byte) ([]byte, storage.StoredObject, error) {
	s.calls.Add(1)
	return s.EvidenceStorage.ResolveVerifiedLegacy(ctx, key, digest)
}

func (s *reviewedContractEvidenceSpy) PutEvidenceVersioned(ctx context.Context, key, contentType string, body []byte, until time.Time) (storage.StoredObject, error) {
	s.calls.Add(1)
	return s.EvidenceStorage.PutEvidenceVersioned(ctx, key, contentType, body, until)
}

func (s *reviewedContractEvidenceSpy) RetainEvidenceVersion(ctx context.Context, key, version string, digest []byte, until time.Time) error {
	s.calls.Add(1)
	return s.EvidenceStorage.RetainEvidenceVersion(ctx, key, version, digest, until)
}
