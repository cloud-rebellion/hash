//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// newTemplateVersionE2E saves version 2 of the fixture's template and returns
// its exact revision row, unapproved.
func newTemplateVersionE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document) *generated.HtmlTemplateRevision {
	t.Helper()
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitHTMLTemplateE2E(t, f, "update", doc.TemplateID.Bytes, htmlTemplateInputE2E(t, 1, "Moved"), cookie)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated {
		t.Fatalf("save template v2=%d %s", w.Code, w.Body.String())
	}
	rev, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: doc.TemplateID.Bytes, OrgID: f.org, Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	return rev
}

// moveInputE2E builds the proposed current source for a design move.
func moveInputE2E(t *testing.T, doc *generated.Document, rev *generated.HtmlTemplateRevision, approvedBy uuid.UUID, version int32) (*generated.Document, json.RawMessage) {
	t.Helper()
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	in.TemplateVersion, in.TemplateContentSHA256 = version, hex.EncodeToString(rev.ContentSha256)
	in.MasterJSON, in.DefaultVarsJSON = rev.HtmlMasterJson, rev.VariablesJson
	in.TemplateApprovedBy, in.TemplateApprovedAt = approvedBy, rev.ApprovedAt.Time
	if !rev.ApprovedAt.Valid {
		in.TemplateApprovedAt = time.Now().Add(-time.Minute)
	}
	candidate := *doc
	candidate.PdfStorageKey = pgtype.Text{String: "org/" + doc.OrgID.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}
	candidate.PdfStorageVersionID = pgtype.Text{String: "synthetic-move-" + uuid.NewString(), Valid: true}
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

func appendMoveE2E(t *testing.T, f lifecycleAuthorizationFixture, candidate *generated.Document, raw json.RawMessage, commit bool) error {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := f.q.WithTx(tx)
	previous, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: candidate.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = htmlmaterialization.Append(f.ctx, q, previous, candidate, htmlmaterialization.AppendInput{SourceJSON: raw, PageCount: 1, PreviousPageCount: 1, ActorID: f.user.ID, Summary: "Moved to a newer approved design"}); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return tx.Commit(f.ctx)
}

// Database guards for the forward template move (M124): unapproved target,
// forged approval, older target, then the accepted forward move.
func TestHTMLDocumentTemplateMoveGuardsE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureE2E(t)
	rev := newTemplateVersionE2E(t, f, doc)

	candidate, raw := moveInputE2E(t, doc, rev, f.user.ID, 2)
	if err := appendMoveE2E(t, f, candidate, raw, true); err == nil {
		t.Fatal("unapproved target version accepted")
	}
	approved, err := f.q.ApproveHTMLTemplateRevision(f.ctx, generated.ApproveHTMLTemplateRevisionParams{TemplateID: rev.TemplateID, OrgID: f.org, ExpectedVersion: 2, ExpectedContentSha256: rev.ContentSha256, ApprovedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	forged, forgedRaw := moveInputE2E(t, doc, approved, uuid.New(), 2)
	if err = appendMoveE2E(t, f, forged, forgedRaw, true); err == nil {
		t.Fatal("forged approver accepted")
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM html_document_materializations WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 1 {
		t.Fatal("refusals committed history", count, err)
	} //nolint:rawsql -- owned rollback inspection

	candidate, raw = moveInputE2E(t, doc, approved, f.user.ID, 2)
	if err = appendMoveE2E(t, f, candidate, raw, true); err != nil {
		t.Fatalf("approved forward move refused: %v", err)
	}
	moved, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || moved.ID != doc.ID || !bytes.Equal(moved.HtmlSourceJson, doc.HtmlSourceJson) || moved.HtmlCurrentMaterializationSequence.Int32 != 2 || moved.HtmlReviewedPdfSha256 != nil {
		t.Fatal("same document, immutable origin, history or review reset lost", err)
	}
	origin, _ := htmlsource.OriginCommitment(moved)
	if first, _ := htmlsource.OriginCommitment(doc); origin != first {
		t.Fatal("origin anchor changed")
	}

	// From version 2 the first design is an older target, whatever its approval.
	old, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: rev.TemplateID, OrgID: f.org, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	back, backRaw := moveInputE2E(t, moved, old, old.ApprovedBy.Bytes, 1)
	if err = appendMoveE2E(t, f, back, backRaw, true); err == nil {
		t.Fatal("older target accepted after a forward move")
	}
}

// A signing document needs a human reviewer; an agent's review of a document
// later switched to signing is not enough at send. Direct SQL, no handlers.
func TestReviewKindGatesSigningSendE2E(t *testing.T) {
	f, doc := htmlMaterializationFixtureE2E(t)
	reviewed, err := f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, ExpectedPdfSha256: doc.PdfSha256, ReviewedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Default metadata means signing: an agent kind must be refused by the database.
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "agent", DocumentID: doc.ID, OrgID: f.org}); err == nil {
		t.Fatal("agent review recorded for a signing document")
	}
	// Non-signing: the agent may review.
	if _, err = f.pool.Exec(f.ctx, `UPDATE documents SET metadata = jsonb_build_object('hash:document-purpose:v1', jsonb_build_object('schema_version',1,'purpose','document')) WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- synthetic purpose fixture
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "agent", DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatalf("agent review of a document refused: %v", err)
	}
	// Switched to signing afterwards: send is blocked by the database.
	if _, err = f.pool.Exec(f.ctx, `UPDATE documents SET metadata = '{}'::jsonb WHERE id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- models the later purpose switch
	_, err = f.pool.Exec(f.ctx, `UPDATE documents SET status='sent' WHERE id=$1`, doc.ID) //nolint:rawsql -- direct-SQL send block
	if err == nil || !strings.Contains(err.Error(), "fresh human review") {
		t.Fatalf("agent-reviewed signing document left draft: %v", err)
	}
	// A later human review of the same PDF lifts the block (the gate no longer names it).
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "human", DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	_, err = f.pool.Exec(f.ctx, `UPDATE documents SET status='sent' WHERE id=$1`, doc.ID) //nolint:rawsql -- direct-SQL send
	if err != nil && strings.Contains(err.Error(), "fresh human review") {
		t.Fatalf("human review did not lift the gate: %v", err)
	}
	_ = reviewed
}

// Imported-PDF draft: revisions are append-only, need a matching latest review,
// and an unreviewed replacement cannot leave draft even through direct SQL.
func TestPDFRevisionGuardsDatabaseE2E(t *testing.T) {
	f, _ := htmlMaterializationFixtureE2E(t)
	digest := bytes.Repeat([]byte{7}, 32)
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Imported PDF fixture", PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: digest, PdfStorageVersionID: pgtype.Text{String: "synthetic-original", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	next := bytes.Repeat([]byte{9}, 32)
	params := generated.InsertDocumentPDFRevisionV1Params{ID: uuid.New(), OrgID: f.org, DocumentID: doc.ID, Sequence: 1,
		PreviousPdfKey: doc.PdfStorageKey.String, PreviousPdfSha256: doc.PdfSha256, PreviousPdfVersionID: doc.PdfStorageVersionID.String,
		PdfKey: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", PdfSha256: next, PdfVersionID: "synthetic-replacement",
		PageCount: 2, MetadataRedactionReport: json.RawMessage(`{}`), Summary: "replace", CreatedBy: f.user.ID}
	bad := params
	bad.PreviousPdfSha256 = bytes.Repeat([]byte{1}, 32)
	if _, err = f.q.InsertDocumentPDFRevisionV1(f.ctx, bad); err == nil {
		t.Fatal("revision with wrong previous pins accepted")
	}
	rev, err := f.q.InsertDocumentPDFRevisionV1(f.ctx, params)
	if err != nil {
		t.Fatalf("valid revision refused: %v", err)
	}
	if _, err = f.pool.Exec(f.ctx, `UPDATE document_pdf_revisions_v1 SET summary='x' WHERE id=$1`, rev.ID); err == nil {
		t.Fatal("revision history is mutable")
	} //nolint:rawsql -- proves append-only trigger
	// Project the replacement, as the future owned writer will.
	if _, err = f.pool.Exec(f.ctx, `UPDATE documents SET pdf_storage_key=$2, pdf_sha256=$3, pdf_storage_version_id=$4 WHERE id=$1`, doc.ID, rev.PdfKey, rev.PdfSha256, rev.PdfVersionID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- stands in for the owned projection
	_, err = f.pool.Exec(f.ctx, `UPDATE documents SET status='sent' WHERE id=$1`, doc.ID) //nolint:rawsql -- direct-SQL send block
	if err == nil || !strings.Contains(err.Error(), "requires review") {
		t.Fatalf("unreviewed replacement left draft: %v", err)
	}
	// Default metadata is signing: no agent review.
	review := generated.InsertDocumentPDFReviewV1Params{ID: uuid.New(), OrgID: f.org, DocumentID: doc.ID, RevisionID: rev.ID, PdfSha256: rev.PdfSha256, ReviewerKind: "agent", ReviewedBy: f.user.ID, VisuallyReviewed: true, ReviewedPages: 2}
	if _, err = f.q.InsertDocumentPDFReviewV1(f.ctx, review); err == nil {
		t.Fatal("agent reviewed a signing document's PDF")
	}
	review.ReviewerKind, review.ReviewedPages = "human", 1
	if _, err = f.q.InsertDocumentPDFReviewV1(f.ctx, review); err == nil {
		t.Fatal("review of fewer pages than the PDF has accepted")
	}
	review.ReviewedPages = 2
	if _, err = f.q.InsertDocumentPDFReviewV1(f.ctx, review); err != nil {
		t.Fatalf("human review refused: %v", err)
	}
	_, err = f.pool.Exec(f.ctx, `UPDATE documents SET status='sent' WHERE id=$1`, doc.ID) //nolint:rawsql -- direct-SQL send
	if err != nil && strings.Contains(err.Error(), "requires review") {
		t.Fatalf("review did not lift the gate: %v", err)
	}
}
