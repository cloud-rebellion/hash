//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// These tests discriminate the wiring of the M124 member review gate. Every
// member here has its own purpose "document", so only the root_signing argument
// of hash_pdf_bytes_reviewed_v1 can make it need a human review: passing false
// in a trigger, making hash_package_root_signing_v1 return false, or dropping
// the force call in hash_pdf_bytes_reviewed_v1 lets the agent-reviewed member
// through and fails a refusal below. Each refusal has a positive control: the
// same member with a human review on top succeeds.

// agentReviewedReplacedMemberE2E imports a document-purpose PDF, replaces it
// and records an agent review through MCP, the way an agent would.
func agentReviewedReplacedMemberE2E(t *testing.T, p *pdfRevisionE2EV1, label string) uuid.UUID {
	t.Helper()
	id := p.importPDF(t, label, "document")
	return agentReplaceAndReviewE2E(t, p, id, label+" replaced")
}

func agentReplaceAndReviewE2E(t *testing.T, p *pdfRevisionE2EV1, id uuid.UUID, text string) uuid.UUID {
	t.Helper()
	if w := p.replace(t, id, fieldBrowserPDF(text), p.pins(p.document(t, id))); w.Code != 201 {
		t.Fatalf("replace=%d %s", w.Code, w.Body.String())
	}
	d := p.document(t, id)
	fieldMCPTextE2E(t, p.mcpCall(t, "review_document_pdf", map[string]any{"document_id": id.String(), "expected_updated_at": d.UpdatedAt, "expected_pdf_sha256": d.PDFSHA256, "visually_reviewed": true, "reviewed_pages": []int{1}}), false)
	if p.document(t, id).PDFReviewRequired {
		t.Fatal("the agent review of a document-purpose PDF must satisfy the member's own gate")
	}
	var kind string
	if err := p.q.f.pool.QueryRow(p.q.f.ctx, `SELECT v.reviewer_kind FROM document_pdf_reviews_v1 v WHERE v.document_id=$1 ORDER BY v.created_at DESC LIMIT 1`, id).Scan(&kind); err != nil || kind != "agent" { //nolint:rawsql -- reviewer-kind oracle
		t.Fatal("fixture review is not an agent review", kind, err)
	}
	return id
}

func TestAgentReviewedPDFMemberRefusedThroughAttachE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	root := p.importPDF(t, "Gate attach root", "")
	member := agentReviewedReplacedMemberE2E(t, p, "Gate attach member")
	rootRow, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	pkg := packageHeader218(t, f, rootRow)
	attach := func() error {
		row, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: member, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, packageFresh218(t, f, pkg.ID), row, 1))
		return err
	}
	// Alone, the agent review satisfies the member's own gate.
	if _, err = f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1, false)`, member); err != nil {
		t.Fatalf("agent review must pass outside a signing package: %v", err)
	}
	packageExpectPG218(t, attach(), "23514")
	if w := p.review(member, p.document(t, member)); w.Code != 200 {
		t.Fatalf("human review=%d %s", w.Code, w.Body.String())
	}
	if err = attach(); err != nil {
		t.Fatalf("a human-reviewed member must attach: %v", err)
	}
}

func TestAgentReviewedPDFMemberRefusedThroughEnvelopeParentE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	parent := p.importPDF(t, "Gate envelope parent", "")
	child := agentReviewedReplacedMemberE2E(t, p, "Gate envelope child")
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET is_envelope=true WHERE id=$1`, parent); err != nil { //nolint:rawsql -- models an envelope root
		t.Fatalf("envelope root cannot be modelled directly: %v", err)
	}
	attach := func() error {
		_, err := f.pool.Exec(f.ctx, `UPDATE documents SET parent_envelope_id=$1 WHERE id=$2`, parent, child) //nolint:rawsql -- exercises the envelope-child trigger
		return err
	}
	packageExpectPG218(t, attach(), "23514")
	var attached bool
	if err := f.pool.QueryRow(f.ctx, `SELECT parent_envelope_id IS NOT NULL FROM documents WHERE id=$1`, child).Scan(&attached); err != nil || attached { //nolint:rawsql -- refusal left no parent
		t.Fatal("the refused attach changed the child", err)
	}
	if w := p.review(child, p.document(t, child)); w.Code != 200 {
		t.Fatalf("human review=%d %s", w.Code, w.Body.String())
	}
	if err := attach(); err != nil {
		t.Fatalf("a human-reviewed child must attach: %v", err)
	}
}

func TestAgentReviewedHTMLMemberRefusedThroughAttachE2E(t *testing.T) {
	f, html := htmlMaterializationFixtureE2E(t)
	// An HTML member whose own purpose is "document", so only the signing
	// package makes it need a human review.
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET metadata = COALESCE(metadata,'{}'::jsonb) || '{"hash:document-purpose:v1":{"purpose":"document"}}'::jsonb, updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond') WHERE id=$1`, html.ID); err != nil { //nolint:rawsql -- models a document-purpose HTML member
		t.Fatal(err)
	}
	html, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: html.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	html = packageFreshSyntheticReport222(t, f, html)
	html, err = f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: html.ID, OrgID: f.org, ExpectedUpdatedAt: html.UpdatedAt, ExpectedPdfSha256: html.PdfSha256, ReviewedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "agent", DocumentID: html.ID, OrgID: f.org}); err != nil {
		t.Fatalf("an agent kind row on a document-purpose HTML document: %v", err)
	}
	root := packagePDF218(t, f, "Gate HTML root")
	pkg := packageHeader218(t, f, root)
	// Outside a signing package the agent review is enough.
	if _, err = f.pool.Exec(f.ctx, `SELECT hash_pdf_bytes_reviewed_v1($1, false)`, html.ID); err != nil {
		t.Fatalf("agent review must pass outside a signing package: %v", err)
	}
	_, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, pkg, html, 1))
	packageExpectPG218(t, err, "23514")
	// Positive control: a human review of the same bytes attaches.
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "human", DocumentID: html.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	pkg = packageFresh218(t, f, pkg.ID)
	if _, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, pkg, html, 1)); err != nil {
		t.Fatalf("a human-reviewed HTML member must attach: %v", err)
	}
}

// L-s3: the capture-member trigger is the only gate that runs at capture, after
// a member's live state changed since it was attached. Dropping
// document_pdf_review_capture_member_v1 must fail this test.
func TestCaptureMemberTriggerRefusesAgentReviewedReplacementE2E(t *testing.T) {
	p := newPDFRevisionE2EV1(t)
	f := p.q.f
	root := p.importPDF(t, "Capture gate root", "")
	member := p.importPDF(t, "Capture gate member", "document")
	rootRow, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	pkg := packageHeader218(t, f, rootRow)
	// A never-replaced member attaches without any review.
	memberRow, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: member, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, pkg, memberRow, 1)); err != nil {
		t.Fatal(err)
	}
	pkg = packageFresh218(t, f, pkg.ID)
	// The member is then replaced and reviewed by an agent. The attachment
	// trigger does not run again; only the capture does.
	agentReplaceAndReviewE2E(t, p, member, "Capture gate replaced")
	input := captureInput219(t, f, pkg, 1, 0)
	_, err = f.q.AppendDocumentPackageCaptureV1(f.ctx, input)
	packageExpectPG218(t, err, "23514")
	var n int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM document_package_captures_v1 WHERE package_id=$1`, pkg.ID).Scan(&n); err != nil || n != 0 { //nolint:rawsql -- refusal stored nothing
		t.Fatalf("refused capture stored %d rows (%v)", n, err)
	}
	// Positive control: a human review on top lets the same capture through.
	if w := p.review(member, p.document(t, member)); w.Code != 200 {
		t.Fatalf("human review=%d %s", w.Code, w.Body.String())
	}
	if _, err = f.q.AppendDocumentPackageCaptureV1(f.ctx, input); err != nil {
		t.Fatalf("capture after a human review: %v", err)
	}
}
