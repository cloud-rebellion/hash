//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Actual REST/PG/isolated-PDF-worker protocol coverage. The renderer and
// exact-version S3 peer are synthetic and do not prove layout/provider recovery.
func setupHTMLRevisionE2E(t *testing.T) (lifecycleAuthorizationFixture, *htmlCreationRendererE2E, *htmlCreationStorageE2E, *generated.Document, string) {
	t.Helper()
	renderer := &htmlCreationRendererE2E{}
	f, peer := setupHTMLDocumentCreationE2E(t, renderer)
	master, _ := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML:     `<p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved scope", MaxChars: 500}},
	})
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Revision design", HTMLMasterJSON: master, VariablesJSON: json.RawMessage(`{"customer":"Original AB"}`)}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create design=%d %s", w.Code, w.Body.String())
	}
	var created templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	w = submitHTMLDocumentCreationE2E(t, f, template.ID, htmlCreationInputE2E(template), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("create HTML doc=%d %s", w.Code, w.Body.String())
	}
	var response struct {
		Document documentResponse `json:"document"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: response.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	f.doc = doc
	return f, renderer, peer, doc, cookie
}

func revisionInputE2E(t *testing.T, doc *generated.Document) htmlDocumentRevisionInput {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	return htmlDocumentRevisionInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment,
		Values: htmlStringMap{"customer": "Negotiated customer AB"}, Sections: htmlStringMap{"scope": "Negotiated <plain> wording & commitment"}, Summary: "Agreed commercial revision"}
}

func submitRevisionE2E(t *testing.T, f lifecycleAuthorizationFixture, in htmlDocumentRevisionInput, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/html/revisions", string(body), cookie)
}

func revisionStateE2E(t *testing.T, f lifecycleAuthorizationFixture) []byte {
	t.Helper()
	var raw []byte
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('document',to_jsonb(d),'history',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.sequence),'[]'::jsonb) FROM html_document_materializations m WHERE m.document_id=d.id),'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.created_at,h.id),'[]'::jsonb) FROM html_document_materialization_snapshots h WHERE h.document_id=d.id),'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY f.id),'[]'::jsonb) FROM document_fields f WHERE f.document_id=d.id),'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.version_no),'[]'::jsonb) FROM document_versions v WHERE v.document_id=d.id),'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.created_at,e.id),'[]'::jsonb) FROM events e WHERE e.document_id=d.id)) FROM documents d WHERE d.id=$1 AND d.org_id=$2`, f.doc.ID, f.org).Scan(&raw) //nolint:rawsql -- exact synthetic rollback inventory
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertHTMLRevisionReportE2E(t *testing.T, raw json.RawMessage, pdfSHA []byte, pages int32) {
	t.Helper()
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.SchemaVersion != 2 || len(envelope.Items) != 1 {
		t.Fatal("materialization lacks one observed sanitation report")
	}
	measured, err := sanitize.DecodePDFReport(envelope.Items[0])
	if err != nil || measured.PDF.OutputSHA256 != hex.EncodeToString(pdfSHA) || measured.PDF.PagesAfter != int(pages) {
		t.Fatal("observed sanitation report does not describe this exact PDF", err)
	}
}

func TestHTMLDocumentRevisionRESTPreservesHistoryAndRequiresFreshReviewAndPlacementE2E(t *testing.T) {
	f, renderer, peer, original, cookie := setupHTMLRevisionE2E(t)
	renderCountBefore := len(renderer.sources())
	path := "/api/v1/documents/" + original.ID.String()
	commitment, _ := htmlsource.Commitment(original)
	review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(review), cookie); w.Code != http.StatusOK {
		t.Fatalf("initial review=%d %s", w.Code, w.Body.String())
	}
	original, _ = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	f.doc = original
	field := addFieldInput{Type: "text", Page: 1, XPct: 10, YPct: 10, WPct: 20, HPct: 5, ExpectedPDFSHA256: hex.EncodeToString(original.PdfSha256), ExpectedHTMLSourceCommitment: commitment}
	body, _ := json.Marshal(field)
	w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(body), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("pinned field placement=%d %s", w.Code, w.Body.String())
	}
	var placed struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &placed); err != nil || placed.ID == uuid.Nil {
		t.Fatal("missing placed field identity")
	}
	before := revisionStateE2E(t, f)
	missing := field
	missing.ExpectedHTMLSourceCommitment = ""
	raw, _ := json.Marshal(missing)
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(raw), cookie); w.Code != http.StatusConflict {
		t.Fatalf("missing field source proof=%d", w.Code)
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("refused field changed current state")
	}
	in := revisionInputE2E(t, original)
	w = submitRevisionE2E(t, f, in, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("declared revision=%d %s", w.Code, w.Body.String())
	}
	var result struct {
		Document documentResponse `json:"document"`
		Revision int32            `json:"materialization_revision"`
		Review   bool             `json:"review_required"`
		Reset    bool             `json:"placement_reset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.Revision != 2 || !result.Review || !result.Reset || !result.Document.HTMLReviewRequired {
		t.Fatal("revision lost review/placement reset response")
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) || len(current.PdfSha256) != sha256.Size || current.PdfStorageKey == original.PdfStorageKey || current.HtmlReviewedBy.Valid || current.HtmlReviewedMaterializationID.Valid {
		t.Fatal("origin changed or new materialization inherited prior review")
	}
	if err := htmlsource.Validate(current, true); !errors.Is(err, htmlsource.ErrReviewRequired) {
		t.Fatal("changed source reused prior review")
	}
	oldRow, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: original.ID, OrgID: f.org, Sequence: 1})
	if err != nil {
		t.Fatal(err)
	}
	currentRow, err := f.q.GetHTMLDocumentMaterialization(f.ctx, generated.GetHTMLDocumentMaterializationParams{DocumentID: original.ID, OrgID: f.org, Sequence: 2})
	if err != nil {
		t.Fatal(err)
	}
	assertHTMLRevisionReportE2E(t, original.MetadataRedactionReport, original.PdfSha256, oldRow.PageCount)
	assertHTMLRevisionReportE2E(t, current.MetadataRedactionReport, current.PdfSha256, currentRow.PageCount)
	if !bytes.Equal(oldRow.MetadataRedactionReport, original.MetadataRedactionReport) || !bytes.Equal(currentRow.MetadataRedactionReport, current.MetadataRedactionReport) {
		t.Fatal("immutable report rows differ from their own PDF projections")
	}
	var capturedReport json.RawMessage
	if err := f.pool.QueryRow(f.ctx, `SELECT metadata_redaction_report FROM html_document_materialization_snapshots WHERE document_id=$1 AND org_id=$2 AND materialization_id=$3 AND kind='draft_superseded'`, original.ID, f.org, oldRow.ID).Scan(&capturedReport); err != nil || !bytes.Equal(capturedReport, original.MetadataRedactionReport) { //nolint:rawsql -- exact old report retained before fresh PDF projection
		t.Fatal("superseded snapshot lost its exact old sanitation report", err)
	}
	historical, err := htmlmaterialization.HistoricalDocument(current, oldRow)
	if err != nil || !bytes.Equal(historical.MetadataRedactionReport, original.MetadataRedactionReport) {
		t.Fatal("historical PDF inherited the fresh PDF report", err)
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, current.ID)
	if err != nil || len(fields) != 0 {
		t.Fatal("new PDF retained old field geometry")
	}
	before = revisionStateE2E(t, f)
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(body), cookie); w.Code != http.StatusConflict {
		t.Fatalf("old PDF/source placement=%d", w.Code)
	}
	deleteProof, _ := json.Marshal(map[string]string{"expected_pdf_sha256": hex.EncodeToString(original.PdfSha256), "expected_html_source_commitment": commitment})
	if w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/fields/"+placed.ID.String(), string(deleteProof), cookie); w.Code != http.StatusNotFound {
		t.Fatalf("superseded field delete=%d", w.Code)
	}
	staleReview := htmlDocumentReviewInput{ExpectedUpdatedAt: current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(current.PdfSha256), ExpectedHTMLSourceCommitment: commitment}
	raw, _ = json.Marshal(staleReview)
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(raw), cookie); w.Code != http.StatusConflict {
		t.Fatalf("old source review=%d", w.Code)
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("stale proof changed current state")
	}
	for _, sequence := range []int{1, 2} {
		w := submitSessionOperationE2E(f.s, http.MethodGet, fmt.Sprintf("%s/html/revisions/%d/pdf", path, sequence), "", cookie)
		wantSHA := original.PdfSha256
		if sequence == 2 {
			wantSHA = current.PdfSha256
		}
		actualSHA := sha256.Sum256(w.Body.Bytes())
		if w.Code != http.StatusOK || w.Header().Get("X-Hash-Materialization-Revision") != fmt.Sprint(sequence) || w.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(wantSHA) || !bytes.Equal(actualSHA[:], wantSHA) || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF")) {
			t.Fatalf("exact historical PDF %d=%d", sequence, w.Code)
		}
	}
	w = submitSessionOperationE2E(f.s, http.MethodGet, path+"/html/history", "", cookie)
	var history struct {
		Revisions []struct {
			Sequence int32 `json:"sequence"`
			Current  bool  `json:"current"`
		} `json:"revisions"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &history) != nil || len(history.Revisions) != 2 || history.Revisions[0].Sequence != 2 || !history.Revisions[0].Current || history.Revisions[1].Current {
		t.Fatal("history does not identify exact current revision")
	}
	for _, sequence := range []int{1, 2} {
		w := submitSessionOperationE2E(f.s, http.MethodGet, fmt.Sprintf("%s/html/revisions/%d/source", path, sequence), "", cookie)
		if w.Code != http.StatusOK || bytes.Contains(w.Body.Bytes(), []byte("data-hash-value")) || bytes.Contains(w.Body.Bytes(), []byte("html_master_json")) {
			t.Fatal("declared source exposed master or lost revision")
		}
		if sequence == 1 && !bytes.Contains(w.Body.Bytes(), []byte("Original AB")) {
			t.Fatal("historical inputs changed")
		}
		if sequence == 2 && !bytes.Contains(w.Body.Bytes(), []byte("Negotiated customer AB")) {
			t.Fatal("new inputs missing")
		}
	}
	currentCommit, _ := htmlsource.Commitment(current)
	freshReview, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(current.PdfSha256), ExpectedHTMLSourceCommitment: currentCommit})
	if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(freshReview), cookie); w.Code != http.StatusOK {
		t.Fatalf("fresh source review=%d %s", w.Code, w.Body.String())
	}
	sources := renderer.sources()
	if len(sources) != renderCountBefore+1 || !strings.Contains(sources[len(sources)-1], "Negotiated &lt;plain&gt; wording &amp; commitment") {
		t.Fatal("revision lost escaped negotiated wording")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 2, 0, 2)
}

func TestHTMLDocumentRevisionSanitizationReportDatabaseGuardsE2E(t *testing.T) {
	f, _, peer, doc, _ := setupHTMLRevisionE2E(t)
	assertHTMLRevisionReportE2E(t, doc.MetadataRedactionReport, doc.PdfSha256, doc.HtmlCurrentPageCount.Int32)
	for _, change := range []struct {
		name string
		sql  string
	}{
		{"current report", `UPDATE documents SET metadata_redaction_report='{}'::jsonb,updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2`},
		{"immutable report", `UPDATE html_document_materializations SET metadata_redaction_report='{}'::jsonb WHERE document_id=$1 AND org_id=$2`},
		{"forged snapshot report", `INSERT INTO html_document_materialization_snapshots (
            document_id,org_id,materialization_id,kind,captured_updated_at,source_json,source_commitment,
            pdf_key,pdf_sha256,pdf_version_id,page_count,rendered_pdf_key,rendered_pdf_sha256,rendered_pdf_version_id,
            reviewed_pdf_sha256,reviewed_by,reviewed_at,fields_json,recipients_json,notice_context_json,ceremony_events_json,
            notice_epoch_at,retain_until,created_by,metadata_redaction_report)
        SELECT d.id,d.org_id,d.html_current_materialization_id,'draft_superseded',d.updated_at,
            COALESCE(d.html_current_source_json,d.html_source_json),decode(COALESCE(d.html_current_source_json,d.html_source_json)->>'commitment','hex'),
            d.pdf_storage_key,d.pdf_sha256,d.pdf_storage_version_id,d.html_current_page_count,
            d.rendered_pdf_key,d.rendered_pdf_sha,d.rendered_pdf_version_id,d.html_reviewed_pdf_sha256,d.html_reviewed_by,d.html_reviewed_at,
            c.fields_json,c.recipients_json,c.notice_context_json,c.ceremony_events_json,NULL,NULL,d.sender_id,'{}'::jsonb
        FROM documents d CROSS JOIN LATERAL hash_html_materialization_snapshot_context(d.id) c
        WHERE d.id=$1 AND d.org_id=$2`},
	} {
		t.Run(change.name, func(t *testing.T) {
			before := revisionStateE2E(t, f)
			requests := peer.requests.Load()
			_, err := f.pool.Exec(f.ctx, change.sql, doc.ID, f.org) //nolint:rawsql -- exact owned tamper simulation must be refused atomically
			var databaseError *pgconn.PgError
			if !errors.As(err, &databaseError) || databaseError.Code != "23514" {
				t.Fatal("database accepted sanitation report tampering", err)
			}
			if !bytes.Equal(before, revisionStateE2E(t, f)) || requests != peer.requests.Load() {
				t.Fatal("refused report tampering changed document/history/audit/storage")
			}
		})
	}
}

func TestHTMLDocumentRevisionRefusesOriginalAuthorityOrSourceChangesDuringRenderE2E(t *testing.T) {
	for _, reason := range []string{"original session expired", "live role revoked", "current source observation changed"} {
		t.Run(reason, func(t *testing.T) {
			f, renderer, peer, doc, cookie := setupHTMLRevisionE2E(t)
			release := make(chan struct{})
			renderer.entered = make(chan struct{}, 1)
			renderer.release = release
			defer closeUnlessClosedRevisionE2E(release)
			if reason == "original session expired" {
				cookie = dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			}
			in := revisionInputE2E(t, doc)
			pending := beginHTMLRevisionRequestE2E(t, f, in, cookie)
			defer pending.stop(t, func() { closeUnlessClosedRevisionE2E(release) })
			select {
			case <-renderer.entered:
			case <-time.After(4 * time.Second):
				t.Fatal("revision did not reach render wait")
			}
			want := http.StatusConflict
			switch reason {
			case "original session expired":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			case "live role revoked":
				if _, err := f.pool.Exec(f.ctx, "UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
					t.Fatal(err)
				}
				want = http.StatusForbidden //nolint:rawsql -- controlled live role revocation
			default:
				if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET name='Concurrent metadata revision',updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2", doc.ID, f.org); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- concurrent legitimate source-observation change
			}
			before := revisionStateE2E(t, f)
			requests := peer.requests.Load()
			close(release)
			w := pending.receive(t)
			if w.Code != want {
				t.Fatalf("late revision refusal=%d want%d %s", w.Code, want, w.Body.String())
			}
			if !bytes.Equal(before, revisionStateE2E(t, f)) || peer.requests.Load() != requests {
				t.Fatal("stale renderer result changed database or object storage")
			}
		})
	}
}

func closeUnlessClosedRevisionE2E(ch chan struct{}) {
	select {
	case <-ch:
	default:
		close(ch)
	}
}

func TestHTMLDocumentRevisionAuditExpiryRollsBackAndCompensatesExactOwnedVersionE2E(t *testing.T) {
	f, _, peer, doc, _ := setupHTMLRevisionE2E(t)
	before := revisionStateE2E(t, f)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, 2*time.Second)
	in := revisionInputE2E(t, doc)
	pending := beginHTMLRevisionRequestE2E(t, f, in, cookie)
	defer pending.stop(t, func() { _ = blocked.Rollback(context.Background()) })
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	w := pending.receive(t)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("audit expiry=%d %s", w.Code, w.Body.String())
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) {
		t.Fatal("audit expiry committed history, review, fields, versions or audit")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 2, 1, 1)
}

type htmlRevisionPendingE2E struct {
	result   chan *httptest.ResponseRecorder
	cancel   context.CancelFunc
	received bool
}

func beginHTMLRevisionRequestE2E(t *testing.T, f lifecycleAuthorizationFixture, in htmlDocumentRevisionInput, cookie string) *htmlRevisionPendingE2E {
	t.Helper()
	body, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	req := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String()+"/html/revisions", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.s.PublicURL)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	pending := &htmlRevisionPendingE2E{result: make(chan *httptest.ResponseRecorder, 1), cancel: cancel}
	go func() { w := httptest.NewRecorder(); f.s.Routes().ServeHTTP(w, req); pending.result <- w }()
	return pending
}

func (p *htmlRevisionPendingE2E) receive(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-p.result:
		p.received = true
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("revision request did not finish after release")
		return nil
	}
}

func (p *htmlRevisionPendingE2E) stop(t *testing.T, unblock func()) {
	t.Helper()
	p.cancel()
	unblock()
	if !p.received {
		select {
		case <-p.result:
			p.received = true
		case <-time.After(20 * time.Second):
			t.Error("canceled revision request did not drain before fixture teardown")
		}
	}
}
