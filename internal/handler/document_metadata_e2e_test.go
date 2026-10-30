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
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual SQL/REST projection coverage uses one bounded sizable approved design,
// not a capacity benchmark. Creation uses the source-built isolated worker;
// Chromium and versioned S3 peers are synthetic. The same-SHA second projection
// is created by the domain protocol with synthetic pins, not a rendering claim.
type metadataProjectionFixtureE2E struct {
	f                                 lifecycleAuthorizationFixture
	renderer                          *htmlCreationRendererE2E
	storage                           *htmlCreationStorageE2E
	cookie                            string
	reviewed, current, legacy, static *generated.Document
}

func metadataReviewE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document, cookie string) *generated.Document {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(body), cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("metadata fixture review status=%d", w.Code)
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func setupMetadataProjectionE2E(t *testing.T) metadataProjectionFixtureE2E {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Fatal("metadata creation fixture requires the source-built isolated HASH_E2E_PDF_WORKER_PATH")
	}
	f, renderer, storage, original, cookie := setupHTMLRevisionE2E(t)
	original = metadataReviewE2E(t, f, original, cookie)
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML:     `<p>` + strings.Repeat("Bounded synthetic approved layout. ", 4096) + `</p><p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved scope", MaxChars: 500}},
	})
	if err != nil {
		t.Fatal(err)
	}
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInput{Name: "Sizable metadata-only design", HTMLMasterJSON: master, VariablesJSON: json.RawMessage(`{"customer":"Metadata AB"}`)}, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("sizable design create status=%d", w.Code)
	}
	var created templateResponse
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	tpl, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	approveHTMLCreationTemplateE2E(t, f, tpl)
	w = submitHTMLDocumentCreationE2E(t, f, tpl.ID, htmlCreationInputE2E(tpl), cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("sizable document create status=%d", w.Code)
	}
	var response struct {
		Document documentResponse `json:"document"`
	}
	if err = json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	big, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: response.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	big = metadataReviewE2E(t, f, big, cookie)
	candidate, source := htmlMaterializationCandidateE2E(t, big, "Revised metadata AB")
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	q := f.q.WithTx(tx)
	locked, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: big.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	current, _, err := htmlmaterialization.Append(f.ctx, q, locked, candidate, htmlmaterialization.AppendInput{SourceJSON: source, PageCount: 1, ActorID: f.user.ID, Summary: "Synthetic same-PDF metadata revision"})
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(current.PdfSha256, big.PdfSha256) || current.HtmlCurrentMaterializationID == big.HtmlCurrentMaterializationID || current.HtmlReviewedBy.Valid || len(current.HtmlSourceJson) < 128<<10 || len(current.HtmlCurrentSourceJson) < 128<<10 {
		t.Fatal("sizable same-SHA new-CID fixture was not established")
	}
	input, err := htmlsource.InputForCurrent(big)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, TemplateID: big.TemplateID, SenderID: f.user.ID, Name: "Unregistered sizable HTML origin", PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: big.PdfSha256, PdfStorageVersionID: pgtype.Text{String: "synthetic-legacy-source-version", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err = f.q.FreezeDocumentVariables(f.ctx, generated.FreezeDocumentVariablesParams{ID: legacy.ID, OrgID: f.org, ExpectedUpdatedAt: legacy.UpdatedAt, VariablesJson: big.VariablesJson})
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := htmlsource.New(input, legacy)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err = f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: legacy.ID, OrgID: f.org, ExpectedUpdatedAt: legacy.UpdatedAt, HtmlSourceJson: anchor})
	if err != nil {
		t.Fatal(err)
	}
	if err = htmlsource.Validate(legacy, false); err != nil || legacy.HtmlCurrentMaterializationID.Valid {
		t.Fatal("legacy origin fixture invalid")
	}
	digest := sha256.Sum256([]byte("synthetic ordinary PDF metadata control"))
	static, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Static PDF control", PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true}, PdfSha256: digest[:], PdfStorageVersionID: pgtype.Text{String: "synthetic-static-version", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	return metadataProjectionFixtureE2E{f, renderer, storage, cookie, original, current, legacy, static}
}

func metadataFullDocumentE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) *generated.Document {
	t.Helper()
	doc, err := f.q.GetDocumentByID(f.ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func metadataAuditCountE2E(t *testing.T, f lifecycleAuthorizationFixture) int {
	t.Helper()
	var count int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.org).Scan(&count); err != nil { //nolint:rawsql -- bounded fixture-owned event count
		t.Fatal(err)
	}
	return count
}

func metadataHistoryStateE2E(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) []byte {
	t.Helper()
	var raw []byte
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('origin',d.html_source_json,'current',d.html_current_source_json,'current_id',d.html_current_materialization_id,'commitment',d.html_effective_source_commitment,'pdf_key',d.pdf_storage_key,'pdf_sha',d.pdf_sha256,'pdf_version',d.pdf_storage_version_id,'review_id',d.html_reviewed_materialization_id,'review_sha',d.html_reviewed_pdf_sha256,'review_by',d.html_reviewed_by,'review_at',d.html_reviewed_at,'variables',d.variables_json,'history',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.sequence),'[]'::jsonb) FROM html_document_materializations m WHERE m.document_id=d.id),'snapshots',(SELECT coalesce(jsonb_agg(to_jsonb(h) ORDER BY h.created_at,h.id),'[]'::jsonb) FROM html_document_materialization_snapshots h WHERE h.document_id=d.id),'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.version_no),'[]'::jsonb) FROM document_versions v WHERE v.document_id=d.id)) FROM documents d WHERE d.id=$1 AND d.org_id=$2`, id, f.org).Scan(&raw) //nolint:rawsql -- fixture-only complete source/history inventory, excluding legitimate envelope topology timestamps
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertMetadataDTOE2E(t *testing.T, got documentResponse, doc *generated.Document) {
	t.Helper()
	want := toDocumentResponse(doc)
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var gotValue, wantValue any
	if err = json.Unmarshal(gotJSON, &gotValue); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(wantJSON, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("metadata DTO lost source/review/pins or ordinary fields for document %s", doc.ID)
	}
}

func assertMetadataNoEffectsE2E(t *testing.T, m metadataProjectionFixtureE2E, events, renders int, requests int64, states map[uuid.UUID][]byte) {
	t.Helper()
	if metadataAuditCountE2E(t, m.f) != events || len(m.renderer.sources()) != renders || m.storage.requests.Load() != requests {
		t.Fatal("metadata read caused an audit/render/storage effect")
	}
	for id, state := range states {
		if !bytes.Equal(state, metadataHistoryStateE2E(t, m.f, id)) {
			t.Fatalf("metadata operation changed source/history for %s", id)
		}
	}
}

func TestDocumentMetadataRESTProjectsSizableHTMLAndPreservesReadStateE2E(t *testing.T) {
	m := setupMetadataProjectionE2E(t)
	f := m.f
	block := seedDocumentDeleteDraft(t, f.ctx, f.q, f.org, f.user.ID)
	for _, doc := range []*generated.Document{block, m.static} {
		if _, err := f.s.Versions.Snapshot(f.ctx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: f.org, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &f.user.ID, Via: versions.ViaHuman, Summary: "Ordinary metadata version control"}); err != nil {
			t.Fatal(err)
		}
	}
	deleted := seedDocumentDeleteDraft(t, f.ctx, f.q, f.org, f.user.ID)
	if _, err := f.s.Versions.Snapshot(f.ctx, versions.SnapshotInput{DocumentID: deleted.ID, OrgID: f.org, Name: deleted.Name, SourceKind: deleted.SourceKind, BlocksJSON: deleted.BlocksJson, VariablesJS: deleted.VariablesJson, CreatedBy: &f.user.ID, Via: versions.ViaHuman}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: deleted.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Foreign metadata fixture", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@metadata.test", Name: "Foreign synthetic owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := seedDocumentDeleteDraft(t, f.ctx, f.q, foreignOrg.ID, foreignUser.ID)
	if _, err := f.s.Versions.Snapshot(f.ctx, versions.SnapshotInput{DocumentID: foreign.ID, OrgID: foreignOrg.ID, Name: foreign.Name, SourceKind: foreign.SourceKind, BlocksJSON: foreign.BlocksJson, VariablesJS: foreign.VariablesJson, CreatedBy: &foreignUser.ID, Via: versions.ViaHuman}); err != nil {
		t.Fatal(err)
	}
	states := map[uuid.UUID][]byte{}
	for _, doc := range []*generated.Document{m.reviewed, m.current, m.legacy, m.static, block} {
		states[doc.ID] = metadataHistoryStateE2E(t, f, doc.ID)
	}
	events, renders, requests := metadataAuditCountE2E(t, f), len(m.renderer.sources()), m.storage.requests.Load()
	for _, tc := range []struct {
		name, path    string
		filter        []string
		limit, offset int32
	}{
		{"default", "/api/v1/documents", nil, 50, 0},
		{"draft page", "/api/v1/documents?status=draft&limit=2&offset=1", []string{"draft"}, 2, 1},
		{"multiple filters", "/api/v1/documents?status=draft&status=completed&limit=3", []string{"draft", "completed"}, 3, 0},
		{"empty filtered page", "/api/v1/documents?status=completed&limit=2", []string{"completed"}, 2, 0},
		{"past end", "/api/v1/documents?limit=2&offset=100", nil, 2, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full, err := f.q.ListDocuments(f.ctx, generated.ListDocumentsParams{OrgID: f.org, Column2: tc.filter, Limit: tc.limit, Offset: tc.offset})
			if err != nil {
				t.Fatal(err)
			}
			thin, err := f.q.ListDocumentMetadataForREST(f.ctx, generated.ListDocumentMetadataForRESTParams{OrgID: f.org, Column2: tc.filter, Limit: tc.limit, Offset: tc.offset})
			if err != nil || len(thin) != len(full) {
				t.Fatalf("thin query length=%d full=%d error=%v", len(thin), len(full), err)
			}
			for i, row := range thin {
				if row.ID == deleted.ID || row.ID == foreign.ID {
					t.Fatal("foreign/deleted document leaked into metadata list")
				}
				assertMetadataDTOE2E(t, toDocumentMetadataResponse(row), full[i])
				wantHTML, wantReview, wantSequence := true, true, int32(1)
				switch row.ID {
				case m.current.ID:
					wantSequence = 2
				case m.reviewed.ID:
					wantReview = false
				case m.legacy.ID:
				default:
					wantHTML, wantReview, wantSequence = false, false, 0
				}
				got := toDocumentMetadataResponse(row)
				if got.HasHTMLSource != wantHTML || got.HTMLReviewRequired != wantReview || got.HTMLMaterializationRevision != wantSequence {
					t.Fatal("SQL origin/review/sequence flags do not describe the established fixture")
				}
				raw, err := json.Marshal(row)
				if err != nil || len(raw) > 8<<10 || bytes.Contains(raw, []byte("Bounded synthetic approved layout.")) {
					t.Fatal("SQL metadata row transferred inline design source")
				}
			}
			w := submitSessionOperationE2E(f.s, http.MethodGet, tc.path, "", m.cookie)
			if w.Code != http.StatusOK {
				t.Fatalf("metadata list status=%d", w.Code)
			}
			var body struct {
				Documents     []documentResponse `json:"documents"`
				Total         int64              `json:"total"`
				Limit, Offset int32
			}
			if err = json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			count, err := f.q.CountDocuments(f.ctx, generated.CountDocumentsParams{OrgID: f.org, Column2: tc.filter})
			if err != nil || body.Total != count || body.Limit != tc.limit || body.Offset != tc.offset || len(body.Documents) != len(full) {
				t.Fatal("REST filter/order/pagination/count parity lost")
			}
			for i, doc := range full {
				assertMetadataDTOE2E(t, body.Documents[i], doc)
			}
		})
	}
	for _, doc := range []*generated.Document{m.reviewed, m.current, m.legacy, m.static, block} {
		projection, err := f.q.GetDocumentReadProjection(f.ctx, generated.GetDocumentReadProjectionParams{ID: doc.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		thin := (*generated.Document)(projection)
		full := metadataFullDocumentE2E(t, f, doc.ID)
		withoutSource := *full
		withoutSource.HtmlSourceJson, withoutSource.HtmlCurrentSourceJson = nil, nil
		if len(thin.HtmlSourceJson) != 0 || len(thin.HtmlCurrentSourceJson) != 0 || !reflect.DeepEqual(thin, &withoutSource) {
			t.Fatal("read projection omitted ordinary metadata or loaded an inline master")
		}
		id, err := f.q.GetActiveDocumentIdentity(f.ctx, generated.GetActiveDocumentIdentityParams{ID: doc.ID, OrgID: f.org})
		if err != nil || id != doc.ID {
			t.Fatal("active identity projection lost scoped identity")
		}
		w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String(), "", m.cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("ordinary detail status=%d", w.Code)
		}
		var detail documentResponse
		if err = json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		assertMetadataDTOE2E(t, detail, full)
	}
	for _, id := range []uuid.UUID{foreign.ID, deleted.ID, uuid.New()} {
		if _, err := f.q.GetActiveDocumentIdentity(f.ctx, generated.GetActiveDocumentIdentityParams{ID: id, OrgID: f.org}); err != pgx.ErrNoRows {
			t.Fatal("identity projection admitted foreign/deleted/missing row")
		}
		if _, err := f.q.GetDocumentReadProjection(f.ctx, generated.GetDocumentReadProjectionParams{ID: id, OrgID: f.org}); err != pgx.ErrNoRows {
			t.Fatal("read projection admitted foreign/deleted/missing row")
		}
		if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+id.String(), "", m.cookie); w.Code != http.StatusNotFound {
			t.Fatalf("scoped detail status=%d", w.Code)
		}
		if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+id.String()+"/versions/1", "", m.cookie); w.Code != http.StatusNotFound {
			t.Fatalf("scoped version detail status=%d", w.Code)
		}
	}
	for _, doc := range []*generated.Document{m.current, m.reviewed, m.static, block} {
		full, err := f.q.GetDocumentVersionByNo(f.ctx, generated.GetDocumentVersionByNoParams{DocumentID: doc.ID, VersionNo: 1})
		if err != nil {
			t.Fatal(err)
		}
		before, err := json.Marshal(full)
		if err != nil {
			t.Fatal(err)
		}
		if doc.ID == m.current.ID && len(full.HtmlSourceJson) < 128<<10 {
			t.Fatal("sizable internal version did not retain exact source")
		}
		projection, err := f.q.GetDocumentVersionByNoForRead(f.ctx, generated.GetDocumentVersionByNoForReadParams{DocumentID: doc.ID, VersionNo: 1})
		if err != nil {
			t.Fatal(err)
		}
		withoutSource := *full
		withoutSource.HtmlSourceJson = nil
		if len(projection.HtmlSourceJson) != 0 || !reflect.DeepEqual((*generated.DocumentVersion)(projection), &withoutSource) {
			t.Fatal("public version query loaded inline source or lost retained ordinary fields")
		}
		w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+doc.ID.String()+"/versions/1", "", m.cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("version metadata read status=%d", w.Code)
		}
		var fields map[string]json.RawMessage
		if err = json.Unmarshal(w.Body.Bytes(), &fields); err != nil {
			t.Fatal(err)
		}
		allowed := map[string]bool{"id": true, "document_id": true, "version_no": true, "name": true, "source_kind": true, "blocks_json": true, "variables_json": true, "created_by": true, "created_via": true, "created_at": true, "parent_id": true, "schema_version": true, "summary": true}
		for key := range fields {
			if !allowed[key] {
				t.Fatalf("version detail disclosed nonpublic field %s", key)
			}
		}
		if len(w.Body.Bytes()) > 8<<10 || bytes.Contains(w.Body.Bytes(), []byte("Bounded synthetic approved layout.")) {
			t.Fatal("version detail transferred inline source/master/asset bytes")
		}
		var got versionDTO
		if err = json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		wantJSON, err := json.Marshal(toVersionDTO(full))
		if err != nil {
			t.Fatal(err)
		}
		var want versionDTO
		if err = json.Unmarshal(wantJSON, &want); err != nil || !reflect.DeepEqual(got, want) {
			t.Fatal("version detail changed ordinary block/static/HTML metadata shape")
		}
		after, err := f.q.GetDocumentVersionByNo(f.ctx, generated.GetDocumentVersionByNoParams{DocumentID: doc.ID, VersionNo: 1})
		if err != nil {
			t.Fatal(err)
		}
		afterJSON, err := json.Marshal(after)
		if err != nil || !bytes.Equal(before, afterJSON) {
			t.Fatal("public version read changed immutable internal snapshot")
		}
	}
	if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+m.current.ID.String()+"/versions/1", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous version read status=%d", w.Code)
	}
	for _, suffix := range []string{"/html/source", "/html/history", "/html/revisions/1/source", "/html/revisions/2/source"} {
		if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/documents/"+m.current.ID.String()+suffix, "", m.cookie); w.Code != http.StatusOK {
			t.Fatalf("full source/history route %s status=%d", suffix, w.Code)
		}
	}
	assertMetadataNoEffectsE2E(t, m, events, renders, requests, states)
}

func TestEnvelopeMetadataReadAndReorderPreserveHTMLPinsE2E(t *testing.T) {
	m := setupMetadataProjectionE2E(t)
	f := m.f
	// The creation fixture only installs dependencies for HTML creation.
	// Envelope routes are mounted when their engine is explicitly configured.
	f.s.Envelopes = envelopes.New(f.q)
	created := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents", `{"name":"Metadata envelope","source_kind":"blocks","blocks_json":{"version":1,"blocks":[]},"variables_json":{}}`, m.cookie)
	var createdParent documentResponse
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &createdParent) != nil || createdParent.ID == uuid.Nil {
		t.Fatalf("actual metadata envelope parent=%d %s", created.Code, created.Body.String())
	}
	parent, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: createdParent.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if promoted := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+parent.ID.String()+"/promote-to-envelope", "{}", m.cookie); promoted.Code != http.StatusOK {
		t.Fatalf("actual metadata envelope promotion=%d %s", promoted.Code, promoted.Body.String())
	}
	children := []*generated.Document{m.current, m.reviewed, m.legacy, m.static}
	for i, doc := range children {
		if _, err := f.q.AttachToEnvelope(f.ctx, generated.AttachToEnvelopeParams{ID: doc.ID, ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: int32(i + 1), Valid: true}, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
	}
	deleted := seedDocumentDeleteDraft(t, f.ctx, f.q, f.org, f.user.ID)
	if _, err := f.q.AttachToEnvelope(f.ctx, generated.AttachToEnvelopeParams{ID: deleted.ID, ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: 5, Valid: true}, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: deleted.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	states := map[uuid.UUID][]byte{}
	for _, doc := range children {
		states[doc.ID] = metadataHistoryStateE2E(t, f, doc.ID)
	}
	events, renders, requests := metadataAuditCountE2E(t, f), len(m.renderer.sources()), m.storage.requests.Load()
	assertChildren := func(path, method, body string) []documentResponse {
		t.Helper()
		w := submitSessionOperationE2E(f.s, method, path, body, m.cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("envelope metadata status=%d", w.Code)
		}
		var result struct {
			Children []documentResponse `json:"children"`
			Count    int                `json:"count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		full, err := f.q.ListEnvelopeChildren(f.ctx, generated.ListEnvelopeChildrenParams{ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, OrgID: f.org})
		if err != nil || len(full) != 5 || result.Count != len(full) || len(result.Children) != len(full) {
			t.Fatal("envelope metadata changed existing deleted-child count semantics")
		}
		thin, err := f.q.ListEnvelopeChildMetadataForRead(f.ctx, generated.ListEnvelopeChildMetadataForReadParams{ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, OrgID: f.org})
		if err != nil || len(thin) != len(full) {
			t.Fatal("thin/full child query parity lost")
		}
		for i, doc := range full {
			assertMetadataDTOE2E(t, result.Children[i], doc)
			assertMetadataDTOE2E(t, toEnvelopeChildMetadataResponse(thin[i]), doc)
			if !thin[i].ParentEnvelopeID.Valid || uuid.UUID(thin[i].ParentEnvelopeID.Bytes) != parent.ID || thin[i].EnvelopePosition != doc.EnvelopePosition || thin[i].IsEnvelope != doc.IsEnvelope {
				t.Fatal("SQL child linkage metadata lost")
			}
			raw, err := json.Marshal(thin[i])
			if err != nil || len(raw) > 8<<10 || bytes.Contains(raw, []byte("Bounded synthetic approved layout.")) {
				t.Fatal("child metadata transferred inline source")
			}
		}
		return result.Children
	}
	path := "/api/v1/envelopes/" + parent.ID.String()
	assertChildren(path+"/children", http.MethodGet, "")
	assertMetadataNoEffectsE2E(t, m, events, renders, requests, states)
	// Foreign org predicate must return no children even for a known parent.
	foreign, err := f.q.ListEnvelopeChildMetadataForRead(f.ctx, generated.ListEnvelopeChildMetadataForReadParams{ParentEnvelopeID: pgtype.UUID{Bytes: parent.ID, Valid: true}, OrgID: uuid.New()})
	if err != nil || len(foreign) != 0 {
		t.Fatal("child metadata crossed tenant boundary")
	}
	ids := []string{m.static.ID.String(), m.legacy.ID.String(), m.reviewed.ID.String(), m.current.ID.String()}
	body, err := json.Marshal(map[string]any{"child_ids": ids})
	if err != nil {
		t.Fatal(err)
	}
	reordered := assertChildren(path+"/reorder", http.MethodPost, string(body))
	for i, id := range ids {
		if reordered[i].ID.String() != id {
			t.Fatalf("reorder response order lost at index %d", i)
		}
	}
	assertChildren(path+"/children", http.MethodGet, "")
	assertMetadataNoEffectsE2E(t, m, events+1, renders, requests, states)
	var auditCount int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id=$2 AND payload_json->>'tool'='reorder_envelope'`, parent.ID, f.user.ID).Scan(&auditCount); err != nil { //nolint:rawsql -- verify the intended committed reorder event in this synthetic fixture
		t.Fatal(err)
	}
	if auditCount != 1 {
		t.Fatal("reorder metadata publication lost its one intended audit event")
	}
	t.Logf("bounded metadata proof retained %d HTML bytes in authoritative current document", len(metadataFullDocumentE2E(t, f, m.current.ID).HtmlCurrentSourceJson))
}
