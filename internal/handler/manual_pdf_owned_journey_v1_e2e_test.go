//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Functional original manual-PDF journey through actual public creators,
// recipients, assigned visible signature fields and cookie-authorized Send.
// Restricted worker and PostgreSQL are real. Renderer/storage/identities are
// the existing bounded synthetic peers. The historical PDF Sign branch is
// exercised functionally; this test does not assert its separate native owned
// resource boundary or enable the intentionally closed pdf-static-v1 driver.
func TestOwnedManualPDFPublicAuthoringSendTwoSignAndFourArtifactsE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Sign.Storage = f.s.Storage // actual concrete native provider owner, same bounded protocol peer
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL})
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Original manually uploaded PDF terms")))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual manual PDF intake=%d %s", response.Code, response.Body.String())
	}
	var imported struct {
		Document  documentResponse `json:"document"`
		PageCount int              `json:"page_count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil || imported.Document.ID == uuid.Nil || imported.PageCount != 1 {
		t.Fatal("actual manual PDF import identity/page count missing", err)
	}
	original, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if original.SourceKind != "pdf" || len(original.HtmlSourceJson) != 0 || len(original.HtmlCurrentSourceJson) != 0 || len(original.BlocksJson) != 0 || !original.EvidenceVersionPinsRequired || !original.PdfStorageKey.Valid || !original.PdfStorageVersionID.Valid || original.PdfStorageVersionID.String == "" || len(original.PdfSha256) != sha256.Size {
		t.Fatal("actual manual source was replaced/fabricated or lacks exact imported bytes/version")
	}
	originalPDF, err := readDocumentArtifact(f.ctx, f.s.Storage, original, original.PdfStorageKey.String, original.PdfSha256, original.PdfStorageVersionID)
	if err != nil || !bytes.HasPrefix(originalPDF, []byte("%PDF-")) {
		t.Fatal("exact cleaned uploaded PDF unavailable", err)
	}
	key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	recipients := make(map[uuid.UUID]string, 2)
	for index, role := range []string{"buyer", "seller"} {
		raw, err := json.Marshal(map[string]any{"email": role + "@manual-pdf.example.test", "name": "Manual PDF " + role, "role": role, "order_index": index, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/recipients", string(raw), q.cookie)
		if response.Code != http.StatusCreated {
			t.Fatalf("actual manual PDF participant=%d %s", response.Code, response.Body.String())
		}
		var recipient recipientResponse
		if err = json.Unmarshal(response.Body.Bytes(), &recipient); err != nil || recipient.ID == uuid.Nil || recipient.DocumentID != original.ID || recipient.Role != role {
			t.Fatal("actual manual PDF recipient identity missing", err)
		}
		recipients[recipient.ID] = role
		response = httptest.NewRecorder()
		f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "MCP", "add_document_field", key.Plaintext, map[string]any{"document_id": original.ID.String(), "recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "x_pct": 1500, "y_pct": 5500 + index*1500, "w_pct": 3000, "h_pct": 800, "required": "true", "label": "Visible " + role + " signature"}, nil))
		fieldMCPTextE2E(t, response, false)
		ownedPlainAssertDrainedV1(t, q)
	}
	var count int
	var exact bool
	err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,bool_and(f.type='signature' AND f.required AND f.page=1 AND f.w_pct=30 AND f.h_pct=8 AND f.recipient_id IS NOT NULL AND c.field_id=f.id AND c.document_id=f.document_id AND c.org_id=d.org_id AND c.options_wire_bytes=octet_length(f.options_json::text) AND c.measurement_server_version_num=current_setting('server_version_num')::integer)
 FROM document_fields f JOIN documents d ON d.id=f.document_id LEFT JOIN field_signing_policy_sizes_v1 c ON c.field_id=f.id WHERE d.id=$1 AND d.org_id=$2`, original.ID, f.org).Scan(&count, &exact)
	if err != nil || count != 2 || !exact {
		t.Fatal("normal native field writers did not establish actual visible signature layout/fresh measurements", err)
	} //nolint:rawsql -- actual source/cache layout oracle; no fabricated stamp, cache insert or static driver
	response = submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("actual cookie-authorized manual PDF Send=%d %s", response.Code, response.Body.String())
	}
	var sent sendDocumentResponse
	if err = json.Unmarshal(response.Body.Bytes(), &sent); err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatal("actual manual PDF Send omitted original links", err)
	}
	ownedPlainAssertDrainedV1(t, q)
	sentDocument, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil || sentDocument.Status != "sent" || sentDocument.SourceKind != "pdf" || sentDocument.PdfStorageKey != original.PdfStorageKey || sentDocument.PdfStorageVersionID != original.PdfStorageVersionID || !bytes.Equal(sentDocument.PdfSha256, original.PdfSha256) || !bytes.Equal(sentDocument.MetadataRedactionReport, original.MetadataRedactionReport) || len(sentDocument.HtmlSourceJson) != 0 || len(sentDocument.HtmlCurrentSourceJson) != 0 {
		t.Fatal("Send changed approved cleaned uploaded PDF/history instead of freezing original source", err)
	}
	finalToken := ""
	var completionOutboxBefore map[uuid.UUID]struct{}
	for index, link := range sent.Links {
		if recipients[link.RecipientID] != link.Role {
			t.Fatal("actual Send link lost original assigned recipient role")
		}
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		token := strings.TrimPrefix(u.Path, "/sign/")
		if token == "" {
			t.Fatal("original magic-link capability missing")
		}
		rc := q.lookupV1(t, token)
		notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		if index == len(sent.Links)-1 {
			completionOutboxBefore = completedCompanionOutboxIDsV1(t, q)
		}
		result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: link.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic actual manual PDF journey"})
		if err != nil {
			t.Fatal("actual manual PDF signature", err)
		}
		if result.Completed != (index == len(sent.Links)-1) {
			var state string
			diagnosticErr := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('status',d.status,'admission',d.signing_admission_policy,'recipients',(SELECT jsonb_agg(jsonb_build_object('id',r.id,'role',r.role,'status',r.status) ORDER BY r.order_index,r.id) FROM recipients r WHERE document_id=d.id),'fields',(SELECT jsonb_agg(jsonb_build_object('id',x.id,'recipient',x.recipient_id,'type',x.type,'required',x.required) ORDER BY x.id) FROM document_fields x WHERE document_id=d.id),'signatures',(SELECT count(*) FROM signatures WHERE document_id=d.id),'finalization_intent',(SELECT jsonb_build_object('stage',CASE WHEN i.retention_completed_at IS NOT NULL THEN 'retention_completed' WHEN i.retention_started_at IS NOT NULL THEN 'retention_started' ELSE 'checkpointed' END,'attempts',i.attempts,'last_error',i.last_error,'retention_started',i.retention_started_at IS NOT NULL,'retention_completed',i.retention_completed_at IS NOT NULL) FROM document_finalization_intents i WHERE i.document_id=d.id AND i.org_id=d.org_id))::text FROM documents d WHERE d.id=$1 AND d.org_id=$2`, original.ID, f.org).Scan(&state) //nolint:rawsql -- bounded actual committed ceremony diagnostic, no capabilities or secrets
			_ = rc.CloseReadV1()
			t.Fatalf("actual manual PDF completion mismatch: index=%d of %d role=%s recipient=%s completed=%v status=%s actual=%s diagnostic_error=%v", index, len(sent.Links), link.Role, link.RecipientID, result.Completed, result.Status, state, diagnosticErr)
		}
		if result.Completed {
			u, err := url.Parse(result.FinalPDFURL)
			if err != nil {
				t.Fatal(err)
			}
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) != 3 || parts[0] != "sign" || parts[2] != "final-pdf" {
				t.Fatal("actual final capability malformed")
			}
			finalToken = parts[1]
			if result.AuditCertURL != "/sign/"+finalToken+"/audit-cert" {
				t.Fatal("actual completed result omitted matching audit certificate capability")
			}
		}
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		q.assertObserversOnlyV1(t)
	}
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil || completed.Status != "completed" {
		t.Fatal("actual manually uploaded PDF not completed", err)
	}
	var signed, signatures int
	if err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*) FROM recipients WHERE document_id=$1 AND status='signed'),(SELECT count(*) FROM signatures WHERE document_id=$1)", original.ID).Scan(&signed, &signatures); err != nil || signed != 2 || signatures != 2 {
		t.Fatal("actual manual PDF required signature persistence missing", err)
	} //nolint:rawsql -- actual completed ceremony oracle only
	type artifact struct {
		key, version pgtype.Text
		digest       []byte
	}
	var verified [][]byte
	for _, item := range []artifact{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if !item.key.Valid || !item.version.Valid || item.version.String == "" || len(item.digest) != sha256.Size {
			t.Fatal("manual PDF completion missing one of four exact artifact pins")
		}
		body, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, item.key.String, item.digest, item.version)
		if err != nil {
			t.Fatal("actual manual PDF artifact retrieval", err)
		}
		verified = append(verified, body)
	}
	if !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(verified[2]), string(verified[3])) {
		t.Fatal("actual manual PDF detached signing evidence signature invalid")
	}
	if !bytes.HasPrefix(verified[0], []byte("%PDF-")) || !bytes.HasPrefix(verified[1], []byte("%PDF-")) {
		t.Fatal("completed final/audit PDFs missing")
	}
	if finalToken == "" {
		t.Fatal("actual final capability absent")
	}
	if response = q.requestV1(finalToken, "/final-pdf"); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), verified[0]) {
		t.Fatalf("actual completed manual PDF public download=%d", response.Code)
	}
	if response = q.requestV1(finalToken, "/audit-cert"); response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), verified[1]) {
		t.Fatalf("actual completed audit certificate public download=%d", response.Code)
	}
	q.assertObserversOnlyV1(t)
	assertCompletedCompanionOutboxV1(t, q, completed, completionOutboxBefore, verified[1])
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		oldToken := strings.TrimPrefix(u.Path, "/sign/")
		if denied := q.requestV1(oldToken, "/audit-cert"); denied.Code != http.StatusNotFound || bytes.Contains(denied.Body.Bytes(), []byte("%PDF-")) {
			t.Fatal("old invitation accessed completed audit certificate")
		}
	}
	assertCompletedCompanionAwaitFencesV1(t, q, completed, finalToken, verified[1])
	q.assertObserversOnlyV1(t)
}
