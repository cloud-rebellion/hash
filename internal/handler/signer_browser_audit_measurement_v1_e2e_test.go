//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Exercise the genuine public-intake/manual source, view and field routes that
// the browser uses before signing. No old event is measured or repaired by the
// test: both the event and its M94 record must come from the same actual writer.
func TestOwnedSignerBrowserViewAndAutosaveKeepCertificateHistoryE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Sign.Storage = f.s.Storage
	actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	doc, party, field, _, invitation := ownedRealBrowserManualAutosaveV1(t, q, fieldBrowserPDF("Reviewed manual browser audit regression"), 1, actor)
	token := strings.TrimPrefix(invitation.Path, "/sign/")
	rc := q.lookupV1(t, token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	post := func(suffix, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/sign/"+token+suffix, strings.NewReader(body)).WithContext(f.ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		return w
	}
	if w := post("/view", `{}`); w.Code != http.StatusOK {
		t.Fatalf("actual browser view status=%d", w.Code)
	}
	q.assertObserversOnlyV1(t)
	if w := post("/view", `{}`); w.Code != http.StatusOK {
		t.Fatalf("idempotent browser view status=%d", w.Code)
	}
	q.assertObserversOnlyV1(t)
	const value = "Reviewed browser reference ÅÄÖ"
	body, err := json.Marshal(submitFieldsInput{Values: []submitFieldValueInput{{FieldID: field.ID.String(), Value: value}}})
	if err != nil {
		t.Fatal(err)
	}
	if w := post("/fields", string(body)); w.Code != http.StatusOK {
		t.Fatalf("actual browser autosave status=%d", w.Code)
	}
	q.assertObserversOnlyV1(t)
	var viewed, filled, measured int
	var saved string
	var noticeMatches bool
	err = f.pool.QueryRow(f.ctx, `SELECT
 count(*) FILTER (WHERE e.kind='document.viewed'),
 count(*) FILTER (WHERE e.kind='document.field_filled'),
 count(*) FILTER (WHERE m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id
 AND m.payload_wire_bytes=octet_length(e.payload_json::text)
 AND m.measurement_server_version_num=current_setting('server_version_num')::integer),
 (SELECT value FROM document_fields WHERE id=$3 AND document_id=$1),
 bool_and(e.payload_json->>'notice_digest'=$5)
 FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id
 WHERE e.document_id=$1 AND e.org_id=$2 AND e.recipient_id=$4
 AND e.kind IN ('document.viewed','document.field_filled')`, doc.ID, f.org, field.ID, party.ID, evidence.Digest).Scan(&viewed, &filled, &measured, &saved, &noticeMatches) //nolint:rawsql -- read-only actual writer/measurement oracle; no backfill
	if err != nil {
		t.Fatal(err)
	}
	if viewed != 1 || filled != 1 || measured != 2 || saved != value || !noticeMatches {
		t.Errorf("browser audit writers must atomically measure original events: viewed=%d filled=%d measured=%d saved_matches=%t notice_matches=%t", viewed, filled, measured, saved == value, noticeMatches)
	}
	rc = q.lookupV1(t, token)
	result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic actual browser audit regression"})
	if closeErr := rc.CloseReadV1(); closeErr != nil {
		t.Fatal(closeErr)
	}
	q.assertObserversOnlyV1(t)
	if err != nil || result == nil || !result.Completed {
		t.Fatalf("view and autosave must preserve complete certificate finalization: err=%v", err)
	}
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || completed.Status != "completed" || !bytes.Equal(completed.PdfSha256, doc.PdfSha256) {
		t.Fatal("completed manual contract lost its approved source", err)
	}
	type pin struct {
		key, version pgtype.Text
		digest       []byte
	}
	var artifacts [][]byte
	for _, p := range []pin{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if !p.key.Valid || !p.version.Valid || p.version.String == "" || len(p.digest) != sha256.Size {
			t.Fatal("browser-audit completion omitted exact terminal artifact pins")
		}
		b, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, p.key.String, p.digest, p.version)
		if err != nil {
			t.Fatal("read exact browser-audit terminal artifact", err)
		}
		artifacts = append(artifacts, b)
	}
	if !bytes.HasPrefix(artifacts[0], []byte("%PDF-")) || !bytes.HasPrefix(artifacts[1], []byte("%PDF-")) || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(artifacts[2]), string(artifacts[3])) {
		t.Fatal("browser-audit final PDFs or detached certificate signature invalid")
	}
}
