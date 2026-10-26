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
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func automationDocumentKeyE2E(t *testing.T, q *ownedPublicReadFixtureV1, scopes ...string) (string, uuid.UUID) {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	row, err := q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, KeyPrefix: key.Prefix, KeyHash: key.Hash, Name: "External product machine API", Scopes: scopes})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	return key.Plaintext, row.ID
}

func automationDocumentRequestE2E(q *ownedPublicReadFixtureV1, ctx context.Context, method, path, key, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, q.f.s.PublicURL+"/api/automation/v1"+path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+key)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, r)
	return w
}

func automationDocumentPreparedE2E(t *testing.T, q *ownedPublicReadFixtureV1) *generated.Document {
	t.Helper()
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(body), q.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("actual document review=%d %s", w.Code, w.Body.String())
	}
	return packageLatest223(t, q, doc.ID)
}

type automationDocumentRuntimeBaselineE2E struct {
	pending pdfadmission.ApplicationSessionPendingV1
	org     workguard.SnapshotV1
	global  workguard.SnapshotV1
}

// Capture this constructor's real observer-only birth state. The authorization
// fixture omits the unrelated legacy lifecycle document, so it cannot inherit
// another fixture's hardcoded two-observer count. Later checks compare this
// entire exact baseline, never an allowed range or a second invented budget.
func automationDocumentRuntimeBaselineV1(t *testing.T, q *ownedPublicReadFixtureV1) automationDocumentRuntimeBaselineE2E {
	t.Helper()
	q.reconcileV1(t)
	baseline := automationDocumentRuntimeBaselineE2E{pending: q.runtime.SessionsV1().PendingV1(), org: q.snapshotV1(t)}
	var err error
	baseline.global, err = q.runtime.SnapshotV1(uuid.Nil)
	p, org, global := baseline.pending, baseline.org, baseline.global
	if err != nil || p.ObserverSessions < 1 || p != (pdfadmission.ApplicationSessionPendingV1{ObserverSessions: p.ObserverSessions}) ||
		org.Global != (workguard.VectorV1{SQLSessions: int64(p.ObserverSessions)}) || org.GlobalGrants != int64(p.ObserverSessions) ||
		org.Organisation != (workguard.VectorV1{SQLSessions: 1}) || org.OrganisationGrants != 1 ||
		global.Global != org.Global || global.GlobalGrants != org.GlobalGrants || global.ActiveOrganisations != org.ActiveOrganisations ||
		global.Organisation != (workguard.VectorV1{}) || global.OrganisationGrants != 0 {
		t.Fatal("actual authorization fixture has work/unknown debt or inconsistent original observer accounting")
	}
	t.Logf("actual fixture observer-only baseline/check: observers=%d global_sql=%d organisation_sql=%d global_grants=%d organisation_grants=%d",
		p.ObserverSessions, org.Global.SQLSessions, org.Organisation.SQLSessions, org.GlobalGrants, org.OrganisationGrants)
	return baseline
}

func assertAutomationDocumentRuntimeBaselineE2E(t *testing.T, q *ownedPublicReadFixtureV1, before automationDocumentRuntimeBaselineE2E) {
	t.Helper()
	if after := automationDocumentRuntimeBaselineV1(t, q); after != before {
		t.Fatal("machine operation did not settle to its exact original process/tenant observer baseline")
	}
}

func automationDocumentCeremonySnapshotE2E(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var extra string
	// f.snapshot includes full documents, recipients/token hashes+expiry,
	// variables, history, lawful-basis confirmation, sealing intent and reminders.
	// Include every org event and this unique disposable DB's entire mail queue
	// too. Deliberately exclude the key/user rows changed by revocation fixtures.
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e WHERE e.org_id=$1),
 'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY ed.id),'[]'::jsonb) FROM email_deliveries ed))::text`, q.f.org).Scan(&extra) //nolint:rawsql -- read-only snapshot of exact isolated synthetic estate
	if err != nil {
		t.Fatal("capture synthetic machine ceremony and outbox state")
	}
	return q.f.snapshot(t) + "\n" + extra
}

func TestAutomationDocumentExistingHTMLSendAndReadE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	runtimeBaseline := automationDocumentRuntimeBaselineV1(t, q)
	doc := automationDocumentPreparedE2E(t, q)
	key, keyID := automationDocumentKeyE2E(t, q, "read", "write:workflow")
	// This external product has no MCP connection or browser session. It sends
	// an already-reviewed real HTML/PDF document, not a blocks API template.
	q.f.s.MCP = nil
	path := "/documents/" + doc.ID.String()
	for _, route := range []string{"/documents", path, path + "/pdf", "/templates", "/templates/" + q.template.ID.String()} {
		w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, route, key, "")
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("machine read %s=%d", route, w.Code)
		}
		if route == path+"/pdf" {
			sum := sha256.Sum256(w.Body.Bytes())
			if !bytes.Equal(sum[:], doc.PdfSha256) {
				t.Fatal("machine source PDF differs from reviewed exact source")
			}
		}
	}
	for _, suffix := range []string{"/final-pdf", "/audit-cert"} {
		if w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+suffix, key, ""); w.Code != http.StatusConflict {
			t.Fatalf("draft completed artifact=%d", w.Code)
		}
	}
	beforeRecipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
	if err != nil || len(beforeRecipients) != 2 {
		t.Fatal("draft fixture did not establish both intended participants")
	}
	var beforeEmails int
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1)`, doc.ID).Scan(&beforeEmails); err != nil || beforeEmails != 0 { //nolint:rawsql -- exact pre-invitation queue baseline
		t.Fatal("draft fixture already contains recipient invitation mail")
	}
	w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodPost, path+"/send", key, `{"lawful_basis":"contract"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("existing HTML API Send=%d %s", w.Code, w.Body.String())
	}
	var response map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response) != 2 || response["document_id"] == nil || string(response["status"]) != `"sent"` {
		t.Fatal("machine Send did not return exact link-free document/status", err)
	}
	if strings.Contains(w.Body.String(), "/sign/") || response["links"] != nil {
		t.Fatal("machine Send disclosed signer bearer capability")
	}
	var invited, sentEvents, invitationEvents, queuedInvites int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id
  WHERE d.id=$1 AND d.org_id=$2 AND d.status='sent' AND d.sent_at IS NOT NULL
    AND r.status='sent' AND r.sent_at IS NOT NULL AND octet_length(r.magic_token_hash)=32
    AND r.magic_token_expires_at>clock_timestamp()),
 (SELECT count(*) FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.sent'),
 (SELECT count(*) FROM events e JOIN recipients r ON r.id=e.recipient_id AND r.document_id=e.document_id
  WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='recipient.invited'),
 (SELECT count(*) FROM email_deliveries ed WHERE ed.to_email IN (SELECT email FROM recipients WHERE document_id=$1)
  AND ed.status='pending' AND ed.attempts=0 AND position($3::text in ed.text_body)>0)`, doc.ID, q.f.org, q.f.s.PublicURL+"/sign/").Scan(&invited, &sentEvents, &invitationEvents, &queuedInvites) //nolint:rawsql -- actual native sent/invitation/audit/queued-mail proof, not SMTP delivery
	if err != nil || invited != 2 || sentEvents != 1 || invitationEvents != 2 || queuedInvites != 2 {
		t.Fatalf("native Send invitation proof: future_sent=%d document_sent_events=%d invitation_events=%d queued_invites=%d query_failed=%t", invited, sentEvents, invitationEvents, queuedInvites, err != nil)
	}
	afterRecipients, err := q.f.q.ListRecipientsByDocument(q.f.ctx, doc.ID)
	if err != nil || len(afterRecipients) != len(beforeRecipients) {
		t.Fatal("native Send changed the intended participant set")
	}
	for _, before := range beforeRecipients {
		found := false
		for _, after := range afterRecipients {
			if before.ID == after.ID {
				found = true
				if bytes.Equal(before.MagicTokenHash, after.MagicTokenHash) {
					t.Fatal("native Send retained a draft token instead of rotating the invitation credential")
				}
			}
		}
		if !found {
			t.Fatal("native Send replaced an intended named participant")
		}
	}
	if w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodPost, path+"/send", key, `{"lawful_basis":"contract"}`); w.Code != http.StatusConflict {
		t.Fatalf("ordinary replay=%d", w.Code)
	}
	if w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path, key, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"sent"`) {
		t.Fatal("same-ID reconciliation lost sent status")
	}
	// A valid API key for another real tenant cannot select this document.
	other, err := q.f.q.CreateOrg(q.f.ctx, generated.CreateOrgParams{Name: "Independent external tenant", Plan: "free"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.f.q.CreateUser(q.f.ctx, generated.CreateUserParams{OrgID: other.ID, Name: "Other owner", Email: uuid.NewString() + "@external-product.test", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: other.ID, UserID: user.ID, Name: "Other product", KeyPrefix: foreign.Prefix, KeyHash: foreign.Hash, Scopes: []string{"read", "write:workflow"}}); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"", "/pdf", "/final-pdf"} {
		if w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+suffix, foreign.Plaintext, ""); w.Code != http.StatusNotFound {
			t.Fatalf("foreign document read %s=%d", suffix, w.Code)
		}
	}
	if _, err = q.f.pool.Exec(q.f.ctx, "UPDATE api_keys SET scopes=ARRAY['write:workflow']::text[] WHERE id=$1", keyID); err != nil {
		t.Fatal(err)
	}
	if w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path, key, ""); w.Code != http.StatusForbidden {
		t.Fatalf("reduced read scope=%d", w.Code)
	}
	assertAutomationDocumentRuntimeBaselineE2E(t, q, runtimeBaseline)
}

func TestAutomationDocumentSendRechecksOriginalCredentialE2E(t *testing.T) {
	for _, change := range []string{"key revoked", "workflow removed", "issuer demoted"} {
		t.Run(change, func(t *testing.T) {
			q := newOwnedAutomationAuthorizationFixtureV1(t)
			runtimeBaseline := automationDocumentRuntimeBaselineV1(t, q)
			doc := automationDocumentPreparedE2E(t, q)
			key, keyID := automationDocumentKeyE2E(t, q, "read", "write:workflow")
			before := automationDocumentCeremonySnapshotE2E(t, q)
			held, err := q.f.pool.Begin(q.f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nativeReminderRollback255(t, held)
			if _, err = q.f.q.WithTx(held).GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: q.f.org}); err != nil {
				t.Fatal(err)
			}
			result, cancel, joined := nativeReminderAsyncHTTP255(q.f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
				return automationDocumentRequestE2E(q, ctx, http.MethodPost, "/documents/"+doc.ID.String()+"/send", key, `{"lawful_basis":"contract"}`)
			})
			defer nativeReminderCleanupHTTP255(t, held, cancel, joined)
			awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, nativeLifecycleLockQuery256("send"), "transactionid")
			switch change {
			case "key revoked":
				_, err = q.f.pool.Exec(q.f.ctx, "DELETE FROM api_keys WHERE id=$1", keyID)
			case "workflow removed":
				_, err = q.f.pool.Exec(q.f.ctx, "UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1", keyID)
			case "issuer demoted":
				_, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = held.Commit(q.f.ctx); err != nil {
				t.Fatal(err)
			}
			w := receiveSessionOperationE2E(t, result)
			if w.Code != http.StatusForbidden {
				t.Fatalf("stale API send=%d %s", w.Code, w.Body.String())
			}
			if before != automationDocumentCeremonySnapshotE2E(t, q) {
				t.Fatal("revoked API Send changed document/recipient credentials, ceremony, audit or outbox state")
			}
			assertAutomationDocumentRuntimeBaselineE2E(t, q, runtimeBaseline)
		})
	}
}

func TestAutomationDocumentCompletedExactArtifactReadsE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	key, _ := automationDocumentKeyE2E(t, q, "read")
	path := "/documents/" + doc.ID.String()
	if w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+"/final-pdf", key, ""); w.Code != http.StatusConflict {
		t.Fatalf("active artifact=%d", w.Code)
	}
	for _, party := range parties {
		rc := q.lookupV1(t, party.Token)
		notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: party.Name, Font: "Caveat", Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic standalone machine artifact qualifier"}); err != nil {
			t.Fatal(err)
		}
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	}
	completed := packageLatest223(t, q, doc.ID)
	if completed.Status != "completed" || !completed.FinalPdfVersionID.Valid || !completed.AuditCertVersionID.Valid {
		t.Fatal("native signing did not publish exact completed artifacts")
	}
	for _, tc := range []struct {
		suffix string
		digest []byte
	}{{"/final-pdf", completed.FinalPdfSha}, {"/audit-cert", completed.AuditCertSha256}} {
		w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+tc.suffix, key, "")
		digest := sha256.Sum256(w.Body.Bytes())
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || !bytes.Equal(digest[:], tc.digest) {
			t.Fatalf("completed API artifact %s=%d exact=%t", tc.suffix, w.Code, bytes.Equal(digest[:], tc.digest))
		}
	}
	q.assertObserversOnlyV1(t)
}

func TestAutomationDocumentPackageObservationAndSealingInspectionE2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	key, _ := automationDocumentKeyE2E(t, q, "read", "write:workflow")
	root := packageImported220(t, q, "External product package observation")
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	path := "/documents/" + root.ID.String()
	w := automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+"/attachments", key, "")
	var inventory pdfadmission.DocumentPackageInventoryV1
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &inventory) != nil || inventory.DocumentID != root.ID {
		t.Fatalf("machine package observation=%d", w.Code)
	}
	var attempt uuid.UUID
	err := withPackageAttempt236(t, q, root, p, packageBirthPlan236{seal: true}, func(_ *pdfadmission.ApplicationHTMLSendOperationV1, _ *pdfadmission.ApplicationSessionV1, meta pdfadmission.HTMLSendPackageIntentMetadataV1, _ authoring.Actor) error {
		attempt = meta.AttemptID
		return nil
	})
	if err != nil || attempt == uuid.Nil {
		t.Fatal("actual native package sealing failed", err)
	}
	w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+"/send-attempts/"+attempt.String(), key, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"outcome":"active"`) || !strings.Contains(w.Body.String(), `"retry_authorized":false`) || strings.Contains(w.Body.String(), "/sign/") {
		t.Fatalf("machine exact sealing inspection=%d %s", w.Code, w.Body.String())
	}
	for _, suffix := range []string{"/final-pdf", "/audit-cert"} {
		if w = automationDocumentRequestE2E(q, q.f.ctx, http.MethodGet, path+suffix, key, ""); w.Code != http.StatusConflict {
			t.Fatalf("sealing final artifact=%d", w.Code)
		}
	}
	q.assertObserversOnlyV1(t)
}
