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
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	evidenceverify "github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/malwarescan"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Genuine no-history fixture, public measured PDF intake/PATCH/recipient writers,
// native Send and actual Article13 lookup/evidence/Accept. Renderer/storage are
// bounded synthetic protocol peers. This is certificate/finalization acceptance,
// not deployed provider, antivirus or configured capacity evidence. No cache
// INSERT, read repair, fake transaction or pre-signed/accepted source is used.
func TestOwnedAcknowledgementTwoAcceptorsFourArtifactsAndLastUseE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Sign.Storage = f.s.Storage
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Both parties acknowledge the exact original uploaded PDF terms.")))
	if response.Code != http.StatusCreated {
		t.Fatalf("actual acknowledgement PDF intake=%d %s", response.Code, response.Body.String())
	}
	var imported struct {
		Document  documentResponse `json:"document"`
		PageCount int              `json:"page_count"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil || imported.Document.ID == uuid.Nil || imported.PageCount != 1 {
		t.Fatal("actual acknowledgement PDF source identity/pages missing", err)
	}
	created, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.Document.ID, OrgID: f.org})
	if err != nil || created.SourceKind != "pdf" || len(created.HtmlSourceJson) != 0 || len(created.HtmlCurrentSourceJson) != 0 || len(created.BlocksJson) != 0 || !created.EvidenceVersionPinsRequired || !created.PdfStorageKey.Valid || !created.PdfStorageVersionID.Valid || created.PdfStorageVersionID.String == "" || len(created.PdfSha256) != sha256.Size {
		t.Fatal("actual acknowledgement source lacks genuine imported PDF pins", err)
	}
	originalPDF, err := readDocumentArtifact(f.ctx, f.s.Storage, created, created.PdfStorageKey.String, created.PdfSha256, created.PdfStorageVersionID)
	if err != nil || !bytes.HasPrefix(originalPDF, []byte("%PDF-")) {
		t.Fatal("actual acknowledgement original cleaned PDF unavailable", err)
	}
	f.doc = created
	q.f.doc = created
	original, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"expected_updated_at": original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/documents/" + created.ID.String()
	patched := submitSessionOperationE2E(f.s, http.MethodPatch, base, string(body), q.cookie)
	if patched.Code != http.StatusOK {
		t.Fatalf("actual acknowledgement PATCH=%d %s", patched.Code, patched.Body.String())
	}
	for _, role := range []string{"buyer", "seller"} {
		raw, err := json.Marshal(map[string]any{"email": role + "@ack.example.test", "name": "Synthetic " + role, "role": role, "order_index": 0, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", string(raw), q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatalf("actual acknowledgement participant=%d %s", w.Code, w.Body.String())
		}
	}
	actor := sendengine.Actor{OrgID: f.org, UserID: &f.user.ID, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
		if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}}
	sent, err := f.s.Send.Send(f.ctx, actor, created.ID)
	defer sent.CloseConsumerV1()
	if err != nil || sent.Status != "sent" || len(sent.Links) != 2 {
		t.Fatalf("actual acknowledgement Send=%+v/%v", sent, err)
	}
	type party struct {
		token     string
		recipient uuid.UUID
	}
	parties := make([]party, 0, 2)
	for _, link := range sent.Links {
		u, err := url.Parse(link.URL)
		if err != nil {
			t.Fatal(err)
		}
		parties = append(parties, party{strings.Clone(strings.TrimPrefix(u.Path, "/sign/")), link.RecipientID})
	}
	sent.Links = nil
	sent.CloseConsumerV1()
	ownedPlainAssertDrainedV1(t, q)
	sourceSnapshot := func() string {
		t.Helper()
		var state string
		err := f.pool.QueryRow(f.ctx, "SELECT jsonb_build_array(d.blocks_json,d.variables_json,d.html_source_json,d.html_current_source_json,d.metadata,d.metadata_redaction_report,to_jsonb(p),to_jsonb(r),to_jsonb(s))::text FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id JOIN document_read_report_sizes_v1 s ON s.document_id=d.id WHERE d.id=$1 AND d.org_id=$2", created.ID, f.org).Scan(&state)
		if err != nil || state == "" {
			t.Fatal("actual acknowledgement immutable source/cache oracle", err)
		}
		return state
	} //nolint:rawsql -- original source/cache read oracle
	before := sourceSnapshot()
	gate := newOwnedPlainAuditGateV1(audit.KindDocumentCompleted)
	defer func() {
		gate.unblock()
		select {
		case <-gate.started:
			ownedPlainAwaitV1(t, gate.returned, "actual acknowledgement terminal hook cleanup")
		default:
		}
	}()
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindDocumentCompleted || e.DocumentID == nil || *e.DocumentID != created.ID {
			return
		}
		gate.eventID = id
		gate.entry = e
		close(gate.started)
		<-gate.release
		close(gate.returned)
	})
	acceptedGate := newOwnedPlainAuditGateV1(audit.KindDocumentAccepted)
	defer func() {
		acceptedGate.unblock()
		select {
		case <-acceptedGate.started:
			ownedPlainAwaitV1(t, acceptedGate.returned, "actual accepted hook cleanup")
		default:
		}
	}()
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindDocumentAccepted || e.DocumentID == nil || *e.DocumentID != created.ID || e.RecipientID == nil || *e.RecipientID != parties[0].recipient {
			return
		}
		acceptedGate.eventID, acceptedGate.entry = id, e
		close(acceptedGate.started)
		<-acceptedGate.release
		close(acceptedGate.returned)
	})
	var finalToken string
	for i, p := range parties {
		rc := q.lookupV1(t, p.token)
		t.Cleanup(func() {
			if err := rc.CloseReadV1(); err != nil {
				t.Error(err)
			}
		})
		if rc.Document.ID != created.ID || rc.Recipient.ID != p.recipient || rc.Document.RequiresSignature {
			t.Fatal("actual acknowledgement lookup/party source differs")
		}
		notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(p.token, ""), rc)
		if err != nil {
			t.Fatal(err)
		}
		evidence, err := signerArticle13NoticeEvidence(rc, notice)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := q.runtime.SnapshotV1(f.org)
		if err != nil {
			t.Fatal(err)
		}
		result, err := f.s.Sign.Accept(f.ctx, rc, sign.ParticipantResponseEvidence{Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic owned acknowledgement qualifier"})
		if err != nil {
			t.Fatal("actual acknowledgement Accept", err)
		}
		if result == nil || result.Completed != (i == len(parties)-1) {
			var state, intent string
			var count int
			diagErr := f.pool.QueryRow(f.ctx, "SELECT d.status,(SELECT count(*)::integer FROM recipients r WHERE r.document_id=d.id AND r.status='accepted'),coalesce((SELECT to_jsonb(i)::text FROM document_finalization_intents i WHERE i.document_id=d.id),'null') FROM documents d WHERE d.id=$1 AND d.org_id=$2", created.ID, f.org).Scan(&state, &count, &intent)
			t.Fatalf("actual acknowledgement completed before/without both required acceptors: result=%+v status=%s accepted=%d intent=%s diagnostic=%v", result, state, count, intent, diagErr)
		} //nolint:rawsql -- safe synthetic failure diagnostics, no retry/repair
		if !result.Completed {
			if result.Status != "in_progress" || result.FinalPDFURL != "" || result.FinalPDFKey != "" {
				t.Fatal("first acceptor received a premature final capability")
			}
			ownedPlainAwaitV1(t, acceptedGate.started, "actual accepted event hook")
			if acceptedGate.entry.OrgID != f.org || acceptedGate.entry.ActorUserID != nil || acceptedGate.entry.RecipientID == nil || *acceptedGate.entry.RecipientID != p.recipient || acceptedGate.entry.Payload["recipient_email"] != rc.Recipient.Email || acceptedGate.entry.Payload["notice_schema"] != evidence.Schema || acceptedGate.entry.Payload["notice_digest"] != evidence.Digest {
				t.Fatal("actual acceptance hook identity/original evidence changed")
			}
			var freshAcceptance bool
			if err = f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.id=$1 AND e.document_id=$2 AND e.org_id=$3 AND e.recipient_id=$4 AND e.actor_user_id IS NULL AND e.kind='document.accepted' AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)", acceptedGate.eventID, created.ID, f.org, p.recipient).Scan(&freshAcceptance); err != nil || !freshAcceptance {
				t.Fatal("actual accepted event lacks fresh native M94", err)
			} //nolint:rawsql -- actual committed fresh acceptance measurement oracle
			if duplicate, duplicateErr := f.s.Sign.Accept(f.ctx, rc, sign.ParticipantResponseEvidence{Notice: evidence, IP: "127.0.0.1", UserAgent: "Synthetic duplicate acknowledgement qualifier"}); !errors.Is(duplicateErr, sign.ErrAlreadyAccepted) || duplicate != nil {
				t.Fatal("duplicate actual acceptance changed original AlreadyAccepted result", duplicate, duplicateErr)
			}
			result = nil
			if err = rc.CloseReadV1(); err != nil {
				t.Fatal(err)
			}
			ownedPlainAssertRetainedV1(t, q, "accepted M94 hook after original response/read lease last use")
			acceptedGate.unblock()
			ownedPlainAwaitV1(t, acceptedGate.returned, "actual accepted event hook last use")
			ownedPlainAssertDrainedV1(t, q)
			continue
		}
		if result.Status != "completed" || result.FinalPDFKey == "" || result.FinalPDFURL == "" {
			t.Fatal("last actual acceptor lacks completed artifact response")
		}
		ownedPlainAwaitV1(t, gate.started, "actual acknowledgement document.completed hook")
		if gate.entry.OrgID != f.org || gate.entry.ActorUserID != nil || gate.entry.RecipientID != nil || gate.eventID == uuid.Nil {
			t.Fatal("actual acknowledgement completion audit identity differs")
		}
		retained, err := q.runtime.SnapshotV1(f.org)
		if err != nil || retained.Global.ParentBytes <= snapshot.Global.ParentBytes || retained.Global.DBStagingBytes <= snapshot.Global.DBStagingBytes {
			t.Fatal("actual acknowledgement certificate/publication result retired before last use", err)
		}
		u, err := url.Parse(result.FinalPDFURL)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) != 3 || parts[0] != "sign" || parts[2] != "final-pdf" {
			t.Fatal("actual acknowledgement final capability shape differs")
		}
		finalToken = strings.Clone(parts[1])
		result = nil
		if err = rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
		ownedPlainAssertRetainedV1(t, q, "acknowledgement M94 hook after actual response/read consumer last use")
		if sourceSnapshot() != before {
			t.Fatal("acknowledgement scalar finalization rewrote original JSON or intrinsic source sizes")
		}
		gate.unblock()
		ownedPlainAwaitV1(t, gate.returned, "actual acknowledgement terminal hook last use")
		ownedPlainAssertDrainedV1(t, q)
	}
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
	if err != nil || completed.Status != "completed" || completed.RequiresSignature {
		t.Fatal("actual acknowledged source did not complete", err)
	}
	var accepted, signatures, events int
	var measured bool
	err = f.pool.QueryRow(f.ctx, "SELECT (SELECT count(*)::integer FROM recipients WHERE document_id=$1 AND status='accepted'),(SELECT count(*)::integer FROM signatures WHERE document_id=$1),(SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='document.completed'),EXISTS(SELECT 1 FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.id=$2 AND e.document_id=$1 AND e.org_id=$3 AND e.kind='document.completed' AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer AND e.actor_user_id IS NULL AND e.recipient_id IS NULL)", created.ID, gate.eventID, f.org).Scan(&accepted, &signatures, &events, &measured)
	if err != nil || accepted != 2 || signatures != 0 || events != 1 || !measured {
		t.Fatal("actual acknowledgement acceptance/terminal M94 counts differ", accepted, signatures, events, measured, err)
	} //nolint:rawsql -- actual source and fresh completion event oracle
	var measuredAcceptances int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.accepted' AND e.actor_user_id IS NULL AND e.recipient_id IS NOT NULL AND m.org_id=e.org_id AND m.document_id=e.document_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer", created.ID, f.org).Scan(&measuredAcceptances); err != nil || measuredAcceptances != 2 {
		t.Fatal("both original acceptance events must have fresh native measurements", measuredAcceptances, err)
	} //nolint:rawsql -- no seeded cache; original accepted event count and fresh measurement oracle
	var hashed []byte
	if err = f.pool.QueryRow(f.ctx, "SELECT payload_hashed FROM events WHERE id=$1 AND org_id=$2 AND document_id=$3", gate.eventID, f.org, created.ID).Scan(&hashed); err != nil {
		t.Fatal(err)
	}
	var completionPayload map[string]any
	if err = json.Unmarshal(hashed, &completionPayload); err != nil {
		t.Fatal("actual acknowledgement terminal hashed payload invalid", err)
	}
	for _, pin := range []struct {
		prefix       string
		key, version pgtype.Text
		digest       []byte
	}{{"final_pdf", completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {"audit_cert", completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {"audit_payload", completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {"audit_signature", completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if completionPayload[pin.prefix+"_key"] != pin.key.String || completionPayload[pin.prefix+"_version_id"] != pin.version.String || completionPayload[pin.prefix+"_sha256"] != hex.EncodeToString(pin.digest) {
			t.Fatal("actual acknowledgement terminal audit differs from exact artifact pins", pin.prefix)
		}
	} //nolint:rawsql -- exact committed original terminal tuple oracle
	type artifact struct {
		key, version pgtype.Text
		digest       []byte
	}
	var verified [][]byte
	for _, a := range []artifact{{completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha}, {completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256}, {completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256}, {completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256}} {
		if !a.key.Valid || !a.version.Valid || a.version.String == "" || len(a.digest) != sha256.Size {
			t.Fatal("actual acknowledgement missing artifact pins")
		}
		body, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, a.key.String, a.digest, a.version)
		if err != nil {
			t.Fatal(err)
		}
		verified = append(verified, body)
	}
	if !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(verified[2]), string(verified[3])) {
		t.Fatal("acknowledgement detached certificate signature invalid")
	}
	if !bytes.Equal(verified[0], originalPDF) {
		t.Fatalf("acknowledgement final must equal exact cleaned original PDF: final_bytes=%d original_bytes=%d final_sha256=%x original_sha256=%x", len(verified[0]), len(originalPDF), sha256.Sum256(verified[0]), sha256.Sum256(originalPDF))
	}
	if !bytes.HasPrefix(verified[0], []byte("%PDF-")) {
		t.Fatal("actual acknowledgement final artifact is not a PDF")
	}
	if !bytes.HasPrefix(verified[1], []byte("%PDF-")) {
		t.Fatal("actual acknowledgement certificate artifact is not a PDF")
	}
	// The ORIGINAL signed artifact is canonical certificate HTML (stored as
	// text/html), not JSON. Verify its original independent commitment schema
	// and exact root event-set digest/count, in addition to detached Ed25519.
	claims, err := evidenceverify.ParseCertificateCommitments(verified[2])
	if err != nil || !bytes.HasPrefix(verified[2], []byte(`<div class="hash-cert-page">`)) || claims.DocumentID != created.ID.String() || claims.OrgID != f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) || claims.CompletionEffectiveAt != completed.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano) || claims.PreFinalChainScope != "organization" || claims.DocumentEventsScope != "ceremony-root" {
		t.Fatal("actual acknowledgement signed HTML certificate commitments differ", err)
	}
	originalEvents, err := f.q.ListEventsByDocument(f.ctx, generated.ListEventsByDocumentParams{DocumentID: pgtype.UUID{Bytes: created.ID, Valid: true}, Limit: 10001})
	if err != nil || len(originalEvents) > 10000 {
		t.Fatal("actual acknowledgement original committed root event-set oracle unavailable", err)
	}
	preFinal := make([]*generated.Event, 0, len(originalEvents))
	for _, event := range originalEvents {
		if event.ID != gate.eventID {
			preFinal = append(preFinal, event)
		}
	}
	_, digest, count, err := evidenceverify.BuildCeremonyEventsJSON(created.ID, preFinal)
	if err != nil || digest != claims.DocumentEventsSHA256 || count != claims.DocumentEventsCount {
		t.Fatal("actual acknowledgement signed event-set commitment differs from complete original root events", count, claims.DocumentEventsCount, err)
	}
	if finalToken == "" {
		t.Fatal("actual acknowledgement final capability missing")
	}
	if w := q.requestV1(finalToken, "/final-pdf"); w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), verified[0]) {
		t.Fatalf("actual acknowledged final download=%d %s", w.Code, w.Body.String())
	}
	ownedPlainAssertDrainedV1(t, q)
}
