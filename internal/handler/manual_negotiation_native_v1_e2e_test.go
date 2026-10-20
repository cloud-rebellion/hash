//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func manualNegotiationFixture264(t *testing.T) (*ownedPublicReadFixtureV1, *generated.Document) {
	t.Helper()
	q, d := nativeBindingDocument259(t, false)
	f := q.f
	// Existing manual MCP registration requires this real application dependency.
	// Manual operations never call its provider; no provider dispatch is asserted.
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, Resolver: f.s.Resolver, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL, Negotiator: &aiapps.Negotiator{}})
	return q, d
}
func manualNegotiationRequest264(q *ownedPublicReadFixtureV1, ctx context.Context, method, path, body, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, q.f.s.PublicURL+path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", q.f.s.PublicURL)
	r.Header.Set("User-Agent", "Native manual negotiation qualification264")
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, r)
	return w
}
func manualNegotiationCreate264(t *testing.T, q *ownedPublicReadFixtureV1, doc uuid.UUID, via, key string) uuid.UUID {
	t.Helper()
	var raw []byte
	if via == "REST" {
		w := manualNegotiationRequest264(q, q.f.ctx, http.MethodPost, "/api/v1/documents/"+doc.String()+"/proposals", `{"block_id":"body","proposal_kind":"counter","proposed_text":"Payment within thirty days","rationale":"Reviewed commercial term","ai_assisted":false,"unknown_original_field":true} {"trailing":"original one Decode accepts this"}`, q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatal("actual manual REST proposal", w.Code, w.Body.String())
		}
		raw = w.Body.Bytes()
	} else {
		raw = []byte(fieldMCPTextE2E(t, submitVariableBindingMCPE2E(variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: q.f}, q.f.ctx, "propose_counter_clause", key, map[string]any{"document_id": doc.String(), "block_id": "body", "proposal_kind": "counter", "proposed_text": "Payment within thirty days", "rationale": "Reviewed commercial term", "ai_assisted": false}), false))
	}
	var row struct {
		ID     uuid.UUID
		Status string
	}
	if json.Unmarshal(raw, &row) != nil || row.ID == uuid.Nil || row.Status != "pending" {
		t.Fatal("actual manual proposal response lost original wire shape", string(raw))
	}
	return row.ID
}
func manualNegotiationStatus264(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID, via, key string) {
	t.Helper()
	var raw []byte
	if via == "REST" {
		w := manualNegotiationRequest264(q, q.f.ctx, http.MethodPatch, "/api/v1/proposals/"+id.String()+"/status", `{"status":"accepted"}`, q.cookie)
		if w.Code != http.StatusOK {
			t.Fatal("actual active REST status", w.Code, w.Body.String())
		}
		raw = w.Body.Bytes()
	} else {
		raw = []byte(fieldMCPTextE2E(t, submitVariableBindingMCPE2E(variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: q.f}, q.f.ctx, "set_proposal_status", key, map[string]any{"proposal_id": id.String(), "status": "accepted"}), false))
	}
	var row struct {
		ID     uuid.UUID
		Status string
	}
	if json.Unmarshal(raw, &row) != nil || row.ID != id || row.Status != "accepted" {
		t.Fatal("actual manual status response lost original wire shape", string(raw))
	}
}
func manualNegotiationSnapshot264(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	base := nativeBindingSnapshot259(t, q, id)
	var proposals string
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object('proposals',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.created_at,p.id),'[]'::jsonb) FROM document_proposals p WHERE p.document_id=$1 AND p.org_id=$2),'wire_sizes',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.proposal_id),'[]'::jsonb) FROM manual_proposal_wire_sizes_v1 m WHERE m.document_id=$1 AND m.org_id=$2))::text`, id, q.f.org).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	return base + "\n" + proposals
}

// Actual source birth, all four fixed manual schemas, native Send and normal
// signer completion qualify the report's original proposal projection plus
// its detached-signed full event-set commitment. Negotiation payloads are not
// misrepresented as public report.Events narrative fields.
func TestNativeManualNegotiationPublicSendAndMandatoryReportV1E2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) {
			q, d := manualNegotiationFixture264(t)
			f := q.f
			base := "/api/v1/documents/" + d.ID.String()
			key := ""
			if via == "MCP" {
				mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				key = mint.Plaintext
			}
			proposal := manualNegotiationCreate264(t, q, d.ID, via, key)
			w := manualNegotiationRequest264(q, f.ctx, http.MethodPatch, base+"/negotiation-enabled", `{"enabled":true,"unknown":1} true`, q.cookie)
			if w.Code != http.StatusOK {
				t.Fatal("actual negotiation setting", w.Code, w.Body.String())
			}
			if w = nativeBindingPublic259(q, f.ctx, d.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); w.Code != http.StatusOK {
				t.Fatal("actual unresolved source", w.Code, w.Body.String())
			}
			w = submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, q.cookie)
			var sent sendDocumentResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
				t.Fatal("actual Send after manual proposal", w.Code, w.Body.String())
			}
			frozen, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
			if err != nil || frozen.Status != "sent" {
				t.Fatal(err)
			}
			manualNegotiationStatus264(t, q, proposal, via, key)
			w = manualNegotiationRequest264(q, f.ctx, http.MethodPatch, base+"/bilingual-target", `{"lang":"en-GB","unknown":true} [1]`, q.cookie)
			if w.Code != http.StatusOK {
				t.Fatal("actual active bilingual target", w.Code, w.Body.String())
			}
			active, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
			if err != nil || active.Status != "sent" || !active.NegotiationEnabled || active.BilingualTargetLang != "en-GB" || !bytes.Equal(active.BlocksJson, frozen.BlocksJson) || !bytes.Equal(active.VariablesJson, frozen.VariablesJson) {
				t.Fatal("manual metadata applied prose or changed frozen ceremony", err)
			}
			nativeBindingMeasurement259(t, f, d.ID)
			u, err := url.Parse(sent.Links[0].URL)
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := ordinaryPreparationSign249(t, q, strings.TrimPrefix(u.Path, "/sign/"), sent.Links[0].Name)
			if err != nil || terminal == nil || !terminal.Completed {
				t.Fatal("normal signature/report after actual manual actions", err)
			}
			completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
			if err != nil || completed.Status != "completed" {
				t.Fatal(err)
			}
			payload, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
			if err != nil {
				t.Fatal(err)
			}
			claims, err := evidence.ParseCertificateCommitments(payload)
			if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.ParticipantReportRows < 4 || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
				t.Fatal("mandatory report or detached signature absent", err)
			}
			report := assertFreshParticipantReport406(t, f, completed, payload)
			if len(report.Proposals) != 1 {
				t.Fatal("actual signed proposal projection absent")
			}
			original, err := f.q.GetProposalForUpdate(f.ctx, generated.GetProposalForUpdateParams{ID: proposal, OrgID: f.org, DocumentID: d.ID})
			if err != nil {
				t.Fatal(err)
			}
			want := render.ParticipantReportProposalV1{ID: proposal.String(), DocumentID: d.ID.String(), Kind: "counter", BlockID: "body", Text: "Payment within thirty days", Rationale: "Reviewed commercial term", Status: "accepted", At: original.CreatedAt.Time.UTC().Format(time.RFC3339Nano), UpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}
			if report.Proposals[0] != want {
				t.Fatal("signed report changed original public proposal record", report.Proposals[0])
			}
			rows, err := f.q.ListEventsByDocumentChronological(f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: d.ID, Valid: true}, Limit: int32(claims.DocumentEventsCount)})
			if err != nil || len(rows) != claims.DocumentEventsCount {
				t.Fatal("signed original event subset absent", err)
			}
			digest, err := audit.DocumentEventSetDigest(rows)
			if err != nil || hex.EncodeToString(digest[:]) != claims.DocumentEventsSHA256 {
				t.Fatal("signed full event-set commitment differs", err)
			}
			kinds := map[string]int{"negotiation.proposed": 0, "negotiation.status_changed": 0, "negotiation.setting_changed": 0, "bilingual.target_changed": 0}
			for _, event := range rows {
				if _, ok := kinds[event.Kind]; !ok {
					continue
				}
				kinds[event.Kind]++
				var fields map[string]any
				actualHash, hashErr := audit.RecomputeEventRowHash(event)
				if json.Unmarshal(event.PayloadHashed, &fields) != nil || hashErr != nil || !bytes.Equal(actualHash, event.RowHash) || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID {
					t.Fatal("manual event original hashed preimage/actor differs", hashErr)
				}
				switch event.Kind {
				case "negotiation.proposed":
					wantLen := 5
					if via == "MCP" {
						wantLen = 6
					}
					if len(fields) != wantLen || fields["via"] != strings.ToLower(via) || fields["proposal_id"] != proposal.String() || fields["block_id"] != "body" || fields["kind"] != "counter" || fields["ai_assisted"] != false || (via == "MCP" && fields["tool"] != "propose_counter_clause") {
						t.Fatal("original manual proposal payload differs", fields)
					}
				case "negotiation.status_changed":
					if len(fields) != 3 || fields["via"] != strings.ToLower(via) || fields["proposal_id"] != proposal.String() || fields["status"] != "accepted" {
						t.Fatal("original manual status payload differs", fields)
					}
				case "negotiation.setting_changed":
					if len(fields) != 2 || fields["via"] != "rest" || fields["enabled"] != true {
						t.Fatal("original negotiation-setting payload differs", fields)
					}
				case "bilingual.target_changed":
					if len(fields) != 2 || fields["via"] != "rest" || fields["lang"] != "en-GB" {
						t.Fatal("original bilingual-setting payload differs", fields)
					}
				}
			}
			for kind, count := range kinds {
				if count != 1 {
					t.Fatal("signed complete event set omitted or duplicated actual manual mutation", kind, count)
				}
			}
			var reports int
			var exact bool
			if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_payload_sha256=$5),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2", d.ID, f.org, claims.ParticipantReportSHA256, completed.FinalPdfSha, completed.AuditPayloadSha256).Scan(&reports, &exact); err != nil || reports != 1 || !exact {
				t.Fatal("mandatory report artifact association differs", err)
			}
			w = httptest.NewRecorder()
			f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(f.ctx))
			if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
				t.Fatal("mandatory report public download", w.Code)
			}
			nativeBindingMeasurement259(t, f, d.ID)
			q.assertObserversOnlyV1(t)
			before := manualNegotiationSnapshot264(t, q, d.ID)
			w = manualNegotiationRequest264(q, f.ctx, http.MethodPatch, base+"/bilingual-target", `{"lang":"sv-SE"}`, q.cookie)
			if w.Code != http.StatusConflict || manualNegotiationSnapshot264(t, q, d.ID) != before {
				t.Fatal("terminal manual mutation changed signed source/evidence", w.Code)
			}
		})
	}
}

func TestNativeManualNegotiationFreshMeasurementAndExpiryRollbackV1E2E(t *testing.T) {
	t.Run("fresh event measurement", func(t *testing.T) {
		q, d := manualNegotiationFixture264(t)
		f := q.f
		before := manualNegotiationSnapshot264(t, q, d.ID)
		name := "manual_measure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid THEN RAISE EXCEPTION 'fixture fresh manual measurement failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON html_snapshot_event_payload_sizes_v1 FOR EACH ROW EXECUTE FUNCTION %s()`, name, d.ID, name, name)); err != nil {
			t.Fatal(err)
		}
		drop := func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := f.pool.Exec(cleanup, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON html_snapshot_event_payload_sizes_v1; DROP FUNCTION IF EXISTS %s()", name, name)); err != nil {
				t.Error(err)
			}
		}
		t.Cleanup(drop)
		w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals", `{"block_id":"body","proposal_kind":"counter","proposed_text":"uncommitted"}`, q.cookie)
		if w.Code != http.StatusInternalServerError || manualNegotiationSnapshot264(t, q, d.ID) != before {
			t.Fatal("failed fresh manual event measurement committed proposal", w.Code, w.Body.String())
		}
		drop()
		manualNegotiationCreate264(t, q, d.ID, "REST", "")
		nativeBindingMeasurement259(t, f, d.ID)
	})
	t.Run("original cookie after audit wait", func(t *testing.T) {
		q, d := manualNegotiationFixture264(t)
		f := q.f
		before := manualNegotiationSnapshot264(t, q, d.ID)
		blocker, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = f.q.WithTx(blocker).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
			nativeReminderRollback255(t, blocker)
			t.Fatal(err)
		}
		cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
		result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
			return manualNegotiationRequest264(q, ctx, http.MethodPatch, "/api/v1/documents/"+d.ID.String()+"/bilingual-target", `{"lang":"sv-SE"}`, cookie)
		})
		defer nativeReminderCleanupHTTP255(t, blocker, cancel, joined)
		awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
		awaitSessionCookieExpiryE2E(t, f.s, cookie)
		if err = blocker.Commit(f.ctx); err != nil {
			t.Fatal(err)
		}
		w := receiveSessionOperationE2E(t, result)
		if w.Code != http.StatusUnauthorized || manualNegotiationSnapshot264(t, q, d.ID) != before {
			t.Fatal("original expired manual credential committed", w.Code, w.Body.String())
		}
	})
}

func TestNativeManualNegotiationAllOrgSenderScopeAndParentPolicyV1E2E(t *testing.T) {
	q, d := manualNegotiationFixture264(t)
	f := q.f
	other, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@manual264.test", Name: "Another actual sender", Role: "sender"})
	if err != nil || other.ID == d.SenderID {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, other.ID, other.SessionGeneration, time.Hour)
	w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals", `{"block_id":"body","proposal_kind":"counter","proposed_text":"Another authorized sender"}`, cookie)
	var parent struct{ ID uuid.UUID }
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &parent) != nil || parent.ID == uuid.Nil {
		t.Fatal("original all-org sender policy narrowed", w.Code, w.Body.String())
	}
	before := manualNegotiationSnapshot264(t, q, d.ID)
	viewer, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Email: uuid.NewString() + "@manual-viewer264.test", Name: "Actual viewer", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	w = manualNegotiationRequest264(q, f.ctx, http.MethodPatch, "/api/v1/documents/"+d.ID.String()+"/negotiation-enabled", `{"enabled":true}`, dsrSessionCookieE2E(t, f.s, viewer.ID, viewer.SessionGeneration, time.Hour))
	if w.Code != http.StatusForbidden {
		t.Fatal("viewer changed manual settings", w.Code)
	}
	// Both body and sign are actual top-level blocks; mismatch must come from
	// the original parent's block association rather than missing-block parsing.
	w = manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals", fmt.Sprintf(`{"block_id":"sign","proposal_kind":"counter","parent_id":"%s"}`, parent.ID), q.cookie)
	if w.Code != http.StatusBadRequest {
		t.Fatal("different-block parent accepted", w.Code, w.Body.String())
	}
	scoped, _ := mintRecipientMCPKeyE2E(t, f, true, 0)
	fieldMCPTextE2E(t, submitVariableBindingMCPE2E(variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: f}, f.ctx, "propose_counter_clause", scoped.Plaintext, map[string]any{"document_id": uuid.NewString(), "block_id": "body", "proposal_kind": "counter"}), true)
	if manualNegotiationSnapshot264(t, q, d.ID) != before {
		t.Fatal("role/parent/scope refusal changed manual source/evidence")
	}
	nativeBindingMeasurement259(t, f, d.ID)
}

// Native birth owns the genuine retained TEXT and fixed JSONB response. A
// separately seeded old arbitrary JSONB row must refuse before its expansion.
func TestNativeManualProposalOwnsRetainedBodyAndRefusesUnmeasuredLegacyV1E2E(t *testing.T) {
	q, d := manualNegotiationFixture264(t)
	f := q.f
	text := strings.Repeat("Retained clause Å<&\n", 1536)
	body, err := json.Marshal(map[string]any{"block_id": "body", "proposal_kind": "counter", "proposed_text": text, "rationale": "original retained rationale"})
	if err != nil {
		t.Fatal(err)
	}
	w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals", string(body), q.cookie)
	var created struct{ ID uuid.UUID }
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		t.Fatal("actual retained proposal birth", w.Code, w.Body.String())
	}
	old, err := f.q.GetProposalForUpdate(f.ctx, generated.GetProposalForUpdateParams{ID: created.ID, OrgID: f.org, DocumentID: d.ID})
	if err != nil {
		t.Fatal(err)
	}
	manualNegotiationStatus264(t, q, old.ID, "REST", "")
	row, err := f.q.GetProposalForUpdate(f.ctx, generated.GetProposalForUpdateParams{ID: old.ID, OrgID: f.org, DocumentID: d.ID})
	if err != nil || row.ProposedText != old.ProposedText || row.Rationale != old.Rationale || row.BlockID != old.BlockID || row.ProposalKind != old.ProposalKind || row.ProposedBy != old.ProposedBy || row.RecipientID != old.RecipientID || row.ParentID != old.ParentID || row.CreatedAt != old.CreatedAt || !bytes.Equal(row.DiffJson, old.DiffJson) || row.Status != "accepted" {
		t.Fatal("public status changed original retained proposal body", err)
	}
	nativeBindingMeasurement259(t, f, d.ID)
	diff, err := json.Marshal(map[string]any{"old_diff": strings.Repeat("legacy JSONB source ", 8192)})
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := f.q.InsertProposal(f.ctx, generated.InsertProposalParams{DocumentID: d.ID, OrgID: f.org, ProposedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, BlockID: "body", ProposalKind: "counter", ProposedText: "unmeasured legacy source", DiffJson: diff})
	if err != nil {
		t.Fatal(err)
	}
	before := manualNegotiationSnapshot264(t, q, d.ID)
	w = manualNegotiationRequest264(q, f.ctx, http.MethodPatch, "/api/v1/proposals/"+legacy.ID.String()+"/status", `{"status":"accepted"}`, q.cookie)
	if w.Code != http.StatusInternalServerError || manualNegotiationSnapshot264(t, q, d.ID) != before {
		t.Fatal("unmeasured old proposal expanded/committed or was silently repaired", w.Code, w.Body.String())
	}
	var cache int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM manual_proposal_wire_sizes_v1 WHERE proposal_id=$1", legacy.ID).Scan(&cache); err != nil || cache != 0 {
		t.Fatal("legacy status fabricated measurement", cache, err)
	}
	q.assertObserversOnlyV1(t)
}

func TestNativeManualNegotiationOriginalSessionAfterRootWaitV1E2E(t *testing.T) {
	for _, op := range []string{"create", "status", "negotiation", "bilingual"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(op+"/"+change, func(t *testing.T) {
				q, d := manualNegotiationFixture264(t)
				f := q.f
				base := "/api/v1/documents/" + d.ID.String()
				method, path, body := http.MethodPatch, base+"/negotiation-enabled", `{"enabled":true}`
				switch op {
				case "create":
					method, path, body = http.MethodPost, base+"/proposals", `{"block_id":"body","proposal_kind":"counter"}`
				case "status":
					id := manualNegotiationCreate264(t, q, d.ID, "REST", "")
					path, body = "/api/v1/proposals/"+id.String()+"/status", `{"status":"accepted"}`
				case "bilingual":
					path, body = base+"/bilingual-target", `{"lang":"sv-SE"}`
				}
				blocker := holdAuthoringDocumentMCPE2E(t, f, d.ID)
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
					return manualNegotiationRequest264(q, ctx, method, path, body, cookie)
				})
				defer nativeReminderCleanupHTTP255(t, blocker, cancel, joined)
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: LockManualNegotiationRootV1", "transactionid")
				want := http.StatusForbidden
				var err error
				switch change {
				case "demotion":
					_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				case "revocation":
					_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				before := manualNegotiationSnapshot264(t, q, d.ID)
				if err = blocker.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				w := receiveSessionOperationE2E(t, result)
				if w.Code != want || manualNegotiationSnapshot264(t, q, d.ID) != before {
					t.Fatal("original manual authority survived root wait or changed source", w.Code, want, w.Body.String())
				}
			})
		}
	}
}

func TestNativeManualNegotiationRegisteredChildDraftAndActiveV1E2E(t *testing.T) {
	for _, sent := range []bool{false, true} {
		t.Run(fmt.Sprintf("sent=%v", sent), func(t *testing.T) {
			q := newOwnedAutomationAuthorizationFixtureV1(t)
			f := setupNativeLifecycleAuthorizationWithFixture257d(t, "owner", sent, true, q)
			q.f = f
			children, err := f.s.Envelopes.Children(f.ctx, f.doc.ID, f.org)
			if err != nil || len(children) != 2 {
				t.Fatal(err)
			}
			child := children[0]
			base := "/api/v1/documents/" + child.ID.String()
			w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, base+"/proposals", `{"block_id":"agreement","proposal_kind":"counter","proposed_text":"Child proposal metadata"}`, q.cookie)
			var proposal struct{ ID uuid.UUID }
			if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &proposal) != nil || proposal.ID == uuid.Nil {
				t.Fatal("actual registered child manual proposal", w.Code, w.Body.String())
			}
			manualNegotiationStatus264(t, q, proposal.ID, "REST", "")
			w = manualNegotiationRequest264(q, f.ctx, http.MethodPatch, base+"/bilingual-target", `{"lang":"sv-SE"}`, q.cookie)
			if w.Code != http.StatusOK {
				t.Fatal("registered child setting", w.Code, w.Body.String())
			}
			actual, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: child.ID, OrgID: f.org})
			if err != nil || actual.ParentEnvelopeID != child.ParentEnvelopeID || actual.Status != child.Status || actual.BilingualTargetLang != "sv-SE" || !bytes.Equal(actual.BlocksJson, child.BlocksJson) || !bytes.Equal(actual.VariablesJson, child.VariablesJson) {
				t.Fatal("child metadata changed actual frozen topology/source", err)
			}
			nativeBindingMeasurement259(t, f, child.ID)
			q.assertObserversOnlyV1(t)
		})
	}
}

// Original sibling-parent negative controls must reach the same parent lookup
// after real native source birth, instead of failing an unrelated missing cache.
func guardedAISiblingNative264(t *testing.T, f lifecycleAuthorizationFixture, name string) (*generated.Document, error) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "source_kind": "blocks", "blocks_json": json.RawMessage(f.doc.BlocksJson), "variables_json": json.RawMessage(`{}`)})
	if err != nil {
		return nil, err
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	response := submitSessionOperationE2E(f.s, "POST", "/api/v1/documents", string(body), cookie)
	var created struct{ ID uuid.UUID }
	if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil || created.ID == uuid.Nil {
		return nil, fmt.Errorf("actual sibling native birth: HTTP %d", response.Code)
	}
	return f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
}

// Retain the request's original provider/manual timeout. Failure cleanup uses
// an independent finite context and joins the actual request before fixtures.
func guardedAIAsync264(parent context.Context, run func(context.Context) *httptest.ResponseRecorder) (<-chan *httptest.ResponseRecorder, context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithCancel(parent)
	result := make(chan *httptest.ResponseRecorder, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); result <- run(ctx) }()
	return result, cancel, joined
}
func guardedAICleanup264(t *testing.T, blocked pgx.Tx, cancel context.CancelFunc, joined <-chan struct{}) {
	t.Helper()
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if blocked != nil {
		if err := blocked.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("original AI blocker cleanup failed", err)
		}
	}
	select {
	case <-joined:
	case <-cleanup.Done():
		t.Error("original AI request failed to join independent cleanup", cleanup.Err())
	}
}

func TestNativeManualProposalWireScopeAndSourceInvalidationV1E2E(t *testing.T) {
	q, d := manualNegotiationFixture264(t)
	f := q.f
	id := manualNegotiationCreate264(t, q, d.ID, "REST", "")
	var exact bool
	if err := f.pool.QueryRow(f.ctx, `SELECT m.document_id=p.document_id AND m.org_id=p.org_id AND m.proposal_created_at=p.created_at AND m.proposal_updated_at=p.updated_at AND m.diff_wire_bytes=octet_length(p.diff_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer FROM manual_proposal_wire_sizes_v1 m JOIN document_proposals p ON p.id=m.proposal_id WHERE p.id=$1`, id).Scan(&exact); err != nil || !exact {
		t.Fatal("genuine native proposal measurement lost source association", err)
	}
	for _, column := range []string{"org_id", "document_id", "proposal_id"} {
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(f.ctx, "UPDATE manual_proposal_wire_sizes_v1 SET "+column+"=$2 WHERE proposal_id=$1", id, uuid.New())
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		rollback := tx.Rollback(cleanup)
		stop()
		if err == nil || rollback != nil {
			t.Fatal("foreign/changed cache identity accepted or cleanup failed", column, err, rollback)
		}
	}
	// A real committed source change invalidates the proof without expanding
	// its JSONB or inventing a replacement. The following public request must
	// refuse unchanged until a separately reviewed legacy workflow exists.
	if tag, err := f.pool.Exec(f.ctx, "UPDATE document_proposals SET diff_json=$2::jsonb WHERE id=$1", id, `{"legacy":"changed old diff"}`); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	}
	before := manualNegotiationSnapshot264(t, q, d.ID)
	w := manualNegotiationRequest264(q, f.ctx, http.MethodPatch, "/api/v1/proposals/"+id.String()+"/status", `{"status":"accepted"}`, q.cookie)
	var count int
	if err := f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM manual_proposal_wire_sizes_v1 WHERE proposal_id=$1", id).Scan(&count); err != nil || count != 0 || w.Code != http.StatusInternalServerError || manualNegotiationSnapshot264(t, q, d.ID) != before {
		t.Fatal("stale source measurement survived or was repaired", count, w.Code, err)
	}
	q.assertObserversOnlyV1(t)
}
