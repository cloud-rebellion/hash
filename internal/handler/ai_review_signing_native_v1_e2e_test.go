//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Exercises the concrete constructor-owned supported provider over real local
// HTTP, not a fake native observation/receipt. The existing renderer/storage
// peers remain synthetic. All document/proposal/audit measurements and terminal
// artifacts are produced by the ordinary public application. Proposal acceptance
// records reviewed metadata; it does not automatically apply new contract prose.
func TestNativeAIReviewedProposalSendAndMandatoryReportV1E2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) {
			q, d := manualNegotiationFixture264(t)
			f := q.f
			beforeSource := bytes.Clone(d.BlocksJson)
			const privateEmail = "negotiation-review@example.test"
			const prefix = "Payment within thirty days for "
			var calls atomic.Int32
			observed := make(chan string, 1)
			token := regexp.MustCompile(`\[shield:email:tok_[0-9a-f]{16}\]`)
			peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer synthetic-ai-297" || r.Header.Get("Content-Type") != "application/json" {
					http.Error(w, "unexpected provider request", http.StatusBadRequest)
					return
				}
				var request struct {
					Model    string                           `json:"model"`
					Messages []struct{ Role, Content string } `json:"messages"`
				}
				if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request); err != nil || request.Model != "synthetic-model-297" {
					http.Error(w, "invalid actual request", http.StatusBadRequest)
					return
				}
				wire, err := json.Marshal(request)
				if err != nil || bytes.Contains(wire, []byte(privateEmail)) {
					http.Error(w, "outbound Shield absent", http.StatusBadRequest)
					return
				}
				shielded := ""
				for _, message := range request.Messages {
					if message.Role == "user" {
						shielded = token.FindString(message.Content)
					}
				}
				if shielded == "" {
					http.Error(w, "actual user token absent", http.StatusBadRequest)
					return
				}
				calls.Add(1)
				select {
				case observed <- shielded:
				default:
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": prefix + shielded + ".\nRationale: Reviewed commercial term."}}}, "usage": map[string]int{"prompt_tokens": 23, "completion_tokens": 11}, "model": "synthetic-model-297"})
			}))
			t.Cleanup(peer.Close)
			provider := ai.NewMistralProvider(peer.URL, "synthetic-ai-297", "synthetic-model-297", true)
			shield, err := ai.NewLocalShield(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			runtime := ai.New(f.q, shield, nil, provider)
			negotiator := &aiapps.Negotiator{Runtime: runtime}
			f.s.Negotiator = negotiator
			f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Storage: f.s.Storage, Billing: f.s.Billing, Resolver: f.s.Resolver, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: f.s.PublicURL, Negotiator: negotiator})
			key := ""
			if via == "MCP" {
				mint, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				key = mint.Plaintext
			}
			var suggested []byte
			args := map[string]any{"block_id": "body", "concern": "Clarify the payment period for " + privateEmail, "red_lines": []string{"Payment remains due within thirty days"}}
			if via == "REST" {
				raw, e := json.Marshal(args)
				if e != nil {
					t.Fatal(e)
				}
				w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals/suggest", string(raw), q.cookie)
				if w.Code != http.StatusOK {
					t.Fatal("actual native REST AI suggestion failed", w.Code, w.Body.String())
				}
				suggested = w.Body.Bytes()
			} else {
				args["document_id"] = d.ID.String()
				suggested = []byte(fieldMCPTextE2E(t, submitVariableBindingMCPE2E(variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: f}, f.ctx, "suggest_counter_clause", key, args), false))
			}
			var result aiapps.CounterResult
			if json.Unmarshal(suggested, &result) != nil || result.RevisedClause != prefix+privateEmail+"." || result.Rationale != "Reviewed commercial term." || result.Provider != "mistral" || result.Model != "synthetic-model-297" || !result.ShieldActive || calls.Load() != 1 {
				t.Fatal("actual provider/restoration/result provenance differs", string(suggested))
			}
			select {
			case <-observed:
			default:
				t.Fatal("no actual supported provider HTTP request observed")
			}
			afterSuggestion, e := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
			if e != nil || !bytes.Equal(beforeSource, afterSuggestion.BlocksJson) {
				t.Fatal("suggestion automatically changed contract prose", e)
			}
			var requestID uuid.UUID
			var in, out int
			var observedProvider, model string
			var shieldActive bool
			if e = f.pool.QueryRow(f.ctx, `SELECT a.id,a.input_tokens,a.output_tokens,a.provider,a.model,a.shield_active FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id=a.actor_user_id AND e.kind='ai.requested' WHERE a.org_id=$1 AND a.document_id=$2 AND a.actor_user_id=$3`, f.org, d.ID, f.user.ID).Scan(&requestID, &in, &out, &observedProvider, &model, &shieldActive); e != nil || requestID == uuid.Nil || in != 23 || out != 11 || observedProvider != "mistral" || model != "synthetic-model-297" || !shieldActive {
				t.Fatal("actual receipt-bound durable usage absent", e)
			}
			nativeBindingMeasurement259(t, f, d.ID)

			// Explicit human-reviewed persistence, through the original API in both
			// transports. No direct proposal INSERT, M112 repair or accepted flag seed.
			proposalArgs := map[string]any{"block_id": "body", "proposal_kind": "counter", "proposed_text": result.RevisedClause, "rationale": result.Rationale, "ai_assisted": true}
			var proposed []byte
			if via == "REST" {
				raw, e := json.Marshal(proposalArgs)
				if e != nil {
					t.Fatal(e)
				}
				w := manualNegotiationRequest264(q, f.ctx, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/proposals", string(raw), q.cookie)
				if w.Code != http.StatusCreated {
					t.Fatal("actual reviewed AI persistence failed", w.Code, w.Body.String())
				}
				proposed = w.Body.Bytes()
			} else {
				proposalArgs["document_id"] = d.ID.String()
				proposed = []byte(fieldMCPTextE2E(t, submitVariableBindingMCPE2E(variableBindingAuthorizationFixture{lifecycleAuthorizationFixture: f}, f.ctx, "propose_counter_clause", key, proposalArgs), false))
			}
			var proposal struct {
				ID     uuid.UUID
				Status string
			}
			if json.Unmarshal(proposed, &proposal) != nil || proposal.ID == uuid.Nil || proposal.Status != "pending" {
				t.Fatal("genuine reviewed proposal response absent", string(proposed))
			}
			manualNegotiationStatus264(t, q, proposal.ID, via, key)
			original, e := f.q.GetProposalForUpdate(f.ctx, generated.GetProposalForUpdateParams{ID: proposal.ID, OrgID: f.org, DocumentID: d.ID})
			if e != nil || !original.AiAssisted || original.ProposedText != result.RevisedClause || original.Rationale != result.Rationale || original.Status != "accepted" {
				t.Fatal("actual reviewed AI proposal lost its provenance", e)
			}
			// This shared fixture has a required customer variable. Resolve it via
			// the ordinary public binding API before Send, as an operator would.
			if binding := nativeBindingPublic259(q, f.ctx, d.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); binding.Code != http.StatusOK {
				t.Fatal("actual required customer binding failed", binding.Code, binding.Body.String())
			}
			nativeBindingMeasurement259(t, f, d.ID)
			w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
			var sent sendDocumentResponse
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
				t.Fatal("actual Send after reviewed AI failed", w.Code, w.Body.String())
			}
			link, e := url.Parse(sent.Links[0].URL)
			if e != nil {
				t.Fatal(e)
			}
			terminal, e := ordinaryPreparationSign249(t, q, strings.TrimPrefix(link.Path, "/sign/"), sent.Links[0].Name)
			if e != nil || terminal == nil || !terminal.Completed {
				t.Fatal("actual signing/mandatory report after AI failed", e)
			}
			completed, e := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
			if e != nil || completed.Status != "completed" || !bytes.Equal(completed.BlocksJson, beforeSource) {
				t.Fatal("actual completed reviewed-proposal source differs", e)
			}
			payload, e := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
			if e != nil {
				t.Fatal(e)
			}
			signature, e := readDocumentArtifact(f.ctx, f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
			if e != nil {
				t.Fatal(e)
			}
			claims, e := evidence.ParseCertificateCommitments(payload)
			if e != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !sign.Verify(f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
				t.Fatal("actual mandatory report detached signature absent", e)
			}
			report := assertFreshParticipantReport406(t, f, completed, payload)
			if len(report.Proposals) != 1 {
				t.Fatal("actual public proposal report absent")
			}
			want := render.ParticipantReportProposalV1{ID: proposal.ID.String(), DocumentID: d.ID.String(), Kind: "counter", BlockID: "body", Text: result.RevisedClause, Rationale: result.Rationale, Status: "accepted", At: original.CreatedAt.Time.UTC().Format(time.RFC3339Nano), UpdatedAt: original.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}
			if report.Proposals[0] != want {
				t.Fatal("signed report changed actual reviewed AI proposal")
			}
			rows, e := f.q.ListEventsByDocumentChronological(f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: d.ID, Valid: true}, Limit: int32(claims.DocumentEventsCount)})
			if e != nil || len(rows) != claims.DocumentEventsCount {
				t.Fatal("actual signed event subset absent", e)
			}
			digest, e := audit.DocumentEventSetDigest(rows)
			if e != nil || hex.EncodeToString(digest[:]) != claims.DocumentEventsSHA256 {
				t.Fatal("signed complete original AI history differs", e)
			}
			counts := map[string]int{"ai.requested": 0, "ai.completed": 0, "ai.result_ready": 0}
			for _, event := range rows {
				if _, ok := counts[event.Kind]; !ok {
					continue
				}
				counts[event.Kind]++
				var fields map[string]any
				hash, err := audit.RecomputeEventRowHash(event)
				if err != nil || !bytes.Equal(hash, event.RowHash) || json.Unmarshal(event.PayloadHashed, &fields) != nil || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID || fields["via"] != strings.ToLower(via) || fields["tool"] != "suggest_counter_clause" {
					t.Fatal("original fresh AI event preimage/scope/actor differs", err)
				}
				if event.Kind == "ai.requested" {
					if event.ID != requestID {
						t.Fatal("actual request receipt differs")
					}
				} else if fields["request_event_id"] != requestID.String() {
					t.Fatal("actual cost/result not bound to original request")
				}
				if event.Kind == "ai.completed" && (fields["usage_id"] != requestID.String() || fields["input_tokens"] != float64(23) || fields["output_tokens"] != float64(11) || fields["success"] != true) {
					t.Fatal("original actual usage/cost event differs")
				}
			}
			for kind, count := range counts {
				if count != 1 {
					t.Fatal("signed event set omitted or duplicated actual AI phase", kind, count)
				}
			}
			var reportCount int
			var exact bool
			if e = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_payload_sha256=$5),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2`, d.ID, f.org, claims.ParticipantReportSHA256, completed.FinalPdfSha, completed.AuditPayloadSha256).Scan(&reportCount, &exact); e != nil || reportCount != 1 || !exact {
				t.Fatal("actual report/final PDF association differs", e)
			}
			download := httptest.NewRecorder()
			f.s.Routes().ServeHTTP(download, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(f.ctx))
			if download.Code != http.StatusOK || !bytes.HasPrefix(download.Body.Bytes(), []byte("%PDF-")) {
				t.Fatal("mandatory AI-history report download failed", download.Code)
			}
			nativeBindingMeasurement259(t, f, d.ID)
			q.assertObserversOnlyV1(t)
		})
	}
}
