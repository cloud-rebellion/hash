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
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/aiapps"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const signerAIPrivate311 = "private-signer-311@example.test"

type signerAINativeFixture311 struct {
	q                   *ownedPublicReadFixtureV1
	document            *generated.Document
	token, name, digest string
	recipient           uuid.UUID
	calls               atomic.Int32
	entered             chan struct{}
	release             chan struct{}
	once                sync.Once
}

func newSignerAINativeFixture311(t *testing.T, blocking bool) *signerAINativeFixture311 {
	t.Helper()
	q, d := manualNegotiationFixture264(t)
	f := &signerAINativeFixture311{q: q, document: d, entered: make(chan struct{}, 1)}
	if blocking {
		f.release = make(chan struct{})
	}
	tokenPattern := regexp.MustCompile(`\[shield:email:tok_[0-9a-f]{16}\]`)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer synthetic-signer-311" {
			http.Error(w, "bad envelope", 400)
			return
		}
		var input struct {
			Messages []struct{ Role, Content string } `json:"messages"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input) != nil {
			http.Error(w, "bad body", 400)
			return
		}
		raw, _ := json.Marshal(input)
		if bytes.Contains(raw, []byte(signerAIPrivate311)) {
			http.Error(w, "Shield absent", 400)
			return
		}
		token := ""
		for _, m := range input.Messages {
			if m.Role == "user" {
				token = tokenPattern.FindString(m.Content)
			}
		}
		if token == "" {
			http.Error(w, "token absent", 400)
			return
		}
		f.calls.Add(1)
		select {
		case f.entered <- struct{}{}:
		default:
		}
		if f.release != nil {
			select {
			case <-f.release:
			case <-r.Context().Done():
				return
			}
		}
		if r.Context().Err() != nil {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": "Explained " + token + "."}}}, "usage": map[string]int{"prompt_tokens": 23, "completion_tokens": 11}, "model": "synthetic-model-311"})
	}))
	t.Cleanup(func() { f.unblock(); peer.CloseClientConnections(); peer.Close() })
	provider := ai.NewMistralProvider(peer.URL, "synthetic-signer-311", "synthetic-model-311", true)
	shield, err := ai.NewLocalShield(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.Clarifier = &aiapps.Clarifier{Runtime: ai.New(q.f.q, shield, nil, provider)}
	if w := nativeBindingPublic259(q, q.f.ctx, d.ID, http.MethodPut, `{"source_kind":"org.setting","source_path":"org.name"}`, q.cookie); w.Code != http.StatusOK {
		t.Fatal("required actual source binding", w.Code, w.Body.String())
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/send", `{"lawful_basis":"contract"}`, q.cookie)
	var sent sendDocumentResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
		t.Fatal("actual signer AI Send", w.Code, w.Body.String())
	}
	link, err := url.Parse(sent.Links[0].URL)
	if err != nil {
		t.Fatal(err)
	}
	f.token, f.name, f.recipient = strings.TrimPrefix(link.Path, "/sign/"), sent.Links[0].Name, sent.Links[0].RecipientID
	rc := q.lookupV1(t, f.token)
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(f.token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	f.digest = notice.NoticeDigest
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	return f
}
func (f *signerAINativeFixture311) unblock() {
	if f.release != nil {
		f.once.Do(func() { close(f.release) })
	}
}
func (f *signerAINativeFixture311) submit(ctx context.Context) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(map[string]string{"block_id": "body", "selection_text": "Explain payment for " + signerAIPrivate311, "question": "Please explain", "locale": "en-GB"})
	r := httptest.NewRequest(http.MethodPost, f.q.f.s.PublicURL+"/sign/"+f.token+"/clarify", bytes.NewReader(raw)).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.q.f.s.PublicURL)
	r.Header.Set(signerNoticeDigestHeader, f.digest)
	w := httptest.NewRecorder()
	f.q.f.s.Routes().ServeHTTP(w, r)
	return w
}
func (f *signerAINativeFixture311) assertUsage(t *testing.T, wantInput, wantOutput, wantEvents int) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var in, out, events, staff int
	var success bool
	err := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT a.id,a.input_tokens,a.output_tokens,a.success,(SELECT count(*)::integer FROM events WHERE org_id=a.org_id AND document_id=a.document_id AND kind IN ('ai.requested','clarifier.requested','ai.completed','clarifier.answered')),(SELECT count(*)::integer FROM events WHERE org_id=a.org_id AND document_id=a.document_id AND kind IN ('ai.requested','clarifier.requested','ai.completed','clarifier.answered') AND actor_user_id IS NOT NULL) FROM ai_completion_audit a JOIN events e ON e.id=a.id AND e.org_id=a.org_id AND e.document_id=a.document_id AND e.actor_user_id IS NULL AND e.kind='ai.requested' JOIN recipients r ON r.id=e.recipient_id AND r.document_id=e.document_id WHERE a.org_id=$1 AND a.document_id=$2 AND a.actor_user_id IS NULL`, f.q.f.org, f.document.ID).Scan(&id, &in, &out, &success, &events, &staff)
	if err != nil || id == uuid.Nil || in != wantInput || out != wantOutput || events != wantEvents || staff != 0 || success != (wantInput == 23) {
		t.Fatal("actual recipient usage/event tuple", id, in, out, success, events, staff, err)
	}
	nativeBindingMeasurement259(t, f.q.f, f.document.ID)
	return id
}
func TestNativeSignerAIClarificationSignAndMandatoryReportV1E2E(t *testing.T) {
	f := newSignerAINativeFixture311(t, false)
	w := f.submit(f.q.f.ctx)
	var answer aiapps.ClarifyResult
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &answer) != nil || answer.Answer != "Explained "+signerAIPrivate311+"." || !answer.ShieldActive || answer.InputTokens != 23 || answer.OutputTokens != 11 || f.calls.Load() != 1 {
		t.Fatal("actual owned signer clarification", w.Code, w.Body.String())
	}
	requestID := f.assertUsage(t, 23, 11, 4)
	terminal, err := ordinaryPreparationSign249(t, f.q, f.token, f.name)
	if err != nil || terminal == nil || !terminal.Completed {
		t.Fatal("actual signer clarification signing/report", err)
	}
	completed, err := f.q.f.q.GetDocument(f.q.f.ctx, generated.GetDocumentParams{ID: f.document.ID, OrgID: f.q.f.org})
	if err != nil || completed.Status != "completed" {
		t.Fatal("completed actual signer AI document", err)
	}
	payload, err := readDocumentArtifact(f.q.f.ctx, f.q.f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := readDocumentArtifact(f.q.f.ctx, f.q.f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !sign.Verify(f.q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatal("actual signer AI mandatory report signature", err)
	}
	assertFreshParticipantReport406(t, f.q.f, completed, payload)
	rows, err := f.q.f.q.ListEventsByDocumentChronological(f.q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: f.document.ID, Valid: true}, Limit: int32(claims.DocumentEventsCount)})
	if err != nil || len(rows) != claims.DocumentEventsCount {
		t.Fatal("signed complete signer AI event set", err)
	}
	digest, err := audit.DocumentEventSetDigest(rows)
	if err != nil || hex.EncodeToString(digest[:]) != claims.DocumentEventsSHA256 {
		t.Fatal("signed signer AI original history digest", err)
	}
	counts := map[string]int{"clarifier.requested": 0, "ai.requested": 0, "ai.completed": 0, "clarifier.answered": 0}
	for _, event := range rows {
		if _, ok := counts[event.Kind]; !ok {
			continue
		}
		counts[event.Kind]++
		var fields map[string]any
		sum, err := audit.RecomputeEventRowHash(event)
		if err != nil || !bytes.Equal(sum, event.RowHash) || json.Unmarshal(event.PayloadHashed, &fields) != nil || event.ActorUserID.Valid || !event.RecipientID.Valid || uuid.UUID(event.RecipientID.Bytes) != f.recipient || fields["via"] != "signer" || fields["tool"] != "clarify_clause" || fields["notice_digest"] != f.digest {
			t.Fatal("original recipient AI preimage/notice/actor", event.Kind, err)
		}
		if event.Kind == "ai.requested" && event.ID != requestID {
			t.Fatal("actual recipient request ID")
		}
		if (event.Kind == "ai.completed" || event.Kind == "clarifier.answered") && fields["request_event_id"] != requestID.String() {
			t.Fatal("actual recipient AI receipt association")
		}
		if bytes.Contains(event.PayloadHashed, []byte(signerAIPrivate311)) {
			t.Fatal("private selection/answer leaked into metadata event")
		}
	}
	for k, n := range counts {
		if n != 1 {
			t.Fatal("signed signer AI phase omitted/duplicated", k, n)
		}
	}
	if _, _, _, err = evidence.BuildCeremonyEventsJSON(f.document.ID, rows); err != nil {
		t.Fatal("independent original signer notice verification", err)
	}
	var reportCount int
	var exact bool
	if err = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT count(*)::integer,coalesce(bool_and(encode(report_sha256,'hex')=$3 AND final_pdf_sha256=$4 AND audit_payload_sha256=$5),false) FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2`, f.document.ID, f.q.f.org, claims.ParticipantReportSHA256, completed.FinalPdfSha, completed.AuditPayloadSha256).Scan(&reportCount, &exact); err != nil || reportCount != 1 || !exact {
		t.Fatal("exact recipient AI mandatory report association", err)
	}
	download := httptest.NewRecorder()
	f.q.f.s.Routes().ServeHTTP(download, httptest.NewRequest(http.MethodGet, terminal.AuditCertURL, nil).WithContext(f.q.f.ctx))
	if download.Code != http.StatusOK || !bytes.HasPrefix(download.Body.Bytes(), []byte("%PDF-")) {
		t.Fatal("actual separate signer AI report download", download.Code)
	}
	nativeBindingMeasurement259(t, f.q.f, f.document.ID)
	assertStaffAIChainE2E(t, guardedAIAppsFixture{lifecycleAuthorizationFixture: f.q.f})
	f.q.assertObserversOnlyV1(t)
}
func TestNativeSignerAIMeasurementFailuresPreservePhaseDurabilityV1E2E(t *testing.T) {
	for _, kind := range []string{"ai.requested", "ai.completed", "clarifier.answered"} {
		t.Run(kind, func(t *testing.T) {
			f := newSignerAINativeFixture311(t, false)
			name := "signer_ai_measure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err := f.q.f.pool.Exec(f.q.f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid AND EXISTS(SELECT 1 FROM events e WHERE e.id=NEW.event_id AND e.kind='%s') THEN RETURN NULL; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON html_snapshot_event_payload_sizes_v1 FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.document.ID, kind, name, name)); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if _, err := f.q.f.pool.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON html_snapshot_event_payload_sizes_v1; DROP FUNCTION IF EXISTS %s()", name, name)); err != nil {
					t.Error("measurement fault cleanup", err)
				}
			})
			w := f.submit(f.q.f.ctx)
			if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "Explained ") {
				t.Fatal("missing actual M94 delivered private result", kind, w.Code, w.Body.String())
			}
			var events, usages int
			if err := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT (SELECT count(*)::integer FROM events WHERE org_id=$1 AND document_id=$2 AND kind IN ('clarifier.requested','ai.requested','ai.completed','clarifier.answered')),(SELECT count(*)::integer FROM ai_completion_audit WHERE org_id=$1 AND document_id=$2)`, f.q.f.org, f.document.ID).Scan(&events, &usages); err != nil {
				t.Fatal(err)
			}
			wantEvents, wantUsage, wantCalls := 0, 0, int32(0)
			if kind == "ai.completed" {
				wantEvents, wantUsage, wantCalls = 2, 1, 1
			}
			if kind == "clarifier.answered" {
				wantEvents, wantUsage, wantCalls = 3, 1, 1
			}
			if events != wantEvents || usages != wantUsage || f.calls.Load() != wantCalls {
				t.Fatal("required fresh measurement phase rollback", kind, events, usages, f.calls.Load())
			}
			nativeBindingMeasurement259(t, f.q.f, f.document.ID)
		})
	}
}
func TestNativeSignerAICancellationAndOriginalExpiryRetainTruthfulUsageV1E2E(t *testing.T) {
	for _, failure := range []string{"cancel", "expiry"} {
		t.Run(failure, func(t *testing.T) {
			f := newSignerAINativeFixture311(t, true)
			if failure == "expiry" {
				if _, err := f.q.f.pool.Exec(f.q.f.ctx, `UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '1 second' WHERE document_id=$1`, f.document.ID); err != nil {
					t.Fatal(err)
				}
			}
			result, cancel, joined := nativeReminderAsyncHTTP255(f.q.f.ctx, func(ctx context.Context) *httptest.ResponseRecorder { return f.submit(ctx) })
			defer func() {
				cancel()
				f.unblock()
				ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				select {
				case <-joined:
				case <-ctx.Done():
					t.Error("actual signer AI worker failed independent join", ctx.Err())
				}
			}()
			select {
			case <-f.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("actual supported provider not entered")
			}
			wantInput, wantOutput, wantHTTP := 0, 0, http.StatusInternalServerError
			if failure == "cancel" {
				cancel()
			} else {
				ctx, stop := context.WithTimeout(f.q.f.ctx, 4*time.Second)
				defer stop()
				tick := time.NewTicker(10 * time.Millisecond)
				defer tick.Stop()
				expired := false
				for !expired {
					if err := f.q.f.pool.QueryRow(ctx, `SELECT magic_token_expires_at<=clock_timestamp() FROM recipients WHERE document_id=$1`, f.document.ID).Scan(&expired); err != nil {
						t.Fatal(err)
					}
					if !expired {
						select {
						case <-tick.C:
						case <-ctx.Done():
							t.Fatal("actual original expiry did not occur")
						}
					}
				}
				f.unblock()
				wantInput, wantOutput, wantHTTP = 23, 11, http.StatusGone
			}
			w := receiveSessionOperationE2E(t, result)
			if w.Code != wantHTTP || strings.Contains(w.Body.String(), "Explained ") {
				t.Fatal("refused original recipient AI result", failure, w.Code, w.Body.String())
			}
			f.assertUsage(t, wantInput, wantOutput, 3)
			f.q.assertObserversOnlyV1(t)
		})
	}
}
