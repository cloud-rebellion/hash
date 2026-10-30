//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual REST import/recipient/field/Send/Sign and committed intent precede
// genuine pinned recovery. The S3 and renderer peers are synthetic providers.
// Current post109 evidence must not be relabelled as legacy. Real pre109
// unmeasured recovery is unsupported/unqualified by this fixture; the existing
// installation is retained separately from the authorized fresh installation.
func TestOwnedHistoricalResumePinnedAndCurrentIntentLegacyRelabelRefusedE2E(t *testing.T) {
	for _, mode := range []string{"pinned", "legacy", "partial"} {
		name := mode
		if mode != "pinned" {
			name = "current_intent_cannot_be_relabelled_" + mode
		}
		t.Run(name, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
					t.Error(err)
				}
			})
			peer := &importStoragePeer{objects: make(map[string][]byte)}
			var providerCalls atomic.Int64
			var blockFinal atomic.Bool
			blockFinal.Store(true)
			objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls.Add(1)
				if blockFinal.Load() && r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/final-") {
					// Refuse only after the actual Stage transaction committed its real intent.
					var staged bool
					if err := f.pool.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM document_finalization_intents WHERE org_id=$1 AND final_pdf_key=$2)", f.org, strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")).Scan(&staged); err != nil {
						http.Error(w, "synthetic witness read failed", http.StatusInternalServerError)
						return
					}
					if staged {
						http.Error(w, "synthetic post-intent read outage", http.StatusForbidden)
						return
					}
				}
				peer.ServeHTTP(w, r)
			}))
			t.Cleanup(objects.Close)
			client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-native-resume", SecretKey: "synthetic-native-resume-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
			if err != nil {
				t.Fatal(err)
			}
			f.s.Storage = client
			f.s.Sign.Storage = client
			f.s.Send.Storage = client
			response := httptest.NewRecorder()
			f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Native source body consumer")))
			if response.Code != http.StatusCreated {
				t.Fatalf("actual source upload=%d %s", response.Code, response.Body.String())
			}
			var imported struct {
				Document documentResponse `json:"document"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &imported); err != nil || imported.Document.ID == uuid.Nil {
				t.Fatal("actual source upload omitted document", err)
			}
			id := imported.Document.ID
			base := "/api/v1/documents/" + id.String()
			response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/recipients", `{"email":"source-input@example.test","name":"Native input signer","role":"buyer","locale":"en"}`, q.cookie)
			var recipient recipientResponse
			if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil {
				t.Fatalf("actual source participant=%d %s", response.Code, response.Body.String())
			}
			field, _ := json.Marshal(map[string]any{"recipient_id": recipient.ID.String(), "type": "signature", "page": 1, "x_pct": 15, "y_pct": 55, "w_pct": 30, "h_pct": 8, "required": true})
			response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/fields", string(field), q.cookie)
			if response.Code != http.StatusCreated {
				t.Fatalf("actual source field=%d %s", response.Code, response.Body.String())
			}
			response = submitSessionOperationE2E(f.s, http.MethodPost, base+"/send", `{"lawful_basis":"contract"}`, q.cookie)
			var sent sendDocumentResponse
			if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &sent) != nil || len(sent.Links) != 1 {
				t.Fatalf("actual source Send=%d %s", response.Code, response.Body.String())
			}
			ownedPlainAssertDrainedV1(t, q)

			link, err := url.Parse(sent.Links[0].URL)
			if err != nil {
				t.Fatal(err)
			}
			token := strings.TrimPrefix(link.Path, "/sign/")
			rc := q.lookupV1(t, token)
			notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
			if err != nil {
				t.Fatal(err)
			}
			noticeEvidence, err := signerArticle13NoticeEvidence(rc, notice)
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.s.Sign.Sign(f.ctx, rc, sign.SignInput{TypedName: sent.Links[0].Name, Font: "Caveat", Notice: noticeEvidence, IP: "127.0.0.1", UserAgent: "actual native Resume witness"})
			if err != nil || result == nil || result.Completed {
				t.Fatal("actual committed intent outage boundary changed", err)
			}
			if err = rc.CloseReadV1(); err != nil {
				t.Fatal(err)
			}
			ownedPlainAssertDrainedV1(t, q)
			before, err := f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: id, OrgID: f.org})
			if err != nil || !before.EvidenceVersionPinsRequired || !before.FinalPdfVersionID.Valid {
				t.Fatal("actual Sign did not commit genuine pinned intent", err)
			}
			if mode != "pinned" {
				assertCurrentIntentLegacyRelabelRefused621(t, f, id, mode, &providerCalls)
				ownedPlainAssertDrainedV1(t, q)
				return
			}
			blockFinal.Store(false)
			if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, id); err != nil {
				t.Fatal("actual native Resume/source/intent/retention/publication", err)
			}
			completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
			if err != nil || completed.Status != "completed" || !completed.FinalPdfKey.Valid || completed.FinalPdfKey.String != before.FinalPdfKey || !bytes.Equal(completed.FinalPdfSha, before.FinalPdfSha256) || !completed.FinalPdfVersionID.Valid || completed.FinalPdfVersionID != before.FinalPdfVersionID {
				t.Fatal("actual publication lost original final evidence tuple", err)
			}
			if _, err = f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: id, OrgID: f.org}); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("published exact intent was not retired", err)
			}
			ownedPlainAssertDrainedV1(t, q)
			if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, id); err != nil {
				t.Fatal("completed retry", err)
			}
			ownedPlainAssertDrainedV1(t, q)
		})
	}
}

// This exact inventory includes the current original-output bodies and all
// published/staged identities, not only the flags targeted by the bad UPDATE.
func currentIntentRelabelInventory621(t *testing.T, f lifecycleAuthorizationFixture, document uuid.UUID) string {
	t.Helper()
	var out string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d) FROM documents d WHERE d.id=$1 AND d.org_id=$2),
 'intent',(SELECT to_jsonb(i) FROM document_finalization_intents i WHERE i.document_id=$1 AND i.org_id=$2),
 'preparation',(SELECT to_jsonb(p) FROM document_ordinary_finalization_preparations_v1 p WHERE p.document_id=$1 AND p.org_id=$2),
 'artifacts',(SELECT jsonb_agg(to_jsonb(o) ORDER BY kind) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=$1 AND o.org_id=$2),
 'reports',(SELECT jsonb_agg(to_jsonb(r) ORDER BY completion_effective_at) FROM document_participant_reports_v1 r WHERE r.document_id=$1 AND r.org_id=$2),
 'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE r.document_id=$1),
 'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE s.document_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE e.document_id=$1 AND e.org_id=$2)
 )::text`, document, f.org).Scan(&out)
	if err != nil {
		t.Fatal("current intent exact inventory", err)
	}
	return out
}

func assertCurrentIntentLegacyRelabelRefused621(t *testing.T, f lifecycleAuthorizationFixture, document uuid.UUID, mode string, calls *atomic.Int64) {
	t.Helper()
	before := currentIntentRelabelInventory621(t, f, document)
	beforeCalls := calls.Load()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Always join the actual failed transaction before leaving this fixture.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	statement := "UPDATE document_finalization_intents SET evidence_version_pins_required=false,final_pdf_version_id=NULL,audit_cert_version_id=NULL,audit_payload_version_id=NULL,audit_signature_version_id=NULL WHERE document_id=$1 AND org_id=$2"
	if mode == "partial" {
		statement = "UPDATE document_finalization_intents SET evidence_version_pins_required=false,audit_cert_version_id=NULL,audit_payload_version_id=NULL,audit_signature_version_id=NULL WHERE document_id=$1 AND org_id=$2"
	} else if mode != "legacy" {
		t.Fatal("unknown current-intent corruption mode")
	}
	tag, refusal := tx.Exec(f.ctx, statement, document, f.org)
	if refusal == nil {
		if tag.RowsAffected() != 1 {
			t.Fatal("bad relabel did not address its exact genuine current intent")
		}
		// M109 owns an initially deferred guard. Force its real validation while
		// rollback is still explicit, rather than treating UPDATE's rowcount as a
		// successful historical producer or committing a counterfeit legacy state.
		_, refusal = tx.Exec(f.ctx, "SET CONSTRAINTS ordinary_finalization_intent_guard_v1 IMMEDIATE")
	}
	var pgError *pgconn.PgError
	if !errors.As(refusal, &pgError) || pgError.Code != "23514" || pgError.Message != "ordinary intent requires exact durable original outputs" {
		t.Fatal("current evidence relabel did not reach exact original-output immutability guard", refusal)
	}
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	rollbackErr := tx.Rollback(cleanup)
	cancel()
	if rollbackErr != nil {
		t.Fatal("join refused current intent relabel rollback", rollbackErr)
	}
	if after := currentIntentRelabelInventory621(t, f, document); after != before {
		t.Fatal("refused relabel changed document, original artifacts, intent or legal evidence")
	}
	if calls.Load() != beforeCalls {
		t.Fatal("refused SQL relabel touched provider artifacts")
	}
}
