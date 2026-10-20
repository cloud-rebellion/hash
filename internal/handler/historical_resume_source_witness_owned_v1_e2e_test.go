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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// Actual REST import/recipient/field/Send/Sign and committed intent precede
// every recovery. The S3 and renderer peers are synthetic protocol providers.
// Only the explicitly labelled legacy/partial row version columns are changed
// to exercise old compatibility states; no source/history/cache row is forged.
func TestOwnedHistoricalResumePinnedAndLegacyExactWitnessE2E(t *testing.T) {
	for _, mode := range []string{"pinned", "legacy", "partial"} {
		t.Run(mode, func(t *testing.T) {
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
			var blockFinal atomic.Bool
			blockFinal.Store(true)
			objects := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
				// Intentional isolated legacy-fixture compatibility state. The four exact
				// artifact objects/version histories and all immutable evidence stay real.
				statement := "UPDATE document_finalization_intents SET evidence_version_pins_required=false,final_pdf_version_id=NULL,audit_cert_version_id=NULL,audit_payload_version_id=NULL,audit_signature_version_id=NULL WHERE document_id=$1 AND org_id=$2"
				if mode == "partial" {
					statement = "UPDATE document_finalization_intents SET evidence_version_pins_required=false,audit_cert_version_id=NULL,audit_payload_version_id=NULL,audit_signature_version_id=NULL WHERE document_id=$1 AND org_id=$2"
				}
				tag, updateErr := f.pool.Exec(f.ctx, statement, id, f.org)
				if updateErr != nil || tag.RowsAffected() != 1 {
					t.Fatal("seed labelled legacy version state", updateErr)
				}
			}
			blockFinal.Store(false)
			if mode == "partial" {
				damaged, readErr := f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: id, OrgID: f.org})
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, id); err == nil || !strings.Contains(err.Error(), "partial VersionId set") {
					t.Fatal("partial legacy intent was not refused at original compatibility gate", err)
				}
				after, readErr := f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: id, OrgID: f.org})
				if readErr != nil || after.EvidenceVersionPinsRequired || after.FinalPdfVersionID != damaged.FinalPdfVersionID || after.AuditCertVersionID.Valid || after.AuditPayloadVersionID.Valid || after.AuditSignatureVersionID.Valid {
					t.Fatal("partial refusal changed pins", readErr)
				}
				ownedPlainAssertDrainedV1(t, q)
				return
			}
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
