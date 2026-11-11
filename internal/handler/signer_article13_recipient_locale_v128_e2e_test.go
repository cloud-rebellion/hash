//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are real PostgreSQL/native Send and response owners, using the existing
// imported-PDF and strict local S3 protocol peers. They do not establish external
// renderer/provider acceptance, real SMTP delivery or legal enforceability.
// Recipient language is created through the ordinary draft API. The root stays
// English so this test cannot accidentally substitute document/package language
// for the saved recipient language that selects Article 13 material.
func article13RecipientLocaleBirthV128(t *testing.T, q *ownedPublicReadFixtureV1, signed bool, locale string) (pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	t.Helper()
	if locale != "en" && locale != "sv" {
		t.Fatal("fixture requires an explicit supported recipient locale")
	}
	root := packageImported220(t, q, "Native recipient-language notice "+locale)
	if root.DefaultLocale != "en" {
		t.Fatal("fixture root must remain English independently of recipient language")
	}
	if !signed {
		raw, err := json.Marshal(map[string]any{"expected_updated_at": root.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "requires_signature": false})
		if err != nil {
			t.Fatal(err)
		}
		if response := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+root.ID.String(), string(raw), q.cookie); response.Code != http.StatusOK {
			t.Fatal("actual draft acknowledgement mode update failed", response.Code)
		}
	}
	var target uuid.UUID
	for i, namedRole := range []string{"provider", "customer"} {
		role := namedRole
		if !signed {
			role = "signer"
		}
		raw, err := json.Marshal(map[string]any{"email": fmt.Sprintf("%s-%s-%d@recipient-notice.test", locale, namedRole, i), "name": "Synthetic " + namedRole, "role": role, "locale": locale})
		if err != nil {
			t.Fatal(err)
		}
		response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(raw), q.cookie)
		var recipient recipientResponse
		if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil || recipient.DocumentID != root.ID || recipient.Locale != locale || recipient.Role != role {
			t.Fatal("ordinary API did not create the actual saved recipient locale", response.Code)
		}
		if signed {
			field := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{
				"document_id": root.ID.String(), "type": "signature", "recipient_id": recipient.ID.String(), "page": 1, "required": true,
				"label": "Signature " + namedRole, "x_pct": 20, "y_pct": 55 + 20*i, "w_pct": 45, "h_pct": 10}, nil))
			if field.Code != http.StatusCreated {
				t.Fatal("genuine visible named signature field unavailable", field.Code)
			}
		}
		target = recipient.ID
	}
	confirmation, err := q.f.q.ConfirmDocumentLawfulBasis(q.f.ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: root.ID, OrgID: q.f.org, LawfulBasis: "contract", ConfirmedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, Via: "test"})
	if err != nil || confirmation == nil || confirmation.DocumentID != root.ID || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		t.Fatal("actual controller/lawful-basis confirmation unavailable", err)
	}
	root = packageLatest223(t, q, root.ID)
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	if root.DefaultLocale != "en" || root.RequiresSignature != signed {
		t.Fatal("fixture changed the independent root language or response mode")
	}
	var intent pdfadmission.HTMLSendPackageIntentMetadataV1
	err = packageCaptureRun234(t, q, root, p, func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1, authoring.Actor) error {
		return nil
	}, func(call context.Context, work *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		if _, err := packageCaptureAppend234(t, call, work, prior); err != nil {
			return err
		}
		var err error
		intent, err = work.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "synthetic-owned-test", Tool: "native-recipient-notice-language"})
		if err != nil {
			return err
		}
		if _, err = work.FreezeBrandingV1(call); err != nil {
			return err
		}
		return work.BeginSendSealingV1(call)
	})
	if err != nil || intent.AttemptID == uuid.Nil || target == uuid.Nil {
		t.Fatal("genuine recipient-language native Send birth failed", err)
	}
	packageWorkerDrained239(t, q)
	return intent, target
}

func article13RecipientLocaleStorageV128(t *testing.T, q *ownedPublicReadFixtureV1) *storage.Client {
	t.Helper()
	inner := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	peer := &packageResponseStoragePeer247{main: inner, until: make(map[string]time.Time), entered: make(chan struct{}), release: make(chan struct{})}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-response-access", SecretKey: "synthetic-response-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		inner.mu.Lock()
		failure := inner.failure
		inner.mu.Unlock()
		if failure != nil {
			t.Error("strict local recipient-notice storage peer", failure)
		}
	})
	q.f.s.Sign.Storage = client
	return client
}

func article13RecipientLocaleFixtureV128(t *testing.T, q *ownedPublicReadFixtureV1, client *storage.Client, signed bool, locale string) (packageResponseHTTPFixture247, signerContextResponse) {
	t.Helper()
	intent, recipient := article13RecipientLocaleBirthV128(t, q, signed, locale)
	packageCompletionRun241(t, q, client, intent, "sent")
	token := signerPackageToken242(t, q, recipient)
	request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+"?locale=en", nil).WithContext(q.f.ctx)
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Accept-Language", "en-US,en;q=0.9")
	request.AddCookie(&http.Cookie{Name: "hash_staff_locale", Value: "en"})
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	var page signerContextResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &page) != nil || page.DocumentID != intent.Capture.DocumentID || page.Recipient.ID != recipient || page.Recipient.Locale != locale || page.Privacy.CopyLocale != locale {
		t.Fatal("actual GET signer context lost trusted recipient language", response.Code)
	}
	material, err := article13.LocalizedNoticeV1(page.DocumentName, "contract", locale)
	if err != nil || page.Privacy.Copy != material.Copy || page.Privacy.PurposeSummary != material.PurposeSummary || page.Privacy.LegalBasis != material.LegalBasisDisclosure {
		t.Fatal("actual GET did not expose the complete server-selected notice material", err)
	}
	packageView := q.requestV1(token, "/package")
	var body struct {
		Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
	}
	if packageView.Code != http.StatusOK || json.Unmarshal(packageView.Body.Bytes(), &body) != nil || body.Package == nil || body.Package.Incorporation != documentpackage.IncorporationCopyV1() || packageView.Header().Get("X-Hash-Notice-Digest") != page.Privacy.NoticeDigest {
		t.Fatal("English frozen package or recipient-specific notice scope changed", packageView.Code)
	}
	fixture := packageResponseHTTPFixture247{q: q, m: intent, recipient: recipient, token: token, notice: page.Privacy.NoticeDigest, path: "accept",
		response: documentpackage.ResponseV1{ManifestSHA256: body.Package.ManifestSHA256, LegalCommitmentSHA256: body.Package.LegalCommitmentSHA256, IncorporationVersion: body.Package.Incorporation.Version, IncorporationSHA256: body.Package.Incorporation.SHA256, Consent: true}}
	if signed {
		fixture.path = "sign"
	}
	return fixture, page
}

func article13StoredRecipientEvidenceV128(t *testing.T, f packageResponseHTTPFixture247) ([]byte, article13.Evidence) {
	t.Helper()
	kind := "document.accepted"
	if f.path == "sign" {
		kind = "document.signed"
	}
	var raw []byte
	err := f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT payload_hashed FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND kind=$4", f.q.f.org, f.m.Capture.DocumentID, f.recipient, kind).Scan(&raw)
	if err != nil || article13.ValidateAuditPayload(raw, f.q.f.org, f.m.Capture.DocumentID, f.recipient) != nil {
		t.Fatal("persisted native response notice evidence failed identity/digest verification", err)
	}
	var payload struct {
		Schema   string             `json:"notice_schema"`
		Digest   string             `json:"notice_digest"`
		Snapshot article13.Snapshot `json:"notice_snapshot"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	evidence := article13.Evidence{Schema: payload.Schema, Digest: payload.Digest, Snapshot: payload.Snapshot}
	if evidence.Validate() != nil || evidence.Digest != f.notice {
		t.Fatal("persisted native response did not bind the acknowledged canonical notice")
	}
	return raw, evidence
}

func TestNativeSwedishRecipientArticle13SignAndAcceptV128E2E(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "accept"
		if signed {
			name = "sign"
		}
		t.Run(name, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			client := article13RecipientLocaleStorageV128(t, q)
			english, englishPage := article13RecipientLocaleFixtureV128(t, q, client, signed, "en")
			if response := english.post247(t, &english.response); response.Code != http.StatusOK {
				t.Fatal("genuine English response unavailable for retained historical evidence", response.Code)
			}
			oldRaw, oldEvidence := article13StoredRecipientEvidenceV128(t, english)
			if oldEvidence.Snapshot.Copy != article13.RenderedCopyV1(englishPage.DocumentName) || oldEvidence.Snapshot.PurposeSummary != article13.PurposeSummaryV1(englishPage.DocumentName) {
				t.Fatal("persisted English notice changed the original rendered copy")
			}

			swedish, page := article13RecipientLocaleFixtureV128(t, q, client, signed, "sv")
			rc := q.lookupV1(t, swedish.token)
			current, err := signerArticle13NoticeEvidence(rc, page.Privacy)
			if closeErr := rc.CloseReadV1(); closeErr != nil {
				t.Fatal(closeErr)
			}
			if err != nil || current.Validate() != nil {
				t.Fatal("actual Swedish GET notice cannot form canonical evidence", err)
			}
			// Construct only a stale public acknowledgement for this same exact
			// identity/epoch/capability. It grants no reader, actor or native authority.
			staleSnapshot := current.Snapshot
			en, err := article13.LocalizedNoticeV1(page.DocumentName, "contract", "en")
			if err != nil {
				t.Fatal(err)
			}
			staleSnapshot.Copy, staleSnapshot.PurposeSummary, staleSnapshot.LegalBasisDisclosure = en.Copy, en.PurposeSummary, en.LegalBasisDisclosure
			stale, err := article13.NewEvidence(staleSnapshot)
			if err != nil || stale.Digest == current.Digest {
				t.Fatal("same-recipient English acknowledgement did not differ from Swedish material", err)
			}
			before := swedish.state247(t)
			oldHeader := swedish
			oldHeader.notice = stale.Digest
			if response := oldHeader.post247(t, &swedish.response); response.Code != http.StatusPreconditionRequired {
				t.Fatal("stale English acknowledgement admitted a Swedish native action", response.Code)
			}
			if after := swedish.state247(t); after != before {
				t.Fatal("refused stale notice changed recipient, response, signature or audit effects")
			}
			if response := swedish.post247(t, &swedish.response); response.Code != http.StatusOK {
				t.Fatal("current Swedish GET notice did not authorize the genuine native response", response.Code)
			}
			_, actual := article13StoredRecipientEvidenceV128(t, swedish)
			if actual.Snapshot != current.Snapshot || actual.Digest != current.Digest || actual.Snapshot.Copy != page.Privacy.Copy || actual.Snapshot.PurposeSummary != page.Privacy.PurposeSummary || actual.Snapshot.LegalBasisDisclosure != page.Privacy.LegalBasis {
				t.Fatal("native action did not persist the exact actual Swedish GET notice bytes")
			}
			canonical, err := actual.Snapshot.CanonicalJSON()
			if err != nil || bytes.Contains(canonical, []byte(`"copy_locale"`)) {
				t.Fatal("view-only locale metadata entered the unchanged canonical snapshot schema", err)
			}
			afterRaw, afterEvidence := article13StoredRecipientEvidenceV128(t, english)
			if !bytes.Equal(afterRaw, oldRaw) || afterEvidence != oldEvidence || oldEvidence.Validate() != nil {
				t.Fatal("stored English evidence changed or stopped verifying after a Swedish response")
			}
			q.assertObserversOnlyV1(t)
		})
	}
}
