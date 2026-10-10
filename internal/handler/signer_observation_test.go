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

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func staticSignerObservationFixture() *sign.RecipientContext {
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Name: "Reviewed offer", SourceKind: "pdf",
		Status: "sent", RequiresSignature: true, RoutingTier: "parallel", EvidenceVersionPinsRequired: true,
		PdfStorageKey:       pgtype.Text{String: "private/source.pdf", Valid: true},
		PdfStorageVersionID: pgtype.Text{String: "private-version-capability", Valid: true},
		PdfSha256:           bytes.Repeat([]byte{0xa7}, sha256.Size)}
	return &sign.RecipientContext{Document: doc, Recipient: &generated.GetRecipientByTokenHashRow{
		ID: uuid.New(), DocumentID: doc.ID, DocOrgID: doc.OrgID, DocStatus: doc.Status, Role: "signer"}}
}

func TestSignerPDFObservationPreservesLegacyExactBytesWithoutInventingPageCount(t *testing.T) {
	rc := staticSignerObservationFixture()
	observation, err := signerPDFObservationFor(rc)
	if err != nil || observation == nil || observation.DocumentID != rc.Document.ID || observation.RecipientID != rc.Recipient.ID ||
		observation.PDFSHA256 != hex.EncodeToString(rc.Document.PdfSha256) || observation.PageCount != 0 || observation.MaterializationRevision != 0 || observation.HTMLSourceCommitment != "" {
		t.Fatalf("unexpected legacy public witness: %v", err)
	}
	if err := validateSignerMaterialization(context.Background(), nil, rc.Document); err != nil {
		t.Fatalf("static PDF must not require nonexistent HTML history: %v", err)
	}
	encoded, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{rc.Document.OrgID.String(), rc.Document.PdfStorageKey.String, rc.Document.PdfStorageVersionID.String,
		"page_count", "materialization_revision", "html_source_commitment", "org_id", "storage", "version_id"} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("public observation exposed private or unmeasured metadata %q", private)
		}
	}
	w := httptest.NewRecorder()
	setSignerPDFObservationHeaders(w, observation)
	if w.Header().Get("X-Hash-PDF-SHA256") != observation.PDFSHA256 || len(w.Header()) != 3 {
		t.Fatalf("unexpected legacy observation headers: %v", w.Header())
	}
}

func TestSignerPDFObservationRefusesDamagedSourceIdentity(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*sign.RecipientContext)
	}{
		{"missing document", func(rc *sign.RecipientContext) { rc.Document = nil }},
		{"missing recipient", func(rc *sign.RecipientContext) { rc.Recipient = nil }},
		{"cross-document recipient", func(rc *sign.RecipientContext) { rc.Recipient.DocumentID = uuid.New() }},
		{"cross-organization recipient", func(rc *sign.RecipientContext) { rc.Recipient.DocOrgID = uuid.New() }},
		{"envelope has no single source", func(rc *sign.RecipientContext) { rc.Document.IsEnvelope = true }},
		{"missing source key", func(rc *sign.RecipientContext) { rc.Document.PdfStorageKey = pgtype.Text{} }},
		{"missing digest", func(rc *sign.RecipientContext) { rc.Document.PdfSha256 = nil }},
		{"missing required version", func(rc *sign.RecipientContext) { rc.Document.PdfStorageVersionID = pgtype.Text{} }},
		{"orphaned registered projection", func(rc *sign.RecipientContext) {
			rc.Document.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}},
		{"invalid saved HTML source", func(rc *sign.RecipientContext) { rc.Document.HtmlSourceJson = []byte(`{"raw_source":"private"}`) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			rc := staticSignerObservationFixture()
			test.mutate(rc)
			if observation, err := signerPDFObservationFor(rc); err == nil || observation != nil {
				t.Fatal("damaged PDF source produced a public witness")
			}
		})
	}
	rc := staticSignerObservationFixture()
	rc.Document.SourceKind = "blocks"
	if observation, err := signerPDFObservationFor(rc); err != nil || observation != nil {
		t.Fatal("block source must not invent a PDF witness")
	}
}

func TestSignerPDFObservationHeadersBindEveryRegisteredPublicField(t *testing.T) {
	observation := &signerPDFObservation{DocumentID: uuid.New(), RecipientID: uuid.New(), PDFSHA256: strings.Repeat("a", 64),
		PageCount: 7, HTMLSourceCommitment: strings.Repeat("b", 64), MaterializationRevision: 3}
	w := httptest.NewRecorder()
	setSignerPDFObservationHeaders(w, observation)
	for key, want := range map[string]string{"X-Hash-Document-Id": observation.DocumentID.String(), "X-Hash-Recipient-Id": observation.RecipientID.String(),
		"X-Hash-PDF-SHA256": observation.PDFSHA256, "X-Hash-PDF-Pages": "7", "X-Hash-HTML-Source-Commitment": observation.HTMLSourceCommitment,
		"X-Hash-Materialization-Revision": "3"} {
		if got := w.Header().Get(key); got != want {
			t.Fatalf("missing or inconsistent %s", key)
		}
	}
	if len(w.Header()) != 6 {
		t.Fatal("unexpected public metadata")
	}
	copy := *observation
	copy.MaterializationRevision++
	if sameSignerPDFObservation(observation, &copy) || sameSignerPDFObservation(nil, observation) || !sameSignerPDFObservation(nil, nil) {
		t.Fatal("artifact witnesses did not retain exact optional-field presence and revision")
	}
}

func TestSignerReadSourceComparisonRejectsChangesButAllowsActiveProgression(t *testing.T) {
	original := staticSignerObservationFixture().Document
	progressed := *original
	progressed.Status = "in_progress"
	progressed.UpdatedAt.Valid = true
	if !sameSignerDocumentSource(original, &progressed) {
		t.Fatal("harmless active read progression was treated as a new source")
	}
	for _, test := range []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"different storage version", func(doc *generated.Document) { doc.PdfStorageVersionID.String += "-new" }},
		{"different PDF bytes", func(doc *generated.Document) { doc.PdfSha256 = bytes.Repeat([]byte{0xb8}, sha256.Size) }},
		{"different routing", func(doc *generated.Document) { doc.RoutingTier = "sequential" }},
		{"different content", func(doc *generated.Document) { doc.BlocksJson = []byte(`{"text":"revised"}`) }},
		{"different values", func(doc *generated.Document) { doc.VariablesJson = []byte(`{"name":"revised"}`) }},
		{"different immutable origin", func(doc *generated.Document) { doc.HtmlSourceJson = []byte(`{"origin":"revised"}`) }},
		{"different current materialization", func(doc *generated.Document) { doc.HtmlCurrentSourceJson = []byte(`{"current":"revised"}`) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := *original
			test.mutate(&changed)
			if sameSignerDocumentSource(original, &changed) {
				t.Fatal("changed source accepted as original observation")
			}
		})
	}
}

func TestSignerReadFailureDoesNotPublishArtifactWitness(t *testing.T) {
	w := httptest.NewRecorder()
	writeSignerReadError(w, sign.ErrMagicLinkExpired)
	if w.Code != http.StatusGone || w.Header().Get("X-Hash-PDF-SHA256") != "" || bytes.Contains(w.Body.Bytes(), []byte("private")) {
		t.Fatal("expired read did not fail without source metadata")
	}
}
