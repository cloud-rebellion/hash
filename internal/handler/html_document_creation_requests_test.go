// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLCreationRecoveryWireRejectsAmbiguousAndNullCommands(t *testing.T) {
	id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	for _, body := range []string{
		`{"request_id":null}`, `{"request_id":"00000000-0000-0000-0000-000000000000"}`,
		`{"request_id":"` + strings.ToUpper(id) + `"}`, `{"request_id":"` + id + `","REQUEST_ID":"` + id + `"}`,
		`{"crm_population":null}`, `{"crm_population":42}`, `{"crm_population":{"confirmed":true,"CONFIRMED":false}}`,
		`{"expected_org_id":"` + id + `"}`, `{"expected_org_id":null,"expected_user_id":"` + id + `"}`,
		`{"expected_org_id":"` + id + `","expected_user_id":"00000000-0000-0000-0000-000000000000"}`,
		`{"expected_org_id":"` + id + `","expected_user_id":"` + strings.ToUpper(id) + `"}`,
		`{"values":{"party":null}}`, `{"sections":null}`,
	} {
		var input htmlDocumentInput
		if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &input); err == nil {
			t.Fatal("ambiguous/null request accepted")
		}
	}
	var input htmlDocumentInput
	if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(`{"request_id":"`+id+`","values":{},"sections":{}}`)), &input); err != nil || input.RequestID.String() != id {
		t.Fatal("canonical request ID refused", err)
	}
	// Preserve the old manual API's body cap; only the new complete CRM
	// candidate adopts the matching observation limit of 256 KiB.
	raw := `{"values":{"manual":"` + strings.Repeat("a", 256<<10) + `"},"crm_population":{}}`
	if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(raw)), &input); err == nil {
		t.Fatal("oversize CRM candidate accepted")
	}
}

func TestHTMLCreationSerializationOmitsOnlyAbsentRecoveryID(t *testing.T) {
	for _, requestID := range []uuid.UUID{uuid.Nil, uuid.New()} {
		raw, err := json.Marshal(htmlDocumentInput{Name: "Manual", RequestID: requestID})
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil {
			t.Fatal("invalid creation serialization")
		}
		value, present := fields["request_id"]
		if present != (requestID != uuid.Nil) {
			t.Fatal("absent request ID serialized or valid request ID dropped")
		}
		if present && string(value) != `"`+requestID.String()+`"` {
			t.Fatal("request ID changed in serialization")
		}
		if _, present := fields["expected_org_id"]; present {
			t.Fatal("absent org witness serialized")
		}
		if _, present := fields["expected_user_id"]; present {
			t.Fatal("absent user witness serialized")
		}
	}
}

func TestHTMLCreationAuditNoRowFailureIsBackendFailure(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).writeHTMLCreationError(w, errors.Join(errHTMLCreationAudit, pgx.ErrNoRows))
	if w.Code != 500 || strings.Contains(w.Body.String(), "revision changed") || strings.Contains(w.Body.String(), pgx.ErrNoRows.Error()) {
		t.Fatal("audit no-row failure classified as a template conflict or leaked diagnostic")
	}
}

func TestHTMLCreationManualActorWitnessPreventsSameOrganizationSwitch(t *testing.T) {
	actor := authoring.Actor{OrgID: uuid.New(), UserID: uuid.New()}
	in := htmlDocumentInput{Name: "Manual", RequestID: uuid.New(), ExpectedOrgID: actor.OrgID, ExpectedUserID: actor.UserID,
		ExpectedTemplateVersion: 1, ExpectedTemplateContentSHA256: strings.Repeat("a", 64), Values: htmlStringMap{}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var decoded htmlDocumentInput
	if err = decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &decoded); err != nil {
		t.Fatal(err)
	}
	templateID := uuid.New()
	original, err := crmTemplateCreateInputDigest(actor, templateID, decoded)
	if err != nil {
		t.Fatal(err)
	}
	foreign := actor
	foreign.UserID = uuid.New()
	if decoded.checkExpectedActor(foreign) == nil {
		t.Fatal("switched manual actor admitted")
	}
	if _, err := crmTemplateCreateInputDigest(foreign, templateID, decoded); err == nil {
		t.Fatal("foreign manual digest admitted")
	}
	decoded.ExpectedOrgID, decoded.ExpectedUserID = uuid.Nil, uuid.Nil
	legacy, err := crmTemplateCreateInputDigest(actor, templateID, decoded)
	if err != nil || original == legacy {
		t.Fatal("actor witness presence lost in semantic command", err)
	}
}

func TestHTMLCreationReplayKeepsInitialPinsSeparateFromCurrentDocument(t *testing.T) {
	doc := htmlRevisionUnitDocument(t)
	row := &generated.HtmlDocumentCreationRequest{OrgID: doc.OrgID, ActorUserID: doc.SenderID, RequestID: uuid.New(), OriginalDocumentID: doc.ID, HtmlMaterializationID: uuid.New(), HtmlSourceCommitment: strings.Repeat("a", 64), PdfSha256: []byte(strings.Repeat("b", 32)), PageCount: 2, CreatedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	// A valid old review timestamp alone cannot approve a later changed PDF.
	doc.HtmlReviewedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	result := (&htmlCreationOutcome{document: doc, pages: 2, request: row, replayed: true}).response()
	if result["review_required"] != true || result["replayed"] != true {
		t.Fatal("replay hid current review requirement")
	}
	if result["org_id"] != row.OrgID || result["user_id"] != row.ActorUserID {
		t.Fatal("creation response lost its original actor witness")
	}
	pins := result["creation"].(htmlCreationPins)
	current := result["document"].(documentResponse)
	if pins.DocumentID != doc.ID || pins.PDFSHA256 == current.PDFSHA256 || pins.HTMLSourceCommitment == current.HTMLSourceCommitment || pins.PageCount != 2 {
		t.Fatal("initial and current evidence conflated")
	}
	result = (&htmlCreationOutcome{pages: 2, request: row, replayed: true}).response()
	raw, err := json.Marshal(result)
	if err != nil || !strings.Contains(string(raw), `"document":null`) || result["creation"].(htmlCreationPins).DocumentID != doc.ID {
		t.Fatal("deleted document lost replay tombstone", err)
	}
	if result["org_id"] != row.OrgID || result["user_id"] != row.ActorUserID {
		t.Fatal("tombstone lost its original actor witness")
	}
}
