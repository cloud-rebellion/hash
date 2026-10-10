// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

func crmTemplateReceiptFixture(t *testing.T) (*Server, *http.Request, authoring.Actor, *crmTemplateContext, CRMTemplateCandidate, *crmTemplateObservation, string) {
	t.Helper()
	current := crmTemplateContextFixture(t)
	actor := authoring.Actor{OrgID: current.response.OrgID, UserID: current.response.UserID}
	cookies, err := auth.NewSignedCookie(strings.Repeat("14", 32))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: actor.UserID})
	cookie := cookies.Mint(payload, time.Hour)
	request := httptest.NewRequest(http.MethodPost, "/", nil)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	server := &Server{Cookies: cookies}
	candidate := CRMTemplateCandidate{Name: "Proposal", Values: htmlStringMap{"price": "1234"}, Sections: htmlStringMap{"scope": "Human terms"}}
	observation, err := server.observeCRMTemplate(context.Background(), current, candidate, []crmDocumentMapping{})
	if err != nil {
		t.Fatal(err)
	}
	token, err := server.mintCRMTemplateReceipt(request, actor, current, observation)
	if err != nil {
		t.Fatal(err)
	}
	return server, request, actor, current, candidate, observation, token
}

func TestCRMTemplateReceiptPurposeOriginalSessionAndCompleteCandidate(t *testing.T) {
	server, request, actor, current, candidate, observation, token := crmTemplateReceiptFixture(t)
	witness := crmTemplateWitnessFor(current)
	validate := func(r *http.Request, a authoring.Actor, id uuid.UUID, w CRMTemplateWitness, c CRMTemplateCandidate, digest, proof string) error {
		_, err := server.validateCRMTemplateReceipt(r, a, id, w, c, observation.Mappings, digest, proof)
		return err
	}
	if validate(request, actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, token) != nil {
		t.Fatal("valid sender confirmation refused")
	}
	for _, c := range []struct {
		name string
		run  func() error
	}{
		{"foreign actor", func() error {
			other := actor
			other.UserID = uuid.New()
			return validate(request, other, current.response.TemplateID, witness, candidate, observation.ReviewDigest, token)
		}},
		{"foreign org", func() error {
			other := actor
			other.OrgID = uuid.New()
			return validate(request, other, current.response.TemplateID, witness, candidate, observation.ReviewDigest, token)
		}},
		{"new cookie", func() error {
			r := httptest.NewRequest("POST", "/", nil)
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "different-original-cookie"})
			return validate(r, actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, token)
		}},
		{"missing cookie", func() error {
			return validate(httptest.NewRequest("POST", "/", nil), actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, token)
		}},
		{"different template", func() error {
			return validate(request, actor, uuid.New(), witness, candidate, observation.ReviewDigest, token)
		}},
		{"different approval", func() error {
			w := witness
			w.ExpectedTemplateApprovedBy = uuid.New()
			return validate(request, actor, current.response.TemplateID, w, candidate, observation.ReviewDigest, token)
		}},
		{"different manual wording", func() error {
			c := candidate
			c.Sections = htmlStringMap{"scope": "Different terms"}
			return validate(request, actor, current.response.TemplateID, witness, c, observation.ReviewDigest, token)
		}},
		{"different values", func() error {
			c := candidate
			c.Values = htmlStringMap{"price": "1235"}
			return validate(request, actor, current.response.TemplateID, witness, c, observation.ReviewDigest, token)
		}},
		{"different name", func() error {
			c := candidate
			c.Name = "Other proposal"
			return validate(request, actor, current.response.TemplateID, witness, c, observation.ReviewDigest, token)
		}},
		{"different review", func() error {
			return validate(request, actor, current.response.TemplateID, witness, candidate, strings.Repeat("a", 64), token)
		}},
		{"ordinary login purpose", func() error {
			cookie, _ := request.Cookie(SessionCookieName)
			return validate(request, actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, cookie.Value)
		}},
		{"owner preview purpose", func() error {
			raw, _ := server.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, token)
			proof, err := server.Cookies.MintPurpose(htmlTemplatePreviewPurpose, raw, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			return validate(request, actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, proof)
		}},
		{"oversized token", func() error {
			return validate(request, actor, current.response.TemplateID, witness, candidate, observation.ReviewDigest, strings.Repeat("x", maxCRMTemplateReceipt+1))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.run() == nil {
				t.Fatal("changed purpose or confirmation admitted")
			}
		})
	}
}

func TestCRMTemplateReceiptStrictEnvelopeAndOriginalReadExpiry(t *testing.T) {
	server, request, actor, current, candidate, observation, token := crmTemplateReceiptFixture(t)
	raw, err := server.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, token)
	if err != nil {
		t.Fatal(err)
	}
	var receipt crmTemplateReceipt
	if json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("fixture receipt invalid")
	}
	for _, c := range []struct {
		name    string
		payload func() []byte
	}{
		{"missing explicit empty identity", func() []byte {
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(raw, &fields)
			delete(fields, "origin")
			body, _ := json.Marshal(fields)
			return body
		}},
		{"null explicit empty identity", func() []byte { return []byte(strings.Replace(string(raw), `"origin":""`, `"origin":null`, 1)) }},
		{"cased member", func() []byte { return []byte(strings.Replace(string(raw), `"schema_version"`, `"SCHEMA_VERSION"`, 1)) }},
		{"duplicate member", func() []byte {
			return []byte(strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))
		}},
		{"trailing object", func() []byte { return append(append([]byte{}, raw...), []byte(`{}`)...) }},
		{"reminted long window", func() []byte {
			p := receipt
			p.ExpiresAt = p.ObservedAt.Add(10 * time.Minute)
			body, _ := json.Marshal(p)
			return body
		}},
		{"expired original read", func() []byte {
			p := receipt
			p.ObservedAt = time.Now().Add(-time.Minute)
			p.IssuedAt = p.ObservedAt
			p.ExpiresAt = p.ObservedAt.Add(resolver.CRMObservationMaxAge)
			body, _ := json.Marshal(p)
			return body
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			proof, err := server.Cookies.MintPurpose(crmTemplateReceiptPurpose, c.payload(), time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = server.validateCRMTemplateReceipt(request, actor, current.response.TemplateID, crmTemplateWitnessFor(current), candidate, observation.Mappings, observation.ReviewDigest, proof); !errors.Is(err, errCRMTemplateReceipt) {
				t.Fatal("malformed or extended original confirmation admitted")
			}
		})
	}
}

func TestCRMTemplateAdmissionChecksBothFreshnessWindowsAndDefensiveValues(t *testing.T) {
	server, request, actor, current, candidate, observation, token := crmTemplateReceiptFixture(t)
	receipt, err := server.validateCRMTemplateReceipt(request, actor, current.response.TemplateID, crmTemplateWitnessFor(current), candidate, observation.Mappings, observation.ReviewDigest, token)
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	admission := &crmTemplatePopulationAdmission{source: current, witness: crmTemplateWitnessFor(current), candidate: candidate, receipt: receipt, observation: observation, now: func() time.Time { return clock }}
	if err := admission.checkDeadline(); err != nil {
		t.Fatal("current private admission refused", err)
	}
	copy := admission.effectiveValues()
	copy["price"] = "forged"
	if admission.effectiveValues()["price"] == "forged" {
		t.Fatal("renderer changed admitted values")
	}
	clock = receipt.ExpiresAt
	observation.observationAt = clock // A new read cannot extend old confirmation.
	if admission.checkDeadline() == nil {
		t.Fatal("fresh read extended human receipt expiry")
	}
	clock = receipt.ObservedAt.Add(10 * time.Second)
	observation.observationAt = clock.Add(-resolver.CRMObservationMaxAge - time.Nanosecond)
	if admission.checkDeadline() == nil {
		t.Fatal("current receipt excused stale fresh read")
	}
	observation.observationAt = clock
	observation.Mappings = []crmDocumentMapping{{"price", "crm.deal", "deal_one", "value"}}
	observation.snapshot = &crmconnection.Snapshot{}
	if admission.checkDeadline() == nil {
		t.Fatal("client-style fabricated proof admitted as empty population")
	}
}
