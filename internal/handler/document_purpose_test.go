// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDocumentPurposeResponseAndRefusalsV1(t *testing.T) {
	for _, p := range []documentpurpose.Purpose{documentpurpose.Document, documentpurpose.Presentation, documentpurpose.Signing} {
		raw, err := documentpurpose.With([]byte(`{}`), p)
		if err != nil {
			t.Fatal(err)
		}
		d := &generated.Document{Metadata: raw}
		if toDocumentResponse(d).Purpose != p {
			t.Fatal("purpose lost in response", p)
		}
	}
	if toDocumentResponse(&generated.Document{}).Purpose != documentpurpose.Signing {
		t.Fatal("legacy response incompatible")
	}
	if toDocumentResponse(&generated.Document{Metadata: []byte(`{"hash:document-purpose:v1":false}`)}).Purpose != "" {
		t.Fatal("invalid purpose appeared as signing")
	}
	s := &Server{}
	for _, cause := range []error{documentpurpose.ErrInvalid, documentpurpose.ErrSigningRequired, documentpurpose.ErrTransition} {
		for name, write := range map[string]func(http.ResponseWriter, error){"send": s.writeSendError, "create": s.writeDocumentCreationError, "plain": s.writeOwnedPlainDraftErrorV1, "recipient": func(w http.ResponseWriter, e error) { s.writeRecipientMutationError(w, "test", e) }, "field": func(w http.ResponseWriter, e error) { s.writeFieldMutationError(w, "test", e) }} {
			t.Run(name+cause.Error(), func(t *testing.T) {
				w := httptest.NewRecorder()
				write(w, errors.Join(errors.New("wrapper"), cause))
				if w.Code != http.StatusConflict {
					t.Fatal("mode refusal became infrastructure failure", w.Code)
				}
			})
		}
	}
}

func TestDocumentPurposeOnlyPatchInputV1(t *testing.T) {
	for _, raw := range []string{`{"purpose":null}`, `{"purpose":""}`, `{"purpose":"signature"}`, `{"purpose":"document","name":"changed"}`, `{"purpose":"document","requires_signature":false}`, `{"purpose":"document","blocks_json":{"version":1,"blocks":[]}}`} {
		var in updateDocumentInput
		if json.Unmarshal([]byte(raw), &in) != nil {
			t.Fatal("fixture malformed")
		}
		if _, present, err := documentPurposeEditInputV1(in); !present || err == nil {
			t.Fatal("invalid/combined purpose edit accepted", raw)
		}
	}
	var old updateDocumentInput
	if _, present, err := documentPurposeEditInputV1(old); present || err != nil {
		t.Fatal("omitted purpose changed legacy patch")
	}
	var valid updateDocumentInput
	_ = json.Unmarshal([]byte(`{"purpose":"presentation","expected_updated_at":"current"}`), &valid)
	p, present, err := documentPurposeEditInputV1(valid)
	if err != nil || !present || p != documentpurpose.Presentation {
		t.Fatal(p, present, err)
	}
}

func TestDocumentPurposePreservesReviewedHTMLContractV1(t *testing.T) {
	for _, p := range []documentpurpose.Purpose{documentpurpose.Document, documentpurpose.Presentation} {
		if !errors.Is(validateHTMLDocumentPurposeV1(p, true), documentpurpose.ErrSigningRequired) {
			t.Fatal("reviewed signing profile was silently converted", p)
		}
		if err := validateHTMLDocumentPurposeV1(p, false); err != nil {
			t.Fatal("ordinary design rejected", p, err)
		}
	}
	for _, p := range []documentpurpose.Purpose{"", documentpurpose.Signing} {
		if err := validateHTMLDocumentPurposeV1(p, true); err != nil {
			t.Fatal("legacy signing profile changed", p, err)
		}
	}
}
