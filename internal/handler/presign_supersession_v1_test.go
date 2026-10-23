// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

func supersessionInputFixtureV1() (authoring.Actor, preSignSupersessionInputV1) {
	actor := authoring.Actor{OrgID: uuid.New(), UserID: uuid.New()}
	template := uuid.New()
	return actor, preSignSupersessionInputV1{Prior: pdfadmission.PreSignSupersessionParentV1{ExecutionID: uuid.New(), ExecutionSHA256: strings.Repeat("a", 64), DocumentID: uuid.New(), SourceCommitment: strings.Repeat("b", 64), MaterializationID: uuid.New(), MaterializationRevision: 1,
		Template: presign.TemplatePin{ID: template, Version: 1, ContentSHA256: strings.Repeat("c", 64), ApprovedBy: uuid.New(), ApprovedAt: time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC)}}, TemplateID: template,
		Source: htmlDocumentInput{Name: "Fresh linked signing draft", ExpectedTemplateVersion: 2, ExpectedTemplateContentSHA256: strings.Repeat("d", 64), Values: htmlStringMap{"customer_name": "Current Customer"}, Sections: htmlStringMap{"scope": "New reviewed wording"}, RequestID: uuid.New(), ExpectedOrgID: actor.OrgID, ExpectedUserID: actor.UserID}}
}
func TestSupersessionCommandBindsActualParentAndFreshSourceRequestV1(t *testing.T) {
	actor, in := supersessionInputFixtureV1()
	original, err := preSignSupersessionInputDigestV1(actor, in)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := crmTemplateCreateInputDigest(actor, in.TemplateID, in.Source)
	if err != nil || original == inner {
		t.Fatal("ordinary source domain reused", err)
	}
	for name, change := range map[string]func(*preSignSupersessionInputV1){
		"request": func(v *preSignSupersessionInputV1) { v.Source.RequestID = uuid.New() }, "execution": func(v *preSignSupersessionInputV1) { v.Prior.ExecutionID = uuid.New() }, "execution hash": func(v *preSignSupersessionInputV1) { v.Prior.ExecutionSHA256 = strings.Repeat("e", 64) },
		"prior document": func(v *preSignSupersessionInputV1) { v.Prior.DocumentID = uuid.New() }, "prior source": func(v *preSignSupersessionInputV1) { v.Prior.SourceCommitment = strings.Repeat("e", 64) }, "prior materialization": func(v *preSignSupersessionInputV1) { v.Prior.MaterializationID = uuid.New() }, "prior revision": func(v *preSignSupersessionInputV1) { v.Prior.MaterializationRevision++ },
		"prior template version": func(v *preSignSupersessionInputV1) { v.Prior.Template.Version++ }, "prior template content": func(v *preSignSupersessionInputV1) { v.Prior.Template.ContentSHA256 = strings.Repeat("e", 64) }, "approval": func(v *preSignSupersessionInputV1) { v.Prior.Template.ApprovedBy = uuid.New() }, "approval time": func(v *preSignSupersessionInputV1) {
			v.Prior.Template.ApprovedAt = v.Prior.Template.ApprovedAt.Add(time.Second)
		},
		"fresh name": func(v *preSignSupersessionInputV1) { v.Source.Name += " changed" }, "fresh revision": func(v *preSignSupersessionInputV1) { v.Source.ExpectedTemplateVersion++ }, "fresh content": func(v *preSignSupersessionInputV1) { v.Source.ExpectedTemplateContentSHA256 = strings.Repeat("e", 64) },
		"fresh value": func(v *preSignSupersessionInputV1) {
			v.Source.Values = htmlStringMap{"customer_name": "Other Customer"}
		}, "fresh wording": func(v *preSignSupersessionInputV1) { v.Source.Sections = htmlStringMap{"scope": "Other wording"} },
	} {
		t.Run(name, func(t *testing.T) {
			v := in
			change(&v)
			changed, err := preSignSupersessionInputDigestV1(actor, v)
			if err != nil || changed == original {
				t.Fatal("changed lineage adopted original request", err)
			}
		})
	}
	for _, change := range []func(*preSignSupersessionInputV1){func(v *preSignSupersessionInputV1) { v.TemplateID = uuid.New() }, func(v *preSignSupersessionInputV1) { v.Source.RequestID = uuid.Nil }, func(v *preSignSupersessionInputV1) { v.Source.ExpectedUserID = uuid.New() }, func(v *preSignSupersessionInputV1) { v.Prior.ExecutionSHA256 = strings.Repeat("A", 64) }} {
		v := in
		change(&v)
		if _, err := preSignSupersessionInputDigestV1(actor, v); err == nil {
			t.Fatal("invalid expected observation accepted")
		}
	}
}

func TestSupersessionWireCannotSupplyLinkSignatureOrAuthorityV1(t *testing.T) {
	_, in := supersessionInputFixtureV1()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"link":             strings.Replace(string(raw), `"prior":`, `"audit_event_id":"`+uuid.NewString()+`","prior":`, 1),
		"signature":        strings.Replace(string(raw), `"prior":`, `"signature":{"signed":true},"prior":`, 1),
		"unknown parent":   strings.Replace(string(raw), `"execution_id":`, `"verified":true,"execution_id":`, 1),
		"duplicate parent": strings.Replace(string(raw), `"execution_id":`, `"execution_id":"`+uuid.NewString()+`","execution_id":`, 1),
		"case alias":       strings.Replace(string(raw), `"template_id":`, `"TemplateID":"`+uuid.NewString()+`","template_id":`, 1),
		"trailing":         string(raw) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			var parsed preSignSupersessionInputV1
			if decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(bad)), &parsed) == nil {
				t.Fatal("caller minted lineage or authority")
			}
		})
	}
	var round preSignSupersessionInputV1
	if err = decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &round); err != nil {
		t.Fatal(err)
	}
	next, err := json.Marshal(round)
	if err != nil || string(next) != string(raw) {
		t.Fatal("closed original command did not roundtrip", err)
	}
}
