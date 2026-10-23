// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

func TestPreSignCRMCommandBindsExactRecordSelectionAndRejectsAmbiguityV1(t *testing.T) {
	in := sourceInputFixtureV1()
	credential := uuid.New()
	binding := strings.Repeat("c", 64)
	in.CRMRecords = []presignregistry.RecordRule{{Kind: "crm.contact", ID: "contact_1"}, {Kind: "crm.deal", ID: "deal_1"}}
	original, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, credential, binding)
	if err != nil {
		t.Fatal(err)
	}
	changed := in
	changed.CRMRecords = []presignregistry.RecordRule{{Kind: "crm.contact", ID: "contact_2"}, {Kind: "crm.deal", ID: "deal_1"}}
	if next, err := preSignSourceInputDigestV1(changed, in.ExpectedOrgID, in.ExpectedUserID, credential, binding); err != nil || next == original {
		t.Fatal("replacement record adopted original request", err)
	}
	for _, bad := range [][]presignregistry.RecordRule{{in.CRMRecords[1], in.CRMRecords[0]}, {in.CRMRecords[0], in.CRMRecords[0]}, {{Kind: "crm.deal", ID: "../secret"}}, {{Kind: "crm.deal"}}, {{Kind: "scanner.finding", ID: "record_1"}}} {
		changed := in
		changed.CRMRecords = bad
		if _, err := preSignSourceInputDigestV1(changed, in.ExpectedOrgID, in.ExpectedUserID, credential, binding); err == nil {
			t.Fatal("ambiguous or foreign source selection accepted")
		}
	}
}

func TestHTMLPopulationSeamPreservesOrdinaryTypedNilAndOriginalValuesV1(t *testing.T) {
	var interactive *crmTemplatePopulationAdmission
	var policy *preSignCRMSourcePopulationV1
	if normalizeHTMLPopulationV1(interactive) != nil || normalizeHTMLPopulationV1(policy) != nil || normalizeHTMLPopulationV1(nil) != nil {
		t.Fatal("typed nil changed ordinary materialization")
	}
	values := map[string]string{"customer_name": "Actual observed customer"}
	original := &crmTemplatePopulationAdmission{observation: &crmTemplateObservation{values: values}}
	actual := normalizeHTMLPopulationV1(original)
	if actual != original || actual.retainedInputValuesV1()["customer_name"] != values["customer_name"] {
		t.Fatal("interactive source changed")
	}
	clone := actual.effectiveValues()
	clone["customer_name"] = "changed clone"
	if values["customer_name"] != "Actual observed customer" {
		t.Fatal("materialization clone mutated original witness")
	}
}
