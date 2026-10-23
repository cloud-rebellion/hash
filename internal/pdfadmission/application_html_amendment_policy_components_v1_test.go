// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unsafe"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/testfixture"
)

func TestAmendmentPolicyNativeInputAndReadinessBounds483(t *testing.T) {
	in, _, _ := testfixture.HTMLContract(t)
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	m.ContractProfile.AmendmentPolicy = &htmlmaster.AmendmentPolicyV1{Term: "scope", ClauseReference: strings.Repeat("<", 512), AllowedModes: []string{"signature", "acknowledgement", "agreed_notice"}, AllowedChannels: []string{"email"}, EffectiveCondition: strings.Repeat("&", 2048)}
	raw, err := json.Marshal(map[string]any{"name": "Reviewed changes", "html_master_json": m, "variables_json": map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := htmlAuthoringInputShapeForV1(context.Background(), HTMLTemplateMasterInputV1, raw); err != nil {
		t.Fatal("real declared policy rejected by native command scanner", err)
	}
	encoded, _ := json.Marshal(m.ContractProfile)
	got, err := htmlRevisionContractReadinessComponentsForV1(m, htmlmaster.Input{Values: in.Values, Sections: in.Sections})
	if err != nil || got.profileJSONBytes < int64(len(encoded)) {
		t.Fatalf("escaped real policy profile bytes omitted: %d < %d: %v", got.profileJSONBytes, len(encoded), err)
	}
	clone, err := htmlRevisionPreparedMasterProjectionV1(m)
	if err != nil {
		t.Fatal(err)
	}
	ceiling, err := htmlRevisionPreparedMasterProjectionCeilingV1()
	if err != nil || ceiling < clone {
		t.Fatal("policy clone arrays exceed before-getter ceiling", err)
	}
	stored, err := htmlStoredPreparedMasterProjectionV1(m)
	if err != nil || stored < clone {
		t.Fatal("stored profile clone omitted policy", err)
	}
	if unsafe.Sizeof(htmlmaster.ContractProfile{}) != 96 {
		t.Fatal("profile typed ownership layout changed")
	}
	m.ContractProfile.AmendmentPolicy.AllowedModes = append(m.ContractProfile.AmendmentPolicy.AllowedModes, "signature")
	raw, _ = json.Marshal(map[string]any{"name": "Oversized changes", "html_master_json": m, "variables_json": map[string]string{}})
	if _, err := htmlAuthoringInputShapeForV1(context.Background(), HTMLTemplateMasterInputV1, raw); err == nil {
		t.Fatal("native parser accepted fourth mode")
	}
	if _, err := htmlRevisionPreparedMasterProjectionV1(m); err == nil {
		t.Fatal("oversized lists admitted before native clone")
	}
}
