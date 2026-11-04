// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package send

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/remindercadence"
	"math"
	"testing"
)

func TestAutomation121PurposeProjectionFailsClosedWithoutReadingWholeMetadata(t *testing.T) {
	for _, tc := range []struct {
		name        string
		object, set bool
		raw         string
		signing     bool
	}{
		{name: "legacy", object: true, signing: true},
		{name: "signing", object: true, set: true, raw: `{"schema_version":1,"purpose":"signing"}`, signing: true},
		{name: "document", object: true, set: true, raw: `{"schema_version":1,"purpose":"document"}`},
		{name: "presentation", object: true, set: true, raw: `{"schema_version":1,"purpose":"presentation"}`},
		{name: "malformed", object: true, set: true, raw: `null`},
		{name: "unknown", object: true, set: true, raw: `{"schema_version":2,"purpose":"signing"}`},
		{name: "nonobject"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := &generated.GetDocumentReminderTargetForUpdateV1Row{MetadataObject: tc.object, PurposeSet: tc.set, ReservedPurpose: json.RawMessage(tc.raw)}
			if automationDocumentSigningV1(row) != tc.signing {
				t.Fatal("unsafe purpose became signing")
			}
		})
	}
}
func TestAutomation121FiniteInputsAndExactDTO(t *testing.T) {
	if automationRevisionV1(-1) || automationRevisionV1(math.MaxInt64) || !automationRevisionV1(0) {
		t.Fatal("revision overflow admitted")
	}
	p, err := automationPolicyViewV1(remindercadence.PolicyV1{Mode: "inherit"})
	if err != nil || p.OffsetsDays == nil || len(p.OffsetsDays) != 0 {
		t.Fatal("inherit not explicit empty offsets")
	}
	raw, err := json.Marshal(p)
	if err != nil || string(raw) != `{"mode":"inherit","interval_days":0,"max_fires":0,"offsets_days":[]}` {
		t.Fatal("contract drift", string(raw), err)
	}
	for _, x := range [][3]int{{0, 0, 2}, {0, 1, 2}, {0, 0, -1}} {
		_, err := automationPolicyRowV1("legacy", int32(x[1]), int32(x[2]))
		if (err == nil) != (x[1] == 0 && x[2] == 2) {
			t.Fatal("malformed stored policy accepted", x)
		}
	}
}
