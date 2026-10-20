// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/article13"
)

func TestSignerFieldsNoticeAndActualCaptureProducerCostsV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	small := article13.Evidence{Schema: article13.SchemaV1, Digest: strings.Repeat("a", 64), Snapshot: article13.Snapshot{Schema: article13.SchemaV1}}
	large := small
	large.Snapshot.Controller = strings.Repeat("\x01é<&", 4096)
	large.Snapshot.Copy.RightsBody = strings.Repeat("\u2028\n\t", 4096)
	a, err := signerFieldsNoticeParentV1(ctx, small)
	if err != nil {
		t.Fatal(err)
	}
	b, err := signerFieldsNoticeParentV1(ctx, large)
	wire, marshalErr := json.Marshal(large)
	if err != nil || marshalErr != nil || b <= a || b <= int64(len(wire)) {
		t.Fatal("notice production must price actual escaped Article13 data before canonicalization", a, b, len(wire), err, marshalErr)
	}
	in := []SignerFieldValueInputV1{{FieldID: "actual-field", Value: "ÅÄÖ"}}
	one, err := signerFieldsCapturedParentV1(ctx, in, a)
	if err != nil {
		t.Fatal(err)
	}
	two, err := signerFieldsCapturedParentV1(ctx, append(in, in...), a)
	if err != nil || two < 2*one {
		t.Fatal("each actual field binder/input must retain its producer", one, two, err)
	}
	if _, err = signerFieldsCapturedParentV1(ctx, append(in, in...), math.MaxInt64); err == nil {
		t.Fatal("captured notice cost overflow admitted")
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = signerFieldsCapturedParentV1(stopped, in, a); err == nil {
		t.Fatal("cancelled input production admitted")
	}
}

func TestSignerFieldsRequestRejectsInventedReaderAndMutationV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var f ApplicationSessionFactoryV1
	var r ApplicationSignerReaderV1
	if h, err := f.NewSignerFieldsRequestV1(ctx, &r, "", "", article13.Evidence{}); err == nil || h != nil {
		t.Fatal("invented reader minted fields provenance")
	}
	var w ApplicationHTMLSendWorkV1
	if finish, err := w.BeginSignerFieldsMutationV1(ctx, &ApplicationSignerFieldsRequestV1{}); err == nil || finish != nil {
		t.Fatal("zero request minted native fields authority")
	}
	var h ApplicationSignerFieldsRequestV1
	if err := h.CaptureValuesV1(ctx, []SignerFieldValueInputV1{{FieldID: "a", Value: "b"}}); err == nil {
		t.Fatal("zero request captured a body")
	}
	if _, err := h.ValuesV1(); err == nil {
		t.Fatal("zero request exposed field inputs")
	}
	h.CloseConsumerV1()
}

func TestSignerFieldsAuditPurposeAllowsOnlyOriginalFieldEvidenceV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	if HTMLAuditSignerFieldFilledV1.KindV1() != "document.field_filled" {
		t.Fatal("field event kind changed")
	}
	payload := map[string]any{"field_id": "actual-field", "type": "text", "label": "Reviewed reference", "value_len": 4, "value_hash": strings.Repeat("a", 64), "notice_schema": article13.SchemaV1, "notice_digest": strings.Repeat("a", 64), "notice_snapshot": article13.Snapshot{Schema: article13.SchemaV1}}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerFieldFilledV1, payload); err != nil {
		t.Fatal(err)
	}
	payload["value"] = "private raw value"
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerFieldFilledV1, payload); err == nil {
		t.Fatal("field event admitted raw value outside original schema")
	}
	delete(payload, "value")
	payload["invented_authority"] = true
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditSignerFieldFilledV1, payload); err == nil {
		t.Fatal("field event admitted invented authority")
	}
}
