// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestHTMLAuthoringStringMapsChargeActualEscapedInputV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, m := range []map[string]string{nil, {}, {"company": "Å😀\\\"<>&\u2028\u0001"}, {"\n": "\t", "quote\"": "\\", "é": "😀"}} {
		raw, wire, err := htmlAuthoringStringMapCostV1(ctx, m)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		// Omitted typed maps have the existing {} meaning, not JSON null.
		if m == nil {
			encoded = []byte("{}")
		}
		pgWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, encoded)
		if err != nil {
			t.Fatal(err)
		}
		if wire < int64(len(encoded)) || wire < pgWire {
			t.Fatalf("string map undercharged: raw=%d wire=%d encoded=%d pg=%d", raw, wire, len(encoded), pgWire)
		}
	}
	if _, _, err := htmlAuthoringStringMapCostV1(ctx, map[string]string{"x": string([]byte{0xff})}); err == nil {
		t.Fatal("invalid UTF8 supplied a string producer bound")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, _, err := htmlAuthoringStringMapCostV1(canceled, map[string]string{"x": "retained"}); err == nil {
		t.Fatal("canceled producer scan accepted")
	}
}
func TestHTMLAuthoringCostOverflowRefusesV1(t *testing.T) {
	for _, cost := range [][2]int64{{-1, 0}, {0, -1}, {math.MaxInt64, 0}, {0, math.MaxInt64}, {math.MaxInt64 / 8, 1}} {
		if _, err := htmlAuthoringResourcesV1(cost[0], cost[1]); err == nil {
			t.Fatalf("overflow/negative accepted: %v", cost)
		}
	}
	if _, err := htmlAuthoringSumV1(math.MaxInt64, 1); err == nil {
		t.Fatal("header sum overflow accepted")
	}
	if _, err := htmlAuthoringSumV1(1, -1); err == nil {
		t.Fatal("missing cache became a zero body")
	}
}
func TestHTMLAuthoringFixedWorkRejectsUnderchargeAndForeignFieldsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := htmlAuthoringResourcesV1(12345, 45678)
	if err != nil {
		t.Fatal(err)
	}
	limit := workguard.VectorV1{ParentBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: 2, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	b := ApplicationBudgetV1{Phase: "locked-html-authoring-read", OrgID: org, DocumentID: uuid.New(), HTMLAuthoringRawBytes: 12345, HTMLAuthoringWireBytes: 45678, WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	for _, bad := range []ApplicationBudgetV1{
		func() ApplicationBudgetV1 { x := b; x.WorkingBytes--; return x }(), func() ApplicationBudgetV1 { x := b; x.DBStagingBytes--; return x }(),
		func() ApplicationBudgetV1 { x := b; x.HTMLInputWireBytes = 1; return x }(), func() ApplicationBudgetV1 { x := b; x.RecipientID = uuid.New(); return x }(),
		func() ApplicationBudgetV1 { x := b; x.AdmissionID = uuid.New(); return x }(), func() ApplicationBudgetV1 { x := b; x.Phase = "locked-html-authoring-header"; return x }(),
	} {
		if close, err := work.ApplicationV1(ctx, bad); err == nil || close != nil {
			t.Fatal("changed fixed loan accepted")
		}
	}
	close, err := work.ApplicationV1(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != limit || got.GlobalGrants != 1 {
		t.Fatalf("actual shared accounting wrong: %+v", got)
	}
	if again, err := work.ApplicationV1(ctx, b); err == nil || again != nil {
		t.Fatal("capacity overrun accepted")
	}
	close()
	if got := coordinator.SnapshotV1(org); got.GlobalGrants != 0 {
		t.Fatalf("closed fixed work remained: %+v", got)
	}
}
func TestHTMLAuthoringRequiresNativeOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, session := range []*ApplicationSessionV1{nil, {}} {
		if reader, err := session.NewHTMLAuthoringReaderV1(ctx); err == nil || reader != nil {
			t.Fatal("external owner shell admitted")
		}
		if writer, err := session.NewHTMLTemplateWriterV1(ctx, HTMLTemplateWriterInputV1{}); err == nil || writer != nil {
			t.Fatal("external writer shell admitted")
		}
	}
	var reader *ApplicationHTMLAuthoringReaderV1
	if _, _, err := reader.ReadTemplateRevisionV1(ctx, uuid.New(), 1); err == nil {
		t.Fatal("nil reader can load an uncached body")
	}
	if _, err := reader.ReadCreationResponseV1(ctx, uuid.New()); err == nil {
		t.Fatal("nil reader can replay")
	}
	reader.CloseConsumerV1()
}
