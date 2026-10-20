// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestHTMLCreationResourcesForV1ActualWireBound(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in := HTMLCreationInputsV1{
		StoredMaster: []byte("{\"n\":1e1000}"), StoredDefaults: []byte("{}"),
		CanonicalMaster: []byte("{\"schema_version\":1}"), CanonicalDefaults: []byte("{}"),
		Variables: []byte("{\"company\":\"é\"}"), Sections: []byte("{\"terms\":\"A\\nB\"}"),
	}
	before := string(in.StoredMaster)
	r, err := HTMLCreationResourcesForV1(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	//1e1000 is1001 decimal bytes; jsonb output also adds the key separator.
	if r.InputRawBytes < 1 || r.InputWireBytes < 1009 || r.SourceWireUpperBound < htmlCreationSourceEnvelopeWireV1 || r.WorkingBytes <= 16*r.InputWireBytes {
		t.Fatalf("expanded numeric cost omitted: %+v", r)
	}
	fixed, err := htmlCreationFixedResourcesV1(r.InputRawBytes, r.InputWireBytes, r.SourceWireUpperBound)
	if err != nil || fixed != r {
		t.Fatalf("cost formula disagreement: %+v %+v %v", r, fixed, err)
	}
	if string(in.StoredMaster) != before {
		t.Fatal("normalised agreed source")
	}
}
func TestHTMLCreationFixedCostCannotUnderchargeV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := htmlCreationFixedResourcesV1(100, 100, htmlCreationSourceEnvelopeWireV1+100)
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
	org, doc := uuid.New(), uuid.New()
	b := ApplicationBudgetV1{Phase: "locked-html-fresh-creation", OrgID: org, DocumentID: doc, HTMLInputRawBytes: r.InputRawBytes, HTMLInputWireBytes: r.InputWireBytes, HTMLSourceWireBytes: r.SourceWireUpperBound, WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	for _, bad := range []ApplicationBudgetV1{
		func() ApplicationBudgetV1 { x := b; x.WorkingBytes--; return x }(),
		func() ApplicationBudgetV1 { x := b; x.DBStagingBytes--; return x }(),
		func() ApplicationBudgetV1 { x := b; x.AdmissionID = uuid.New(); return x }(),
		func() ApplicationBudgetV1 { x := b; x.RecipientID = uuid.New(); return x }(),
		func() ApplicationBudgetV1 { x := b; x.SourceBytes = 1; return x }(),
	} {
		if close, err := work.ApplicationV1(ctx, bad); err == nil || close != nil {
			t.Fatal("accepted changed cost vector")
		}
	}
	close, err := work.ApplicationV1(ctx, b)
	if err != nil {
		t.Fatal(err)
	}
	got := coordinator.SnapshotV1(org)
	if got.Global != limit || got.GlobalGrants != 1 {
		t.Fatalf("grant not charged: %+v", got)
	}
	if again, err := work.ApplicationV1(ctx, b); err == nil || again != nil {
		t.Fatal("capacity overrun accepted")
	}
	close()
	if got := coordinator.SnapshotV1(org); got.GlobalGrants != 0 || got.Global != (workguard.VectorV1{}) {
		t.Fatalf("grant close not accounted: %+v", got)
	}
}
func TestHTMLCreationWriterRequiresNativeOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var nilSession *ApplicationSessionV1
	if w, err := nilSession.NewHTMLCreationWriterV1(ctx, HTMLCreationInputsV1{}); w != nil || err == nil {
		t.Fatal("nil owner accepted")
	}
	if w, err := (&ApplicationSessionV1{}).NewHTMLCreationWriterV1(ctx, HTMLCreationInputsV1{}); w != nil || err == nil {
		t.Fatal("caller shell owner accepted")
	}
	var nilWriter *ApplicationHTMLCreationWriterV1
	if err := nilWriter.MeasureFreshPolicyV1(ctx); err == nil {
		t.Fatal("caller shell can measure old row")
	}
	nilWriter.CloseConsumerV1()
}
func TestHTMLCreationFixedResourcesV1OverflowRefuses(t *testing.T) {
	for _, pair := range [][2]int64{{-1, 16384}, {0, 16384}, {1, 0}, {math.MaxInt64, 16384}, {1, math.MaxInt64}, {math.MaxInt64 / 8, 16384}} {
		if _, err := htmlCreationFixedResourcesV1(100, pair[0], pair[1]); err == nil {
			t.Fatalf("invalid/overflow accepted: %v", pair)
		}
	}
}

func TestHTMLCreationResourcesForV1RetainedWhitespaceCannotUndercharge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	in := HTMLCreationInputsV1{StoredMaster: []byte("{}"), StoredDefaults: []byte("{}"), CanonicalMaster: []byte("{}"), CanonicalDefaults: []byte("{}"), Variables: []byte("{}"), Sections: []byte("{}")}
	small, err := HTMLCreationResourcesForV1(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.StoredMaster = []byte(strings.Repeat(" ", 1<<20) + "{}")
	padded, err := HTMLCreationResourcesForV1(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if padded.InputWireBytes != small.InputWireBytes || padded.InputRawBytes-small.InputRawBytes != 1<<20 || padded.WorkingBytes-small.WorkingBytes != 8*(1<<20) || padded.DBStagingBytes != small.DBStagingBytes {
		t.Fatalf("raw retention was not charged: small=%+v padded=%+v", small, padded)
	}
}
