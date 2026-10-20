// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"math"
	"strings"
	"testing"
	"unsafe"
)

// Canonical original Parse/Bind, actual individual event shapes and checked
// aggregate resource arithmetic. No model below authorizes SQL or measurement;
// only the separate real-PG journey can establish fresh writer authority.
func TestPDFLayoutAuditAggregateOriginal100Parties1000FieldsV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	layout := &pdflayout.Layout{Version: 1, Parties: make([]pdflayout.Party, pdflayout.MaxParties), Fields: make([]pdflayout.Field, pdflayout.MaxFields)}
	bindings := make([]pdflayout.Binding, pdflayout.MaxParties)
	for i := range layout.Parties {
		role := fmt.Sprintf("s%060d%03d", 0, i)
		layout.Parties[i] = pdflayout.Party{Role: role, Label: "Actual original party slot"}
		bindings[i] = pdflayout.Binding{Role: role, Name: strings.Repeat("😀", 200), Email: fmt.Sprintf("layout%03d@example.test", i), Locale: "en"}
	}
	for i := range layout.Fields {
		layout.Fields[i] = pdflayout.Field{PartyRole: layout.Parties[i%len(layout.Parties)].Role, Type: "signature", Page: 1, XPct: 0, YPct: 0, WPct: 10, HPct: 3, Required: true, Label: strings.Repeat("f", 64)}
	}
	raw, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := pdflayout.Parse(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	values, err := actual.Bind(bindings, "en")
	if err != nil {
		t.Fatal(err)
	}
	version := int32(7)
	source := &applicationPDFTemplateDocumentStateV1{layout: actual, values: values, fieldIDs: make([]uuid.UUID, len(actual.Fields)), input: PDFTemplateDocumentInputV1{Name: "Exact source materialization", TemplateText: uuid.NewString(), Via: "mcp", Tool: "create_document", ExpectedTemplateVersion: &version, Parties: bindings}}
	count := len(values) + len(actual.Fields) + 1
	var sum htmlAuditShapeV1
	var singleParent, singleDB int64
	for i := 0; i < count; i++ {
		purpose, shape, err := source.auditSourceShapeV1(ctx, i)
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if i < len(values) {
			v := values[i]
			payload = map[string]any{"role": v.Role, "name": v.Name, "email": v.Email, "via": "mcp", "template_layout_version": actual.Version}
		} else if i < len(values)+len(actual.Fields) {
			f := actual.Fields[i-len(values)]
			payload = map[string]any{"field_id": uuid.Nil, "recipient_id": uuid.Nil, "party_role": f.PartyRole, "type": "signature", "page": f.Page, "required": true, "via": "mcp"}
		} else {
			payload = map[string]any{"name": source.input.Name, "source_kind": "pdf", "via": "mcp", "tool": "create_document", "template_id": source.input.TemplateText, "template_version": version, "layout_version": 1, "party_count": len(bindings)}
		}
		original, err := htmlAuditPayloadShapeV1(ctx, purpose, payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range [...]string{purpose.KindV1(), "", ""} {
			if err = original.text(text, false); err != nil {
				t.Fatal(err)
			}
		}
		if err = original.add(192, 4096, 16); err != nil {
			t.Fatal(err)
		}
		if original != shape {
			t.Fatalf("pre-allocation source shape differs from actual original event %d: %+v %+v", i, shape, original)
		}
		resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
		if err != nil {
			t.Fatal(err)
		}
		singleParent += resources.WorkingBytes
		singleDB += resources.DBStagingBytes
		if err = sum.add(shape.raw, shape.wire, shape.nodes); err != nil {
			t.Fatal(err)
		}
	}
	aggregate, err := pdfLayoutAuditBatchResourcesV1(int64(count), sum.raw, sum.wire, sum.nodes)
	if err != nil {
		t.Fatal(err)
	}
	controls := 2*int64(unsafe.Sizeof(applicationPDFLayoutAuditBatchV1{})) + 2*int64(count)*int64(unsafe.Sizeof(applicationPDFLayoutAuditSlotV1{}))
	if count != 1101 || aggregate.WorkingBytes != singleParent+controls || aggregate.DBStagingBytes != singleDB {
		t.Fatal("finite aggregate lost original event or real control cost", count, aggregate, singleParent, singleDB, controls)
	}
	if aggregate.WorkingBytes > 2<<30 || aggregate.DBStagingBytes > 384<<20 {
		t.Fatal("original max event source exceeds unchanged controlled fixture", aggregate)
	}
	for _, bad := range [][4]int64{{0, 0, 0, 0}, {1102, 0, 2204, 1102}, {1, -1, 2, 1}, {1, 0, 1, 1}, {1, 0, 2, 0}, {1, math.MaxInt64, 2, 1}, {1, 0, math.MaxInt64, 1}, {1, 0, 2, math.MaxInt64}} {
		if _, err = pdfLayoutAuditBatchResourcesV1(bad[0], bad[1], bad[2], bad[3]); err == nil {
			t.Fatal("invalid or wrapping aggregate accepted", bad)
		}
	}
	// Public sizes alone cannot create the new aggregate authority.
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20}, MaxGrants: 128, MaxOrganisationGrants: 64})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	org := uuid.New()
	if close, err := work.ApplicationV1(ctx, ApplicationBudgetV1{Phase: "locked-pdf-layout-fresh-events", OrgID: org, DocumentID: uuid.New(), PDFLayoutAuditEventCount: 1101, HTMLAuditRawBytes: sum.raw, HTMLAuditWireBytes: sum.wire, HTMLAuditNodes: sum.nodes, WorkingBytes: aggregate.WorkingBytes, DBStagingBytes: aggregate.DBStagingBytes}); err == nil || close != nil {
		t.Fatal("caller sizes manufactured private aggregate source authority")
	}
	if coordinator.SnapshotV1(org) != (workguard.SnapshotV1{}) {
		t.Fatal("refused source retained a grant")
	}
	var empty *applicationPDFLayoutAuditBatchV1
	if empty.validBudgetV1(ctx, work, ApplicationBudgetV1{}) {
		t.Fatal("nil private owner accepted")
	}
	original := &applicationPDFLayoutAuditBatchV1{}
	original.self = original
	copy := &applicationPDFLayoutAuditBatchV1{self: original.self}
	if copy.self != original || copy.self == copy {
		t.Fatal("copy did not retain original self identity")
	}
	if copy.validBudgetV1(ctx, work, ApplicationBudgetV1{}) {
		t.Fatal("copied private owner accepted")
	}
}
