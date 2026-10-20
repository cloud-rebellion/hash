// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func TestHTMLAuditConcreteFixedV1CheckedPositiveInventory(t *testing.T) {
	fixed, err := htmlAuditFixedResourcesV1()
	if err != nil {
		t.Fatal(err)
	}
	raw := int64(0)
	seen := map[string]bool{}
	for _, c := range htmlAuditFixedComponentsV1() {
		if c.Name == "" || seen[c.Name] || c.Bytes <= 0 {
			t.Fatal("missing/duplicated/nonpositive actual component", c)
		}
		seen[c.Name] = true
		if !htmlStoredRetentionAllocV1(&raw, c.Bytes) {
			t.Fatal("fixed inventory overflow")
		}
	}
	exact, err := htmlStoredRetentionFinishV1(raw)
	if err != nil || fixed != exact || fixed < raw {
		t.Fatal("fixed inventory not charged", fixed, raw, err)
	}
	if fixed >= 32<<20 {
		t.Fatal("legacy broad32MiB estimate remains", fixed)
	}
	r, err := htmlAuditResourcesV1(11, 23, 7)
	if err != nil || r.WorkingBytes != fixed+16*11+32*23+256*7 || r.DBStagingBytes != fixed+16*23 {
		t.Fatal("original dynamic terms changed", r, err)
	}
	for _, x := range [][3]int64{{math.MaxInt64, 2, 1}, {0, math.MaxInt64, 1}, {0, 2, math.MaxInt64}, {-1, 2, 1}, {0, 1, 1}, {0, 2, 0}} {
		if _, err := htmlAuditResourcesV1(x[0], x[1], x[2]); err == nil {
			t.Fatal("invalid/wrapping producer accepted", x)
		}
	}
}

// This is the original public layout cardinality and actual canonical parser/
// binder, followed by source-derived event pricing and ONE shared coordinator.
// It proves finite audit cost arithmetic/resource competition only. It does
// not claim PostgreSQL acceptance or that1101 native individual loans fit
// ApplicationAdmission's512-row registry: the eventual atomic layout writer
// needs a genuine aggregate owner rather than cap growth or early refund.
func TestHTMLAuditConcreteFixedV1OriginalMaximumLayoutCalculation(t *testing.T) {
	ctx := applicationTestContextV1(t)
	layout := &pdflayout.Layout{Version: 1, Parties: make([]pdflayout.Party, pdflayout.MaxParties), Fields: make([]pdflayout.Field, pdflayout.MaxFields)}
	bindings := make([]pdflayout.Binding, pdflayout.MaxParties)
	for i := range layout.Parties {
		role := fmt.Sprintf("s%060d%03d", 0, i)
		layout.Parties[i] = pdflayout.Party{Role: role, Label: "Party slot"}
		bindings[i] = pdflayout.Binding{Role: role, Name: strings.Repeat("😀", 200), Email: fmt.Sprintf("sales%03d@example.com", i), Locale: "en"}
	}
	for i := range layout.Fields {
		layout.Fields[i] = pdflayout.Field{PartyRole: layout.Parties[i%len(layout.Parties)].Role, Type: "signature", Page: 1, XPct: 0, YPct: 0, WPct: 10, HPct: 3, Required: true, Label: strings.Repeat("f", 64)}
	}
	raw, err := json.Marshal(layout)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := pdflayout.Parse(raw, 1)
	if err != nil {
		t.Fatal("original maximum layout refused", err)
	}
	parties, err := accepted.Bind(bindings, "en")
	if err != nil {
		t.Fatal("original full party binding refused", err)
	}
	if len(parties) != 100 || len(accepted.Fields) != 1000 {
		t.Fatal("original maxima narrowed")
	}
	type event struct {
		purpose HTMLAuditPurposeV1
		payload map[string]any
	}
	events := make([]event, 0, len(parties)+len(accepted.Fields)+1)
	for _, party := range parties {
		events = append(events, event{HTMLAuditPlainLayoutRecipientCreatedV1, map[string]any{"role": party.Role, "name": party.Name, "email": party.Email, "via": "rest", "template_layout_version": accepted.Version}})
	}
	for _, field := range accepted.Fields {
		events = append(events, event{HTMLAuditPlainFieldAddedV1, map[string]any{"field_id": uuid.New(), "recipient_id": uuid.New(), "party_role": field.PartyRole, "type": "signature", "page": field.Page, "required": true, "via": "rest"}})
	}
	events = append(events, event{HTMLAuditPlainPDFCreatedV1, map[string]any{"name": "Exact source contract", "source_kind": "pdf", "template_id": uuid.New().String(), "template_version": int32(1), "layout_version": 1, "party_count": len(parties)}})
	// Explicit synthetic arithmetic fixture; these limits do not replace any
	// application limits, factory registry, runtime profile or live capacity proof.
	limit := workguard.VectorV1{ParentBytes: 256 << 20, DBStagingBytes: 256 << 20}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limit, Organisation: limit, MaxGrants: int64(len(events)), MaxOrganisationGrants: int64(len(events))})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	org, document := uuid.New(), uuid.New()
	closes := make([]func(), 0, len(events))
	defer func() {
		for _, close := range closes {
			close()
		}
	}()
	var totalParent, totalDB int64
	for _, event := range events {
		shape, err := htmlAuditPayloadShapeV1(ctx, event.purpose, event.payload)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range [...]string{event.purpose.KindV1(), "", ""} {
			if err = shape.text(text, false); err != nil {
				t.Fatal(err)
			}
		}
		if err = shape.add(192, 4096, 16); err != nil {
			t.Fatal(err)
		}
		resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
		if err != nil {
			t.Fatal(err)
		}
		close, err := work.ApplicationV1(ctx, ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: org, DocumentID: document, HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
		if err != nil {
			t.Fatalf("actual1101-event cost exceeds fixture before final event: %v", err)
		}
		closes = append(closes, close)
		totalParent += resources.WorkingBytes
		totalDB += resources.DBStagingBytes
	}
	snapshot := coordinator.SnapshotV1(org)
	if snapshot.Global.ParentBytes != totalParent || snapshot.Global.DBStagingBytes != totalDB || snapshot.GlobalGrants != int64(len(events)) || len(events) != 1101 {
		t.Fatal("event costs not actually retained", snapshot, len(events))
	}
	t.Logf("actual1101event source arithmetic: parent=%d db=%d canonical_layout=%d", totalParent, totalDB, len(raw))
	for _, close := range closes {
		close()
	}
	if got := coordinator.SnapshotV1(org); got != (workguard.SnapshotV1{}) {
		t.Fatal("resource fixture did not retire", got)
	}
}
