// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func testLayout() Layout {
	return Layout{Version: 1, Parties: []Party{{Role: "provider", Label: "Provider"}, {Role: "client", Label: "Client"}}, Fields: []Field{
		{PartyRole: "provider", Type: "signature", Page: 1, XPct: 10, YPct: 70, WPct: 25, HPct: 8, Required: true, Label: "Provider signature"},
		{PartyRole: "client", Type: "signature", Page: 1, XPct: 55, YPct: 70, WPct: 25, HPct: 8, Required: true, Label: "Client signature"},
	}}
}

func TestLayoutRequiresDeclaredSignatureSlotsAndBoundedPlacement(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Layout)
	}{
		{"unknown version", func(l *Layout) { l.Version = 2 }},
		{"duplicate role", func(l *Layout) { l.Parties[1].Role = "provider" }},
		{"unowned party", func(l *Layout) { l.Fields = l.Fields[:1] }},
		{"foreign slot", func(l *Layout) { l.Fields[0].PartyRole = "stranger" }},
		{"fillable text", func(l *Layout) { l.Fields[0].Type = "text" }},
		{"optional signature", func(l *Layout) { l.Fields[0].Required = false }},
		{"bad geometry", func(l *Layout) { l.Fields[0].XPct = 90 }},
		{"wrong page", func(l *Layout) { l.Fields[0].Page = 2 }},
		{"control label", func(l *Layout) { l.Parties[0].Label = "Provider\n" }},
		{"unsupported viewer", func(l *Layout) { l.Parties[0].Role = "viewer" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			layout := testLayout()
			tt.change(&layout)
			if !errors.Is(layout.Validate(1), ErrInvalid) {
				t.Fatal("invalid design accepted")
			}
		})
	}
	layout := testLayout()
	if err := layout.Validate(1); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(layout)
	if strings.Contains(string(raw), "recipient_id") || strings.Contains(string(raw), "email") {
		t.Fatal("layout includes identity")
	}
	if _, err := CanonicalForUpdate([]byte(`[{"recipient_id":"stale"}]`), 1); err == nil {
		t.Fatal("new legacy array accepted")
	}
	if layout, err := Parse([]byte(`[{"recipient_id":"stale"}]`), 1); err != nil || layout != nil {
		t.Fatal("legacy identifiers were materialized")
	}
	if _, err := Parse([]byte(`{"version":1,"recipient_id":"stale"}`), 1); err == nil {
		t.Fatal("unknown identifier accepted")
	}
	for _, raw := range []string{`{"version":1,"version":1}`, `{"VERSION":1}`, `{"version":1,"parties":[{"role":"signer","label":"\ud800"}]}`, `{"version":1,"parties":[{"role":"signer","label":"\udc00"}]}`} {
		if _, err := Parse([]byte(raw), 1); err == nil {
			t.Fatal("ambiguous or changed Unicode layout accepted")
		}
	}
}

func TestLayoutBindingsRequireCompleteFreshCanonicalIdentities(t *testing.T) {
	layout := testLayout()
	bindings := []Binding{{Role: "client", Name: " Client Name ", Email: "client@example.test", Locale: "sv-SE"}, {Role: "provider", Name: "Provider", Email: "provider@example.test"}}
	values, err := layout.Bind(bindings, "en")
	if err != nil {
		t.Fatal(err)
	}
	if values[0].Role != "provider" || values[0].OrderIndex != 0 || values[1].Name != "Client Name" || values[1].Locale != "sv" {
		t.Fatalf("bad role binding: %+v", values)
	}
	for _, input := range [][]Binding{nil, bindings[:1], {bindings[0], bindings[0]}, {{Role: "provider", Name: "", Email: "provider@example.test"}, bindings[0]}, {{Role: "wrong", Name: "Provider", Email: "provider@example.test"}, bindings[0]}} {
		if _, err := layout.Bind(input, "en"); err == nil {
			t.Fatal("incomplete or ambiguous identity accepted")
		}
	}
	raw, _ := json.Marshal(layout)
	template := &generated.Template{SourceKind: "pdf", Version: 3, FieldsJson: raw, PageCount: pgtype.Int4{Int32: 1, Valid: true}, PdfStorageKey: pgtype.Text{String: "source.pdf", Valid: true}, PdfSha256: make([]byte, 32)}
	if _, _, err := Prepare(template, nil, bindings); err == nil {
		t.Fatal("unpinned layout accepted")
	}
	wrong := int32(2)
	if _, _, err := Prepare(template, &wrong, bindings); !errors.Is(err, ErrPrecondition) {
		t.Fatal("stale layout accepted")
	}
	current := int32(3)
	if _, _, err := Prepare(template, &current, bindings); err != nil {
		t.Fatal(err)
	}
}
