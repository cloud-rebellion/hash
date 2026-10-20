// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// The frozen basis must require exactly the ordinary base pages that Hash's
// PDF stamping and migration86 capture policies require. Otherwise checked/x
// fields can strand a valid finalization at independent index verification.
func TestFitsIndexFrozenCheckboxBasePagePolicyV1(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		checked     bool
	}{
		{"true", "true", true}, {"one", "1", true},
		{"yes", "yes", true}, {"on", "on", true},
		{"checked", "checked", true}, {"x", "x", true},
		{"normalized-checked", " \tCHECKED\n", true},
		{"normalized-x", " X ", true},
		{"false", "false", false}, {"zero", "0", false},
		{"off", "off", false}, {"blank", " ", false},
		{"unrecognized", "checked-off", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			docID := uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			basis := indexFieldBasisDocumentV1{
				Schema: "hash-manual-finalization-field-basis-v1", DocumentID: docID,
				Fields: []indexFieldBasisV1{{
					ID:   uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"),
					Type: "checkbox", Page: 1, X: "10", Y: "10", W: "5", H: "5",
					Value: tc.value, ValueValid: true,
				}}, Legacy: []indexLegacyBasisV1{},
			}
			raw, err := json.Marshal(basis)
			if err != nil {
				t.Fatal(err)
			}
			doc := indexDocumentWireV1{
				DocumentID:        docID,
				Geometry:          indexGeometryWireV1{Pages: make([]indexPageWireV1, 1)},
				FieldSnapshotJSON: raw, FieldSnapshotSHA256: authoritySHA256V1(raw),
			}
			if tc.checked {
				doc.BasePages = []indexBaseWireV1{{Page: 1}}
			}
			if err := validateIndexFieldBasisV1(doc, nil, nil); err != nil {
				t.Fatalf("the exact PDF checkbox policy rejected its required base set: %v", err)
			}
			// The opposite base inventory must fail rather than silently omit
			// a printed checked value or invent an ordinary base page.
			if tc.checked {
				doc.BasePages = nil
			} else {
				doc.BasePages = []indexBaseWireV1{{Page: 1}}
			}
			if err := validateIndexFieldBasisV1(doc, nil, nil); err == nil {
				t.Fatal("contradictory checkbox base inventory accepted")
			}
		})
	}
}
