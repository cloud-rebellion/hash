// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"testing"
)

func TestPlainPDFAuditPurposesV1PreserveOriginalFinitePayloads(t *testing.T) {
	ctx := applicationTestContextV1(t)
	cases := []struct {
		purpose HTMLAuditPurposeV1
		kind    string
		payload map[string]any
	}{
		{HTMLAuditPlainPDFCreatedV1, "document.created", map[string]any{"name": "Contract Åsa", "source_kind": "pdf", "intake": "import"}},
		{HTMLAuditPlainPDFCreatedV1, "document.created", map[string]any{"name": "Exact proposal", "source_kind": "pdf", "via": "mcp", "tool": "create_pdf_document"}},
		{HTMLAuditPlainFieldAddedV1, "document.field_added", map[string]any{"field_id": "d2e37f30-b707-4ef7-92c3-a07a1b4eae79", "type": "dropdown", "page": int32(1), "required": true, "via": "rest"}},
	}
	for _, test := range cases {
		t.Run(test.kind, func(t *testing.T) {
			if test.purpose.KindV1() != test.kind {
				t.Fatal("original audit kind changed")
			}
			shape, err := htmlAuditPayloadShapeV1(ctx, test.purpose, test.payload)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(test.payload)
			if err != nil || int64(len(raw)) > shape.wire || shape.nodes < 1 {
				t.Fatal("exact original payload is not funded", err)
			}
			test.payload["undeclared_legal_prose"] = "refuse"
			if _, err = htmlAuditPayloadShapeV1(ctx, test.purpose, test.payload); err == nil {
				t.Fatal("unreviewed payload key admitted")
			}
		})
	}
}
