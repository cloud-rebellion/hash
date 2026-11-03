// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"testing"
)

func TestDocumentPurposeNativeAuditShapeV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	payload := map[string]any{"purpose": "presentation", "via": "mcp", "tool": "set_document_purpose"}
	if HTMLAuditDocumentPurposeUpdatedV1.KindV1() != "document.updated" {
		t.Fatal("wrong durable audit kind")
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditDocumentPurposeUpdatedV1, payload); err != nil {
		t.Fatal("actual purpose audit refused", err)
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditPlainDraftUpdatedV1, payload); err == nil {
		t.Fatal("old audit schema widened")
	}
	payload["unbounded_extra"] = true
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditDocumentPurposeUpdatedV1, payload); err == nil {
		t.Fatal("purpose audit admitted unknown fields")
	}
}
