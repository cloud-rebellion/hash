// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"testing"
)

func TestCurrentReadProjectionPreservesEveryCurrentSourceCheckV1(t *testing.T) {
	_, q := fixture(t)
	doc, row, err := RegisterOrigin(context.Background(), q, q.doc, 1, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	row.Summary = "synthetic retained description outside read projection"
	row.ChangedSections = []string{"scope"}
	full, err := Current(context.Background(), q, doc)
	if err != nil || full == nil || full.Summary != row.Summary || len(full.ChangedSections) != 1 {
		t.Fatal("full history behavior changed")
	}
	if err := ValidateCurrentReadProjectionV1(doc, currentReadProjectionV1(row)); err != nil {
		t.Fatal("exact normalized read projection refused")
	}
	cases := []struct {
		name   string
		mutate func(*generated.HtmlDocumentMaterialization)
	}{
		{"row identity", func(r *generated.HtmlDocumentMaterialization) { r.ID = uuid.New() }},
		{"document scope", func(r *generated.HtmlDocumentMaterialization) { r.DocumentID = uuid.New() }},
		{"organisation scope", func(r *generated.HtmlDocumentMaterialization) { r.OrgID = uuid.New() }},
		{"sequence", func(r *generated.HtmlDocumentMaterialization) { r.Sequence++ }},
		{"pages", func(r *generated.HtmlDocumentMaterialization) { r.PageCount++ }},
		{"PDF key", func(r *generated.HtmlDocumentMaterialization) { r.PdfKey += "-other" }},
		{"PDF version", func(r *generated.HtmlDocumentMaterialization) { r.PdfVersionID += "-other" }},
		{"PDF bytes", func(r *generated.HtmlDocumentMaterialization) { r.PdfSha256 = bytes.Repeat([]byte{9}, 32) }},
		{"source commitment", func(r *generated.HtmlDocumentMaterialization) { r.SourceCommitment = bytes.Repeat([]byte{8}, 32) }},
		{"immutable origin", func(r *generated.HtmlDocumentMaterialization) { r.OriginCommitment = bytes.Repeat([]byte{7}, 32) }},
		{"stored source body", func(r *generated.HtmlDocumentMaterialization) { r.SourceJson = []byte(`{"changed":"body"}`) }},
		{"report provenance", func(r *generated.HtmlDocumentMaterialization) {
			r.MetadataRedactionReport = []byte(`{"changed":"report"}`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed := *row
			tc.mutate(&changed)
			q.rows[row.ID] = &changed
			defer func() { q.rows[row.ID] = row }()
			if got, err := Current(context.Background(), q, doc); err == nil || got != nil {
				t.Fatal("full current validation accepted drift")
			}
			if err := ValidateCurrentReadProjectionV1(doc, currentReadProjectionV1(&changed)); err == nil {
				t.Fatal("read projection dropped an existing source/identity/report check")
			}
		})
	}
	if err := ValidateCurrentReadProjectionV1(doc, nil); err == nil {
		t.Fatal("registered current source accepted missing row")
	}
}
func TestCurrentReadProjectionPreservesLegacyOriginWithoutCurrentRowV1(t *testing.T) {
	_, q := fixture(t)
	if row, err := Current(context.Background(), nil, q.doc); err != nil || row != nil {
		t.Fatal("legacy source acquired a normalized-row requirement")
	}
	if err := ValidateCurrentReadProjectionV1(q.doc, nil); err != nil {
		t.Fatal("legacy exact origin refused by read projection")
	}
	if err := ValidateCurrentReadProjectionV1(q.doc, &CurrentReadProjectionV1{ID: uuid.New()}); err == nil {
		t.Fatal("orphaned current-row projection was adopted")
	}
}
