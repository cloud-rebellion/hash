// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestDocumentMetadataMapperPreservesOriginReviewAndCurrentPins(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 34, 56, 123456000, time.UTC)
	base := generated.ListDocumentMetadataForRESTRow{
		ID: uuid.New(), OrgID: uuid.New(), TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
		Name: "Metadata mapper", Status: "draft", RoutingMode: "parallel", SourceKind: "pdf", RequiresSignature: true,
		BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{"customer":"Synthetic AB"}`),
		PdfStorageKey: pgtype.Text{String: "org/synthetic/documents/source.pdf", Valid: true}, PdfSha256: bytes.Repeat([]byte{3}, 32),
		FinalPdfKey: pgtype.Text{String: "org/synthetic/final.pdf", Valid: true}, FinalPdfSha: bytes.Repeat([]byte{4}, 32),
		AuditCertKey: pgtype.Text{String: "org/synthetic/certificate.pdf", Valid: true},
		ExpiresAt:    pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true}, SentAt: pgtype.Timestamptz{Time: now, Valid: true},
		CompletedAt: pgtype.Timestamptz{Time: now.Add(time.Minute), Valid: true}, SenderID: uuid.New(),
		Metadata: json.RawMessage(`{"crm_deal":"synthetic"}`), DefaultLocale: "sv", CreatedAt: pgtype.Timestamptz{Time: now, Valid: true},
		UpdatedAt: pgtype.Timestamptz{Time: now, Valid: true}, ParentEnvelopeID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
		EnvelopePosition: pgtype.Int4{Int32: 2, Valid: true}, HtmlEffectiveSourceCommitment: pgtype.Text{String: strings.Repeat("a", 64), Valid: true},
	}
	for _, tc := range []struct {
		name         string
		html, review bool
		sequence     pgtype.Int4
		wantRevision int32
	}{
		{name: "legacy origin unreviewed", html: true, review: true, wantRevision: 1},
		{name: "legacy origin reviewed", html: true, wantRevision: 1},
		{name: "registered origin reviewed", html: true, sequence: pgtype.Int4{Int32: 1, Valid: true}, wantRevision: 1},
		{name: "new CID same PDF requires review", html: true, review: true, sequence: pgtype.Int4{Int32: 2, Valid: true}, wantRevision: 2},
		{name: "current materialization reviewed", html: true, sequence: pgtype.Int4{Int32: 2, Valid: true}, wantRevision: 2},
		{name: "ordinary PDF", wantRevision: 0},
		{name: "acknowledgement PDF", wantRevision: 0},
		{name: "ordinary blocks", wantRevision: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := base
			row.HasHtmlSource, row.HtmlReviewRequired, row.HtmlCurrentMaterializationSequence = tc.html, tc.review, tc.sequence
			if tc.name == "ordinary blocks" {
				row.SourceKind = "blocks"
			}
			if tc.name == "acknowledgement PDF" {
				row.RequiresSignature = false
			}
			got := toDocumentMetadataResponse(&row)
			if got.HasHTMLSource != tc.html || got.HTMLReviewRequired != tc.review || got.HTMLMaterializationRevision != tc.wantRevision {
				t.Fatalf("explicit source/review/revision projection lost: %t/%t/%d", got.HasHTMLSource, got.HTMLReviewRequired, got.HTMLMaterializationRevision)
			}
			wantCommitment := ""
			if tc.html {
				wantCommitment = base.HtmlEffectiveSourceCommitment.String
			}
			if got.HTMLSourceCommitment != wantCommitment || got.PDFSHA256 != hex.EncodeToString(base.PdfSha256) || got.UpdatedAt != now.Format(time.RFC3339Nano) {
				t.Fatal("source/PDF/observation pins changed in metadata response")
			}
			if got.ID != row.ID || got.OrgID != row.OrgID || got.TemplateID != uuid.UUID(row.TemplateID.Bytes).String() || got.Name != row.Name || got.Status != row.Status || got.RoutingMode != row.RoutingMode || got.SourceKind != row.SourceKind || got.RequiresSignature != row.RequiresSignature || got.SenderID != row.SenderID || got.DefaultLocale != row.DefaultLocale || !bytes.Equal(got.BlocksJSON, row.BlocksJson) || !bytes.Equal(got.VariablesJSON, row.VariablesJson) || !bytes.Equal(got.Metadata, row.Metadata) || got.PDFStorageKey != row.PdfStorageKey.String || got.FinalPDFKey != row.FinalPdfKey.String || got.AuditCertKey != row.AuditCertKey.String || got.ExpiresAt != row.ExpiresAt.Time.Format(time.RFC3339) || got.SentAt != row.SentAt.Time.Format(time.RFC3339) || got.CompletedAt != row.CompletedAt.Time.Format(time.RFC3339) || got.CreatedAt != now.Format(time.RFC3339) {
				t.Fatal("ordinary metadata compatibility lost")
			}
			child := generated.ListEnvelopeChildMetadataForReadRow(row)
			if !reflect.DeepEqual(got, toEnvelopeChildMetadataResponse(&child)) {
				t.Fatal("envelope and document metadata DTOs differ")
			}
		})
	}
}
