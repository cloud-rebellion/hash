// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLCreationReplayProjectionPreservesEveryResponseFieldV1(t *testing.T) {
	stamp := pgtype.Timestamptz{Time: time.Date(2026, 10, 14, 12, 34, 56, 123456000, time.FixedZone("fixture", 3600)), Valid: true}
	for _, hasSource := range []bool{false, true} {
		for _, reviewRequired := range []bool{false, true} {
			d := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, Name: "Å fixture", Status: "draft", RoutingMode: "parallel", SourceKind: "pdf", RequiresSignature: true,
				BlocksJson: json.RawMessage("{\"fixture\":1}"), VariablesJson: json.RawMessage("{\"company\":\"Å\"}"), PdfStorageKey: pgtype.Text{String: "source", Valid: true}, PdfSha256: bytes.Repeat([]byte{7}, 32), FinalPdfKey: pgtype.Text{String: "final", Valid: true}, AuditCertKey: pgtype.Text{String: "audit", Valid: true},
				ExpiresAt: stamp, SentAt: stamp, CompletedAt: stamp, SenderID: uuid.New(), Metadata: json.RawMessage("{\"fixture\":true}"), DefaultLocale: "sv", CreatedAt: stamp, UpdatedAt: stamp,
				HtmlEffectiveSourceCommitment: pgtype.Text{String: "real-stored-commitment", Valid: true}, HtmlCurrentMaterializationSequence: pgtype.Int4{Int32: 7, Valid: true}}
			if hasSource {
				d.HtmlSourceJson = json.RawMessage("{\"schema_version\":3}")
			}
			if !reviewRequired {
				d.HtmlReviewedBy = pgtype.UUID{Bytes: uuid.New(), Valid: true}
				d.HtmlReviewedAt = stamp
				d.HtmlReviewedPdfSha256 = bytes.Clone(d.PdfSha256)
			}
			row := &generated.ReadHTMLCreationResponseV1Row{ID: d.ID, OrgID: d.OrgID, TemplateID: d.TemplateID, Name: d.Name, Status: d.Status, RoutingMode: d.RoutingMode, SourceKind: d.SourceKind, RequiresSignature: d.RequiresSignature,
				BlocksJson: d.BlocksJson, VariablesJson: d.VariablesJson, PdfStorageKey: d.PdfStorageKey, PdfSha256: d.PdfSha256, FinalPdfKey: d.FinalPdfKey, AuditCertKey: d.AuditCertKey,
				ExpiresAt: d.ExpiresAt, SentAt: d.SentAt, CompletedAt: d.CompletedAt, SenderID: d.SenderID, Metadata: d.Metadata, DefaultLocale: d.DefaultLocale, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
				HasHtmlSource: hasSource, HtmlReviewRequired: hasSource && reviewRequired, HtmlEffectiveSourceCommitment: d.HtmlEffectiveSourceCommitment, HtmlCurrentMaterializationSequence: d.HtmlCurrentMaterializationSequence}
			before, err := json.Marshal(toDocumentResponse(d))
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(htmlCreationDocumentProjectionV1(row))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatalf("projection changed response: before=%s after=%s", before, after)
			}
		}
	}
}
func TestHTMLCreationOwnedConsumerSurvivesResponseMappingV1(t *testing.T) {
	var closed int
	result := &htmlCreationOutcome{documentView: &documentResponse{ID: uuid.New(), HasHTMLSource: true, HTMLReviewRequired: true}}
	result.addOwnedConsumerV1(func() { closed++ })
	response := result.response()
	if closed != 0 || response["document"] == nil || response["review_required"] != true {
		t.Fatal("response mapping retired the live consumer")
	}
	if _, err := json.Marshal(response); err != nil {
		t.Fatal(err)
	}
	if closed != 0 {
		t.Fatal("serialization retired the consumer before response writer completion")
	}
	result.closeOwnedWriterV1()
	result.closeOwnedWriterV1()
	if closed != 1 {
		t.Fatal("owned consumer did not close once after response")
	}
}
