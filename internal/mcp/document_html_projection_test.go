// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLDocumentMCPListingsDoNotMultiplyEmbeddedDesignAssets(t *testing.T) {
	asset := json.RawMessage(`{"inline_asset":"` + strings.Repeat("private-design-asset", 4096) + `"}`)
	rows := make([]*generated.Document, 50)
	for i := range rows {
		rows[i] = &generated.Document{ID: uuid.New(), Name: "Bounded document", SourceKind: "pdf", HtmlSourceJson: asset, HtmlCurrentSourceJson: asset, HtmlEffectiveSourceCommitment: pgtype.Text{String: strings.Repeat("a", 64), Valid: true}}
	}
	projection := documentListReadProjection(rows)
	body, err := json.Marshal(projection)
	if err != nil || len(body) > 150000 || bytes.Contains(body, []byte("private-design-asset")) {
		t.Fatal("bulk document metadata duplicated inline master/assets")
	}
	for i := range rows {
		if projection[i].ID != rows[i].ID || projection[i].HtmlEffectiveSourceCommitment != rows[i].HtmlEffectiveSourceCommitment || !bytes.Equal(rows[i].HtmlSourceJson, asset) || !bytes.Equal(rows[i].HtmlCurrentSourceJson, asset) {
			t.Fatal("bounded projection changed stored source or lost artifact identity")
		}
	}
	legacy := &generated.Document{ID: uuid.New(), SourceKind: "blocks", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`)}
	if documentReadProjection(legacy) != legacy {
		t.Fatal("legacy document read behavior changed")
	}
}

func TestHTMLDocumentMCPDetailEmitsUsableCurrentFieldPinsAndReviewReset(t *testing.T) {
	current := pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc := &generated.Document{ID: uuid.New(), SourceKind: "pdf", PdfSha256: bytes.Repeat([]byte{3}, 32), HtmlSourceJson: json.RawMessage(`{"private":"master"}`), HtmlCurrentSourceJson: json.RawMessage(`{"private":"current master"}`), HtmlCurrentMaterializationID: current, HtmlReviewedMaterializationID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, HtmlReviewedPdfSha256: bytes.Repeat([]byte{3}, 32), HtmlReviewedBy: pgtype.UUID{Bytes: uuid.New(), Valid: true}, HtmlReviewedAt: pgtype.Timestamptz{Valid: true}}
	projection := htmlDocumentReadProjection(doc, strings.Repeat("b", 64))
	body, err := json.Marshal(projection)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		HasHTMLSource  bool   `json:"has_html_source"`
		ReviewRequired bool   `json:"html_review_required"`
		PDF            string `json:"expected_pdf_sha256"`
		Source         string `json:"expected_html_source_commitment"`
	}
	if json.Unmarshal(body, &wire) != nil || !wire.HasHTMLSource || !wire.ReviewRequired || wire.PDF != hex.EncodeToString(doc.PdfSha256) || wire.Source != strings.Repeat("b", 64) || bytes.Contains(body, []byte("master")) {
		t.Fatal("MCP detail lost exact field pins or inherited review from same-byte old source")
	}
}

func TestHTMLDocumentMCPProjectionExcludesCurrentSourceWithoutOrigin(t *testing.T) {
	asset := json.RawMessage(`{"inline_asset":"private-current-design-asset"}`)
	doc := &generated.Document{ID: uuid.New(), SourceKind: "pdf", HtmlCurrentSourceJson: asset}
	projection := documentReadProjection(doc)
	body, err := json.Marshal(projection)
	if err != nil || bytes.Contains(body, []byte("private-current-design-asset")) || len(projection.HtmlSourceJson) != 0 || len(projection.HtmlCurrentSourceJson) != 0 {
		t.Fatal("current-only embedded source escaped the metadata projection")
	}
	if projection == doc || !bytes.Equal(doc.HtmlCurrentSourceJson, asset) || len(doc.HtmlSourceJson) != 0 || projection.ID != doc.ID {
		t.Fatal("projection changed the supplied source or artifact identity")
	}
	if documentReadProjection(nil) != nil {
		t.Fatal("nil metadata projection changed")
	}
}
