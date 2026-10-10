// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestHTMLDocumentRequestRefusesTextCoercion(t *testing.T) {
	for _, field := range []string{"values", "sections"} {
		for _, raw := range []string{"null", `[]`, `true`, `42`, `"text"`, `{"customer":null}`, `{"customer":42}`, `{"customer":true}`, `{"customer":[]}`, `{"customer":{}}`, `{"customer":"a","customer":"b"}`} {
			t.Run(field+"/"+raw, func(t *testing.T) {
				r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"Contract","`+field+`":`+raw+`}`))
				var in htmlDocumentInput
				if err := decodeSignerJSON(r, &in); err == nil {
					t.Fatal("request silently coerced HTML content")
				}
			})
		}
	}
	for _, raw := range []string{`{"name":"Contract"}`, `{"values":{},"sections":{}}`, `{"values":{"customer":"Approved AB"},"sections":{"scope":"Plain <text> & new prose"}}`} {
		var in htmlDocumentInput
		if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(raw)), &in); err != nil {
			t.Fatalf("valid string maps: %v", err)
		}
		if in.Sections["scope"] != "" && in.Sections["scope"] != "Plain <text> & new prose" {
			t.Fatal("decoder changed plain text")
		}
	}
}

func TestHTMLDocumentResponseRequiresMatchingPDFReview(t *testing.T) {
	doc := generated.Document{HtmlSourceJson: []byte(`{}`), PdfSha256: bytes.Repeat([]byte{1}, 32)}
	if !toDocumentResponse(&doc).HTMLReviewRequired || !toDocumentResponse(&doc).HasHTMLSource {
		t.Fatal("missing review was hidden")
	}
	doc.HtmlReviewedBy = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlReviewedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	doc.HtmlReviewedPdfSha256 = bytes.Repeat([]byte{2}, 32)
	if !toDocumentResponse(&doc).HTMLReviewRequired {
		t.Fatal("review of a different PDF was presented as current")
	}
	doc.HtmlReviewedPdfSha256 = bytes.Clone(doc.PdfSha256)
	if toDocumentResponse(&doc).HTMLReviewRequired || !toDocumentResponse(&doc).HasHTMLSource {
		t.Fatal("matching complete review marker was ignored")
	}
	doc.HtmlSourceJson = nil
	doc.HtmlReviewedBy = pgtype.UUID{}
	if toDocumentResponse(&doc).HTMLReviewRequired || toDocumentResponse(&doc).HasHTMLSource {
		t.Fatal("legacy document gained HTML review requirement")
	}
}

func TestHTMLTemplateListDTOOmitsMasterAssets(t *testing.T) {
	template := &generated.Template{SourceKind: "html", VariablesJson: json.RawMessage(`{}`),
		HtmlMasterJson: []byte(`{"large":"asset content"}`), HtmlContentSha256: bytes.Repeat([]byte{7}, 32)}
	response, err := toTemplateResponse(template)
	if err != nil || len(response.HTMLMasterJSON) != 0 || len(response.ContentSHA256) != 64 {
		t.Fatalf("list DTO=%+v, err=%v", response, err)
	}
	recorder := httptest.NewRecorder()
	writeTemplateResponse(recorder, 200, template)
	var detail templateResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &detail); err != nil || !bytes.Equal(detail.HTMLMasterJSON, template.HtmlMasterJson) {
		t.Fatalf("explicit detail lost master: %v", err)
	}
}
