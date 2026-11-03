// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSavedPDFDownloadRequiresExactSavedSnapshot(t *testing.T) {
	stamp := time.Date(2026, 11, 3, 12, 0, 0, 123456000, time.UTC)
	doc := &generated.Document{Status: "draft", SourceKind: "pdf", UpdatedAt: pgtype.Timestamptz{Time: stamp, Valid: true}, PdfSha256: make([]byte, 32)}
	good := url.Values{"download": {"1"}, "expected_updated_at": {stamp.Format(time.RFC3339Nano)}, "expected_pdf_sha256": {strings.Repeat("0", 64)}}
	request := func(q url.Values) error {
		return checkSavedPDFDownload(httptest.NewRequest("GET", "/pdf?"+q.Encode(), nil), doc)
	}
	if err := request(good); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"expected_updated_at", "expected_pdf_sha256", "download"} {
		t.Run("missing-"+key, func(t *testing.T) {
			q := url.Values{}
			for k, v := range good {
				q[k] = append([]string(nil), v...)
			}
			q.Del(key)
			if request(q) == nil {
				t.Fatal("missing observation admitted")
			}
		})
		t.Run("duplicate-"+key, func(t *testing.T) {
			q := url.Values{}
			for k, v := range good {
				q[k] = append([]string(nil), v...)
			}
			q.Add(key, q.Get(key))
			if request(q) == nil {
				t.Fatal("ambiguous observation admitted")
			}
		})
	}
	q := url.Values{}
	for k, v := range good {
		q[k] = append([]string(nil), v...)
	}
	q.Set("expected_updated_at", stamp.Add(time.Nanosecond).Format(time.RFC3339Nano))
	if request(q) == nil {
		t.Fatal("stale clock admitted")
	}
	q = url.Values{}
	for k, v := range good {
		q[k] = append([]string(nil), v...)
	}
	q.Set("expected_pdf_sha256", strings.Repeat("a", 64))
	if request(q) == nil {
		t.Fatal("changed source admitted")
	}
	doc.Status = "completed"
	if request(good) == nil {
		t.Fatal("completed contract could use original source")
	}
	doc.Status = "draft"
	doc.SourceKind = "blocks"
	good.Del("expected_pdf_sha256")
	if err := request(good); err != nil {
		t.Fatal(err)
	}
}

func TestSavedBlocksDownloadPreservesTextAndBreaksWithoutAddingSigningEvidence(t *testing.T) {
	doc := &generated.Document{BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"one","type":"paragraph","text":"Hello {{customer}}"},{"id":"break","type":"page_break"},{"id":"two","type":"paragraph","text":"Second page"}]}`)}
	html, err := savedBlocksDownloadHTML(doc, map[string]string{"customer": "<Test Company>"}, "<style>:root{--hash-text:#18181b}</style>")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Hello &lt;Test Company&gt;", "Second page", "page-break", "--hash-text:#18181b"} {
		if !strings.Contains(html, want) {
			t.Fatalf("missing saved content %q", want)
		}
	}
	if strings.Contains(html, "class=\"hash-cert-page\"") || strings.Contains(html, "<script") {
		t.Fatal("download added evidence or active markup")
	}
	doc.BlocksJson = json.RawMessage(`{broken`)
	if _, err := savedBlocksDownloadHTML(doc, nil, ""); err == nil {
		t.Fatal("invalid stored blocks admitted")
	}
}
