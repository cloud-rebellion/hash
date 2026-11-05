// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

func TestDesignSourceLinks783OwnedCanonicalNavigation(t *testing.T) {
	for name, source := range map[string]string{
		"https":           `<main><p>Reference: <a href="https://docs.example.invalid/reference?q=one&amp;page=2#section"><strong>Primary source</strong></a></p></main>`,
		"uppercase-names": `<main><A HREF="https://docs.example.invalid/reference">Primary source</A></main>`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			org := uuid.New()
			f, c := htmlInputFactoryTestV1(t, 8<<30)
			master := htmlmaster.Master{SchemaVersion: 1, HTML: source}
			h := designInput783(t, ctx, f, org, master)
			actual, err := h.CanonicalTemplateV1(ctx)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(master)
			if err != nil {
				t.Fatal(err)
			}
			expected, err := htmlmaster.CanonicalTemplate(raw, []byte(`{}`))
			if err != nil {
				t.Fatal(err)
			}
			if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) || !bytes.Equal(actual.DefaultsJSON, expected.DefaultsJSON) {
				t.Fatal("owned source-link input changed the native canonical commitment")
			}
			canonical, err := htmlmaster.Decode(actual.MasterJSON)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := htmlmaster.Compile(canonical)
			if err != nil {
				t.Fatal(err)
			}
			materialized, err := compiled.Materialize(htmlmaster.Input{})
			if err != nil || !strings.Contains(materialized.HTML, `href="https://docs.example.invalid/reference`) || len(canonical.Assets) != 0 {
				t.Fatal("navigation was lost or became a render asset")
			}
			h.CloseConsumerV1()
			if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
				t.Fatal("owned source-link input did not retire")
			}
		})
	}
}

func TestDesignSourceLinks783OwnedCanonicalRefusesActiveResources(t *testing.T) {
	for name, source := range map[string]string{
		"script":         `<a href="javascript:alert(1)">source</a>`,
		"encoded-script": `<a href="jav&#x61;script:alert(1)">source</a>`,
		"relative":       `<a href="/private">source</a>`,
		"http":           `<a href="http://example.invalid">source</a>`,
		"userinfo":       `<a href="https://user:password@example.invalid">source</a>`,
		"backslash":      `<a href="https://example.invalid\@other.invalid">source</a>`,
		"control":        "<a href=\"https://example.invalid/\nnext\">source</a>",
		"oversized":      `<a href="https://example.invalid/` + strings.Repeat("x", 1024) + `">source</a>`,
		"event":          `<a href="https://example.invalid" onclick="x">source</a>`,
		"download":       `<a href="https://example.invalid" download="private">source</a>`,
		"non-anchor":     `<p href="https://example.invalid">source</p>`,
		"remote-image":   `<img src="https://example.invalid/logo.png">`,
		"remote-css":     `<p>source</p>`,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			org := uuid.New()
			f, c := htmlInputFactoryTestV1(t, 8<<30)
			master := htmlmaster.Master{SchemaVersion: 1, HTML: source}
			if name == "remote-css" {
				master.CSS = `p{background-image:url("https://example.invalid/background.png");}`
			}
			h := designInput783(t, ctx, f, org, master)
			if result, err := h.CanonicalTemplateV1(ctx); err == nil || result.SHA256 != "" || len(result.MasterJSON) != 0 {
				t.Fatal("owned source-link input accepted an active, ambiguous or oversized source")
			}
			h.CloseConsumerV1()
			if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
				t.Fatal("refused source-link input retained native grants")
			}
		})
	}
}
