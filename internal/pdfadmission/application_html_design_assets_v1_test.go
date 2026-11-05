// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/png"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

func designAsset783(t *testing.T) htmlmaster.Asset {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b.Bytes())
	return htmlmaster.Asset{Name: "brand_primary", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(b.Bytes()), SHA256: hex.EncodeToString(sum[:])}
}
func designInput783(t *testing.T, ctx context.Context, f *ApplicationSessionFactoryV1, org uuid.UUID, master htmlmaster.Master) *ApplicationHTMLAuthoringInputV1 {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"name": "Neutral design", "html_master_json": master, "variables_json": map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.CloseConsumerV1)
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	return h
}
func TestDesignAssetExpansion783CanonicalBytesAndLastUse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 8<<30)
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<main><img src="hash-asset:brand_primary" alt="Example organization"><p>Exact &amp; retained text</p></main>`, CSS: `@page{size:A4;margin:20mm;}`}
	h := designInput783(t, ctx, f, org, master)
	a := designAsset783(t)
	release, err := h.RetainDesignBundleV1(ctx, 128, 128, int64(base64.StdEncoding.DecodedLen(len(a.DataBase64))), int64(len(a.DataBase64)), 1)
	if err != nil {
		t.Fatal(err)
	}
	expanded, err := h.ExpandDesignAssetsV1(ctx, []htmlmaster.Asset{a})
	if err != nil {
		t.Fatal(err)
	}
	defer expanded.CloseConsumerV1()
	actual, err := expanded.CanonicalTemplateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	master.Assets = []htmlmaster.Asset{a}
	raw, _ := json.Marshal(master)
	expected, err := htmlmaster.CanonicalTemplate(raw, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) || !bytes.Equal(actual.DefaultsJSON, expected.DefaultsJSON) {
		t.Fatal("expanded native producer changed canonical content/commitments")
	}
	if _, err = h.CanonicalTemplateV1(ctx); err == nil {
		t.Fatal("original pre-expansion owner was canonicalized")
	}
	copy := *h
	h.CloseConsumerV1()
	copy.CloseConsumerV1()
	expanded.CloseConsumerV1()
	if f.PendingV1().HTMLInputProducers != 1 || c.SnapshotV1(org).GlobalGrants == 0 {
		t.Fatal("original bundle bytes retired before their active catalog consumer")
	}
	release()
	release()
	if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("closed original/bundle/expanded producers leaked native grants")
	}
}
func TestDesignAssetExpansion783RejectsCollisionsLimitsAndReuse(t *testing.T) {
	for _, kind := range []string{"client-name", "bundle-name", "count", "oversized", "reuse", "cancelled", "closed"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			org := uuid.New()
			f, c := htmlInputFactoryTestV1(t, 8<<30)
			asset := designAsset783(t)
			master := htmlmaster.Master{SchemaVersion: 1, HTML: `<p>Neutral exact design</p>`}
			if kind == "client-name" {
				master.Assets = []htmlmaster.Asset{asset}
			}
			h := designInput783(t, ctx, f, org, master)
			assets := []htmlmaster.Asset{asset}
			switch kind {
			case "bundle-name":
				assets = append(assets, asset)
			case "count":
				assets = make([]htmlmaster.Asset, 17)
			case "oversized":
				assets[0].DataBase64 = strings.Repeat("A", base64.StdEncoding.EncodedLen(htmlmaster.MaxAssetBytes)+1)
			case "reuse":
				x, err := h.ExpandDesignAssetsV1(ctx, assets)
				if err != nil {
					t.Fatal(err)
				}
				x.CloseConsumerV1()
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				h.CloseConsumerV1()
			}
			if x, err := h.ExpandDesignAssetsV1(ctx, assets); err == nil {
				if x != nil {
					x.CloseConsumerV1()
				}
				t.Fatal("invalid expansion admitted")
			}
			h.CloseConsumerV1()
			if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
				t.Fatal("rejected expansion leaked work")
			}
		})
	}
}
func TestDesignBundle783AdmissionRefusesInvalidMeasuresBeforeRead(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 8<<30)
	h := designInput783(t, ctx, f, org, htmlmaster.Master{SchemaVersion: 1, HTML: `<p>Neutral</p>`})
	if close, err := h.RetainDesignBundleV1(context.Background(), 0, 0, 0, 0, 0); err == nil {
		if close != nil {
			close()
		}
		t.Fatal("unbounded context admitted catalog work")
	}
	if expanded, err := h.ExpandDesignAssetsV1(context.Background(), []htmlmaster.Asset{designAsset783(t)}); err == nil || expanded != nil {
		if expanded != nil {
			expanded.CloseConsumerV1()
		}
		t.Fatal("unbounded context admitted native source expansion")
	}

	for _, m := range [][5]int64{{-1, 0, 0, 0, 0}, {65537, 0, 0, 0, 0}, {0, 131073, 0, 0, 0}, {0, 0, htmlmaster.MaxTotalAssetBytes + 1, 0, 0}, {0, 0, 0, 0, 17}} {
		if close, err := h.RetainDesignBundleV1(ctx, m[0], m[1], m[2], m[3], int(m[4])); err == nil {
			close()
			t.Fatal("invalid catalog measure admitted")
		}
	}
	h.CloseConsumerV1()
	if f.PendingV1().HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("rejected bundle measure leaked native owner")
	}
}
