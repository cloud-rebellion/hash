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
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"image"
	"image/png"
	"math"
	"testing"
	"unsafe"
)

func TestHTMLStoredPreparedTinyAndOverflowV1(t *testing.T) {
	n := int64(0)
	if !htmlStoredRetentionAllocV1(&n, 1) || n < 16 {
		t.Fatalf("tiny allocator class not priced: %d", n)
	}
	n = math.MaxInt64
	if htmlStoredRetentionAllocV1(&n, 1) {
		t.Fatal("overflow accepted")
	}
	n = 0
	if htmlStoredRetentionAllocV1(&n, -1) {
		t.Fatal("negative allocation accepted")
	}
	for _, n := range []int64{-1, math.MaxInt64, math.MaxInt64 - 1} {
		if _, err := htmlStoredRetentionFinishV1(n); err == nil {
			t.Fatalf("invalid final size accepted: %d", n)
		}
	}
	for _, n := range []int64{0, 1, 8191, 8192, 8193} {
		size, err := htmlStoredRetentionFinishV1(n)
		if err != nil || size < n || size%8192 != 0 {
			t.Fatalf("unrounded size %d ->%d,%v", n, size, err)
		}
	}
	if _, err := htmlStoredPreparedTemplateRetentionV1(htmlStoredCanonicalOutputV1{masterJSONBytes: math.MaxInt64}); err == nil {
		t.Fatal("template output overflow accepted")
	}
}

func TestHTMLStoredPreparedActualCompileOutputOracleV1(t *testing.T) {
	ctx := context.Background()
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pngBytes.Bytes())
	encoded := base64.StdEncoding.EncodeToString(pngBytes.Bytes())
	wrapped := encoded[:40] + "\r\n" + encoded[40:]
	master := htmlmaster.Master{SchemaVersion: 1, HTML: "<main><img src=\"hash-asset:logo\"/><p>Ready</p></main>", CSS: "main { color: #112233; }", Assets: []htmlmaster.Asset{{Name: "logo", MediaType: "image/png", SHA256: hex.EncodeToString(sum[:]), DataBase64: wrapped}}}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	out, err := htmlStoredCanonicalOutputUpperV1(raw, []byte("{}"), master, stats)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	var normalized htmlmaster.Master
	if err = json.Unmarshal(compiled.CanonicalJSON(), &normalized); err != nil {
		t.Fatal(err)
	}
	if normalized.Assets[0].DataBase64 != encoded || len(normalized.Assets[0].DataBase64) >= len(wrapped) {
		t.Fatal("fixture did not exercise accepted non-growing CR/LF base64 canonicalization")
	}
	retained, err := htmlStoredPreparedCompiledRetentionV1(master, stats, out)
	if err != nil {
		t.Fatal(err)
	}
	// Independent actual outputs and fixed object storage form a necessary lower
	// bound; full scratch remains separately priced by the existing canonical unit.
	actualLower := int64(len(compiled.CanonicalJSON())+len(compiled.Digest())+len(normalized.HTML)+len(normalized.CSS)+len(encoded)+len("data:image/png;base64,")+len(encoded)) + int64(unsafe.Sizeof(*compiled))
	if retained < actualLower {
		t.Fatalf("retained actual output underpriced: %d<%d", retained, actualLower)
	}
	templateBytes, err := htmlStoredTemplateResultRetentionV1(canonical)
	if err != nil || templateBytes < int64(len(canonical.MasterJSON)+len(canonical.DefaultsJSON)+len(canonical.SHA256)) {
		t.Fatalf("actual TemplateCommitment omitted: %d,%v", templateBytes, err)
	}
	altered := stats
	altered.pixels = math.MaxInt64
	noPixels, err := htmlStoredPreparedCompiledRetentionV1(master, altered, out)
	if err != nil || noPixels != retained {
		t.Fatalf("retained component includes ephemeral image decoder arena: %d/%d,%v", noPixels, retained, err)
	}
}
