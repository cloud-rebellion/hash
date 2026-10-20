// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"sync"
	"testing"
	"time"
)

func layoutArgs226(root, pkg uuid.UUID, count int) []byte {
	members := make([]map[string]any, count)
	for i := range members {
		members[i] = map[string]any{"document_id": uuid.NewString(), "title": strings.Repeat("x", 512), "category": strings.Repeat("c", 128)}
	}
	raw, _ := json.Marshal(map[string]any{"document_id": root.String(), "expected_updated_at": "2026-10-18T00:00:00.123456Z", "expected_package_id": pkg.String(), "expected_generation": "9223372036854775807", "members": members})
	return raw
}
func TestDocumentPackageLayoutInputClosedGrammarV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root, pkg := uuid.New(), uuid.New()
	raw := layoutArgs226(root, pkg, 16)
	if len(raw) <= 4096 {
		t.Fatal("full-layout fixture did not exercise larger exact cap")
	}
	got, e := decodeDocumentPackageLayoutV1(ctx, uuid.Nil, raw, true)
	if e != nil || got.Count != 16 || got.Draft.Generation != 9223372036854775807 {
		t.Fatal("valid full layout or bigint changed", got, e)
	}
	one := string(layoutArgs226(root, pkg, 1))
	for _, tc := range []struct{ name, raw string }{
		{"duplicate root", strings.TrimSuffix(one, "}") + `,"members":[]}`},
		{"unknown pin", strings.TrimSuffix(one, "}") + `,"pdf_sha256":"untrusted"}`},
		{"duplicate member field", strings.Replace(one, `"title":`, `"document_id":"`+uuid.NewString()+`","title":`, 1)},
		{"case alias", strings.Replace(one, "expected_generation", "Expected_Generation", 1)},
		{"numeric generation", strings.Replace(one, `"expected_generation":"9223372036854775807"`, `"expected_generation":9223372036854775807`, 1)},
		{"trailing", one + "[]"},
		{"too many", string(layoutArgs226(root, pkg, 17))},
		{"null members", `{"document_id":"` + root.String() + `","expected_updated_at":"2026-10-18T00:00:00Z","expected_package_id":"` + pkg.String() + `","expected_generation":"1","members":null}`},
		{"invalid scalar Unicode", strings.Replace(one, strings.Repeat("x", 512), string([]byte{92, 'u', 'd', '8', '0', '0'}), 1)},
		{"invalid literal UTF8", strings.Replace(one, strings.Repeat("x", 512), string([]byte{255}), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := decodeDocumentPackageLayoutV1(ctx, uuid.Nil, []byte(tc.raw), true); e == nil {
				t.Fatal("invalid layout accepted")
			}
		})
	}
}
func TestDocumentPackageLayoutInputRetainsOriginalBorrowV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, coordinator := htmlInputFactoryTestV1(t, 64<<20)
	org, root, pkg := uuid.New(), uuid.New(), uuid.New()
	raw := layoutArgs226(root, pkg, 16)
	input, e := f.NewDocumentPackageLayoutArgumentsV1(ctx, org, raw)
	if e != nil {
		t.Fatal(e)
	}
	defer input.CloseConsumerV1()
	copy := *input
	raw[0] = '['
	if e = input.ReadLayoutArgumentsV1(ctx); e != nil {
		t.Fatal("owned arguments changed", e)
	}
	renewed, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if e = input.WithLayoutV1(renewed, org, func(DocumentPackageLayoutInputV1) error { return nil }); e == nil {
		t.Fatal("renewed context accepted")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	joined := false
	t.Cleanup(func() {
		cancel()
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("layout borrow did not join")
			}
		}
		input.CloseConsumerV1()
	})
	go func() {
		done <- input.WithLayoutV1(ctx, org, func(in DocumentPackageLayoutInputV1) error {
			if in.Root != root || in.Count != 16 {
				return ErrDocumentPackageInputV1
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copy.CloseConsumerV1()
	cancel()
	if coordinator.SnapshotV1(org).GlobalGrants != 1 || f.PendingV1().HTMLInputProducers != 1 {
		t.Fatal("active layout borrow refunded")
	}
	unblock()
	select {
	case e = <-done:
		joined = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("layout work did not join")
	}
	if coordinator.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("layout owner leaked")
	}
}
