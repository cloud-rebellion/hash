// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"strings"
	"sync"
	"testing"
	"time"
)

func packageArgs225(root, member uuid.UUID, mcp bool) []byte {
	fields := map[string]any{"member_document_id": member.String(), "expected_updated_at": "2026-10-18T00:00:00Z", "expected_member_updated_at": "2026-10-18T00:00:01Z", "expected_package_id": "", "expected_generation": "0", "ordinal": 1, "title": "NDA", "category": ""}
	if mcp {
		fields["document_id"] = root.String()
	}
	raw, _ := json.Marshal(fields)
	return raw
}
func TestDocumentPackageInputClosedGrammarV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	root, member := uuid.New(), uuid.New()
	base := string(packageArgs225(root, member, false))
	for _, tc := range []struct{ name, raw string }{
		{"duplicate", strings.TrimSuffix(base, "}") + ",\"title\":\"DPA\"}"},
		{"unknown pin", strings.TrimSuffix(base, "}") + ",\"pdf_key\":\"untrusted\"}"},
		{"case alias", strings.Replace(base, "\"title\"", "\"Title\"", 1)},
		{"year zero", strings.Replace(base, "2026-10-18T00:00:00Z", "0000-10-18T00:00:00Z", 1)},
		{"null", strings.Replace(base, "\"title\":\"NDA\"", "\"title\":null", 1)},
		{"numeric generation", strings.Replace(base, "\"expected_generation\":\"0\"", "\"expected_generation\":0", 1)},
		{"decimal ordinal", strings.Replace(base, "\"ordinal\":1", "\"ordinal\":1.0", 1)},
		{"negative ordinal", strings.Replace(base, "\"ordinal\":1", "\"ordinal\":-1", 1)},
		{"trailing", base + " {}"},
		{"surrogate", strings.Replace(base, "NDA", `\ud800`, 1)},
		{"nul", strings.Replace(base, "NDA", `\u0000`, 1)},
		{"invalid utf8", strings.Replace(base, "NDA", string([]byte{255}), 1)},
		{"absent header disagreement", strings.Replace(base, "\"expected_generation\":\"0\"", "\"expected_generation\":\"1\"", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, e := decodeDocumentPackageSelectionV1(ctx, root, []byte(tc.raw), false); !errors.Is(e, ErrDocumentPackageInputV1) {
				t.Fatal("invalid request accepted", e)
			}
		})
	}
	for _, mcp := range []bool{false, true} {
		raw := packageArgs225(root, member, mcp)
		got, e := decodeDocumentPackageSelectionV1(ctx, root, raw, mcp)
		if e != nil || got.Root != root || got.Member != member || got.Draft.Generation != 0 || got.Intent.Title != "NDA" {
			t.Fatal("valid choice changed", got, e)
		}
	}
	raw := strings.Replace(base, "\"expected_package_id\":\"\"", "\"expected_package_id\":\""+uuid.New().String()+"\"", 1)
	raw = strings.Replace(raw, "\"expected_generation\":\"0\"", "\"expected_generation\":\"9223372036854775807\"", 1)
	got, e := decodeDocumentPackageSelectionV1(ctx, root, []byte(raw), false)
	if e != nil || got.Draft.Generation != 9223372036854775807 {
		t.Fatal("bigint rounded", got, e)
	}
	if _, e = decodeDocumentPackageRootV1(ctx, []byte("{\"document_id\":\""+root.String()+"\",\"document_id\":\""+member.String()+"\"}")); e == nil {
		t.Fatal("duplicate inventory identity accepted")
	}
}
func TestDocumentPackageInputRetainsOriginalContextAndBorrowerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, coordinator := htmlInputFactoryTestV1(t, 64<<20)
	org, root, member := uuid.New(), uuid.New(), uuid.New()
	raw := packageArgs225(root, member, true)
	input, e := f.NewDocumentPackageArgumentsV1(ctx, org, raw)
	if e != nil {
		t.Fatal(e)
	}
	copy := *input
	raw[0] = '['
	if e = input.ReadArgumentsV1(ctx); e != nil {
		t.Fatal("original args not retained", e)
	}
	renewed, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if e = input.WithSelectionV1(renewed, org, func(DocumentPackageSelectionInputV1) error { return nil }); e == nil {
		t.Fatal("replacement context accepted")
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var releaseOnce sync.Once
	unblock := func() { releaseOnce.Do(func() { close(release) }) }
	joined := false
	t.Cleanup(func() {
		cancel()
		unblock()
		if !joined {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("borrow cleanup did not join")
			}
		}
		input.CloseConsumerV1()
	})
	go func() {
		done <- input.WithSelectionV1(ctx, org, func(in DocumentPackageSelectionInputV1) error {
			if in.Root != root || in.Member != member {
				return errors.New("identity changed")
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
		t.Fatal("active service refunded")
	}
	unblock()
	select {
	case e = <-done:
		joined = true
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("borrow did not join")
	}
	if coordinator.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("joined input leaked")
	}
}
