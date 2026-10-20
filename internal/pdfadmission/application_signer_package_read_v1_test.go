// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
)

// These tests exercise consumer ownership and the intentionally limited public
// projection. Actual token/SQL/capture authority is qualified by the handler
// PostgreSQL tests; an in-memory value never establishes that authority.
func TestSignerPackagePresentationConsumerV1(t *testing.T) {
	t.Run("copied close waits for actual callback", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		released := 0
		state := &applicationSignerPackagePresentationStateV1{ctx: ctx, body: []byte(`{"package":null}`), close: func() { released++ }}
		state.self = state
		h := &ApplicationSignerPackagePresentationV1{state: state}
		copied := *h
		marker := errors.New("writer result")
		err := h.WithJSONV1(func(body []byte) error {
			copied.CloseConsumerV1()
			cancel()
			if released != 0 || string(body) != `{"package":null}` || len(state.body) == 0 {
				t.Fatal("copied close or cancellation refunded active output")
			}
			return marker
		})
		if !errors.Is(err, marker) || released != 1 || state.body != nil || state.close != nil {
			t.Fatal("actual last use did not retire once", err, released)
		}
		h.CloseConsumerV1()
		copied.CloseConsumerV1()
		if released != 1 {
			t.Fatal("copied close released twice")
		}
		if err = h.WithJSONV1(func([]byte) error { t.Fatal("closed output was delivered"); return nil }); err == nil {
			t.Fatal("closed output accepted")
		}
	})
	t.Run("cancel before delivery retains until close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		released := false
		state := &applicationSignerPackagePresentationStateV1{ctx: ctx, body: []byte("{}"), close: func() { released = true }}
		state.self = state
		h := &ApplicationSignerPackagePresentationV1{state: state}
		cancel()
		if h.WithJSONV1(func([]byte) error { t.Fatal("cancelled output delivered"); return nil }) == nil || released {
			t.Fatal("cancellation became release authority")
		}
		h.CloseConsumerV1()
		if !released {
			t.Fatal("actual close did not retire output")
		}
	})
	t.Run("nil and unbound copies refuse", func(t *testing.T) {
		for _, h := range []*ApplicationSignerPackagePresentationV1{nil, {}, {state: &applicationSignerPackagePresentationStateV1{ctx: context.Background(), close: func() {}}}} {
			if h.WithJSONV1(func([]byte) error { t.Fatal("unbound output delivered"); return nil }) == nil {
				t.Fatal("unbound output accepted")
			}
			h.CloseConsumerV1()
		}
		if _, _, err := new(ApplicationSessionFactoryV1).NewSignerPackageReadOperationV1(new(ApplicationSignerPackageReadInputV1)); err == nil {
			t.Fatal("caller shell became native operation")
		}
	})
}
func TestSignerPackageProjectionBoundaryV1(t *testing.T) {
	org, root := uuid.New(), uuid.New()
	main := documentpackage.MemberV1{DocumentID: root, Title: "Agreement <Å>", Category: "Agreement", PDF: documentpackage.PDFPinV1{Key: "org/" + org.String() + "/private-main.pdf", VersionID: " private-version ", SHA256: strings.Repeat("a", 64), Bytes: 321, Pages: 2}, Source: documentpackage.SourcePinV1{Kind: documentpackage.SourcePDFImportV1}}
	members := []documentpackage.MemberV1{main, main, main}
	for i := 1; i < len(members); i++ {
		members[i].DocumentID = uuid.New()
		members[i].Title = []string{"", "DPA", "NDA"}[i]
		members[i].Category = members[i].Title
		members[i].PDF.Key += "-annex" + members[i].Title
		members[i].PDF.SHA256 = strings.Repeat([]string{"a", "b", "c"}[i], 64)
		members[i].PDF.Bytes += int64(i)
		members[i].PDF.Pages += int32(i)
	}
	manifest, err := documentpackage.NewManifestV1(documentpackage.InputV1{Binding: documentpackage.BindingV1{OrgID: org, DocumentID: root, PackageID: uuid.New(), Revision: 9007199254740993}, Main: members[0], Annexes: members[1:]})
	if err != nil {
		t.Fatal(err)
	}
	input := manifest.Input()
	projected := make([]SignerPackageMemberPresentationV1, 0, 3)
	for _, m := range append([]documentpackage.MemberV1{input.Main}, input.Annexes...) {
		projected = append(projected, signerPackageMemberProjectionV1(m))
	}
	raw, err := json.Marshal(projected)
	if err != nil {
		t.Fatal(err)
	}
	for i, m := range members {
		p := projected[i]
		if p.Title != m.Title || p.Category != m.Category || p.PDFSHA256 != m.PDF.SHA256 || p.Bytes != m.PDF.Bytes || p.Pages != m.PDF.Pages {
			t.Fatal("projection lost committed order or PDF identity", i)
		}
	}
	for _, secret := range []string{org.String(), root.String(), "private-main", "private-version", "source", "document_id", "version_id", "storage"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("public projection leaked private capture data", secret)
		}
	}
	if bytes.Equal(raw, manifest.CanonicalJSON()) {
		t.Fatal("internal manifest exposed as public descriptor")
	}
}
func TestSignerPackageBodyBoundsV1(t *testing.T) {
	for _, n := range []int32{-1, documentpackage.MaxManifestBytesV1 + 1} {
		if _, _, err := signerPackageReadBodyCostV1(n); err == nil {
			t.Fatal("invalid manifest bound accepted", n)
		}
	}
	small, _, err := signerPackageReadBodyCostV1(0)
	if err != nil || small <= 0 {
		t.Fatal("legacy null output was unfunded", err)
	}
	large, wire, err := signerPackageReadBodyCostV1(documentpackage.MaxManifestBytesV1)
	if err != nil || large <= small || wire != documentpackage.MaxManifestBytesV1 || large < 32*int64(wire) {
		t.Fatal("maximum immutable manifest was not bounded before decode", err)
	}
}
