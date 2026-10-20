// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCatalogRuleStreamingInputPreservesOriginalSingleDecodeV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	// The previous handler accepted one JSON value without requiring EOF, even
	// with trailing malformed or over-limit bytes after that completed value.
	for _, tail := range []string{"", " trailing", strings.Repeat("x", 40<<10)} {
		input, err := f.NewCatalogRuleHTTPInputV1(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		raw := `{"name":"SE","predicate_json":{"field":"country","op":"==","value":"SE"},"required_tier":"SES"}`
		value, err := input.DecodeCreateV1(ctx, httptest.NewRecorder(), io.NopCloser(strings.NewReader(raw+tail)))
		if err != nil || value.Name != "SE" {
			t.Fatal("original single Decode semantics changed", err)
		}
		if err = input.ValidateRuleV1(ctx, value.Predicate, eidas.Tier(value.RequiredTier)); err != nil {
			t.Fatal(err)
		}
		if s := c.SnapshotV1(org); s.GlobalGrants != 2 || s.Global.ParentBytes <= 128*(32<<10) {
			t.Fatal("actual decoder/validator grants not retained", s)
		}
		input.CloseConsumerV1()
		if c.SnapshotV1(org).GlobalGrants != 0 {
			t.Fatal("actual decoder/validator last use leaked")
		}
	}
	input, err := f.NewCatalogRuleHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	_, err = input.DecodePatchV1(ctx, httptest.NewRecorder(), io.NopCloser(strings.NewReader(`{"reason":"`+strings.Repeat("x", 33<<10)+`"}`)))
	var tooLarge *http.MaxBytesError
	if !errors.As(err, &tooLarge) || tooLarge.Limit != 32<<10 {
		t.Fatal("original32KiB decoder ceiling changed", err)
	}
	input.CloseConsumerV1()
	if c.SnapshotV1(org).Global != (workguard.VectorV1{}) {
		t.Fatal("original size refusal retained a closed consumer")
	}
}
func TestCatalogRuleValidationPricesActualDeepCopiesBeforeValidatorV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	raw := `{"field":"country","op":"==","value":"SE"}`
	for range 128 {
		raw = `{"all":[` + raw + `]}`
	}
	if err := eidas.ValidateRule([]byte(raw), eidas.TierSES); err != nil {
		t.Fatal(err)
	}
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	h, err := f.NewCatalogRuleArgumentsV1(ctx, org, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	base := c.SnapshotV1(org).Global.ParentBytes
	component, err := catalogRulePredicateComponentsForV1([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	h.CloseConsumerV1()
	f, c = htmlInputFactoryTestV1(t, base+component.parentBytes-1)
	h, err = f.NewCatalogRuleArgumentsV1(ctx, org, []byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err = h.ValidateRuleV1(ctx, []byte(raw), eidas.TierSES); !errors.Is(err, ErrCatalogRuleInputV1) {
		t.Fatal("recursive validator ran without its actual raw/path work credit", err)
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 1 || s.Global.ParentBytes != base {
		t.Fatal("refused validator changed original input debt", s)
	}
	h.CloseConsumerV1()
	// Exact original errors remain with available work; pricing grants no schema
	// authority and adds no predicate-count or depth restriction.
	f, c = htmlInputFactoryTestV1(t, 64<<20)
	h, err = f.NewCatalogRuleArgumentsV1(ctx, org, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []json.RawMessage{nil, []byte(`[]`), []byte(`{"field":"country","op":"==","value":false}`), []byte(raw)} {
		want := eidas.ValidateRule(raw, eidas.TierSES)
		got := h.ValidateRuleV1(ctx, raw, eidas.TierSES)
		if (want == nil) != (got == nil) || (want != nil && want.Error() != got.Error()) {
			t.Fatal("original recursive validator result changed", want, got)
		}
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("closed validation errors leaked")
	}
}

func TestCatalogRuleBlockedDecodeCannotRefundOnCloseOrShutdownV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	h, err := f.NewCatalogRuleHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	copy := *h
	b := &htmlInputBlockedBodyV1{started: make(chan struct{}), finish: make(chan struct{})}
	done := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(b.finish) }) }
	t.Cleanup(func() {
		cancel()
		unblock()
		select {
		case <-done:
			h.CloseConsumerV1()
		case <-time.After(2 * time.Second):
			t.Error("original blocked decoder did not join; its work remains charged")
		}
	})
	go func() { _, _ = h.DecodeCreateV1(ctx, httptest.NewRecorder(), b); close(done) }()
	select {
	case <-b.started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copy.CloseConsumerV1()
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = f.CloseV1(cleanup); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("factory invented actual blocked decode retirement", err)
	}
	if p := f.PendingV1(); p.HTMLInputProducers != 1 || c.SnapshotV1(org).GlobalGrants != 1 {
		t.Fatal("actual blocked input work refunded", p)
	}
	unblock()
	select {
	case <-done:
	case <-cleanup.Done():
		t.Fatal("actual decoder failed to join")
	}
	h.CloseConsumerV1()
	if p := f.PendingV1(); p.HTMLInputProducers != 0 || c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("joined decoder did not retire", p)
	}
}
