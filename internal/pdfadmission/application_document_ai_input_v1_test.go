// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNativeAIInputPreservesActualSingleDecodeAndWireLimit295(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	factory, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	for _, tail := range []string{"", " malformed trailing", strings.Repeat("x", 2<<20)} {
		owner, err := factory.NewAIHTTPInputV1(ctx, org, "suggest_counter_clause")
		if err != nil {
			t.Fatal(err)
		}
		var value struct {
			Concern string `json:"concern"`
		}
		body := http.MaxBytesReader(nil, io.NopCloser(strings.NewReader(`{"concern":"first","unknown":{"x":[1,true]},"CONCERN":"最後"}`+tail)), 32*1024)
		err = owner.WithBodyV1(ctx, body, func(r io.Reader) error { return json.NewDecoder(r).Decode(&value) })
		if err != nil || value.Concern != "最後" {
			t.Fatal("original duplicate/Unicode/trailing acceptance changed", err, value)
		}
		owner.CloseConsumerV1()
		if c.SnapshotV1(org).GlobalGrants != 0 || factory.PendingV1().HTMLInputProducers != 0 {
			t.Fatal("actual input consumer did not retire")
		}
	}
	owner, err := factory.NewAIHTTPInputV1(ctx, org, "suggest_counter_clause")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.CloseConsumerV1()
	err = owner.WithBodyV1(ctx, http.MaxBytesReader(nil, io.NopCloser(strings.NewReader(`{"concern":"`+strings.Repeat("x", 32*1024)+`"}`)), 32*1024), func(r io.Reader) error { var v struct{ Concern string }; return json.NewDecoder(r).Decode(&v) })
	var maximum *http.MaxBytesError
	if !errors.As(err, &maximum) || maximum.Limit != 32*1024 {
		t.Fatal("original32KiB ceiling changed", err)
	}
}

type blockedAIInput295 struct {
	entered, release chan struct{}
	once             sync.Once
}

func (b *blockedAIInput295) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return 0, io.EOF
}
func TestNativeAIInputCannotRefundOriginalBlockedDecoder295(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	factory, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	owner, err := factory.NewMCPEnvelopeInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	copy := *owner
	body := &blockedAIInput295{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	var release sync.Once
	finish := func() { release.Do(func() { close(body.release) }) }
	t.Cleanup(func() {
		finish()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("input worker failed independent cleanup join")
		}
		owner.CloseConsumerV1()
	})
	go func() {
		done <- owner.WithBodyV1(ctx, body, func(r io.Reader) error { _, e := io.ReadAll(r); return e })
	}()
	select {
	case <-body.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copy.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 1 || factory.PendingV1().HTMLInputProducers != 1 {
		t.Fatal("blocked original Read was credited as retired")
	}
	finish()
	// Cleanup independently joins even if this assertion or deadline fails.
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	for factory.PendingV1().HTMLInputProducers != 0 {
		select {
		case <-deadline.C:
			t.Fatal("actual input join did not retire")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("joined input remained charged")
	}
}
