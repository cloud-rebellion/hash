// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"strings"
	"testing"
	"time"
)

func TestBlockInputUsesOriginalArgsAndKeepsActiveDecoderDebtV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	args := []byte("{\"source_kind\":\"blocks\",\"blocks_json\":{\"version\":1,\"blocks\":[]}}")
	h, err := f.NewBlocksArgumentsV1(ctx, org, args)
	if err != nil {
		t.Fatal(err)
	}
	copy := *h
	args[0] = '['
	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- h.WithArgumentsV1(ctx, func(raw []byte) error {
			if len(raw) == 0 || raw[0] != '{' {
				return errors.New("original owned args replaced")
			}
			close(started)
			<-finish
			return nil
		})
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copy.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 1 || f.PendingV1().HTMLInputProducers != 1 {
		t.Fatal("still-active original decoder was refunded")
	}
	close(finish)
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("actual decoder join did not retire input")
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("retired input was reused", err)
	}
}
func TestBlockHTTPInputFundsOriginalDecodeBeforeEnteringItV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	h, err := f.NewBlocksHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	base := c.SnapshotV1(org).Global.ParentBytes
	h.CloseConsumerV1()
	f, c = htmlInputFactoryTestV1(t, base+1)
	h, err = f.NewBlocksHTTPInputV1(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	err = h.WithHTTPBodyV1(ctx, io.NopCloser(strings.NewReader("{\"blocks_json\":{\"version\":1,\"blocks\":[]}}")), func([]byte) error { called = true; return nil })
	if !errors.Is(err, ErrBlocksInputV1) || called {
		t.Fatal("uncharged strict decoder ran", err, called)
	}
	if c.SnapshotV1(org).Global.ParentBytes != base {
		t.Fatal("refused parse changed original read grant")
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("closed refusal leaked")
	}
}

func TestBlockStreamingInputKeepsOriginalSingleDecodeAndTrailingBytesV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 64<<20)
	org := uuid.New()
	for _, tail := range []string{"", " trailing malformed", strings.Repeat("x", 2<<20)} {
		h, err := f.NewBlocksHTTPInputV1(ctx, org)
		if err != nil {
			t.Fatal(err)
		}
		var value struct{ Name string }
		err = h.WithStreamingBodyV1(ctx, io.NopCloser(strings.NewReader("{\"Name\":\"final\",\"Name\":\"kept\"}"+tail)), func(raw []byte) error {
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			return decoder.Decode(&value)
		})
		if err != nil || value.Name != "kept" {
			t.Fatal("original single Decode/duplicate/trailing behavior changed", err, value)
		}
		h.CloseConsumerV1()
		if c.SnapshotV1(org).GlobalGrants != 0 {
			t.Fatal("original decoder last use leaked")
		}
	}
}
func TestBlockInputEarlyReplacementPricesOriginalDecimalV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	raw := []byte("{\"version\":1,\"blocks\":[{\"type\":\"conditional\",\"attrs\":{\"expression\":\"1e1000000 > 0\"},\"content\":[{\"type\":\"paragraph\",\"text\":\"body\"}]}]}")
	f, _ := htmlInputFactoryTestV1(t, 256<<10)
	h, err := f.NewBlocksArgumentsV1(ctx, org, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = h.WithArgumentsV1(ctx, func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, err = h.ParseTreeV1(ctx, raw)
	if !errors.Is(err, ErrBlocksInputV1) {
		t.Fatal("original huge decimal executed before actual input grant", err)
	}
	h.CloseConsumerV1()
}
