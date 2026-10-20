// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"
)

// Controlled synchronous SDK responses, not a live S3/retention qualification.
func pinnedPDFFixture220(raw []byte) (*fitOwnedBodyForTestV1, *fitResponseTransportForTestV1) {
	b := &fitOwnedBodyForTestV1{reader: bytes.NewReader(raw), closeEntered: make(chan struct{}), finishClose: make(chan struct{})}
	return b, &fitResponseTransportForTestV1{body: b, version: "opaque+/=version-220", size: int64(len(raw))}
}
func TestPinnedPDFV1ObservationOwnsExactTupleAndOneRead(t *testing.T) {
	raw := []byte("%PDF-synthetic-pinned220")
	sum := sha256.Sum256(raw)
	expected := bytes.Clone(sum[:])
	b, tr := pinnedPDFFixture220(raw)
	close(b.finishClose)
	client := fitOwnedClientForTestV1(t, tr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	observed, err := client.ObservePinnedPDFV1(ctx, fitTestKey, tr.version, expected)
	if err != nil || observed.SizeV1() != int64(len(raw)) {
		t.Fatal(err)
	}
	if tr.heads.Load() != 1 || tr.gets.Load() != 0 {
		t.Fatal("observation read body or skipped HEAD")
	}
	clear(expected) // Original expected digest bytes cannot replace retained pins.
	copied := *observed
	body, err := copied.ReadV1(ctx)
	if err != nil || !bytes.Equal(body, raw) {
		t.Fatal("exact read", err)
	}
	if tr.heads.Load() != 1 || tr.gets.Load() != 1 || b.closeCalls.Load() != 1 {
		t.Fatal("read did not own one exact GET/Close")
	}
	if body, err = observed.ReadV1(ctx); !errors.Is(err, ErrPinnedPDFReadV1) || len(body) != 0 {
		t.Fatal("copied handle repeated read", err)
	}
}
func TestPinnedPDFV1RejectsUnusableObservationsBeforeGET(t *testing.T) {
	for _, size := range []int64{-1, 0, (50 << 20) + 1} {
		t.Run(time.Duration(size).String(), func(t *testing.T) {
			raw := []byte("%PDF-synthetic")
			sum := sha256.Sum256(raw)
			b, tr := pinnedPDFFixture220(raw)
			close(b.finishClose)
			tr.size = size
			client := fitOwnedClientForTestV1(t, tr)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if _, err := client.ObservePinnedPDFV1(ctx, fitTestKey, tr.version, sum[:]); !errors.Is(err, ErrPinnedPDFReadV1) {
				t.Fatal("bad HEAD accepted", err)
			}
			if tr.gets.Load() != 0 {
				t.Fatal("bad observation reached GET")
			}
		})
	}
	raw := []byte("%PDF-synthetic")
	sum := sha256.Sum256(raw)
	b, tr := pinnedPDFFixture220(raw)
	close(b.finishClose)
	client := fitOwnedClientForTestV1(t, tr)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, version := range []string{"", " null ", DevelopmentVersionID, "\u00a0" + DevelopmentVersionID + "\u00a0", "bad\nversion"} {
		if _, err := client.ObservePinnedPDFV1(ctx, fitTestKey, version, sum[:]); !errors.Is(err, ErrPinnedPDFReadV1) {
			t.Fatal("reserved version accepted", err)
		}
	}
	if _, err := client.ObservePinnedPDFV1(context.Background(), fitTestKey, tr.version, sum[:]); !errors.Is(err, ErrPinnedPDFReadV1) {
		t.Fatal("unbounded operation", err)
	}
	if _, err := client.ObservePinnedPDFV1(ctx, fitTestKey, tr.version, make([]byte, 32)); !errors.Is(err, ErrPinnedPDFReadV1) {
		t.Fatal("zero digest", err)
	}
	if tr.heads.Load() != 0 || tr.gets.Load() != 0 {
		t.Fatal("invalid declarations reached provider")
	}
}
func TestPinnedPDFV1ActualGETMetadataLengthDigestAndCloseFaults(t *testing.T) {
	for _, mode := range []string{"wrong GET version", "wrong GET size", "short body", "extra body", "wrong digest", "close error"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("%PDF-synthetic-exact-pinned220")
			sum := sha256.Sum256(raw)
			b, tr := pinnedPDFFixture220(raw)
			close(b.finishClose)
			switch mode {
			case "wrong GET version":
				tr.getVersion = "wrong-version"
			case "wrong GET size":
				tr.getSize = tr.size + 1
			case "short body":
				b.reader = bytes.NewReader(raw[:len(raw)-1])
			case "extra body":
				b.reader = bytes.NewReader(append(bytes.Clone(raw), 'x'))
			case "wrong digest":
				sum = sha256.Sum256([]byte("other"))
			case "close error":
				b.closeErr = errors.New("synthetic close failure")
			}
			client := fitOwnedClientForTestV1(t, tr)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			observed, err := client.ObservePinnedPDFV1(ctx, fitTestKey, tr.version, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			body, err := observed.ReadV1(ctx)
			if !errors.Is(err, ErrPinnedPDFReadV1) || len(body) != 0 {
				t.Fatal("drift accepted", err)
			}
			if tr.heads.Load() != 1 || tr.gets.Load() != 1 || b.closeCalls.Load() != 1 {
				t.Fatal("response not closed or unexpected lookup")
			}
			if mode == "wrong GET version" || mode == "wrong GET size" {
				if b.reader.Len() != len(raw) {
					t.Fatal("mismatching GET metadata allocated/read body")
				}
			}
		})
	}
}
func TestPinnedPDFV1JoinsSynchronousCloseBeforeReturning(t *testing.T) {
	for _, mode := range []string{"success", "cancel during close", "close error"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("%PDF-synthetic-close220")
			sum := sha256.Sum256(raw)
			b, tr := pinnedPDFFixture220(raw)
			client := fitOwnedClientForTestV1(t, tr)
			if mode == "close error" {
				b.closeErr = errors.New("synthetic close failure")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			observed, err := client.ObservePinnedPDFV1(ctx, fitTestKey, tr.version, sum[:])
			if err != nil {
				cancel()
				close(b.finishClose)
				t.Fatal(err)
			}
			type outcome struct {
				body []byte
				err  error
			}
			done := make(chan outcome, 1)
			joined := make(chan struct{})
			var finish sync.Once
			go func() { defer close(joined); body, err := observed.ReadV1(ctx); done <- outcome{body, err} }()
			t.Cleanup(func() {
				cancel()
				finish.Do(func() { close(b.finishClose) })
				select {
				case <-joined:
				case <-time.After(3 * time.Second):
					t.Error("response consumer not joined")
				}
			})
			select {
			case <-b.closeEntered:
			case <-ctx.Done():
				t.Fatal("actual Close not reached")
			}
			select {
			case <-done:
				t.Fatal("returned before actual response Close")
			default:
			}
			if mode == "cancel during close" {
				cancel()
			}
			finish.Do(func() { close(b.finishClose) })
			select {
			case out := <-done:
				if mode == "success" {
					if out.err != nil || !bytes.Equal(out.body, raw) {
						t.Fatal(out.err)
					}
				} else if out.err == nil || len(out.body) != 0 {
					t.Fatal("close failure/cancellation succeeded", out.err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Close result not joined")
			}
		})
	}
}
