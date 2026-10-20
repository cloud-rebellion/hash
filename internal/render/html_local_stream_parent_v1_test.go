// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/workguard"
)

func TestHTMLLocalPDFV1JoinedStreamAllowsNextRealLaneWhileOutputParentBorrowed(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	pdf := []byte("%PDF-actual local protocol peer\n")
	var requests atomic.Int32
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = w.Write(pdf)
	}))
	defer peer.Close()
	renderer := NewGotenberg(peer.URL)
	options := PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 4096}
	first, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<p>Actual first</p>", options, coordinator, org)
	if first != nil {
		defer first.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- first.WithPDFV1(func(actual []byte) error {
			if !bytes.Equal(actual, pdf) {
				return errors.New("actual first returned bytes changed")
			}
			close(entered)
			<-release
			if !bytes.Equal(actual, pdf) {
				return errors.New("active first output was erased")
			}
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	copied := *first
	copied.CloseConsumerV1()
	first.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		close(release)
		<-done
		t.Fatal("joined stream retained or active output Parent credited", got)
	}
	// This is an actual second HTTP conversion on the SAME one-provider
	// coordinator, not an extra axis or a capacity-only placeholder/probe.
	second, err := renderer.HTMLToPDFLocalOwnedV1(ctx, "<p>Actual second</p>", options, coordinator, org)
	if second != nil {
		defer second.CloseConsumerV1()
	}
	if err != nil {
		close(release)
		<-done
		t.Fatal("joined first stream blocked actual next lane", err)
	}
	if err = second.WithPDFV1(func(actual []byte) error {
		if !bytes.Equal(actual, pdf) {
			return errors.New("actual second returned bytes changed")
		}
		return nil
	}); err != nil {
		close(release)
		<-done
		t.Fatal(err)
	}
	second.CloseConsumerV1()
	if requests.Load() != 2 {
		close(release)
		<-done
		t.Fatal("real second lane did not dispatch exactly", requests.Load())
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes <= 0 || got.GlobalGrants != 1 {
		close(release)
		<-done
		t.Fatal("second lane credited still-live first output Parent", got)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("actual nested local lanes/output borrowers did not drain", got)
	}
}
