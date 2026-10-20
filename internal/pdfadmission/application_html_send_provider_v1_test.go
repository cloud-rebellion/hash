// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/workguard"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type htmlSendProviderTransportV1 func(*http.Request) (*http.Response, error)

func (f htmlSendProviderTransportV1) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type htmlSendProviderBodyV1 struct {
	io.Reader
	entered chan struct{}
	join    chan struct{}
	once    sync.Once
}

func (b *htmlSendProviderBodyV1) Close() error {
	b.once.Do(func() { close(b.entered) })
	<-b.join
	return nil
}

// Native Work/source/coordinator with explicitly synthetic opened SQL witness;
// the concrete HTTP stage and blocking response Close execute for real here.
func TestHTMLSendHTTPProviderDenialAndActualBodyCloseJoinV1(t *testing.T) {
	for _, deny := range []bool{true, false} {
		t.Run(map[bool]string{true: "denied-no-dispatch", false: "body-close-joins-before-refund"}[deny], func(t *testing.T) {
			work, source, _, fixture, coordinator, _ := htmlSendEvidenceFixtureV1(t, HTMLSendPreparationV1)
			ctx := source.state.owner.binding.ctx
			p := &applicationHTMLSendResolverV1{work: work, source: source.state, document: work.sourceDocument, active: 1}
			p.self = p
			work.resolverOwner = p
			actual := resolver.NewScannerFindingSource("https://source.example.test", "synthetic-token")
			var dispatches atomic.Int32
			entered, join := make(chan struct{}), make(chan struct{})
			var joinOnce sync.Once
			unblock := func() { joinOnce.Do(func() { close(join) }) }
			t.Cleanup(unblock)
			actual.Client = &http.Client{Transport: htmlSendProviderTransportV1(func(_ *http.Request) (*http.Response, error) {
				dispatches.Add(1)
				return &http.Response{StatusCode: 200, Body: &htmlSendProviderBodyV1{Reader: strings.NewReader("{\"value\":\"actual-value\"}"), entered: entered, join: join}, Header: make(http.Header)}, nil
			})}
			native := &htmlSendNativeHTTPSourceV1{owner: p, source: actual}
			ref := resolver.Ref{OrgID: fixture.scope.OrgID, DocID: fixture.scope.DocumentID, Source: "finding-1", Path: "value"}
			var occupied *workguard.GrantV1
			var err error
			if deny {
				occupied, err = coordinator.TryAcquireV1(ctx, fixture.scope.OrgID, workguard.VectorV1{ProviderStreams: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer occupied.Close()
			}
			owner := source.state.owner
			if err = owner.beginV1(); err != nil {
				t.Fatal(err)
			}
			finish := func() { p.mu.Lock(); p.active--; p.retireV1(); p.mu.Unlock(); owner.finishV1() }
			if deny {
				_, err = native.Fetch(ctx, ref)
				finish()
				if !errors.Is(err, ErrHTMLSendWorkV1) || dispatches.Load() != 0 {
					t.Fatalf("provider refusal dispatched real HTTP: calls=%d err=%v", dispatches.Load(), err)
				}
				return
			}
			done := make(chan error, 1)
			go func() {
				value, e := native.Fetch(ctx, ref)
				if e == nil && value != "actual-value" {
					e = errors.New("actual decode changed")
				}
				finish()
				done <- e
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("real body Close was not entered")
			}
			before := coordinator.SnapshotV1(fixture.scope.OrgID)
			if before.Global.ProviderStreams != 1 || before.Organisation.ProviderStreams != 1 {
				t.Fatal("actual HTTP call lacked shared stream", before)
			}
			work.CloseConsumerV1()
			during := coordinator.SnapshotV1(fixture.scope.OrgID)
			if during.Global.ProviderStreams != 1 || during.Organisation.ProviderStreams != 1 {
				t.Fatal("cancellation refunded blocking actual body Close", during)
			}
			select {
			case <-done:
				t.Fatal("HTTP producer returned before body Close joined")
			default:
			}
			unblock()
			select {
			case e := <-done:
				if e == nil {
					t.Fatal("cancelled source unexpectedly accepted decoded result")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("actual provider did not join")
			}
			after := coordinator.SnapshotV1(fixture.scope.OrgID)
			if after.Global.ProviderStreams != 0 || after.Organisation.ProviderStreams != 0 || dispatches.Load() != 1 {
				t.Fatal("joined HTTP provider stream did not settle", after)
			}
			if !applicationDoneV1(fixture.done) {
				close(fixture.done)
			}
			cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err = fixture.adapter.ReconcileCleanupV1(cleanup); err != nil {
				t.Fatal(err)
			}
		})
	}
}
