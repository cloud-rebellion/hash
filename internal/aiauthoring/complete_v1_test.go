// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package aiauthoring

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// Tests actual joined result lifetime only. No metadata shell grants native
// request, provider, M94, SQL, transaction or authenticated response authority.
func resultFixture296(t *testing.T) (*ResultV1[string], context.Context, *atomic.Int32) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	var closes atomic.Int32
	body := &resultBodyV1[string]{value: "private generated result"}
	state := &resultStateV1{original: ctx, workflow: ctx, cancel: func() { closes.Add(1) }, erase: func() { body.value = "" }}
	return &ResultV1[string]{state: state, body: body}, ctx, &closes
}
func TestDocumentAIResultCloseJoinsActualSerializationV1(t *testing.T) {
	result, ctx, closes := resultFixture296(t)
	copied := *result
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- result.WithValueV1(ctx, func(value string) error {
			if value != "private generated result" {
				return errors.New("original result differs")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual serialization borrower did not enter")
	}
	result.CloseConsumerV1()
	copied.CloseConsumerV1()
	result.state.mu.Lock()
	held := result.state.active == 1 && !result.state.retired
	result.state.mu.Unlock()
	if !held || closes.Load() != 0 || copied.body.value == "" {
		close(release)
		<-done
		t.Fatal("Close refunded/erased an executing serializer")
	}
	if err := copied.WithValueV1(ctx, func(string) error { t.Error("closed copy exposed private result"); return nil }); err == nil {
		t.Error("Close permitted another consumer")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 || copied.body.value != "" || !result.state.retired || result.state.phases != nil || result.state.usages != nil || result.state.accounting != nil || result.state.factory != nil || result.state.original != nil || result.state.workflow != nil {
		t.Fatal("actual last serializer did not retire all copied private result views")
	}
	result.CloseConsumerV1()
	if closes.Load() != 1 {
		t.Fatal("duplicate close repeated source retirement")
	}
}
func TestDocumentAIResultCancelAndFailureNeverExposeValueV1(t *testing.T) {
	for _, mode := range []string{"parent-cancel", "workflow-cancel", "failed", "foreign-context"} {
		t.Run(mode, func(t *testing.T) {
			result, ctx, closes := resultFixture296(t)
			useCtx := ctx
			switch mode {
			case "parent-cancel":
				c, stop := context.WithCancel(ctx)
				stop()
				result.state.original = c
				useCtx = c
			case "workflow-cancel":
				c, stop := context.WithCancel(ctx)
				stop()
				result.state.workflow = c
			case "failed":
				result.state.failed = true
			case "foreign-context":
				type key struct{}
				useCtx = context.WithValue(ctx, key{}, true)
			}
			if err := result.WithValueV1(useCtx, func(string) error { t.Error("canceled/failed/foreign delivery exposed result"); return nil }); err == nil {
				t.Error("invalid delivery context acquired actual consumer")
			}
			result.CloseConsumerV1()
			if closes.Load() != 1 || result.body.value != "" {
				t.Fatal("failed delivery retained private result")
			}
		})
	}
}
func TestDocumentAIResultCancellationDuringWriteRechecksV1(t *testing.T) {
	result, ctx, _ := resultFixture296(t)
	delivery, stop := context.WithCancel(ctx)
	result.state.original = delivery
	err := result.WithValueV1(delivery, func(string) error { stop(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatal("successful callback masked actual canceled delivery", err)
	}
	result.CloseConsumerV1()
}
