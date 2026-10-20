// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package catalogrules

import (
	"context"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/google/uuid"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The actual logger invokes this callback only after every real hook call has
// returned. Closing the response or canceling its original request cannot
// substitute for that join, even if a hook deliberately ignores cancellation.
func TestCatalogRuleResponseAndActualAuditHooksBothOwnLastUseV1(t *testing.T) {
	for _, responseFirst := range []bool{false, true} {
		t.Run(map[bool]string{true: "response first", false: "hooks first"}[responseFirst], func(t *testing.T) {
			logger := audit.New(nil, nil)
			started, finish, returned, closed := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(finish) }) }
			logger.Subscribe(func(context.Context, uuid.UUID, audit.Entry) { close(started); <-finish; close(returned) })
			var releases atomic.Int64
			consumers := &catalogRuleConsumersV1{release: func() { releases.Add(1); close(closed) }}
			logger.PublishJoinedV1(audit.PendingEvent{ID: uuid.New(), Entry: audit.Entry{OrgID: uuid.New(), Kind: audit.KindDocumentUpdated, Payload: map[string]any{"source_name": "Synthetic retained source"}}}, consumers.auditFinishedV1)
			t.Cleanup(func() {
				unblock()
				select {
				case <-returned:
				case <-time.After(time.Second):
					t.Error("original hook did not return")
				}
			})
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("actual subscribed hook never started")
			}
			if responseFirst {
				consumers.responseFinishedV1()
				consumers.responseFinishedV1()
				if releases.Load() != 0 {
					t.Fatal("blocked actual audit hook lost original native result loan")
				}
				unblock()
			} else {
				unblock()
				select {
				case <-returned:
				case <-time.After(time.Second):
					t.Fatal("actual hook did not return")
				}
				if releases.Load() != 0 {
					t.Fatal("audit join closed still-unserialized response")
				}
				consumers.responseFinishedV1()
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("both actual consumers failed to close original loan")
			}
			consumers.auditFinishedV1()
			consumers.responseFinishedV1()
			if releases.Load() != 1 {
				t.Fatal("original final use released more than once")
			}
		})
	}
}
