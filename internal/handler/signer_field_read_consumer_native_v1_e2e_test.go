//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
)

func TestOwnedSignerFieldReadOriginalAndResponseConsumerE2E(t *testing.T) {
	for _, scenario := range []string{"http_cancel", "original_close_first"} {
		t.Run(scenario, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			ctx, cancel := context.WithCancel(q.f.ctx)
			defer cancel()
			request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+parties[0].Token+"/fields", nil).WithContext(ctx)
			before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			var body []byte
			if scenario == "http_cancel" {
				w := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: q.f.ctx}
				done := make(chan struct{})
				var release sync.Once
				defer func() {
					release.Do(func() { close(w.release) })
					cancel()
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("real field response did not join")
					}
				}()
				go func() { defer close(done); q.f.s.Routes().ServeHTTP(w, request) }()
				select {
				case <-w.entered:
				case <-done:
					t.Fatal("field GET returned before held write")
				case <-time.After(5 * time.Second):
					t.Fatal("field GET did not reach actual response write")
				}
				pending := q.runtime.SessionsV1().PendingV1()
				snapshot := q.snapshotV1(t)
				want := pdfadmission.ApplicationSessionPendingV1{ObserverSessions: 2, HTMLAdmissions: 2, HTMLInputProducers: 1, SignerReaders: 1, SignerScopes: 1}
				if w.Code != http.StatusOK || pending != want || snapshot.Organisation.ParentBytes <= 0 || snapshot.Organisation.DBStagingBytes <= 32<<20 || snapshot.Global.SQLSessions != 2 || snapshot.Organisation.SQLSessions != 1 {
					t.Fatal("held field response lost real SQL retirement or paid input/body ownership", pending)
				}
				cancel()
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				err := q.runtime.ReconcileCleanupV1(cleanup)
				stop()
				if err != nil || q.snapshotV1(t) != snapshot || q.runtime.SessionsV1().PendingV1() != pending {
					t.Fatal("cancellation/refence refunded a still-writing field body", err)
				}
				release.Do(func() { close(w.release) })
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("field GET did not join after real Write release")
				}
				if w.timedOut.Load() {
					t.Fatal("writer timeout substituted for actual release")
				}
				body = w.Body.Bytes()
			} else {
				rc, err := q.f.s.Sign.LookupSignerFieldsByTokenV1(ctx, auth.HashMagicToken(parties[0].Token))
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := rc.CloseReadV1(); err != nil {
						t.Error(err)
					}
				}()
				observation, err := q.f.s.captureSignerReadObservation(request, rc)
				if err != nil {
					t.Fatal(err)
				}
				page, err := q.f.s.Sign.SignerFieldListV1(ctx, rc, func(fresh *sign.RecipientContext) error {
					return q.f.s.validateSignerReadObservation(request, rc, observation, fresh)
				})
				if err != nil {
					t.Fatal(err)
				}
				defer page.CloseConsumerV1()
				pending := q.runtime.SessionsV1().PendingV1()
				snapshot := q.snapshotV1(t)
				if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLInputProducers != 1 || pending.HTMLAdmissions != 2 || pending.SignerReaders != 1 || len(page.JSON) == 0 {
					t.Fatal("real field result lost consumers before application use", pending)
				}
				cancel()
				if err := rc.CloseReadV1(); err == nil {
					t.Fatal("original close falsely retired a borrowed field result")
				}
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				_ = q.runtime.ReconcileCleanupV1(cleanup)
				stop()
				if q.snapshotV1(t) != snapshot || q.runtime.SessionsV1().PendingV1() != pending || len(page.JSON) == 0 {
					t.Fatal("early original close/cancel refunded live field bytes")
				}
				// Actual JSON use completes before the owning result closes.
				body = append([]byte(nil), page.JSON...)
				page.CloseConsumerV1()
				if page.JSON != nil {
					t.Fatal("closed result kept exposed field bytes")
				}
			}
			var result struct {
				Fields []json.RawMessage `json:"fields"`
				Count  int               `json:"count"`
			}
			if json.Unmarshal(body, &result) != nil || result.Count <= 0 || result.Count != len(result.Fields) {
				t.Fatal("actual retained field response lost complete JSON")
			}
			q.assertObserversOnlyV1(t)
			if nativeCommentWholeState164V1(t, q, doc, q.f.pool) != before {
				t.Fatal("field read/consumer lifecycle changed business state")
			}
		})
	}
}
