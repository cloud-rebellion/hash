//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Actual native initial->retired SQL->exact provider retention->fresh native
// transaction under the UNCHANGED allocated fixture limits. Synthetic versioned
// S3/retention peers make no real provider, delivery or legal-effect claim.
func TestLaterNoticeNativeBoundedStageHandoff484E2E(t *testing.T) {
	t.Run("same_allocated_budget_completes_and_retires", func(t *testing.T) {
		f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
		notice, in := issueLaterNotice483(t, f)
		if len(notice.Deliveries) != 1 || notice.Deliveries[0].RecipientEmail != in.RecipientEmails[0] || notice.Deliveries[0].State != "queued" || len(notice.VerifiedReceipts) != 0 {
			t.Fatal("actual bounded native handoff lost exact legal audience or invented receipt")
		}
		if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
			t.Fatal("detached comparison owner changed original evidence")
		}
		f.q.assertObserversOnlyV1(t)
	})
	t.Run("fresh_owner_refusal_after_provider_last_use", func(t *testing.T) {
		f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
		entered, release := make(chan struct{}), make(chan struct{})
		var blocked atomic.Bool
		base := laterAmendmentRetainedPeer483{base: f.completed.peer}
		provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
			if r.Method == http.MethodPut && r.URL.Query().Has("retention") && key == f.candidate.PdfStorageKey.String && blocked.CompareAndSwap(false, true) {
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
					return
				}
			}
			base.ServeHTTP(w, r)
		}))
		defer provider.Close()
		client, err := storage.New(f.q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(provider.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-notice-stage", SecretKey: "synthetic-notice-stage-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
		if err != nil {
			t.Fatal(err)
		}
		f.q.f.s.Storage = client
		f.q.f.s.NoticeAccess, err = f.q.runtime.NewLaterAmendmentNoticeAccessV1(client, f.q.f.s.Cookies, f.q.f.s.PublicURL)
		if err != nil {
			t.Fatal(err)
		}
		candidate := packageLatest223(t, f.q, f.candidate.ID)
		in := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: f.record.Revision, ExpectedDocumentUpdatedAt: candidate.UpdatedAt.Time, Subject: "Synthetic bounded notice", Text: "Read the exact proposed files; no acceptance is inferred.", RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		var beforeQueue int
		if err = f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT count(*) FROM email_deliveries").Scan(&beforeQueue); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- preserve the already-committed separate creation owner alert
		ctx, cancel := context.WithTimeout(f.q.f.ctx, 20*time.Second)
		defer cancel()
		done := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			done <- submitSessionOperationContextE2E(ctx, f.q.f.s, http.MethodPost, "/api/v1/documents/"+f.original.ID.String()+"/amendments/"+f.record.ID.String()+"/notice", string(raw), f.q.cookie)
		}()
		released, joined := false, false
		defer func() {
			if !released {
				close(release)
			}
			cancel()
			if !joined {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("actual notice request did not join after provider release")
				}
			}
		}()
		select {
		case <-entered:
		case response := <-done:
			joined = true
			t.Fatalf("native notice finished before real provider fence: status=%d", response.Code)
		case <-ctx.Done():
			t.Fatal("native notice never reached real retention PUT", ctx.Err())
		}
		// No live initial SQL borrower may block this ordinary legitimate role
		// change. The final fresh read must reject it even after verified retention.
		if _, err = f.q.f.q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: f.q.f.user.ID, OrgID: f.q.f.org, Role: "viewer"}); err != nil {
			t.Fatal("owner change during physically retired provider phase", err)
		}
		close(release)
		released = true
		var response *httptest.ResponseRecorder
		select {
		case response = <-done:
			joined = true
		case <-ctx.Done():
			t.Fatal("fresh owner check did not finish", ctx.Err())
		}
		if response.Code != http.StatusForbidden {
			t.Fatal("detached original metadata bypassed fresh current actor policy", response.Code, response.Body.String())
		}
		var notices, deliveries, access, queue, events int
		err = f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT
 (SELECT count(*) FROM document_amendment_notices_v1 WHERE amendment_id=$1),
 (SELECT count(*) FROM document_amendment_notice_deliveries_v1),
 (SELECT count(*) FROM document_amendment_notice_access_v1),
 (SELECT count(*) FROM email_deliveries),
 (SELECT count(*) FROM events WHERE org_id=$2 AND kind='document.amendment_notice_queued')`, f.record.ID, f.q.f.org).Scan(&notices, &deliveries, &access, &queue, &events) //nolint:rawsql -- complete disposable target refusal effects
		if err != nil || notices != 0 || deliveries != 0 || access != 0 || queue != beforeQueue || events != 0 {
			t.Fatal("fresh refusal left notice/capability/legal-mail/owner-alert/audit effects", err)
		}
		if laterAmendmentOriginalSnapshot483(t, f.q, f.original.ID) != f.before {
			t.Fatal("fresh refusal changed original source/signature/report evidence")
		}
		f.q.assertObserversOnlyV1(t)
	})
}
