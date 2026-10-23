//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

// Genuine registered policy approval/self-grant and source review, with the
// existing owned PostgreSQL/native protocol fixture. Only the crash point is
// arranged directly: production ReservePreparationV1 commits the unfinished
// original producer before any rendering or PUT. This is not a render/storage
// qualification or an unowned replacement for the full production journey.
type preSign488PreparationFixtureV1 struct {
	q        *ownedPublicReadFixtureV1
	h        presign488HTTP
	template *generated.Template
}

func newPreSign488PreparationFixtureV1(t *testing.T) preSign488PreparationFixtureV1 {
	t.Helper()
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	s := q.f.s
	s.PreSignExecutionEnabled = true
	s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	var router http.Handler
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { router.ServeHTTP(w, r) }))
	base := "https://" + server.Listener.Addr().String()
	s.PublicURL = base
	s.Send.PublicURL = base
	s.Sign.BaseURL = base
	router = s.Routes()
	server.StartTLS()
	t.Cleanup(server.Close)
	client := server.Client()
	t.Cleanup(client.CloseIdleConnections)
	h := presign488HTTP{base: base, cookie: q.cookie, client: client}
	template := createBrandedDesignVariantE2E(t, q.f, q.cookie, func(_ *htmlmaster.Master, values map[string]string) {
		values["provider_name"] = q.f.user.Name
		values["provider_email"] = q.f.user.Email
	})
	approveBrandedDesignE2E(t, q.f, template, q.storagePeer, q.cookie)
	return preSign488PreparationFixtureV1{q: q, h: h, template: template}
}
func preSign488IntentForV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, request uuid.UUID, policy, grant presign.Reference) presignexecute.IntentV1 {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	return presignexecute.IntentV1{RequestID: request, ExpectedOrgID: q.f.org, ExpectedUserID: q.f.user.ID, DocumentID: doc.ID, DocumentUpdatedAt: doc.UpdatedAt.Time.UTC(),
		MaterializationID: uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes), MaterializationRevision: int64(doc.HtmlCurrentMaterializationSequence.Int32), SourceCommitment: commitment,
		Policy: policy, Grant: grant, LawfulBasis: "contract"}
}
func preSign488RendererCallsV1(q *ownedPublicReadFixtureV1) int {
	q.renderer.protocol.mu.Lock()
	defer q.renderer.protocol.mu.Unlock()
	return len(q.renderer.protocol.html)
}

func TestPreSign488OriginalPreparationPendingAndDifferentIntentConflictE2E(t *testing.T) {
	f := newPreSign488PreparationFixtureV1(t)
	q := f.q
	first := presign488Review(t, q, createBrandedDocumentE2E(t, q.f, f.template, q.cookie))
	second := presign488Review(t, q, createBrandedDocumentE2E(t, q.f, f.template, q.cookie))
	policy, grant := presign488Authority(t, q, f.h, f.template, first)
	request := uuid.New()
	original := preSign488IntentForV1(t, q, first, request, policy, grant)
	different := preSign488IntentForV1(t, q, second, request, policy, grant)
	// Both real sources and exact real authority references receive genuine
	// confirmation receipts BEFORE the original producer's crash reservation.
	preview := presign488Decode[presignexecute.PreviewV1](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/executions/preview", original, true, "", http.StatusOK).body)
	changed := presign488Decode[presignexecute.PreviewV1](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/executions/preview", different, true, "", http.StatusOK).body)
	session, err := presignregistry.NewSessionActor(q.f.s.Cookies, q.cookie, q.f.org, q.f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := presignregistry.NewSessionExecutionActorV1(session)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	if _, err = presignregistry.LockExecutionAuthorityV1(q.f.ctx, tx, actor, policy, grant); err != nil {
		t.Fatal("actual source authority was not admitted", err)
	}
	var locked uuid.UUID
	if err = tx.QueryRow(q.f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND id=$2 FOR UPDATE`, q.f.org, first.ID).Scan(&locked); err != nil || locked != first.ID {
		t.Fatal("actual original root lock missing", err)
	}
	key := presignexecute.RequestKey{OrgID: q.f.org, Executor: actor.Identity(), RequestID: request}
	if err = presignexecute.ReservePreparationV1(q.f.ctx, tx, key, original, actor.CredentialCommitment(), uuid.New(), preview.ExpiresAt); err != nil {
		t.Fatal("actual original preparation reserve refused", err)
	}
	if err = tx.Commit(q.f.ctx); err != nil {
		t.Fatal("actual original preparation commit failed", err)
	}
	inventory := preSignAuthFixture488{owned: q}
	before := inventory.snapshot(t)
	renders, provider := preSign488RendererCallsV1(q), q.storagePeer.requests.Load()
	presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/executions", presignexecute.ConfirmV1{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}, true, "", http.StatusServiceUnavailable)
	inventory.unchanged(t, before)
	presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/executions", presignexecute.ConfirmV1{Intent: changed.Intent, Receipt: changed.Receipt, Confirmed: true}, true, "", http.StatusConflict)
	inventory.unchanged(t, before)
	if preSign488RendererCallsV1(q) != renders || q.storagePeer.requests.Load() != provider {
		t.Fatal("duplicate or changed original request rendered or reached storage before durable reservation ownership")
	}
}
