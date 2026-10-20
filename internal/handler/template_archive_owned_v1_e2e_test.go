//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type ownedTemplateArchiveResponseGateV1 struct {
	*httptest.ResponseRecorder
	started, release  chan struct{}
	once, releaseOnce sync.Once
}

func (w *ownedTemplateArchiveResponseGateV1) WriteHeader(code int) {
	w.once.Do(func() { close(w.started); <-w.release })
	w.ResponseRecorder.WriteHeader(code)
}
func (w *ownedTemplateArchiveResponseGateV1) unblock() { w.releaseOnce.Do(func() { close(w.release) }) }

// Actual DELETE deliberately needs only the active scalar parent, even when
// its cold source cache was removed. No full Template or cache repair supports
// the archive result or its original org-only audit publication.
func TestOwnedTemplateArchiveActualUncachedParentAndHooksE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	create := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/templates", map[string]any{"name": "Archive scalar parent", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Retain exact archived content"}]}`), "variables_json": map[string]string{"customer": "Exact archived variable"}})
	if create.Code != http.StatusCreated {
		t.Fatalf("genuine archive source creation=%d %s", create.Code, create.Body.String())
	}
	var response templateResponse
	if err := json.Unmarshal(create.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	id := response.ID
	original, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: id, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if tag, e := f.pool.Exec(f.ctx, "DELETE FROM pdf_template_source_sizes_v1 WHERE template_id=$1 AND org_id=$2", id, f.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("negative M97 deletion", e)
	}
	route := "/api/v1/templates/" + id.String()
	read := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodGet, route, nil)
	if read.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing real source cache must refuse body=%d %s", read.Code, read.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
		t.Fatal(err)
	}
	denied := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodDelete, route, nil)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("original archive live role=%d %s", denied.Code, denied.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role=$3 WHERE id=$1 AND org_id=$2", f.user.ID, f.org, f.user.Role); err != nil {
		t.Fatal(err)
	}
	hook := newOwnedPlainAuditGateV1(audit.KindTemplateArchived)
	t.Cleanup(hook.unblock)
	f.s.Audit.Subscribe(func(_ context.Context, event uuid.UUID, e audit.Entry) {
		if e.Kind != audit.KindTemplateArchived {
			return
		}
		hook.eventID = event
		hook.entry = e
		close(hook.started)
		<-hook.release
		close(hook.returned)
	})
	gate := &ownedTemplateArchiveResponseGateV1{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
	t.Cleanup(gate.unblock)
	request := ownedBlocksTemplateRequestV1(t, f, cookie, http.MethodDelete, route, nil)
	done := make(chan struct{})
	defer func() {
		gate.unblock()
		hook.unblock()
		ownedPlainAwaitV1(t, done, "archive handler actual exit on cleanup")
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	go func() { defer close(done); f.s.Routes().ServeHTTP(gate, request) }()
	ownedPlainAwaitV1(t, gate.started, "actual archive response")
	ownedPlainAwaitV1(t, hook.started, "actual archive org-only hook")
	if hook.eventID == uuid.Nil || hook.entry.DocumentID != nil || hook.entry.RecipientID != nil || hook.entry.ActorUserID == nil || *hook.entry.ActorUserID != f.user.ID || hook.entry.Payload["template_id"] != id {
		t.Fatal("original template.archived event scope changed")
	}
	var name string
	var version int32
	var blocks, variables []byte
	var archived bool
	var caches int
	err = f.pool.QueryRow(f.ctx, "SELECT t.name,t.version,t.blocks_json,t.variables_json,t.archived_at IS NOT NULL,(SELECT count(*) FROM pdf_template_source_sizes_v1 c WHERE c.template_id=t.id) FROM templates t WHERE t.id=$1 AND t.org_id=$2", id, f.org).Scan(&name, &version, &blocks, &variables, &archived, &caches)
	if err != nil || !archived || name != original.Name || version != original.Version || !bytes.Equal(blocks, original.BlocksJson) || !bytes.Equal(variables, original.VariablesJson) || caches != 0 {
		t.Fatal("archive changed or repaired cold source", err)
	}
	ownedPlainAssertRetainedV1(t, q, "actual archive response and hook")
	gate.unblock()
	ownedPlainAwaitV1(t, done, "archive response last use")
	if gate.Code != http.StatusNoContent {
		t.Fatalf("native archive=%d %s", gate.Code, gate.Body.String())
	}
	ownedPlainAssertRetainedV1(t, q, "archive hook after response")
	hook.unblock()
	ownedPlainAwaitV1(t, hook.returned, "actual archive hook return")
	ownedCreationAssertDrainedV1(t, q, 2)
	again := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodDelete, route, nil)
	if again.Code != http.StatusNotFound {
		t.Fatalf("already archived parent=%d %s", again.Code, again.Body.String())
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}
