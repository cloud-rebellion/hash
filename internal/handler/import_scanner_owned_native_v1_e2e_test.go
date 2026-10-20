//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
)

// Preserve the original scanner-before-persistence assertion with an actual
// initialized runtime, authenticated owner and native-created block document.
// Missing provider is an outage test, not scanner efficacy or EICAR acceptance.
func TestOwnedReplacementImportScannerUnavailableBeforePersistenceE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", q.cookie, map[string]any{"name": "Real scanner-outage replacement target", "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Original scanner-protected clause"}]}`), "variables_json": map[string]string{}}), "rest")
	ownedPlainAssertDrainedV1(t, q)
	before := nativeCommentWholeState164V1(t, q, doc, f.pool)
	cache := ownedBlockCacheStateV1(t, f, doc.ID)
	if err := malwarescan.Configure(f.ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
		t.Fatal("actual missing scanner not unavailable", err)
	}
	for _, spec := range []struct{ kind, key, text string }{{"html", "html", "<p>replacement</p>"}, {"md", "markdown", "replacement"}} {
		t.Run(spec.kind, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{spec.key: spec.text, "expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)})
			if err != nil {
				t.Fatal(err)
			}
			w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/import-"+spec.kind, string(body), q.cookie)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "upload scanning unavailable") {
				t.Fatal("actual scanner outage lost original fail-closed gate", w.Code)
			}
			ownedPlainAssertDrainedV1(t, q)
			if nativeCommentWholeState164V1(t, q, doc, f.pool) != before || ownedBlockCacheStateV1(t, f, doc.ID) != cache {
				t.Fatal("scanner outage persisted source, event, measurement, intent or notification changes")
			}
			release, err := importguard.Shared.Acquire(f.org)
			if err != nil {
				t.Fatal("scanner rejection leaked original import admission", err)
			}
			release()
		})
	}
}
