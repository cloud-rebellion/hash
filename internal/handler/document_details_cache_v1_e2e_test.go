//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"net/http"
	"testing"
	"time"
)

// These tests reuse the genuine same-runtime fresh creator from public113.
// They do not seed cache rows, refresh old rows, change metadata intent or
// claim to admit legacy REST/MCP/CRM full-model/input work.
type ownedDetailsCachesV1 struct{ policy, response, report string }

func ownedDetailsCachesReadV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) ownedDetailsCachesV1 {
	t.Helper()
	var s ownedDetailsCachesV1
	err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT to_jsonb(p)::text FROM document_signing_policy_sizes_v1 p WHERE p.document_id=$1 AND p.org_id=$2),(SELECT to_jsonb(r)::text FROM html_creation_response_sizes_v1 r WHERE r.document_id=$1 AND r.org_id=$2),(SELECT to_jsonb(m)::text FROM document_read_report_sizes_v1 m WHERE m.document_id=$1 AND m.org_id=$2)", doc.ID, q.f.org).Scan(&s.policy, &s.response, &s.report) //nolint:rawsql -- exact three genuine fresh cache witnesses, never insertion/repair
	if err != nil || s.policy == "" || s.response == "" || s.report == "" {
		t.Fatal("genuine fresh derived cache absent", err)
	}
	return s
}
func ownedDetailsDocumentV1(t *testing.T, q *ownedPublicReadFixtureV1, id *generated.Document) *generated.Document {
	t.Helper()
	doc, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: id.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
func ownedDetailsResponseReadV1(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, wantAvailable bool) {
	t.Helper()
	o, err := q.f.s.openHTMLAuthoringV1(q.f.ctx, q.f.org, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer o.closeConsumerV1(q.f.ctx)
	defer func() {
		if err := o.closeSQLV1(q.f.ctx); err != nil {
			t.Error(err)
		}
	}()
	var row *generated.ReadHTMLCreationResponseV1Row
	err = o.session.WithTxV1(q.f.ctx, func(owned context.Context, _ generated.DBTX) error {
		var readErr error
		row, readErr = o.reader.ReadCreationResponseV1(owned, doc.ID)
		return readErr
	})
	if !wantAvailable {
		if !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || row != nil {
			t.Fatal("true metadata replacement failed to refuse missing response cache", err)
		}
		return
	}
	if err != nil || row == nil || row.ID != doc.ID || row.Name != doc.Name || row.ExpiresAt != doc.ExpiresAt || !bytes.Equal(row.Metadata, doc.Metadata) {
		t.Fatal("bounded actual response read lost updated details or original metadata", err)
	}
	if err := o.session.CommitV1(q.f.ctx); err != nil {
		t.Fatal(err)
	}
}
func ownedDetailsConsumedV1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	q.reconcileV1(t)
	pending := q.runtime.SessionsV1().PendingV1()
	s := q.snapshotV1(t)
	if pending.WorkSessions != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 1 || s.Global != (workguard.VectorV1{SQLSessions: 1}) || s.Organisation != (workguard.VectorV1{SQLSessions: 1}) || s.GlobalGrants != 1 || s.OrganisationGrants != 1 {
		t.Fatal("actual details regression leaked work or erased tenant observer debt", pending, s)
	}
}
func TestOwnedDocumentDetailsRESTPreservesFreshResponseCacheE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	before := ownedDetailsCachesReadV1(t, q, doc)
	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	input := updateDocumentInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Name: "Renamed genuine fresh HTML contract", ExpiresAt: expiry.Format(time.RFC3339)}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+doc.ID.String(), string(raw), q.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("actual draft details PATCH=%d %s", w.Code, w.Body.String())
	}
	current := ownedDetailsDocumentV1(t, q, doc)
	expected := *doc
	expected.Name = input.Name
	if !sameSignerDocumentSource(&expected, current) || !bytes.Equal(doc.Metadata, current.Metadata) || !current.ExpiresAt.Valid || !current.ExpiresAt.Time.Equal(expiry) || !current.UpdatedAt.Time.After(doc.UpdatedAt.Time) {
		t.Fatal("actual details mutation changed source/metadata or failed intended name/expiry/edit witness")
	}
	if after := ownedDetailsCachesReadV1(t, q, current); after != before {
		t.Fatal("name/expiry intent rewrote or deleted genuine cache rows")
	}
	ownedDetailsResponseReadV1(t, q, current, true)
	ownedDetailsConsumedV1(t, q)
	stale := submitSessionOperationE2E(q.f.s, http.MethodPatch, "/api/v1/documents/"+doc.ID.String(), string(raw), q.cookie)
	if stale.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale original CAS=%d want412", stale.Code)
	}
	afterRefusal := ownedDetailsDocumentV1(t, q, current)
	if afterRefusal.UpdatedAt != current.UpdatedAt || afterRefusal.Name != current.Name || ownedDetailsCachesReadV1(t, q, current) != before {
		t.Fatal("stale details retry changed document or derived cache")
	}
}
func TestOwnedDocumentDetailsCRMMappingOnlyPreservesFreshResponseCacheE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	q.f.doc = doc
	before := ownedDetailsCachesReadV1(t, q, doc)
	context := crmDocumentReadContextE2E(t, q.f, q.cookie)
	in := CRMMappingRequest{CRMDocumentWitnessE2E(context), []crmDocumentMapping{}}
	observation := crmDocumentObserveE2E(t, q.f, q.cookie, in)
	if observation.ContentChanged {
		t.Fatal("explicit empty reviewed mapping unexpectedly changed literal values")
	}
	w := crmDocumentRequestE2E(t, q.f, q.f.ctx, http.MethodPost, "apply", q.cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if w.Code != http.StatusOK {
		t.Fatalf("actual reviewed mapping-only apply=%d %s", w.Code, w.Body.String())
	}
	current := ownedDetailsDocumentV1(t, q, doc)
	if !sameSignerDocumentSource(doc, current) || !bytes.Equal(doc.Metadata, current.Metadata) || !current.UpdatedAt.Time.After(doc.UpdatedAt.Time) {
		t.Fatal("mapping-only review changed literal source/metadata or failed parent edit witness")
	}
	if ownedDetailsCachesReadV1(t, q, current) != before {
		t.Fatal("mapping-only parent witness invalidated genuine fresh response cache")
	}
	if crmDocumentReadContextE2E(t, q.f, q.cookie).MappingReviewRequired {
		t.Fatal("actual reviewed empty mapping failed durable CRM review")
	}
	ownedDetailsResponseReadV1(t, q, current, true)
	ownedDetailsConsumedV1(t, q)
	stale := crmDocumentRequestE2E(t, q.f, q.f.ctx, http.MethodPost, "apply", q.cookie, crmDocumentApplyInputE2E(in, observation.ReviewDigest))
	if stale.Code != http.StatusConflict {
		t.Fatalf("old CRM witness=%d want409", stale.Code)
	}
	if latest := ownedDetailsDocumentV1(t, q, current); latest.UpdatedAt != current.UpdatedAt || ownedDetailsCachesReadV1(t, q, latest) != before {
		t.Fatal("stale CRM observation changed document/cache")
	}
}
func TestOwnedDocumentDetailsMCPExpiryPreservesAndMetadataWriteInvalidatesE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	doc := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	q.f.doc = doc
	q.f.enableMCP()
	before := ownedDetailsCachesReadV1(t, q, doc)
	mint, _ := mintDocumentMetadataKeyE2E(t, q.f, true)
	fieldMCPTextE2E(t, submitDocumentMetadataE2E(q.f, q.f.ctx, "set_expiry", mint.Plaintext), false)
	current := ownedDetailsDocumentV1(t, q, doc)
	if !sameSignerDocumentSource(doc, current) || !bytes.Equal(doc.Metadata, current.Metadata) || !current.ExpiresAt.Valid || !current.ExpiresAt.Time.After(time.Now()) || !current.UpdatedAt.Time.After(doc.UpdatedAt.Time) || ownedDetailsCachesReadV1(t, q, current) != before {
		t.Fatal("MCP explicit expiry intent changed metadata/source/cache or failed intended edit")
	}
	key, err := q.f.q.GetDocAgentTokenByPrefix(q.f.ctx, mint.Prefix)
	if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
		t.Fatal("actual one-use original credential accounting changed", err)
	}
	if replay := submitDocumentMetadataE2E(q.f, q.f.ctx, "set_expiry", mint.Plaintext); replay.Code != http.StatusUnauthorized {
		t.Fatalf("exhausted original MCP credential=%d want401", replay.Code)
	}
	if latest := ownedDetailsDocumentV1(t, q, current); latest.UpdatedAt != current.UpdatedAt || ownedDetailsCachesReadV1(t, q, latest) != before {
		t.Fatal("exhausted original document credential acquired replacement mutation authority")
	}
	ownedDetailsResponseReadV1(t, q, current, true)
	ownedDetailsConsumedV1(t, q)
	actualMetadataKey, _ := mintDocumentMetadataKeyE2E(t, q.f, false)
	fieldMCPTextE2E(t, submitDocumentMetadataE2E(q.f, q.f.ctx, "attach_metadata", actualMetadataKey.Plaintext), false)
	changed := ownedDetailsDocumentV1(t, q, current)
	var metadata map[string]string
	if json.Unmarshal(changed.Metadata, &metadata) != nil || metadata["crm_deal"] != "metadata-fixture-deal" || bytes.Equal(changed.Metadata, current.Metadata) {
		t.Fatal("true metadata intent was suppressed")
	}
	var caches int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM html_creation_response_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org).Scan(&caches); err != nil || caches != 0 {
		t.Fatal("true metadata write retained stale response measurement", err)
	} //nolint:rawsql -- exact expected invalidation, never repair
	ownedDetailsResponseReadV1(t, q, changed, false)
	ownedDetailsConsumedV1(t, q)
}
