//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Installed on this one fixture's original pool before its runtime or document
// exists. The real driver dispatch fails; no query, row or session is replaced.
// Scope is set once, before enabling the atomic fault, and never changes after.
type ordinaryBrandingQueryFault250 struct {
	enabled       atomic.Bool
	refused       atomic.Int64
	document, org uuid.UUID
}

func (f *ordinaryBrandingQueryFault250) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !f.enabled.Load() || !strings.HasPrefix(data.SQL, "-- name: GetHistoricalFinalizationFrozenBrandingReadHeaderV1 :one\n") || len(data.Args) != 2 {
		return ctx
	}
	document, docOK := data.Args[0].(uuid.UUID)
	org, orgOK := data.Args[1].(uuid.UUID)
	if !docOK || !orgOK || document != f.document || org != f.org {
		return ctx
	}
	f.refused.Add(1)
	refused, cancel := context.WithCancel(ctx)
	cancel()
	return refused
}
func (*ordinaryBrandingQueryFault250) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {
}

// Genuine approved-HTML Send/Sign reaches the native frozen-branding SQL gate.
// Only that fixed query's dispatch is refused. Signatures must remain committed
// and finalizing, with no final rendering, ordinary capture or final-output PUT.
// Clearing the fault then uses the original runtime/pool and completes normally.
// External renderer/S3 protocol peers remain synthetic; no provider or layout
// acceptance is inferred from this refusal/recovery test.
func TestOrdinaryFinalizationFreshNativeBrandingRefusalV1E2E(t *testing.T) {
	fault := &ordinaryBrandingQueryFault250{}
	q := newOwnedPublicReadFixtureProfileV1(t, false, false, fault)
	f := q.f
	doc, parties := q.createSentV1(t)
	fault.document, fault.org = doc.ID, f.org

	peer := &ordinaryPreparationFaultPeer249{base: q.storagePeer, puts: map[string]int{}}
	objects := httptest.NewServer(peer)
	defer objects.Close()
	client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-branding-refusal", SecretKey: "synthetic-branding-refusal-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	f.s.Storage, f.s.Sign.Storage = client, client
	var renders atomic.Int64
	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renders.Add(1)
		q.renderer.ServeHTTP(w, r)
	}))
	defer renderer.Close()
	f.s.Sign.PDF = render.NewGotenberg(renderer.URL)
	fault.enabled.Store(true)
	for i, party := range parties {
		result, err := ordinaryPreparationSign249(t, q, party.Token, party.Name)
		if err != nil || result == nil || result.Completed {
			t.Fatalf("signature %d must commit while branding prevents completion: %+v %v", i, result, err)
		}
	}
	if fault.refused.Load() == 0 {
		t.Fatal("genuine native branding query was not reached and refused")
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.Status != "finalizing" {
		t.Fatal("native branding refusal did not leave genuine pending finalization", err)
	}
	signatures, err := f.q.ListSignaturesByDocument(f.ctx, doc.ID)
	if err != nil || len(signatures) != len(parties) {
		t.Fatal("actual signatures did not commit before finalization refusal", err)
	}
	recipients, err := f.q.ListRecipientsByDocument(f.ctx, doc.ID)
	if err != nil || len(recipients) != len(parties) {
		t.Fatal("actual signed recipients unavailable", err)
	}
	for _, party := range parties {
		signed, archived := false, false
		for _, rec := range recipients {
			signed = signed || (rec.ID == party.RecipientID && rec.Status == "signed")
		}
		for _, sig := range signatures {
			archived = archived || (sig.RecipientID == party.RecipientID && sig.TypedName == party.Name && sig.ImageVersionID.Valid)
		}
		if !signed || !archived {
			t.Fatal("genuine signature or committed recipient state missing", party.RecipientID)
		}
	}
	if renders.Load() != 0 {
		t.Fatal("final rendering occurred after refused fresh branding lookup")
	}
	for key := range peer.putCounts249() {
		if strings.Contains(key, "/final-") || strings.Contains(key, "/audit-") {
			t.Fatal("final-output provider PUT occurred after refused fresh branding lookup", key)
		}
	}
	var preparations, outputs, intents, reports int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1),(SELECT count(*) FROM document_ordinary_finalization_outputs_v1 WHERE document_id=$1),(SELECT count(*) FROM document_finalization_intents WHERE document_id=$1),(SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1)`, doc.ID).Scan(&preparations, &outputs, &intents, &reports); err != nil || preparations != 0 || outputs != 0 || intents != 0 || reports != 0 {
		t.Fatal("ordinary output capture/publication occurred after refused fresh branding lookup", preparations, outputs, intents, reports, err)
	} //nolint:rawsql -- exact absent effects on the actual pending root

	fault.enabled.Store(false)
	if err := f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
		t.Fatal("fresh native recovery after branding fault clear failed", err)
	}
	current, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.Status != "completed" || renders.Load() == 0 {
		t.Fatal("actual finalization did not recover after native branding lookup recovered", err)
	}
	var retired, verified int64
	var deliveries int64
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE payload IS NULL AND version_id IS NOT NULL AND verified_at IS NOT NULL) FROM document_ordinary_finalization_outputs_v1 WHERE document_id=$1`, doc.ID).Scan(&retired, &verified); err != nil || retired != 4 || verified != 4 {
		t.Fatal("recovered exact four verified outputs were not published/retired", retired, verified, err)
	} //nolint:rawsql -- actual successful recovery evidence
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1)`, doc.ID).Scan(&reports, &deliveries); err != nil || reports != 1 || deliveries != int64(len(parties)+1) {
		t.Fatal("recovered mandatory report/delivery effects absent", reports, deliveries, err)
	} //nolint:rawsql -- real report and exact delivery-reference witness
	ownedCreationAssertDrainedV1(t, q, 2)
}
