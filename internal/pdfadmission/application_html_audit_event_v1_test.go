// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type htmlAuditCustomMarshalerV1 struct{ calls *atomic.Int64 }

func (x htmlAuditCustomMarshalerV1) MarshalJSON() ([]byte, error) {
	x.calls.Add(1)
	return []byte("{}"), nil
}

func TestHTMLAuditConcretePayloadBoundAndDetachedValuesV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	notice := article13.Snapshot{Schema: article13.SchemaV1, DocumentID: uuid.New(), OrgID: uuid.New(), RecipientID: uuid.New(), Controller: strings.Repeat("\x01é<&", 1000), Copy: article13.Copy{RightsBody: strings.Repeat("\u2028\n\t", 1000)}}
	observations := []map[string]any{{"variable": "company", "connection_id": uuid.New(), "observed_at": time.Now().UTC().Truncate(time.Microsecond), "source_path": strings.Repeat("é<&\n", 1024)}}
	party := []htmlsource.PartyBinding{{Slot: "signer", RecipientID: uuid.New()}}
	cases := []struct {
		purpose HTMLAuditPurposeV1
		payload map[string]any
	}{
		{HTMLAuditChangesRequestedV1, map[string]any{"message": strings.Repeat("\x01é<&", 4096), "notice_snapshot": notice, "notice_schema": article13.SchemaV1, "notice_digest": strings.Repeat("a", 64)}},
		{HTMLAuditCRMObservedV1, map[string]any{"observations": observations, "assurance": "time-of-read"}},
		{HTMLAuditDocumentCreatedV1, map[string]any{"template_id": uuid.New(), "template_version": int32(17), "contract_party_bindings": party, "changed_sections": []string{"terms", "price"}, "creation_request_id": uuid.Nil}},
		{HTMLAuditCeremonyRetiredV1, nil},
	}
	for _, tc := range cases {
		shape, err := htmlAuditPayloadShapeV1(ctx, tc.purpose, tc.payload)
		if err != nil {
			t.Fatal(err)
		}
		original := tc.payload
		if original == nil {
			original = map[string]any{}
		}
		before, err := json.Marshal(original)
		if err != nil {
			t.Fatal(err)
		}
		actual, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, before)
		if err != nil || shape.wire < actual || shape.wire < int64(len(before)) {
			t.Fatalf("pre-Marshal bound omits real escaped/nested producer output: got=%+v actual=%d err=%v", shape, actual, err)
		}
		detached, err := htmlAuditCloneValueV1(ctx, original, 0)
		if err != nil || !reflect.DeepEqual(detached, original) {
			t.Fatal("detached payload changed original concrete UUID/time/notice/binding values", err)
		}
		for key := range original {
			delete(original, key)
		}
		observations[0]["source_path"] = observations[0]["source_path"].(string) + ":changed"
		party[0].Slot += ":changed"
		after, err := json.Marshal(detached)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("original mutable payload/collection reuse changed retained hook/hash values", err)
		}
	}
}

func TestHTMLAuditPreflightRejectsUnboundedProducersWithoutMarshalV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var called atomic.Int64
	cycle := map[string]any{}
	cycle["cycle"] = cycle
	for _, v := range []any{json.RawMessage("{\"number\":1e100000}"), []byte("opaque"), htmlAuditCustomMarshalerV1{&called}, math.Inf(1), cycle} {
		if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditCRMObservedV1, map[string]any{"observations": v}); err == nil {
			t.Fatal("unbounded/custom/raw/cyclic producer accepted before admission")
		}
	}
	if called.Load() != 0 {
		t.Fatal("custom marshaler dispatched before native admission")
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditCeremonyRetiredV1, map[string]any{"invented": true}); err == nil {
		t.Fatal("fixed existing event purpose widened")
	}
	stopped, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := htmlAuditPayloadShapeV1(stopped, HTMLAuditCeremonyRetiredV1, nil); err == nil {
		t.Fatal("cancelled preflight accepted")
	}
	for _, v := range [][3]int64{{-1, 2, 1}, {1, -1, 1}, {1, 2, -1}, {math.MaxInt64, 2, 1}, {1, math.MaxInt64, 1}, {1, 2, math.MaxInt64}} {
		if _, err := htmlAuditResourcesV1(v[0], v[1], v[2]); err == nil {
			t.Fatal("wrapping or invalid resource tuple accepted", v)
		}
	}
}

func TestHTMLAuditNativeOwnerScopeAndOriginalConsumerConjunctionV1(t *testing.T) {
	// Explicit native BOOKKEEPING fixture only: fixed synthetic tx/backend
	// observer states do not establish PG protocol or physical retirement. Real
	// creator+blocked-hook acceptance supplies that separate evidence.
	f, session, coordinator := applicationRequestLoanFixtureV1(t)
	factory := session.state.factory
	factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	payload := map[string]any{"html_pdf_reviewed": true, "pdf_sha256": strings.Repeat("a", 64), "html_source_commitment": strings.Repeat("b", 64)}
	if owner, err := session.NewHTMLAuditEventV1(ctx, HTMLAuditHTMLReviewV1, f.scope.OrgID, f.scope.DocumentID, pgtype.UUID{}, pgtype.UUID{}, "document.updated", "", "", payload); owner != nil || err == nil {
		t.Fatal("owner minted outside actual tracked callback")
	}
	var owner *ApplicationHTMLAuditEventConsumerV1
	t.Cleanup(func() {
		if owner != nil {
			owner.CloseConsumerV1()
		}
		if !applicationDoneV1(f.done) {
			close(f.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = f.adapter.CloseV1(cleanup)
	})
	err := session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		owner, err = session.NewHTMLAuditEventV1(call, HTMLAuditHTMLReviewV1, f.scope.OrgID, f.scope.DocumentID, pgtype.UUID{}, pgtype.UUID{}, "document.updated", "", "", payload)
		return err
	})
	if err != nil || owner == nil {
		t.Fatal("actual fixed callback/bookkeeping owner failed", err)
	}
	payload["pdf_sha256"] = "reused caller map"
	if bytes.Contains(owner.raw, []byte("reused caller map")) || owner.payload["pdf_sha256"] == "reused caller map" {
		t.Fatal("actual constructor retained mutable original payload map")
	}
	before := coordinator.SnapshotV1(f.scope.OrgID)
	want, resourceErr := htmlAuditResourcesV1(owner.shape.raw, owner.shape.wire, owner.shape.nodes)
	if resourceErr != nil || want.WorkingBytes <= 0 || want.DBStagingBytes <= 0 || owner.resources != want || before.Global.ParentBytes != want.WorkingBytes || before.Global.DBStagingBytes != want.DBStagingBytes || before.GlobalGrants != 1 {
		t.Fatal("native same-coordinator event loan missing", before)
	}
	copied := &ApplicationHTMLAuditEventConsumerV1{self: owner, session: owner.session, queries: owner.queries, org: owner.org, document: owner.document, purpose: owner.purpose, closeConsumer: owner.closeConsumer, payload: owner.payload, raw: owner.raw}
	copied.CloseConsumerV1()
	if _, _, err := copied.BeginPublicationV1(uuid.New()); err == nil {
		t.Fatal("copied owner created dispatch permission")
	}
	if coordinator.SnapshotV1(f.scope.OrgID) != before || f.adapter.PendingV1().Loans != 1 {
		t.Fatal("copy shell changed original debt")
	}
	owner.CloseConsumerV1()
	if coordinator.SnapshotV1(f.scope.OrgID) != before {
		t.Fatal("consumer close credited live physical owner")
	}
	// This fixture advances ONLY its explicit synthetic observer witness; it
	// proves cleanup conjunction bookkeeping, never actual backend absence.
	close(f.done)
	if err := f.adapter.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
	if coordinator.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
		t.Fatal("retired synthetic fixture did not release original loan")
	}
	var zero ApplicationHTMLAuditEventConsumerV1
	zero.CloseConsumerV1()
	if _, _, err := zero.BeginPublicationV1(uuid.New()); err == nil {
		t.Fatal("zero owner fabricated acknowledgement")
	}
}

func TestHTMLAuditHeadPreservesFiniteOrderedPredecessorV1(t *testing.T) {
	valid := generated.GetOwnedHTMLAuditChainHeadV1Row{RowHash: bytes.Repeat([]byte{7}, 32), CreatedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 14, 0, 0, 0, 1, time.UTC), Valid: true}, IsValidHash: true}
	if !htmlAuditHeadValidV1(&valid) {
		t.Fatal("finite original predecessor refused")
	}
	if htmlAuditHeadValidV1(nil) {
		t.Fatal("missing head became a valid predecessor")
	}
	for _, stamp := range []pgtype.Timestamptz{{}, {Valid: true}, {Time: valid.CreatedAt.Time, Valid: true, InfinityModifier: pgtype.Infinity}, {Time: valid.CreatedAt.Time, Valid: true, InfinityModifier: pgtype.NegativeInfinity}, {Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}, {Time: time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), Valid: true}} {
		bad := valid
		bad.CreatedAt = stamp
		if htmlAuditHeadValidV1(&bad) {
			t.Fatal("non-finite/zero/out-of-range audit head accepted")
		}
	}
	for _, n := range []int{0, 31, 33} {
		bad := valid
		bad.RowHash = make([]byte, n)
		if htmlAuditHeadValidV1(&bad) {
			t.Fatal("unbounded/missing hash became predecessor")
		}
	}
	bad := valid
	bad.IsValidHash = false
	if htmlAuditHeadValidV1(&bad) {
		t.Fatal("fixed SQL invalid hash flag ignored")
	}
}
