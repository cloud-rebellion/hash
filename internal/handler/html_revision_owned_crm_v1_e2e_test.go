//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// Read ONLY actual committed producer receipts. Missing/stale rows are test
// failures, never grounds to insert/backfill caches or substitute source data.
func assertCRMNativeRevisionMeasurements621(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document) []byte {
	t.Helper()
	h, err := f.q.GetHTMLRevisionDocumentReadHeaderV1(f.ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || h == nil || h.ServerVersionNum <= 0 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
		t.Fatal("CRM producer omitted current native document measurements", err)
	}
	m, err := f.q.GetSignerCurrentMaterializationHeaderV1(f.ctx, generated.GetSignerCurrentMaterializationHeaderV1Params{DocumentID: doc.ID, OrgID: f.org})
	if err != nil || m == nil || m.MeasurementServerVersionNum != h.ServerVersionNum || !doc.HtmlCurrentMaterializationID.Valid || m.MaterializationID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || m.SourceWireBytes != int64(len(doc.HtmlCurrentSourceJson)) {
		t.Fatal("CRM producer omitted exact current materialization measurements", err)
	}
	var events, measured int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id IS NOT NULL AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2`, doc.ID, f.org).Scan(&events, &measured); err != nil || events == 0 || measured != events {
		t.Fatal("CRM producer omitted genuine source event measurements", err, events, measured)
	} //nolint:rawsql -- read-only exact producer oracle
	state, err := json.Marshal([]any{h, m, events, measured})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// This actual REST/PG/intake journey fails the SECOND final audit, proving the
// first CRM event/review and the new native source/fields/measurements roll back
// in the same transaction. Synthetic renderer/S3 remains no live-provider proof.
func TestCRMApplyNativeRevisionAuditFailureRollsBackAndRetryRemainsEditableE2E(t *testing.T) {
	f, _, peer, original, cookie := setupHTMLOptionalEmptyE2E(t, false)
	f.doc = original
	request, observation := optionalEmptyCRMObservationE2E(t, f, cookie)
	before, beforeCRM := revisionStateE2E(t, f), crmDocumentStateE2E(t, f)
	beforeMeasurements := assertCRMNativeRevisionMeasurements621(t, f, original)
	var published atomic.Int32
	f.s.Audit.Subscribe(func(_ context.Context, _ uuid.UUID, entry audit.Entry) {
		if entry.DocumentID != nil && *entry.DocumentID == original.ID {
			published.Add(1)
		}
	})
	name := "hash_crm_revision621_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid AND NEW.kind='document.updated' THEN RAISE EXCEPTION 'synthetic CRM revision audit refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, name, original.ID, name, name)); err != nil {
		t.Fatal(err)
	} //nolint:rawsql,gosec -- generated UUID fixture-only function/trigger
	drop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON events; DROP FUNCTION IF EXISTS %s()", name, name)); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(drop)
	w := crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(request, observation.ReviewDigest))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "synthetic CRM revision audit refusal") {
		t.Fatalf("native CRM audit failure status/privacy=%d", w.Code)
	}
	if !bytes.Equal(before, revisionStateE2E(t, f)) || beforeCRM != crmDocumentStateE2E(t, f) || !bytes.Equal(beforeMeasurements, assertCRMNativeRevisionMeasurements621(t, f, original)) || published.Load() != 0 {
		t.Fatal("failed second audit committed source/review/mapping/measurement/history or published either event")
	}
	assertImportStorageE2E(t, peer.importStoragePeer, 2, 1, 1)
	drop()
	w = crmDocumentRequestE2E(t, f, f.ctx, http.MethodPost, "apply", cookie, crmDocumentApplyInputE2E(request, observation.ReviewDigest))
	if w.Code != http.StatusOK {
		t.Fatalf("native CRM retry=%d", w.Code)
	}
	current := reloadHTMLOptionalEmptyE2E(t, f, original.ID)
	if current.HtmlCurrentMaterializationSequence.Int32 != 2 || published.Load() != 2 {
		t.Fatal("native CRM retry omitted its exact source and two acknowledged event publications")
	}
	assertCRMNativeRevisionMeasurements621(t, f, current)
	commitment, err := htmlsource.Commitment(current)
	if err != nil {
		t.Fatal(err)
	}
	input := htmlDocumentRevisionInput{ExpectedUpdatedAt: current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{htmlOptionalEmptyVariableE2E: "Next actual declared value"}, Summary: "Native edit after actual CRM Apply"}
	w = submitRevisionE2E(t, f, input, cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("fresh CRM source could not enter the next native revision=%d", w.Code)
	}
	latest := reloadHTMLOptionalEmptyE2E(t, f, original.ID)
	if latest.HtmlCurrentMaterializationSequence.Int32 != 3 {
		t.Fatal("next native revision did not append the exact next source")
	}
	assertCRMNativeRevisionMeasurements621(t, f, latest)
	assertImportStorageE2E(t, peer.importStoragePeer, 4, 1, 3)
}
