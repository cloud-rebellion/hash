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
	"github.com/google/uuid"
)

func crmBlocksProducerState622(t *testing.T, f lifecycleAuthorizationFixture) []byte {
	t.Helper()
	h, err := f.q.GetHTMLRevisionDocumentReadHeaderV1(f.ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || h == nil || h.ServerVersionNum <= 0 || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum || h.HtmlOriginWireBytes != 0 || h.HtmlCurrentWireBytes != 0 {
		t.Fatal("blocks Apply left missing/stale native source receipts", err)
	}
	var events, measured int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer,count(*) FILTER(WHERE m.event_id IS NOT NULL AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer)::integer FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=$1 AND e.org_id=$2`, f.doc.ID, f.org).Scan(&events, &measured); err != nil || events == 0 || events != measured {
		t.Fatal("blocks Apply omitted actual source event measurements", err, events, measured)
	} //nolint:rawsql -- read-only exact producer oracle
	raw, err := json.Marshal([]any{h, events, measured})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCRMBlocksApplyReviewAndSecondAuditFailureRollBackThenEditAndSendE2E(t *testing.T) {
	for _, fault := range []string{"mapping-review", "second-audit"} {
		t.Run(fault, func(t *testing.T) {
			f := setupCRMSourceAuthorizationE2E(t)
			f.source.setDeal(t, "Actual native reviewed blocks retry")
			c := crmDocumentReadContextE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
			request := CRMMappingRequest{CRMDocumentWitnessE2E(c), crmDocumentDefaultMappingsE2E()}
			observation := crmDocumentObserveE2E(t, f.lifecycleAuthorizationFixture, f.cookie, request)
			if !observation.ContentChanged {
				t.Fatal("fixture lacks an actual provider value change")
			}
			before := crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture)
			measurements := crmBlocksProducerState622(t, f.lifecycleAuthorizationFixture)
			var published atomic.Int32
			f.s.Audit.Subscribe(func(_ context.Context, _ uuid.UUID, e audit.Entry) {
				if e.DocumentID != nil && *e.DocumentID == f.doc.ID {
					published.Add(1)
				}
			})
			name := "hash_crm_blocks622_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			table, when, condition := "events", "INSERT", "NEW.kind='document.updated'"
			if fault == "mapping-review" {
				table, when, condition = "document_crm_mapping_reviews", "INSERT OR UPDATE", "true"
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid AND (%s) THEN RAISE EXCEPTION 'synthetic native blocks CRM refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.doc.ID, condition, name, when, table, name)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql,gosec -- generated owned synthetic trigger
			drop := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := f.pool.Exec(ctx, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()", name, table, name)); err != nil {
					t.Error(err)
				}
			}
			t.Cleanup(drop)
			w := crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", f.cookie, crmDocumentApplyInputE2E(request, observation.ReviewDigest))
			if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "synthetic native blocks CRM refusal") {
				t.Fatalf("native blocks refusal=%d", w.Code)
			}
			if before != crmDocumentStateE2E(t, f.lifecycleAuthorizationFixture) || !bytes.Equal(measurements, crmBlocksProducerState622(t, f.lifecycleAuthorizationFixture)) || published.Load() != 0 {
				t.Fatal("failed review/second event changed source, snapshots, receipts, mapping/review or published either event")
			}
			drop()
			w = crmDocumentRequestE2E(t, f.lifecycleAuthorizationFixture, f.ctx, http.MethodPost, "apply", f.cookie, crmDocumentApplyInputE2E(request, observation.ReviewDigest))
			if w.Code != http.StatusOK || published.Load() != 2 {
				t.Fatalf("native blocks retry=%d publications=%d", w.Code, published.Load())
			}
			crmBlocksProducerState622(t, f.lifecycleAuthorizationFixture)
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(current.BlocksJson, f.doc.BlocksJson) {
				t.Fatal("CRM value update rewrote original manual tree bytes")
			}
			var values map[string]string
			if json.Unmarshal(current.VariablesJson, &values) != nil || values["customer"] != "Actual native reviewed blocks retry" {
				t.Fatal("native retry did not retain exact protected scalar")
			}
			values["manual"] = "Native edit after CRM Apply"
			encoded, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			f.doc, err = nativeRevisionEditE2E(t, f.lifecycleAuthorizationFixture, current, current.BlocksJson, encoded)
			if err != nil {
				t.Fatal(err)
			}
			// The next real edit invalidates CRM content review; a genuine mapping-only
			// Apply reaffirms the reviewed source without rewriting its tree/values.
			applyCRMSourceFixtureReviewE2E(t, f.lifecycleAuthorizationFixture, f.cookie)
			crmBlocksProducerState622(t, f.lifecycleAuthorizationFixture)
			if w = f.lifecycleAuthorizationFixture.submit("send", f.cookie); w.Code != http.StatusOK {
				t.Fatalf("CRM Apply -> real edit -> mapping-only -> native Send=%d", w.Code)
			}
		})
	}
}
