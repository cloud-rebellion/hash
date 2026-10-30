// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/google/uuid"
)

func crmRevisionInputFixtureV1(t *testing.T, org, actor uuid.UUID, mappings int) (string, *crmconnection.Snapshot) {
	t.Helper()
	connection := uuid.New()
	items := make([]map[string]string, mappings)
	for i := range items {
		items[i] = map[string]string{"variable": fmt.Sprintf("field_%d", i), "source_kind": "crm.deal", "source_ref": "deal1", "source_path": "currency"}
	}
	body, err := json.Marshal(map[string]any{"expected_org_id": org, "expected_user_id": actor, "expected_updated_at": "2026-10-30T12:00:00Z", "expected_html_source_commitment": strings.Repeat("a", 64), "expected_binding_fingerprint": strings.Repeat("b", 64), "expected_connection_id": connection.String(), "expected_connection_generation": "2", "mappings": items, "reviewed_digest": strings.Repeat("c", 64), "confirmed": true})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := &crmconnection.Snapshot{Identity: crmconnection.Identity{ID: connection, OrgID: org, Generation: 2, Origin: "https://crm.example.test", CRMTeamID: "team1", CRMUserID: "user1"}, Records: []crmconnection.RecordObservation{{Kind: crmconnection.Deal, ID: "deal1", Fields: map[string]crmconnection.Scalar{"currency": {Present: true, Value: strings.Repeat("x", crmconnection.MaxScalarBytes)}}}}}
	return string(body), snapshot
}

func TestHTMLCRMRevisionCapturesActualBodyAndProtectedScalarsUntilRetirementV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, coordinator := htmlInputFactoryTestV1(t, 32<<20)
	org, actor, document := uuid.New(), uuid.New(), uuid.New()
	raw, snapshot := crmRevisionInputFixtureV1(t, org, actor, 64)
	input, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCRMDocumentApplyInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	before := coordinator.SnapshotV1(org)
	op, err := f.NewHTMLCRMRevisionOperationV1(ctx, org, document, actor, input, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if op.state.declaration.ExpectedUpdatedAt != "2026-10-30T12:00:00Z" || len(op.state.declaration.Values) != 64 || op.state.declaration.Sections != nil || op.state.declaration.Summary != "Reviewed CRM information applied" {
		t.Fatal("native declaration was not derived from the actual Apply body")
	}
	if delta := coordinator.SnapshotV1(org).Global.ParentBytes - before.Global.ParentBytes; delta < 64*crmconnection.MaxScalarBytes {
		t.Fatalf("repeated selection copies were priced only once: %d", delta)
	}
	snapshot.Records[0].Fields["currency"] = crmconnection.Scalar{Present: true, Value: "changed after native capture"}
	if op.state.declaration.Values["field_0"] != strings.Repeat("x", crmconnection.MaxScalarBytes) {
		t.Fatal("mutable caller snapshot replaced captured declared text")
	}
	input.CloseConsumerV1()
	if f.PendingV1().HTMLInputProducers != 1 {
		t.Fatal("body consumer close retired a still-live native declaration")
	}
	op.CloseConsumerV1()
	if f.PendingV1().HTMLInputProducers != 0 || coordinator.SnapshotV1(org).Global.ParentBytes != 0 {
		t.Fatal("settled native declaration retained original body/value loans")
	}
	if err = f.CloseV1(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestHTMLCRMRevisionRejectsForeignClosedOrWrongInputWithoutNewDebtV1(t *testing.T) {
	for _, mode := range []string{"foreign-org", "foreign-actor", "foreign-connection", "closed-input", "revision-profile", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			f, coordinator := htmlInputFactoryTestV1(t, 32<<20)
			org, actor := uuid.New(), uuid.New()
			raw, snapshot := crmRevisionInputFixtureV1(t, org, actor, 1)
			profile := HTMLCRMDocumentApplyInputV1
			if mode == "revision-profile" {
				profile, raw = HTMLDocumentRevisionInputV1, `{}`
			}
			input, err := f.NewHTMLAuthoringInputV1(ctx, org, profile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(raw))); err != nil {
				t.Fatal(err)
			}
			if mode == "foreign-org" {
				org = uuid.New()
			}
			if mode == "foreign-actor" {
				actor = uuid.New()
			}
			if mode == "foreign-connection" {
				snapshot.Identity.ID = uuid.New()
			}
			if mode == "closed-input" {
				input.CloseConsumerV1()
			}
			if mode == "cancelled" {
				cancel()
			}
			before := coordinator.SnapshotV1(org)
			op, err := f.NewHTMLCRMRevisionOperationV1(ctx, org, uuid.New(), actor, input, snapshot)
			if err == nil || op != nil {
				t.Fatal("invalid source became a native revision")
			}
			if coordinator.SnapshotV1(org) != before {
				t.Fatal("refused declaration leaked a new native loan")
			}
			input.CloseConsumerV1()
		})
	}
}

func TestHTMLCRMRevisionOriginal128KiBCeilingAndNoValuesSubstituteV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, _ := htmlInputFactoryTestV1(t, 32<<20)
	input, err := f.NewHTMLAuthoringInputV1(ctx, uuid.New(), HTMLCRMDocumentApplyInputV1)
	if err != nil {
		t.Fatal(err)
	}
	defer input.CloseConsumerV1()
	_, err = input.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(strings.Repeat(" ", (128<<10)+1))))
	var max *http.MaxBytesError
	if !errors.As(err, &max) || max.Limit != 128<<10 {
		t.Fatalf("original Apply ceiling changed: %v", err)
	}
	if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLCRMDocumentApplyInputV1, []byte(`{"values":{"field":"invented"}}`)); err == nil {
		t.Fatal("arbitrary values replaced protected CRM scalar selection")
	}
}
