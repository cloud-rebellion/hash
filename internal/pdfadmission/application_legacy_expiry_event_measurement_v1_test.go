// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func legacyExpiryFixtureV1(t *testing.T) (*generated.Event, legacyExpiryEventHeaderV1) {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"via": "mcp", "tool": "set_expiry", "expires_at": "2026-10-19T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	e := &generated.Event{ID: uuid.New(), OrgID: uuid.New(), DocumentID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, ActorUserID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, Kind: "document.updated", CreatedAt: pgtype.Timestamptz{Time: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC), Valid: true}, PayloadHashed: payload, PayloadJson: bytes.Clone(payload)}
	e.RowHash, err = audit.RecomputeEventRowHash(e)
	if err != nil {
		t.Fatal(err)
	}
	return e, legacyExpiryEventHeaderV1{id: e.ID, display: int64(len(payload)), original: int64(len(payload)), rowHash: 32, uncompressed: true, updated: true, closedDisplay: true, server: 160015}
}

func TestLegacyExpiryMeasurementValidOriginalAndClosedFailuresV1(t *testing.T) {
	for _, name := range []string{"valid", "clear", "other_org", "other_document", "recipient", "no_actor", "future_event", "hash", "display", "unknown_key", "duplicate", "noncanonical", "other_tool", "invalid_time", "compressed", "numeric_display", "oversized_original", "oversized_display", "oversized_ua", "wrong_kind", "wrong_hash_width"} {
		t.Run(name, func(t *testing.T) {
			e, h := legacyExpiryFixtureV1(t)
			org, doc, cutoff := e.OrgID, uuid.UUID(e.DocumentID.Bytes), e.CreatedAt
			payload := map[string]string{}
			_ = json.Unmarshal(e.PayloadHashed, &payload)
			rehash := false
			switch name {
			case "clear":
				payload["expires_at"], rehash = "", true
			case "other_org":
				org = uuid.New()
			case "other_document":
				doc = uuid.New()
			case "recipient":
				e.RecipientID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			case "no_actor":
				e.ActorUserID = pgtype.UUID{}
			case "future_event":
				cutoff.Time = cutoff.Time.Add(-time.Microsecond)
			case "hash":
				e.RowHash = bytes.Repeat([]byte{7}, 32)
			case "display":
				e.PayloadJson = []byte(`{"via":"mcp","tool":"set_expiry","expires_at":""}`)
			case "unknown_key":
				payload["extra"], rehash = "unrelated", true
			case "duplicate":
				e.PayloadHashed = []byte(`{"expires_at":"","tool":"set_expiry","via":"mcp","via":"mcp"}`)
				e.PayloadJson = []byte(`{"expires_at":"","tool":"set_expiry","via":"mcp"}`)
				h.original = int64(len(e.PayloadHashed))
				e.RowHash, _ = audit.RecomputeEventRowHash(e)
			case "noncanonical":
				e.PayloadHashed = append([]byte(" "), e.PayloadHashed...)
				h.original = int64(len(e.PayloadHashed))
				e.RowHash, _ = audit.RecomputeEventRowHash(e)
			case "other_tool":
				payload["tool"], rehash = "attach_metadata", true
			case "invalid_time":
				payload["expires_at"], rehash = "invalid", true
			case "compressed":
				h.uncompressed = false
			case "numeric_display":
				h.closedDisplay = false
			case "oversized_original":
				h.original = 4097
			case "oversized_display":
				h.display = 4097
			case "oversized_ua":
				h.ua = 4097
			case "wrong_kind":
				h.updated = false
			case "wrong_hash_width":
				h.rowHash = 31
			}
			if rehash {
				e.PayloadHashed, _ = json.Marshal(payload)
				e.PayloadJson = bytes.Clone(e.PayloadHashed)
				h.original = int64(len(e.PayloadHashed))
				e.RowHash, _ = audit.RecomputeEventRowHash(e)
			}
			if got := legacyExpiryEventValidV1(e, h, org, doc, cutoff); got != (name == "valid" || name == "clear") {
				t.Fatalf("valid=%v", got)
			}
		})
	}
}

func TestLegacyExpiryMeasurementUsesBoundedExistingPricingV1(t *testing.T) {
	r, err := htmlAuthoringRetainedBodyResourcesV1(65536, 32768)
	if err != nil || r.WorkingBytes > 2<<20 || r.DBStagingBytes > 1<<20 || r.WorkingBytes < 32768+65536 || r.DBStagingBytes < 32768 {
		t.Fatalf("actual native quote exceeds fixed bound: %+v %v", r, err)
	}
	if legacyExpiryEventMaximumV1 != 64 {
		t.Fatal("historical recovery maximum changed")
	}
	for _, work := range []*ApplicationHTMLSendWorkV1{nil, {}, {self: &ApplicationHTMLSendWorkV1{}}} {
		if err := work.measureLegacyExpiryEventsLockedV1(context.Background(), pgtype.Timestamptz{}); err == nil {
			t.Fatal("unissued response acquired historical measurement authority")
		}
	}
	t.Logf("actual per-row native quote: parent=%d db=%d", r.WorkingBytes, r.DBStagingBytes)
}

func TestOwnedExpiryAuditPurposeOnlyAdmitsItsExistingFieldsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	payload := map[string]any{"via": "mcp", "tool": "set_expiry", "expires_at": ""}
	if HTMLAuditDocumentExpiryUpdatedV1.KindV1() != "document.updated" {
		t.Fatal("expiry event kind changed")
	}
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditDocumentExpiryUpdatedV1, payload); err != nil {
		t.Fatal(err)
	}
	payload["unrelated"] = "not expiry"
	if _, err := htmlAuditPayloadShapeV1(ctx, HTMLAuditDocumentExpiryUpdatedV1, payload); err == nil {
		t.Fatal("expiry purpose admitted unrelated event fields")
	}
}
