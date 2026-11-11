// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const legacyExpiryEventMaximumV1 = 64

type legacyExpiryEventHeaderV1 struct {
	id                                       uuid.UUID
	display, original, ua, previous, rowHash int64
	uncompressed, updated, closedDisplay     bool
	server                                   int32
}

func (h legacyExpiryEventHeaderV1) boundedV1() bool {
	return h.id != uuid.Nil && h.updated && h.uncompressed && h.closedDisplay && h.display > 0 && h.display <= 4096 && h.original > 0 && h.original <= 4096 && h.ua >= 0 && h.ua <= 4096 && (h.previous == 0 || h.previous == 32) && h.rowHash == 32 && h.server > 0
}

// This is the sole historical exception, not a general audit-cache backfill.
// The original response already holds its root UPDATE and organization chain
// locks. Scalar headers never expand JSONB; compressed values refuse rather
// than treating a compressed size as an allocation bound. Stale/mis-scoped
// existing caches are deliberately left for the unchanged report guard.
func (w *ApplicationHTMLSendWorkV1) measureLegacyExpiryEventsLockedV1(call context.Context, cutoff pgtype.Timestamptz) error {
	if !w.valid(call) || !w.responseReportAttempted || !w.responseReportFamilyPrepared || w.familyRoot != nil || w.sourceDocument == nil || w.sourceDocument.ParentEnvelopeID.Valid || !applicationStampV1(cutoff) {
		return ErrHTMLSendWorkV1
	}
	closeHeader, err := w.actor.acquireOwnedRetainedBodyV1(call, 65536, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeHeader)
	db := &applicationOwnedDBTXV1{session: w.session.state}
	rows, err := db.Query(call, `SELECT e.id,pg_column_size(e.payload_json)::bigint,
 octet_length(e.payload_hashed)::bigint,COALESCE(octet_length(e.ua),0)::bigint,
 COALESCE(octet_length(e.prev_hash),0)::bigint,octet_length(e.row_hash)::bigint,
 pg_column_compression(e.payload_json) IS NULL,e.kind='document.updated',
 CASE WHEN pg_column_compression(e.payload_json) IS NULL AND pg_column_size(e.payload_json) BETWEEN 1 AND 4096
 THEN CASE WHEN jsonb_typeof(e.payload_json)='object' THEN COALESCE(
 (e.payload_json-ARRAY['via','tool','expires_at']::text[])='{}'::jsonb
 AND e.payload_json->'via'='"mcp"'::jsonb AND e.payload_json->'tool'='"set_expiry"'::jsonb
 AND jsonb_typeof(e.payload_json->'expires_at')='string',false) ELSE false END
 ELSE false END,current_setting('server_version_num')::integer
 FROM events e WHERE e.document_id=$1 AND e.org_id=$2 AND e.created_at<=$3
 AND NOT EXISTS(SELECT 1 FROM html_snapshot_event_payload_sizes_v1 c WHERE c.event_id=e.id)
 ORDER BY e.created_at,e.id LIMIT 65`, w.logicalDocumentV1(), w.session.state.org, cutoff) //nolint:rawsql -- funded scalar headers of this original locked root only
	if err != nil {
		return err
	}
	headers := make([]legacyExpiryEventHeaderV1, 0, legacyExpiryEventMaximumV1+1)
	for rows.Next() {
		var h legacyExpiryEventHeaderV1
		if err = rows.Scan(&h.id, &h.display, &h.original, &h.ua, &h.previous, &h.rowHash, &h.uncompressed, &h.updated, &h.closedDisplay, &h.server); err != nil {
			rows.Close()
			return err
		}
		headers = append(headers, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(headers) > legacyExpiryEventMaximumV1 {
		return render.ErrParticipantReportV1
	}
	for _, h := range headers {
		if !h.boundedV1() {
			return render.ErrParticipantReportV1
		}
		// Existing native pricing adds its actual fixed grant/reader overhead.
		// Tests bound the complete quote, not just these source byte arguments.
		closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, 65536, 32768)
		if err != nil {
			return err
		}
		w.closes = append(w.closes, closeBody)
		event, err := w.queries.GetEventByID(call, h.id)
		if err != nil {
			return err
		}
		if !legacyExpiryEventValidV1(event, h, w.session.state.org, w.logicalDocumentV1(), cutoff) {
			return render.ErrParticipantReportV1
		}
		cache, err := w.queries.MeasureHTMLSnapshotEventPayloadV1(call, generated.MeasureHTMLSnapshotEventPayloadV1Params{EventID: h.id, DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
		if err != nil {
			return err
		}
		if cache == nil || cache.EventID != h.id || cache.DocumentID != w.logicalDocumentV1() || cache.OrgID != w.session.state.org || cache.PayloadWireBytes != int64(len(event.PayloadJson)) || cache.MeasurementServerVersionNum != h.server || !applicationStampV1(cache.MeasuredAt) {
			return ErrHTMLSendWorkV1
		}
	}
	return nil
}

// The original Logger marshals exactly this three-string map. Canonical byte
// equality rejects duplicates, extra fields and alternative payload shapes;
// display JSON must still describe those same original facts. No historical
// timestamp is required to remain in the future at the time of this read.
func legacyExpiryEventValidV1(e *generated.Event, h legacyExpiryEventHeaderV1, org, document uuid.UUID, cutoff pgtype.Timestamptz) bool {
	if !h.boundedV1() || e == nil || e.ID != h.id || e.OrgID != org || org == uuid.Nil || document == uuid.Nil || !e.DocumentID.Valid || uuid.UUID(e.DocumentID.Bytes) != document || e.RecipientID.Valid || !e.ActorUserID.Valid || uuid.UUID(e.ActorUserID.Bytes) == uuid.Nil || e.Kind != "document.updated" || !applicationStampV1(e.CreatedAt) || !applicationStampV1(cutoff) || e.CreatedAt.Time.After(cutoff.Time) || len(e.PayloadJson) > 32768 || int64(len(e.PayloadHashed)) != h.original || int64(len(e.Ua.String)) != h.ua || int64(len(e.PrevHash)) != h.previous || len(e.RowHash) != 32 {
		return false
	}
	var original, display map[string]string
	if json.Unmarshal(e.PayloadHashed, &original) != nil || len(original) != 3 || original["via"] != "mcp" || original["tool"] != "set_expiry" {
		return false
	}
	expiry, present := original["expires_at"]
	if !present || len(expiry) > 40 {
		return false
	}
	if expiry != "" {
		if at, err := time.Parse(time.RFC3339, expiry); err != nil || at.IsZero() {
			return false
		}
	}
	canonical, err := json.Marshal(original)
	if err != nil || !bytes.Equal(canonical, e.PayloadHashed) || json.Unmarshal(e.PayloadJson, &display) != nil || len(display) != 3 {
		return false
	}
	for k, v := range original {
		if actual, exists := display[k]; !exists || actual != v {
			return false
		}
	}
	digest, err := audit.RecomputeEventRowHash(e)
	return err == nil && subtle.ConstantTimeCompare(digest, e.RowHash) == 1
}
