// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// PublicationV1 is durable state, not current grant eligibility. Published
// evidence remains readable after grant expiry/revocation. Callers still hold
// their actual staff/signing-token authorization and document observation.
type PublicationV1 struct {
	State                string
	CustomerRecipientID  uuid.UUID
	RetainUntil          time.Time
	RetentionStartedAt   time.Time
	RetentionCompletedAt time.Time
	PublishedAt          time.Time
}

type RetainedAssetsV1 struct {
	record      Record
	assets      AssetSetV1
	publication PublicationV1
}

func (r RetainedAssetsV1) Execution() presign.Execution { return r.record.execution }
func (r RetainedAssetsV1) Command() Command             { return r.record.command }
func (r RetainedAssetsV1) AuditEventID() uuid.UUID      { return r.record.auditEventID }
func (r RetainedAssetsV1) Policy() presign.Policy       { return r.record.policy }
func (r RetainedAssetsV1) Grant() presign.Grant         { return r.record.grant }
func (r RetainedAssetsV1) Assets() AssetSetV1           { return r.assets }
func (r RetainedAssetsV1) Publication() PublicationV1   { return r.publication }

// LoadRetainedAssetsV1 is a fixed repository read within the caller's real
// owned transaction. It does not admit a grant, authorize a signer, acquire an
// I/O budget, read storage, or allow a fallback to the original source PDF.
// ErrNoRows is the sole absent-execution result; malformed explicit evidence
// returns an integrity error and must never enter the historical manual path.
func LoadRetainedAssetsV1(ctx context.Context, tx pgx.Tx, org, document uuid.UUID) (RetainedAssetsV1, error) {
	var out RetainedAssetsV1
	if tx == nil || ctx == nil || ctx.Err() != nil || org == uuid.Nil || document == uuid.Nil {
		return out, ErrInvalid
	}
	q := generated.New(tx)
	row, err := q.GetPresignExecutionByDocument(ctx, generated.GetPresignExecutionByDocumentParams{OrgID: org, DocumentID: document})
	if err != nil {
		return out, err
	}
	k := RequestKey{OrgID: org, Executor: presign.ExecutorIdentity{Kind: row.ExecutorKind, UserID: row.ExecutorUserID, CredentialID: row.ExecutorCredentialID}, RequestID: row.RequestID}
	o, err := LoadOutcome(ctx, tx, k)
	if err != nil || o.State != "committed" || o.Record == nil || o.Record.execution.Snapshot().ID != row.ID {
		return out, ErrIntegrity
	}
	var raw, hash []byte
	var preparation uuid.UUID
	var p PublicationV1
	var started, completed, published pgtype.Timestamptz
	var event pgtype.UUID
	err = tx.QueryRow(ctx, `SELECT a.canonical_assets,a.assets_sha256,a.preparation_id,
	 p.state,p.customer_recipient_id,p.retain_until,p.retention_started_at,p.retention_completed_at,p.published_at,p.publication_event_id
	 FROM presign_execution_assets_v1 a JOIN presign_execution_publications_v1 p
	 ON p.org_id=a.org_id AND p.execution_id=a.execution_id AND p.document_id=a.document_id
	 JOIN presign_preparations_v1 r ON r.org_id=a.org_id AND r.id=a.preparation_id AND r.document_id=a.document_id
	 WHERE a.org_id=$1 AND a.execution_id=$2 AND a.document_id=$3 AND r.state='committed' AND r.execution_id=a.execution_id`, org, row.ID, document).
		Scan(&raw, &hash, &preparation, &p.State, &p.CustomerRecipientID, &p.RetainUntil, &started, &completed, &published, &event)
	if err != nil {
		return out, ErrIntegrity
	}
	a, err := DecodeAssetSetV1(o.Record.execution, raw)
	if err != nil || len(hash) != 32 || a.Commitment() != hex.EncodeToString(hash) {
		return out, ErrIntegrity
	}
	i, err := q.GetSendSealingIntent(ctx, generated.GetSendSealingIntentParams{DocumentID: document, OrgID: org})
	if err != nil || !i.PresignExecutionID.Valid || uuid.UUID(i.PresignExecutionID.Bytes) != row.ID || !i.RetainUntil.Valid ||
		!p.RetainUntil.Equal(i.RetainUntil.Time) || started != i.RetentionStartedAt || completed != i.RetentionCompletedAt ||
		p.CustomerRecipientID != o.Record.execution.Snapshot().Document.Parties[0].ID {
		return out, ErrIntegrity
	}
	if started.Valid {
		p.RetentionStartedAt = started.Time.UTC()
	}
	if completed.Valid {
		p.RetentionCompletedAt = completed.Time.UTC()
	}
	if published.Valid {
		p.PublishedAt = published.Time.UTC()
	}
	if (p.State != "retaining" && p.State != "published" && p.State != "expired") ||
		(p.State == "published") != (published.Valid && event.Valid) || (published.Valid != event.Valid) ||
		(p.State != "retaining" && !completed.Valid) || (completed.Valid && (!started.Valid || completed.Time.Before(started.Time))) {
		return out, ErrIntegrity
	}
	// All eight exact objects must remain the resolved original reservation.
	// This is bounded descriptor SQL; actual bytes are verified by each owned
	// storage consumer before use and all eight versions before publication.
	rows, err := tx.Query(ctx, `SELECT role,content_type,object_key,version_id,object_sha256,object_bytes
	 FROM presign_preparation_objects_v1 WHERE org_id=$1 AND preparation_id=$2
	 AND upload_attempted AND resolved_at IS NOT NULL AND version_id IS NOT NULL AND cleanup_started_at IS NULL AND deleted_at IS NULL
	 ORDER BY CASE role WHEN 'signature_span' THEN 0 WHEN 'signature_font' THEN 1 WHEN 'inter_font' THEN 2
	 WHEN 'overlay_recipe' THEN 3 WHEN 'signature_fragment' THEN 4 WHEN 'disclosure_fragment' THEN 5 WHEN 'overlay_proof' THEN 6 WHEN 'visible_pdf' THEN 7 ELSE 8 END`, org, preparation)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		if n >= len(a.snapshot.Objects) {
			return out, ErrIntegrity
		}
		var role, mime, key, version string
		var sha []byte
		var size int64
		if rows.Scan(&role, &mime, &key, &version, &sha, &size) != nil {
			return out, ErrIntegrity
		}
		want := a.snapshot.Objects[n]
		if role != want.Role || mime != want.ContentType || key != want.Object.StorageKey || version != want.Object.VersionID ||
			!bytes.Equal(sha, unhex(want.Object.SHA256)) || size != want.Object.Bytes {
			return out, ErrIntegrity
		}
		n++
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if n != 8 {
		return out, ErrIntegrity
	}
	return RetainedAssetsV1{record: *o.Record, assets: a, publication: p}, nil
}
