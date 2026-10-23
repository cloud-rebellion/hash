// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const IntentDomainV1 = "hash:presign-execution-intent:v1\x00"

// A surviving original producer is neither permission to start another one
// nor evidence that the reviewed intent changed. The caller may recover the
// original outcome or explicitly close the request, preserving all upload debt.
var ErrPreparationPendingV1 = errors.New("original pre-sign preparation requires recovery")

func CanonicalIntentV1(in IntentV1) ([]byte, string, error) {
	if in.RequestID == uuid.Nil || in.ExpectedOrgID == uuid.Nil || in.ExpectedUserID == uuid.Nil || in.DocumentID == uuid.Nil ||
		in.DocumentUpdatedAt.IsZero() || in.MaterializationID == uuid.Nil || in.MaterializationRevision < 1 || in.MaterializationRevision > 2147483647 || !validSHA(in.SourceCommitment) ||
		in.Policy.ID == uuid.Nil || in.Policy.Revision < 1 || in.Policy.Revision > presign.MaxRevision || !validSHA(in.Policy.SHA256) ||
		in.Grant.ID == uuid.Nil || in.Grant.Revision < 1 || in.Grant.Revision > presign.MaxRevision || !validSHA(in.Grant.SHA256) ||
		in.LawfulBasis != "contract" {
		return nil, "", ErrInvalid
	}
	in.DocumentUpdatedAt = in.DocumentUpdatedAt.UTC()
	raw, err := json.Marshal(in)
	if err != nil || len(raw) > 8192 {
		return nil, "", ErrInvalid
	}
	return raw, digest(IntentDomainV1, raw), nil
}

func reserveKeyV1(k RequestKey, in IntentV1, credential string) error {
	if validateKey(k) != nil || k.OrgID != in.ExpectedOrgID || k.Executor.UserID != in.ExpectedUserID || k.RequestID != in.RequestID || !validSHA(credential) {
		return ErrInvalid
	}
	return nil
}

// ReservePreparationV1 claims the original finite request before rendering.
// The caller has its actual actor/credential, parent and registry locks. A
// surviving reservation is never silently restarted; the original request is
// recovered/explicitly closed and uncertain uploads remain inventory debt.
func ReservePreparationV1(ctx context.Context, tx pgx.Tx, k RequestKey, in IntentV1, credential string, id uuid.UUID, deadline time.Time) error {
	if ctx == nil || ctx.Err() != nil || tx == nil || id == uuid.Nil || reserveKeyV1(k, in, credential) != nil {
		return ErrInvalid
	}
	raw, h, err := CanonicalIntentV1(in)
	if err != nil {
		return err
	}
	q := generated.New(tx)
	if err = q.LockPresignExecutionRequest(ctx, generated.LockPresignExecutionRequestParams{OrgID: k.OrgID, ExecutorKind: k.Executor.Kind, ExecutorUserID: k.Executor.UserID, ExecutorCredentialID: k.Executor.CredentialID, RequestID: k.RequestID}); err != nil {
		return err
	}
	if _, err = q.GetPresignExecutionRequest(ctx, requestParams(k)); err == nil {
		return ErrPreparationPendingV1
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO presign_preparations_v1(org_id,id,executor_kind,executor_user_id,executor_credential_id,request_id,document_id,
	 intent_canonical,intent_sha256,original_credential_sha256,expires_at)
	 SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11 WHERE $11>clock_timestamp() AND $11<=clock_timestamp()+interval '45 seconds'
	 ON CONFLICT DO NOTHING`, k.OrgID, id, k.Executor.Kind, k.Executor.UserID, k.Executor.CredentialID, k.RequestID, in.DocumentID, raw, unhex(h), unhex(credential), deadline.UTC())
	if err != nil {
		return writeError(err)
	}
	if tag.RowsAffected() != 1 {
		// Compare inside SQL after the original request lock. No canonical body
		// is scanned without a body loan, and a different command never becomes
		// a pending acknowledgement of this producer's original request.
		var same bool
		err = tx.QueryRow(ctx, `SELECT document_id=$6 AND intent_canonical=$7 AND intent_sha256=$8
		 AND original_credential_sha256=$9 AND state IN('preparing','committed')
		 FROM presign_preparations_v1 WHERE org_id=$1 AND executor_kind=$2 AND executor_user_id=$3
		 AND executor_credential_id=$4 AND request_id=$5`, k.OrgID, k.Executor.Kind, k.Executor.UserID, k.Executor.CredentialID, k.RequestID,
			in.DocumentID, raw, unhex(h), unhex(credential)).Scan(&same)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConflict
		}
		if err != nil {
			return err
		}
		if !same {
			return ErrConflict
		}
		return ErrPreparationPendingV1
	}
	return nil
}

// ReserveObjectsV1 persists every exact role before any PUT; all possible
// attempts are durably marked in the SAME short transaction. A COMMIT error
// authorizes neither upload nor a second reservation. Actual provider result
// readback is installed only by ResolvePreparationObjectsV1.
func ReserveObjectsV1(ctx context.Context, tx pgx.Tx, k RequestKey, id uuid.UUID, objects [8]storage.PresignTransientReservationV1) error {
	if tx == nil || ctx == nil || validateKey(k) != nil || id == uuid.Nil {
		return ErrInvalid
	}
	var document uuid.UUID
	var state string
	var live bool
	err := tx.QueryRow(ctx, `SELECT document_id,state,expires_at>clock_timestamp() FROM presign_preparations_v1
	 WHERE org_id=$1 AND id=$2 AND executor_kind=$3 AND executor_user_id=$4 AND executor_credential_id=$5 AND request_id=$6 FOR UPDATE`,
		k.OrgID, id, k.Executor.Kind, k.Executor.UserID, k.Executor.CredentialID, k.RequestID).Scan(&document, &state, &live)
	if err != nil {
		return err
	}
	if state != "preparing" || !live {
		return ErrConflict
	}
	for i, r := range objects {
		if r.OrgID != k.OrgID || r.DocumentID != document || r.PreparationID != id || r.Role != assetRolesV1[i] || r.ContentTypeV1() != assetContentTypeV1(r.Role) ||
			r.Bytes < 1 || r.Bytes > presign.MaxPDFBytes || r.SHA256 == [32]byte{} {
			return ErrInvalid
		}
		if _, err = tx.Exec(ctx, `INSERT INTO presign_preparation_objects_v1(org_id,preparation_id,role,object_key,content_type,object_sha256,object_bytes)
		 VALUES($1,$2,$3,$4,$5,$6,$7)`, k.OrgID, id, r.Role, r.KeyV1(), r.ContentTypeV1(), r.SHA256[:], r.Bytes); err != nil {
			return writeError(err)
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE presign_preparation_objects_v1 SET upload_attempted=TRUE WHERE org_id=$1 AND preparation_id=$2 AND NOT upload_attempted AND version_id IS NULL`, k.OrgID, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 8 {
		return ErrIntegrity
	}
	return nil
}

// ResolvePreparationObjectsV1 installs the concrete storage handles' verified
// exact VersionIds. It does not accept a latest-object alias or replace pins.
func ResolvePreparationObjectsV1(ctx context.Context, tx pgx.Tx, k RequestKey, id uuid.UUID, objects [8]AssetV1) error {
	if tx == nil || ctx == nil || validateKey(k) != nil || id == uuid.Nil {
		return ErrInvalid
	}
	for i, a := range objects {
		maximum := int64(presign.MaxSignatureBytes)
		if i == 4 || i == 5 || i == 7 {
			maximum = presign.MaxPDFBytes
		}
		if a.Role != assetRolesV1[i] || a.ContentType != assetContentTypeV1(a.Role) || !validAssetPinV1(a.Object, maximum) {
			return ErrInvalid
		}
		tag, err := tx.Exec(ctx, `UPDATE presign_preparation_objects_v1 o SET version_id=$8,resolved_at=clock_timestamp()
		 FROM presign_preparations_v1 p WHERE p.org_id=o.org_id AND p.id=o.preparation_id
		 AND p.org_id=$1 AND p.id=$2 AND p.executor_kind=$3 AND p.executor_user_id=$4 AND p.executor_credential_id=$5 AND p.request_id=$6
		 AND p.state='preparing' AND p.expires_at>clock_timestamp() AND o.role=$7 AND o.upload_attempted AND o.version_id IS NULL
		 AND o.object_key=$9 AND o.content_type=$10 AND o.object_sha256=$11 AND o.object_bytes=$12`,
			k.OrgID, id, k.Executor.Kind, k.Executor.UserID, k.Executor.CredentialID, k.RequestID, a.Role, a.Object.VersionID, a.Object.StorageKey, a.ContentType, unhex(a.Object.SHA256), a.Object.Bytes)
		if err != nil {
			return writeError(err)
		}
		if tag.RowsAffected() != 1 {
			return ErrConflict
		}
	}
	return nil
}

// AppendPreparedRecordV1 appends the WHOLE M82 pair and M116 ownership/assets/
// publication in the actual final transaction after fresh authority, source,
// natural deadlines and chained audit were rechecked. It never commits or
// applies retention, and a commit error never permits compensating these pins.
func AppendPreparedRecordV1(ctx context.Context, tx pgx.Tx, id uuid.UUID, record Record, assets AssetSetV1) error {
	if tx == nil || ctx == nil || id == uuid.Nil {
		return ErrInvalid
	}
	r, err := NewRecord(record.policy, record.grant, record.execution, record.command, record.admission, record.auditEventID)
	if err != nil {
		return err
	}
	a, err := DecodeAssetSetV1(r.execution, assets.CanonicalJSON())
	if err != nil || a.Commitment() != assets.Commitment() {
		return ErrInvalid
	}
	k := r.command.RequestKey()
	x := r.execution.Snapshot()
	c := r.command.Snapshot()
	var intentRaw, intentSHA, credential []byte
	var document uuid.UUID
	var state string
	var live bool
	err = tx.QueryRow(ctx, `SELECT intent_canonical,intent_sha256,original_credential_sha256,document_id,state,expires_at>clock_timestamp()
	 FROM presign_preparations_v1 WHERE org_id=$1 AND id=$2 AND executor_kind=$3 AND executor_user_id=$4 AND executor_credential_id=$5 AND request_id=$6 FOR UPDATE`,
		k.OrgID, id, k.Executor.Kind, k.Executor.UserID, k.Executor.CredentialID, k.RequestID).Scan(&intentRaw, &intentSHA, &credential, &document, &state, &live)
	if err != nil {
		return err
	}
	var in IntentV1
	if json.Unmarshal(intentRaw, &in) != nil {
		return ErrIntegrity
	}
	raw, h, err := CanonicalIntentV1(in)
	if err != nil || !bytes.Equal(raw, intentRaw) || !bytes.Equal(intentSHA, unhex(h)) || !bytes.Equal(credential, unhex(c.OriginalCredentialSHA256)) ||
		reserveKeyV1(k, in, c.OriginalCredentialSHA256) != nil || state != "preparing" || !live || document != x.Document.ID || in.Policy != x.Policy || in.Grant != x.Grant ||
		in.MaterializationID != x.Document.Materialization.ID || in.MaterializationRevision != x.Document.Materialization.Revision || in.SourceCommitment != c.SourceCommitment {
		return ErrConflict
	}
	if _, err = r.AppendAtomic(ctx, tx); err != nil {
		return err
	}
	tag, err := tx.Exec(ctx, `UPDATE presign_preparations_v1 SET state='committed',execution_id=$3 WHERE org_id=$1 AND id=$2 AND state='preparing' AND expires_at>clock_timestamp()`, k.OrgID, id, x.ID)
	if err != nil {
		return writeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO presign_execution_assets_v1(org_id,execution_id,document_id,preparation_id,canonical_assets,assets_sha256) VALUES($1,$2,$3,$4,$5,$6)`,
		k.OrgID, x.ID, x.Document.ID, id, a.CanonicalJSON(), unhex(a.Commitment())); err != nil {
		return writeError(err)
	}
	tag, err = tx.Exec(ctx, `INSERT INTO presign_execution_publications_v1(org_id,execution_id,document_id,customer_recipient_id,retain_until)
	 SELECT e.org_id,e.id,e.document_id,$4,i.retain_until FROM presign_executions e JOIN send_sealing_intents i ON i.org_id=e.org_id AND i.document_id=e.document_id AND i.presign_execution_id=e.id
	 WHERE e.org_id=$1 AND e.id=$2 AND e.document_id=$3`, k.OrgID, x.ID, x.Document.ID, x.Document.Parties[0].ID)
	if err != nil {
		return writeError(err)
	}
	if tag.RowsAffected() != 1 {
		return ErrIntegrity
	}
	return nil
}

func AssetsFromStoredV1(reservations [8]storage.PresignTransientReservationV1, stored [8]storage.StoredObject) ([8]AssetV1, error) {
	var out [8]AssetV1
	for i, r := range reservations {
		if r.Role != assetRolesV1[i] || stored[i].SHA256 != r.SHA256 {
			return out, ErrIntegrity
		}
		p := presign.ArtifactPin{StorageKey: r.KeyV1(), VersionID: stored[i].VersionID, SHA256: hex.EncodeToString(r.SHA256[:]), Bytes: r.Bytes}
		maximum := int64(presign.MaxSignatureBytes)
		if i == 4 || i == 5 || i == 7 {
			maximum = presign.MaxPDFBytes
		}
		if !validAssetPinV1(p, maximum) {
			return out, ErrIntegrity
		}
		out[i] = AssetV1{Role: r.Role, ContentType: r.ContentTypeV1(), Object: p}
	}
	return out, nil
}
