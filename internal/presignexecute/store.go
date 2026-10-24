// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func unhex(s string) []byte { b, _ := hex.DecodeString(s); return b }
func writeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrConflict
	}
	var p *pgconn.PgError
	if errors.As(err, &p) && (p.Code == "23505" || p.Code == "23514") {
		return fmt.Errorf("%w: atomic pairing refused", ErrConflict)
	}
	return err
}
func requestParams(k RequestKey) generated.GetPresignExecutionRequestParams {
	return generated.GetPresignExecutionRequestParams{OrgID: k.OrgID, ExecutorKind: k.Executor.Kind,
		ExecutorUserID: k.Executor.UserID, ExecutorCredentialID: k.Executor.CredentialID, RequestID: k.RequestID}
}

// AppendAtomic appends the complete execution/use/signature/status/intent/outcome
// pair to a caller-owned transaction after its real epoch and chained audit have
// been created. It does not commit, authenticate, render, store or re-admit
// retries. Existing outcomes must go through LoadOutcome before fresh work.
func (r Record) AppendAtomic(ctx context.Context, tx pgx.Tx) (*generated.PresignExecution, error) {
	if tx == nil {
		return nil, invalid("owned transaction required")
	}
	checked, err := NewRecord(r.policy, r.grant, r.execution, r.command, r.admission, r.auditEventID)
	if err != nil {
		return nil, err
	}
	r = checked
	q := generated.New(tx)
	k := r.command.RequestKey()
	x := r.execution.Snapshot()
	if err := q.LockPresignExecutionRequest(ctx, generated.LockPresignExecutionRequestParams{
		OrgID: k.OrgID, ExecutorKind: k.Executor.Kind, ExecutorUserID: k.Executor.UserID,
		ExecutorCredentialID: k.Executor.CredentialID, RequestID: k.RequestID}); err != nil {
		return nil, err
	}
	if _, err := q.GetPresignExecutionRequest(ctx, requestParams(k)); err == nil {
		return nil, ErrConflict
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	row, err := q.InsertPresignExecution(ctx, generated.InsertPresignExecutionParams{
		CanonicalExecution: r.execution.CanonicalJSON(), ExecutionSha256: unhex(r.execution.Commitment()),
		RequestID: k.RequestID, CommandCanonical: r.command.CanonicalJSON(), CommandSha256: unhex(r.command.Commitment()),
		OriginalCredentialSha256: unhex(r.command.Snapshot().OriginalCredentialSHA256),
		AdmissionCanonical:       r.admission.CanonicalJSON(), AdmissionSha256: unhex(r.admission.Commitment()), AuditEventID: r.auditEventID})
	if err != nil {
		return nil, writeError(err)
	}
	if err = q.InsertPresignExecutionUse(ctx, generated.InsertPresignExecutionUseParams{OrgID: x.OrgID, ID: x.ID}); err != nil {
		return nil, writeError(err)
	}
	if _, err = q.InsertPresignDelegatedSignature(ctx, generated.InsertPresignDelegatedSignatureParams{OrgID: x.OrgID, ID: x.ID}); err != nil {
		return nil, writeError(err)
	}
	if _, err = q.MarkPresignProviderSigned(ctx, generated.MarkPresignProviderSignedParams{OrgID: x.OrgID, ID: x.ID}); err != nil {
		return nil, writeError(err)
	}
	if _, err = q.BindPresignSealingIntent(ctx, generated.BindPresignSealingIntentParams{OrgID: x.OrgID, ID: x.ID}); err != nil {
		return nil, writeError(err)
	}
	if _, err = q.BeginDocumentSendSealing(ctx, generated.BeginDocumentSendSealingParams{ID: x.Document.ID, OrgID: x.OrgID}); err != nil {
		return nil, writeError(err)
	}
	if _, err = q.InsertCommittedPresignExecutionRequest(ctx, generated.InsertCommittedPresignExecutionRequestParams{OrgID: x.OrgID, ID: x.ID}); err != nil {
		return nil, writeError(err)
	}
	return row, nil
}

func decodeStored(row *generated.PresignExecution, p presign.Policy, g presign.Grant) (Record, error) {
	if row == nil {
		return Record{}, ErrIntegrity
	}
	e, err := presign.DecodeExecution(row.CanonicalExecution)
	if err != nil || !bytes.Equal(e.CanonicalJSON(), row.CanonicalExecution) {
		return Record{}, ErrIntegrity
	}
	c, err := DecodeCommand(row.CommandCanonical)
	if err != nil {
		return Record{}, ErrIntegrity
	}
	a, err := presignregistry.DecodeDataAdmission(row.AdmissionCanonical)
	if err != nil {
		return Record{}, ErrIntegrity
	}
	r, err := NewRecord(p, g, e, c, a, row.AuditEventID)
	if err != nil {
		return Record{}, ErrIntegrity
	}
	x, commandSnapshot := e.Snapshot(), c.Snapshot()
	if row.OrgID != x.OrgID || row.ID != x.ID || row.DocumentID != x.Document.ID || row.GrantID != x.Grant.ID ||
		row.GrantRevision != x.Grant.Revision || row.PolicyID != x.Policy.ID || row.PolicyRevision != x.Policy.Revision ||
		row.ExecutorKind != x.Executor.Kind || row.ExecutorUserID != x.Executor.UserID || row.ExecutorCredentialID != x.Executor.CredentialID ||
		row.RequestID != commandSnapshot.RequestID || row.SignatureID != x.Signature.ID || row.ProviderRecipientID != x.Signature.RecipientID ||
		row.ProviderFieldID != x.Signature.FieldID || row.MaterializationID != x.Document.Materialization.ID || row.UseNumber != x.UseNumber ||
		!row.CeremonyEpoch.Valid || !row.ExecutedAt.Valid || !row.CeremonyEpoch.Time.Equal(x.CeremonyEpoch) || !row.ExecutedAt.Time.Equal(x.ExecutedAt) ||
		hex.EncodeToString(row.GrantSha256) != g.Commitment() || hex.EncodeToString(row.PolicySha256) != p.Commitment() ||
		hex.EncodeToString(row.ExecutionSha256) != e.Commitment() || hex.EncodeToString(row.CommandSha256) != c.Commitment() ||
		hex.EncodeToString(row.AdmissionSha256) != a.Commitment() || hex.EncodeToString(row.SourceCommitment) != commandSnapshot.SourceCommitment ||
		hex.EncodeToString(row.OriginalCredentialSha256) != commandSnapshot.OriginalCredentialSHA256 {
		return Record{}, ErrIntegrity
	}
	return r, nil
}

// LoadOutcome is integrity readback on a caller-owned, original-actor
// authenticated transaction. It never checks current grant eligibility or
// consumes allowance; revoked/expired grants retain committed evidence.
func LoadOutcome(ctx context.Context, tx pgx.Tx, k RequestKey) (Outcome, error) {
	if tx == nil {
		return Outcome{}, invalid("owned read transaction required")
	}
	if err := validateKey(k); err != nil {
		return Outcome{}, err
	}
	q := generated.New(tx)
	req, err := q.GetPresignExecutionRequest(ctx, requestParams(k))
	if err != nil {
		return Outcome{}, err
	}
	if req.State == "closed" {
		// Closed outcomes rely on migration82's exact insert-time audit
		// lineage and immutable row/event guards. This shape check does not
		// independently reconstruct or verify a corrupted audit chain.
		if req.ExecutionID.Valid || len(req.ExecutionSha256) != 0 || len(req.CommandCanonical) != 0 || len(req.CommandSha256) != 0 ||
			req.AuditEventID == uuid.Nil || len(req.OriginalCredentialSha256) != 32 || !req.OccurredAt.Valid {
			return Outcome{}, ErrIntegrity
		}
		return Outcome{Key: k, State: "closed"}, nil
	}
	if req.State != "committed" || !req.ExecutionID.Valid {
		return Outcome{}, ErrIntegrity
	}
	row, err := q.GetPresignExecutionByID(ctx, generated.GetPresignExecutionByIDParams{OrgID: k.OrgID, ID: uuid.UUID(req.ExecutionID.Bytes)})
	if err != nil {
		return Outcome{}, err
	}
	policyRow, err := q.GetPresignPolicyRevisionForShare(ctx, generated.GetPresignPolicyRevisionForShareParams{OrgID: row.OrgID, PolicyID: row.PolicyID, Revision: row.PolicyRevision})
	if err != nil {
		return Outcome{}, err
	}
	grantRow, err := q.GetPresignGrantRevisionForShare(ctx, generated.GetPresignGrantRevisionForShareParams{OrgID: row.OrgID, GrantID: row.GrantID, Revision: row.GrantRevision})
	if err != nil {
		return Outcome{}, err
	}
	p, err := presign.DecodePolicy(policyRow.CanonicalPolicy)
	if err != nil || !bytes.Equal(p.CanonicalJSON(), policyRow.CanonicalPolicy) || hex.EncodeToString(policyRow.PolicySha256) != p.Commitment() {
		return Outcome{}, ErrIntegrity
	}
	g, err := presign.DecodeGrant(grantRow.CanonicalGrant)
	if err != nil || !bytes.Equal(g.CanonicalJSON(), grantRow.CanonicalGrant) || hex.EncodeToString(grantRow.GrantSha256) != g.Commitment() {
		return Outcome{}, ErrIntegrity
	}
	r, err := decodeStored(row, p, g)
	if err != nil || r.command.RequestKey() != k || req.AuditEventID != row.AuditEventID ||
		!req.OccurredAt.Valid || !req.OccurredAt.Time.Equal(r.execution.Snapshot().ExecutedAt) ||
		!bytes.Equal(req.ExecutionSha256, row.ExecutionSha256) || !bytes.Equal(req.CommandCanonical, row.CommandCanonical) ||
		!bytes.Equal(req.CommandSha256, row.CommandSha256) || !bytes.Equal(req.OriginalCredentialSha256, row.OriginalCredentialSha256) {
		return Outcome{}, ErrIntegrity
	}
	if err = q.ValidatePresignExecutionIntegrity(ctx, generated.ValidatePresignExecutionIntegrityParams{OrgID: k.OrgID, DocumentID: row.DocumentID}); err != nil {
		return Outcome{}, ErrIntegrity
	}
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: row.DocumentID, OrgID: row.OrgID})
	if err != nil {
		return Outcome{}, err
	}
	if presignregistry.ValidateDataAdmissionDocument(r.admission, doc) != nil {
		return Outcome{}, ErrIntegrity
	}
	return Outcome{Key: k, State: "committed", Record: &r}, nil
}
