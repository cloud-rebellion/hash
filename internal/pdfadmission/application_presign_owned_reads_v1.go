// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

// These are fixed in-process pre-sign producers, not caller-selected sizes or
// row authority. Scalar SQL measures the exact selected immutable revisions;
// no canonical body/model is scanned before the original session's body loan.
// Every loan stays with this SAME work through its actual last consumer.
func (w *ApplicationHTMLSendWorkV1) AcquirePresignAuthorityV1(ctx context.Context, policy uuid.UUID, policyRevision int64, grant uuid.UUID, grantRevision int64) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.presignAuthorityAttempted || policy == uuid.Nil || grant == uuid.Nil ||
		policyRevision < 1 || policyRevision > presign.MaxRevision || grantRevision < 1 || grantRevision > presign.MaxRevision {
		return ErrHTMLSendWorkV1
	}
	w.presignAuthorityAttempted = true
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var grantor uuid.UUID
	if err := db.QueryRow(ctx, `SELECT grantor_user_id FROM presign_grants WHERE org_id=$1 AND id=$2`, w.session.state.org, grant).Scan(&grantor); err != nil {
		return err
	}
	if err := w.actor.AcquireActorV1(ctx, w.session.state.org, grantor, false); err != nil {
		return err
	}
	var definitionBytes, policyBytes, grantBytes int64
	err := db.QueryRow(ctx, `SELECT octet_length(p.canonical_definition)::bigint,octet_length(p.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint
	 FROM presign_workflow_revisions p JOIN presign_grant_revisions g ON g.org_id=p.org_id
	 WHERE p.org_id=$1 AND p.policy_id=$2 AND p.revision=$3 AND g.grant_id=$4 AND g.revision=$5
	 AND g.policy_id=p.policy_id AND g.policy_revision=p.revision AND g.policy_sha256=p.policy_sha256`,
		w.session.state.org, policy, policyRevision, grant, grantRevision).Scan(&definitionBytes, &policyBytes, &grantBytes)
	if err != nil {
		return err
	}
	if definitionBytes < 1 || definitionBytes > 256*1024 || policyBytes < 1 || policyBytes > 64*1024 || grantBytes < 1 || grantBytes > 64*1024 {
		return ErrHTMLSendWorkV1
	}
	raw, err := htmlAuthoringSumV1(definitionBytes, policyBytes, grantBytes)
	if err != nil {
		return err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	return nil
}

// A POST replay must repeat the complete original confirmation, even though a
// GET recovery needs only the original opaque request. The immutable relation
// supplies these bytes; callers cannot replace it with reconstructed fields.
func (w *ApplicationHTMLSendWorkV1) ReadOriginalPreSignIntentV1(ctx context.Context) ([]byte, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.stage.purpose != HTMLPreSignRecoveryV1 || !w.presignEvidenceAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var size int64
	err := db.QueryRow(ctx, `SELECT octet_length(p.intent_canonical)::bigint FROM presign_preparations_v1 p
  JOIN presign_executions e ON e.org_id=p.org_id AND e.id=p.execution_id AND e.document_id=p.document_id
  WHERE p.org_id=$1 AND p.document_id=$2 AND p.state='committed'`, w.session.state.org, w.logicalDocumentV1()).Scan(&size)
	if err != nil {
		return nil, err
	}
	if size < 1 || size > 8192 {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, size, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeBody)
	var raw, digest []byte
	err = db.QueryRow(ctx, `SELECT p.intent_canonical,p.intent_sha256 FROM presign_preparations_v1 p
  JOIN presign_executions e ON e.org_id=p.org_id AND e.id=p.execution_id AND e.document_id=p.document_id
  WHERE p.org_id=$1 AND p.document_id=$2 AND p.state='committed' AND octet_length(p.intent_canonical)=$3`, w.session.state.org, w.logicalDocumentV1(), size).Scan(&raw, &digest)
	if err != nil || int64(len(raw)) != size {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:presign-execution-intent:v1\x00"))
	_, _ = h.Write(raw)
	if !bytes.Equal(h.Sum(nil), digest) {
		return nil, ErrHTMLSendWorkV1
	}
	return raw, nil
}

// AcquirePresignEvidenceV1 accounts for the complete immutable execution,
// original command/data admission, policy, grant, asset descriptor and fixed
// eight reservations. Absent execution returns the original SQL no-row error;
// explicit incomplete evidence is refused by the subsequent typed loader.
func (w *ApplicationHTMLSendWorkV1) AcquirePresignEvidenceV1(ctx context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil || w.presignEvidenceAttempted {
		return ErrHTMLSendWorkV1
	}
	w.presignEvidenceAttempted = true
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var executionBytes, commandBytes, admissionBytes, policyBytes, grantBytes, assetBytes int64
	err := db.QueryRow(ctx, `SELECT octet_length(e.canonical_execution)::bigint,octet_length(e.command_canonical)::bigint,
	 octet_length(e.admission_canonical)::bigint,octet_length(p.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint,
	 COALESCE(octet_length(a.canonical_assets),0)::bigint
	 FROM presign_executions e JOIN presign_workflow_revisions p ON p.org_id=e.org_id AND p.policy_id=e.policy_id AND p.revision=e.policy_revision
	 JOIN presign_grant_revisions g ON g.org_id=e.org_id AND g.grant_id=e.grant_id AND g.revision=e.grant_revision
	 LEFT JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id AND a.document_id=e.document_id
	 WHERE e.org_id=$1 AND e.document_id=$2`, w.session.state.org, w.logicalDocumentV1()).
		Scan(&executionBytes, &commandBytes, &admissionBytes, &policyBytes, &grantBytes, &assetBytes)
	if err != nil {
		return err
	}
	for _, n := range []int64{executionBytes, commandBytes, admissionBytes, policyBytes, grantBytes, assetBytes} {
		if n < 1 || n > 64*1024 {
			return ErrHTMLSendWorkV1
		}
	}
	// Fixed row/key/version backing is at most eight 1024-byte keys/versions
	// plus bounded scalar fields. Body acquisition applies the existing
	// retained-body decode/copy/DB allowance to this real producer inventory.
	raw, err := htmlAuthoringSumV1(executionBytes, commandBytes, admissionBytes, policyBytes, grantBytes, assetBytes, 8*(2048+256))
	if err != nil {
		return err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	return nil
}
