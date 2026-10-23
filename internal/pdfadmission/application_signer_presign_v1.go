// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
)

// Only this actual reader may load the optional immutable execution relation.
// Scalar lengths precede canonical bodies; both copies and decoding stay under
// the original retained model loan through the last response consumer.
func (r *ApplicationSignerReaderV1) readPresignAssetsV1(ctx context.Context, db generated.DBTX) (*presignexecute.RetainedAssetsV1, error) {
	if r == nil || r.self != r || r.session == nil || !r.read || r.consumerClosed || r.released {
		return nil, ErrSignerReadV1
	}
	var lengths [6]int64
	err := db.QueryRow(ctx, `SELECT octet_length(e.canonical_execution)::bigint,octet_length(e.command_canonical)::bigint,
 octet_length(e.admission_canonical)::bigint,octet_length(p.canonical_policy)::bigint,octet_length(g.canonical_grant)::bigint,
 COALESCE(octet_length(a.canonical_assets),0)::bigint
 FROM presign_executions e LEFT JOIN presign_workflow_revisions p ON p.org_id=e.org_id AND p.policy_id=e.policy_id AND p.revision=e.policy_revision
 LEFT JOIN presign_grant_revisions g ON g.org_id=e.org_id AND g.grant_id=e.grant_id AND g.revision=e.grant_revision
 LEFT JOIN presign_execution_assets_v1 a ON a.org_id=e.org_id AND a.execution_id=e.id AND a.document_id=e.document_id
 WHERE e.org_id=$1 AND e.document_id=$2`, r.scope.org, r.scope.document).
		Scan(&lengths[0], &lengths[1], &lengths[2], &lengths[3], &lengths[4], &lengths[5])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	raw := int64(32768 + 8*(2048+256))
	for _, n := range lengths {
		if n < 1 || n > presign.MaxSnapshotBytes {
			return nil, ErrSignerReadV1
		}
		var err error
		raw, err = htmlAuthoringSumV1(raw, n)
		if err != nil {
			return nil, ErrSignerReadV1
		}
	}
	closeBody, err := r.session.acquireSignerReadModelsV1(ctx, "locked-signer-read-body", raw, 0, r)
	if err != nil {
		return nil, err
	}
	r.appendConsumerV1(closeBody)
	// The raw transaction never escapes this trusted fixed producer. Its actual
	// SQL borrower remains live across every nested immutable-relation read.
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, r.session.state, true)
	if err != nil {
		return nil, err
	}
	defer done()
	retained, err := presignexecute.LoadRetainedAssetsV1(owned, tx, r.scope.org, r.scope.document)
	if err != nil {
		return nil, errors.Join(ErrSignerReadV1, err)
	}
	return &retained, nil
}

// WithPresignPDFV1 reads only the immutable derivative selected by the actual
// native model owner. No caller key/hash/byte slice can supply provenance. The
// genuine SDK read, its stream close, recheck and HTTP writer all join before
// body capacity is credited. Reader close cannot retire an active consumer.
func (r *ApplicationSignerReaderV1) WithPresignPDFV1(ctx context.Context, client *storage.Client, consume func([]byte) error) error {
	if r == nil || r.self != r || client == nil || consume == nil || !applicationContextV1(ctx) {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	if r.creating || !r.read || r.consumerClosed || r.released || r.models == nil || r.models.Presign == nil || r.factory == nil || r.factory.state == nil {
		r.mu.Unlock()
		return ErrSignerReadV1
	}
	retained := *r.models.Presign
	pin := retained.Assets().Snapshot().Objects[7].Object
	org := r.scope.org
	p := r.factory.state
	r.presignBorrowers++
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.presignBorrowers--
		closes := r.retireBlockSigningReadConsumersV1()
		r.mu.Unlock()
		for _, close := range closes {
			close()
		}
	}()
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil || pin.Bytes < 1 || pin.Bytes > limits.ObjectBytes || pin.Bytes > presign.MaxPDFBytes {
		return ErrSignerReadV1
	}
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return ErrSignerReadV1
	}
	raw := int64(0)
	if !htmlInputAddV1(&raw, limits.ObjectBytes+1, 4) || !htmlInputAddV1(&raw, limits.MetadataBytes, 4) ||
		!htmlInputAddV1(&raw, limits.HeaderBytes, 4) || !htmlInputAddV1(&raw, limits.VersionIDBytes, 2) {
		return ErrSignerReadV1
	}
	bodyGrant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return errors.Join(ErrSignerReadV1, err)
	}
	defer bodyGrant.Close()
	stream, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		return errors.Join(ErrSignerReadV1, err)
	}
	digest, err := hex.DecodeString(pin.SHA256)
	if err != nil || len(digest) != 32 {
		stream.Close()
		return ErrSignerReadV1
	}
	body, err := client.GetVerifiedVersionForSendV1(ctx, pin.StorageKey, pin.VersionID, digest)
	stream.Close()
	defer func() { clear(body) }()
	if err != nil {
		return err
	}
	if int64(len(body)) != pin.Bytes || len(body) < 5 || string(body[:5]) != "%PDF-" || ctx.Err() != nil {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	valid := !r.consumerClosed && !r.released && r.models != nil && r.models.Presign != nil && r.models.Presign.Assets().Commitment() == retained.Assets().Commitment()
	r.mu.Unlock()
	if !valid {
		return ErrSignerReadV1
	}
	return consume(body)
}
