// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SQLJournalV1 owns autocommit pool queries. In particular, an upload-attempt
// result may not come from a caller's transaction that could still roll back
// after object I/O. Callers must keep the pool alive until the operation ends.
// Each positive result acknowledges the provider's committed SQL statement;
// errors, including cancellation/transport loss, never authorize a PUT.
type SQLJournalV1 struct{ queries *generated.Queries }

func NewSQLJournalV1(pool *pgxpool.Pool) *SQLJournalV1 {
	if pool == nil {
		return nil
	}
	return &SQLJournalV1{generated.New(pool)}
}
func (j *SQLJournalV1) Get(ctx context.Context, p generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error) {
	return j.queries.GetSignatureFitPreparation(ctx, p)
}
func (j *SQLJournalV1) Reserve(ctx context.Context, p generated.ReserveSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error) {
	return j.queries.ReserveSignatureFitPreparation(ctx, p)
}
func (j *SQLJournalV1) Claim(ctx context.Context, p generated.ClaimSignatureFitPreparationLeaseParams) (*generated.SignatureFitPreparation, error) {
	return j.queries.ClaimSignatureFitPreparationLease(ctx, p)
}
func (j *SQLJournalV1) Objects(ctx context.Context, p generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error) {
	return j.queries.ListSignatureFitObjects(ctx, p)
}
func (j *SQLJournalV1) ReserveObject(ctx context.Context, p generated.ReserveSignatureFitObjectParams) (*generated.SignatureFitObject, error) {
	return j.queries.ReserveSignatureFitObject(ctx, p)
}
func (j *SQLJournalV1) Attempt(ctx context.Context, p generated.MarkSignatureFitUploadAttemptedParams) (*generated.SignatureFitObject, error) {
	return j.queries.MarkSignatureFitUploadAttempted(ctx, p)
}
func (j *SQLJournalV1) Pin(ctx context.Context, p generated.PinSignatureFitObjectVersionParams) (*generated.SignatureFitObject, error) {
	return j.queries.PinSignatureFitObjectVersion(ctx, p)
}
func (j *SQLJournalV1) Verified(ctx context.Context, p generated.MarkSignatureFitObjectReadbackVerifiedParams) (*generated.SignatureFitObject, error) {
	return j.queries.MarkSignatureFitObjectReadbackVerified(ctx, p)
}
func (j *SQLJournalV1) Prepared(ctx context.Context, p generated.MarkSignatureFitPreparationPreparedParams) (*generated.SignatureFitPreparation, error) {
	return j.queries.MarkSignatureFitPreparationPrepared(ctx, p)
}

var _ JournalV1 = (*SQLJournalV1)(nil)
