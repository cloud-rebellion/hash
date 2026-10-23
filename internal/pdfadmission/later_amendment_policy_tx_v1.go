// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This private facade preserves existing actor/CRM/audit query interfaces inside
// the native Session.WithTx callback. Its embedded DBTX is the actual tracked
// owner supplied by that callback; it is never made from a Pool or caller Tx.
// No nested transaction, raw connection or transaction completion is exposed.
type laterAmendmentPolicyTxV1 struct {
	generated.DBTX
}

var errLaterAmendmentPolicyControlV1 = errors.New("Later amendment transaction control belongs to its native session")

func (*laterAmendmentPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errLaterAmendmentPolicyControlV1
}
func (*laterAmendmentPolicyTxV1) Commit(context.Context) error {
	return errLaterAmendmentPolicyControlV1
}
func (*laterAmendmentPolicyTxV1) Rollback(context.Context) error {
	return errLaterAmendmentPolicyControlV1
}
func (*laterAmendmentPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errLaterAmendmentPolicyControlV1
}
func (*laterAmendmentPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return laterAmendmentRefusedBatchV1{}
}
func (*laterAmendmentPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*laterAmendmentPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errLaterAmendmentPolicyControlV1
}
func (*laterAmendmentPolicyTxV1) Conn() *pgx.Conn { return nil }

type laterAmendmentRefusedBatchV1 struct{}

func (laterAmendmentRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errLaterAmendmentPolicyControlV1
}
func (laterAmendmentRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errLaterAmendmentPolicyControlV1
}
func (laterAmendmentRefusedBatchV1) QueryRow() pgx.Row { return laterAmendmentRefusedRowV1{} }
func (laterAmendmentRefusedBatchV1) Close() error      { return errLaterAmendmentPolicyControlV1 }

type laterAmendmentRefusedRowV1 struct{}

func (laterAmendmentRefusedRowV1) Scan(...any) error { return errLaterAmendmentPolicyControlV1 }

var _ pgx.Tx = (*laterAmendmentPolicyTxV1)(nil)
