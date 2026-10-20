// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send

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
type sendOwnedPolicyTxV1 struct {
	generated.DBTX
}

var errSendOwnedPolicyControlV1 = errors.New("HTML send transaction control belongs to its native session")

func (*sendOwnedPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errSendOwnedPolicyControlV1
}
func (*sendOwnedPolicyTxV1) Commit(context.Context) error   { return errSendOwnedPolicyControlV1 }
func (*sendOwnedPolicyTxV1) Rollback(context.Context) error { return errSendOwnedPolicyControlV1 }
func (*sendOwnedPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errSendOwnedPolicyControlV1
}
func (*sendOwnedPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return sendOwnedRefusedBatchV1{}
}
func (*sendOwnedPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*sendOwnedPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errSendOwnedPolicyControlV1
}
func (*sendOwnedPolicyTxV1) Conn() *pgx.Conn { return nil }

type sendOwnedRefusedBatchV1 struct{}

func (sendOwnedRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errSendOwnedPolicyControlV1
}
func (sendOwnedRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errSendOwnedPolicyControlV1
}
func (sendOwnedRefusedBatchV1) QueryRow() pgx.Row { return sendOwnedRefusedRowV1{} }
func (sendOwnedRefusedBatchV1) Close() error      { return errSendOwnedPolicyControlV1 }

type sendOwnedRefusedRowV1 struct{}

func (sendOwnedRefusedRowV1) Scan(...any) error { return errSendOwnedPolicyControlV1 }

var _ pgx.Tx = (*sendOwnedPolicyTxV1)(nil)
