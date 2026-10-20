// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fields

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
type nativeFieldPolicyTxV1 struct {
	generated.DBTX
}

var errNativeFieldPolicyControlV1 = errors.New("PDF creation transaction control belongs to its native session")

func (*nativeFieldPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativeFieldPolicyControlV1
}
func (*nativeFieldPolicyTxV1) Commit(context.Context) error   { return errNativeFieldPolicyControlV1 }
func (*nativeFieldPolicyTxV1) Rollback(context.Context) error { return errNativeFieldPolicyControlV1 }
func (*nativeFieldPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativeFieldPolicyControlV1
}
func (*nativeFieldPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativeFieldRefusedBatchV1{}
}
func (*nativeFieldPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeFieldPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativeFieldPolicyControlV1
}
func (*nativeFieldPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativeFieldRefusedBatchV1 struct{}

func (nativeFieldRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativeFieldPolicyControlV1
}
func (nativeFieldRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativeFieldPolicyControlV1
}
func (nativeFieldRefusedBatchV1) QueryRow() pgx.Row { return nativeFieldRefusedRowV1{} }
func (nativeFieldRefusedBatchV1) Close() error      { return errNativeFieldPolicyControlV1 }

type nativeFieldRefusedRowV1 struct{}

func (nativeFieldRefusedRowV1) Scan(...any) error { return errNativeFieldPolicyControlV1 }

var _ pgx.Tx = (*nativeFieldPolicyTxV1)(nil)
