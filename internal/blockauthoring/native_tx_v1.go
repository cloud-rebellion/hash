// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blockauthoring

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
type nativeBlocksPolicyTxV1 struct {
	generated.DBTX
}

var errNativeBlocksPolicyControlV1 = errors.New("Block authoring transaction control belongs to its native session")

func (*nativeBlocksPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativeBlocksPolicyControlV1
}
func (*nativeBlocksPolicyTxV1) Commit(context.Context) error   { return errNativeBlocksPolicyControlV1 }
func (*nativeBlocksPolicyTxV1) Rollback(context.Context) error { return errNativeBlocksPolicyControlV1 }
func (*nativeBlocksPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativeBlocksPolicyControlV1
}
func (*nativeBlocksPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativeBlocksRefusedBatchV1{}
}
func (*nativeBlocksPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeBlocksPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativeBlocksPolicyControlV1
}
func (*nativeBlocksPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativeBlocksRefusedBatchV1 struct{}

func (nativeBlocksRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativeBlocksPolicyControlV1
}
func (nativeBlocksRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativeBlocksPolicyControlV1
}
func (nativeBlocksRefusedBatchV1) QueryRow() pgx.Row { return nativeBlocksRefusedRowV1{} }
func (nativeBlocksRefusedBatchV1) Close() error      { return errNativeBlocksPolicyControlV1 }

type nativeBlocksRefusedRowV1 struct{}

func (nativeBlocksRefusedRowV1) Scan(...any) error { return errNativeBlocksPolicyControlV1 }

var _ pgx.Tx = (*nativeBlocksPolicyTxV1)(nil)
