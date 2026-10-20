// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package aiauthoring

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
type nativeAIPolicyTxV1 struct {
	generated.DBTX
}

var errNativeAIPolicyControlV1 = errors.New("Document AI transaction control belongs to its native session")

func (*nativeAIPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativeAIPolicyControlV1
}
func (*nativeAIPolicyTxV1) Commit(context.Context) error {
	return errNativeAIPolicyControlV1
}
func (*nativeAIPolicyTxV1) Rollback(context.Context) error {
	return errNativeAIPolicyControlV1
}
func (*nativeAIPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativeAIPolicyControlV1
}
func (*nativeAIPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativeAIRefusedBatchV1{}
}
func (*nativeAIPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeAIPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativeAIPolicyControlV1
}
func (*nativeAIPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativeAIRefusedBatchV1 struct{}

func (nativeAIRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativeAIPolicyControlV1
}
func (nativeAIRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativeAIPolicyControlV1
}
func (nativeAIRefusedBatchV1) QueryRow() pgx.Row { return nativeAIRefusedRowV1{} }
func (nativeAIRefusedBatchV1) Close() error      { return errNativeAIPolicyControlV1 }

type nativeAIRefusedRowV1 struct{}

func (nativeAIRefusedRowV1) Scan(...any) error { return errNativeAIPolicyControlV1 }

var _ pgx.Tx = (*nativeAIPolicyTxV1)(nil)
