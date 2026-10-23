// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package amendmentauthoring

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
type nativePolicyTxV1 struct {
	generated.DBTX
}

var errNativePackagePolicyControlV1 = errors.New("Package authoring transaction control belongs to its native session")

func (*nativePolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativePackagePolicyControlV1
}
func (*nativePolicyTxV1) Commit(context.Context) error   { return errNativePackagePolicyControlV1 }
func (*nativePolicyTxV1) Rollback(context.Context) error { return errNativePackagePolicyControlV1 }
func (*nativePolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativePackagePolicyControlV1
}
func (*nativePolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativePackageRefusedBatchV1{}
}
func (*nativePolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativePolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativePackagePolicyControlV1
}
func (*nativePolicyTxV1) Conn() *pgx.Conn { return nil }

type nativePackageRefusedBatchV1 struct{}

func (nativePackageRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativePackagePolicyControlV1
}
func (nativePackageRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativePackagePolicyControlV1
}
func (nativePackageRefusedBatchV1) QueryRow() pgx.Row { return nativePackageRefusedRowV1{} }
func (nativePackageRefusedBatchV1) Close() error      { return errNativePackagePolicyControlV1 }

type nativePackageRefusedRowV1 struct{}

func (nativePackageRefusedRowV1) Scan(...any) error { return errNativePackagePolicyControlV1 }

var _ pgx.Tx = (*nativePolicyTxV1)(nil)
