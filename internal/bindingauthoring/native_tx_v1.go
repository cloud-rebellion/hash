// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package bindingauthoring

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
type nativeBindingPolicyTxV1 struct {
	generated.DBTX
}

var errNativeBindingPolicyControlV1 = errors.New("Binding authoring transaction control belongs to its native session")

func (*nativeBindingPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativeBindingPolicyControlV1
}
func (*nativeBindingPolicyTxV1) Commit(context.Context) error { return errNativeBindingPolicyControlV1 }
func (*nativeBindingPolicyTxV1) Rollback(context.Context) error {
	return errNativeBindingPolicyControlV1
}
func (*nativeBindingPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativeBindingPolicyControlV1
}
func (*nativeBindingPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativeBindingRefusedBatchV1{}
}
func (*nativeBindingPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeBindingPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativeBindingPolicyControlV1
}
func (*nativeBindingPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativeBindingRefusedBatchV1 struct{}

func (nativeBindingRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativeBindingPolicyControlV1
}
func (nativeBindingRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativeBindingPolicyControlV1
}
func (nativeBindingRefusedBatchV1) QueryRow() pgx.Row { return nativeBindingRefusedRowV1{} }
func (nativeBindingRefusedBatchV1) Close() error      { return errNativeBindingPolicyControlV1 }

type nativeBindingRefusedRowV1 struct{}

func (nativeBindingRefusedRowV1) Scan(...any) error { return errNativeBindingPolicyControlV1 }

var _ pgx.Tx = (*nativeBindingPolicyTxV1)(nil)
