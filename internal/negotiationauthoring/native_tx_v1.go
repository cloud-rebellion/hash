// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package negotiationauthoring

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
type nativeNegotiationPolicyTxV1 struct {
	generated.DBTX
}

var errNativeNegotiationPolicyControlV1 = errors.New("Manual negotiation transaction control belongs to its native session")

func (*nativeNegotiationPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativeNegotiationPolicyControlV1
}
func (*nativeNegotiationPolicyTxV1) Commit(context.Context) error {
	return errNativeNegotiationPolicyControlV1
}
func (*nativeNegotiationPolicyTxV1) Rollback(context.Context) error {
	return errNativeNegotiationPolicyControlV1
}
func (*nativeNegotiationPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativeNegotiationPolicyControlV1
}
func (*nativeNegotiationPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativeNegotiationRefusedBatchV1{}
}
func (*nativeNegotiationPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeNegotiationPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativeNegotiationPolicyControlV1
}
func (*nativeNegotiationPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativeNegotiationRefusedBatchV1 struct{}

func (nativeNegotiationRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativeNegotiationPolicyControlV1
}
func (nativeNegotiationRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativeNegotiationPolicyControlV1
}
func (nativeNegotiationRefusedBatchV1) QueryRow() pgx.Row { return nativeNegotiationRefusedRowV1{} }
func (nativeNegotiationRefusedBatchV1) Close() error      { return errNativeNegotiationPolicyControlV1 }

type nativeNegotiationRefusedRowV1 struct{}

func (nativeNegotiationRefusedRowV1) Scan(...any) error { return errNativeNegotiationPolicyControlV1 }

var _ pgx.Tx = (*nativeNegotiationPolicyTxV1)(nil)
