// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package recipientauthoring

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
type nativeRecipientPolicyTxV1 struct {
	generated.DBTX
}

var errNativePDFPolicyControlV1 = errors.New("PDF creation transaction control belongs to its native session")

func (*nativeRecipientPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errNativePDFPolicyControlV1
}
func (*nativeRecipientPolicyTxV1) Commit(context.Context) error   { return errNativePDFPolicyControlV1 }
func (*nativeRecipientPolicyTxV1) Rollback(context.Context) error { return errNativePDFPolicyControlV1 }
func (*nativeRecipientPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errNativePDFPolicyControlV1
}
func (*nativeRecipientPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return nativePDFRefusedBatchV1{}
}
func (*nativeRecipientPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*nativeRecipientPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errNativePDFPolicyControlV1
}
func (*nativeRecipientPolicyTxV1) Conn() *pgx.Conn { return nil }

type nativePDFRefusedBatchV1 struct{}

func (nativePDFRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errNativePDFPolicyControlV1
}
func (nativePDFRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errNativePDFPolicyControlV1
}
func (nativePDFRefusedBatchV1) QueryRow() pgx.Row { return nativePDFRefusedRowV1{} }
func (nativePDFRefusedBatchV1) Close() error      { return errNativePDFPolicyControlV1 }

type nativePDFRefusedRowV1 struct{}

func (nativePDFRefusedRowV1) Scan(...any) error { return errNativePDFPolicyControlV1 }

var _ pgx.Tx = (*nativeRecipientPolicyTxV1)(nil)
