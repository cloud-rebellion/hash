// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type htmlCeremonyPolicyTxV1 struct {
	generated.DBTX
}

var errHTMLCreationPolicyControlV1 = errors.New("HTML creation transaction control belongs to its native session")

func (*htmlCeremonyPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (*htmlCeremonyPolicyTxV1) Commit(context.Context) error   { return errHTMLCreationPolicyControlV1 }
func (*htmlCeremonyPolicyTxV1) Rollback(context.Context) error { return errHTMLCreationPolicyControlV1 }
func (*htmlCeremonyPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errHTMLCreationPolicyControlV1
}
func (*htmlCeremonyPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return htmlCeremonyRefusedBatchV1{}
}
func (*htmlCeremonyPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*htmlCeremonyPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (*htmlCeremonyPolicyTxV1) Conn() *pgx.Conn { return nil }

type htmlCeremonyRefusedBatchV1 struct{}

func (htmlCeremonyRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errHTMLCreationPolicyControlV1
}
func (htmlCeremonyRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (htmlCeremonyRefusedBatchV1) QueryRow() pgx.Row { return htmlCeremonyRefusedRowV1{} }
func (htmlCeremonyRefusedBatchV1) Close() error      { return errHTMLCreationPolicyControlV1 }

type htmlCeremonyRefusedRowV1 struct{}

func (htmlCeremonyRefusedRowV1) Scan(...any) error { return errHTMLCreationPolicyControlV1 }

var _ pgx.Tx = (*htmlCeremonyPolicyTxV1)(nil)
