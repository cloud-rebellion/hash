// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This private facade preserves existing actor/CRM/audit query interfaces inside
// the native Session.WithTx callback. Its embedded DBTX is the actual tracked
// owner supplied by that callback; it is never made from a Pool or caller Tx.
// No nested transaction, raw connection or transaction completion is exposed.
type htmlCreationPolicyTxV1 struct {
	generated.DBTX
	reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
}

var errHTMLCreationPolicyControlV1 = errors.New("HTML creation transaction control belongs to its native session")

func (*htmlCreationPolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (*htmlCreationPolicyTxV1) Commit(context.Context) error   { return errHTMLCreationPolicyControlV1 }
func (*htmlCreationPolicyTxV1) Rollback(context.Context) error { return errHTMLCreationPolicyControlV1 }
func (*htmlCreationPolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errHTMLCreationPolicyControlV1
}
func (*htmlCreationPolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return htmlCreationRefusedBatchV1{}
}
func (*htmlCreationPolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*htmlCreationPolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (*htmlCreationPolicyTxV1) Conn() *pgx.Conn { return nil }

type htmlCreationRefusedBatchV1 struct{}

func (htmlCreationRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errHTMLCreationPolicyControlV1
}
func (htmlCreationRefusedBatchV1) Query() (pgx.Rows, error) {
	return nil, errHTMLCreationPolicyControlV1
}
func (htmlCreationRefusedBatchV1) QueryRow() pgx.Row { return htmlCreationRefusedRowV1{} }
func (htmlCreationRefusedBatchV1) Close() error      { return errHTMLCreationPolicyControlV1 }

type htmlCreationRefusedRowV1 struct{}

func (htmlCreationRefusedRowV1) Scan(...any) error { return errHTMLCreationPolicyControlV1 }

type htmlCreationAttachQueriesV1 struct {
	*generated.Queries
	writer *pdfadmission.ApplicationHTMLCreationWriterV1
}

func (q *htmlCreationAttachQueriesV1) CreatePDFDocument(ctx context.Context, p generated.CreatePDFDocumentParams) (*generated.Document, error) {
	if q == nil || q.writer == nil {
		return nil, pdfadmission.ErrHTMLCreationWriterV1
	}
	return q.writer.CreatePDFDocument(ctx, p)
}

var _ pgx.Tx = (*htmlCreationPolicyTxV1)(nil)

func (q *htmlCreationAttachQueriesV1) UpdateMetadataRedactionReport(ctx context.Context, p generated.UpdateMetadataRedactionReportParams) error {
	if q == nil || q.writer == nil {
		return pdfadmission.ErrHTMLCreationWriterV1
	}
	return q.writer.UpdateMetadataRedactionReport(ctx, p)
}

// Async event hooks can outlive response serialization. Copy UUIDs
// out of their parent structs so these tiny pointers cannot keep a full HTML
// Document/raw producer alive after its real response consumer closes.
// The event ID/payload/hash/actor/legal meaning is unchanged.
func detachHTMLCreationEventIDsV1(event audit.PendingEvent) audit.PendingEvent {
	if event.Entry.DocumentID != nil {
		id := *event.Entry.DocumentID
		event.Entry.DocumentID = &id
	}
	if event.Entry.RecipientID != nil {
		id := *event.Entry.RecipientID
		event.Entry.RecipientID = &id
	}
	if event.Entry.ActorUserID != nil {
		id := *event.Entry.ActorUserID
		event.Entry.ActorUserID = &id
	}
	return event
}
