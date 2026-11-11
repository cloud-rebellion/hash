// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/i18n"
)

// Only fresh creator handles can record this setting. Their complete source
// and original transaction remain owned until audit, response and cleanup join.
// Omission retains the existing English default for API/MCP callers.
func freshDocumentLocaleV1(ctx context.Context, q *generated.Queries, old *generated.Document, locale string, hold func(context.Context, int64, int64) error) (*generated.Document, error) {
	if old == nil || old.Status != "draft" || old.DeletedAt.Valid || old.SentAt.Valid || hold == nil {
		return nil, ErrBlocksWriterV1
	}
	if locale == "" || locale == old.DefaultLocale {
		return old, nil
	}
	if old.DefaultLocale != "en" || len(locale) > 16 || !i18n.Has(locale) {
		return nil, ErrBlocksWriterV1
	}
	raw, err := htmlAuthoringSumV1(2*signerDocumentRawBytesV1(old), 2*int64(unsafe.Sizeof(generated.Document{})), 2*int64(unsafe.Sizeof(generated.SetFreshDocumentLocaleV1Params{})), int64(len(locale)))
	if err != nil {
		return nil, err
	}
	wire, err := htmlAuthoringSumV1(int64(len(old.HtmlSourceJson)), int64(len(old.HtmlCurrentSourceJson)), int64(len(old.BlocksJson)), int64(len(old.VariablesJson)), int64(len(old.Metadata)), int64(len(old.MetadataRedactionReport)))
	if err != nil {
		return nil, err
	}
	wire, err = htmlAuthoringSumV1(wire, wire)
	if err != nil {
		return nil, err
	}
	if err = hold(ctx, raw, wire); err != nil {
		return nil, err
	}
	row, err := q.SetFreshDocumentLocaleV1(ctx, generated.SetFreshDocumentLocaleV1Params{DocumentID: old.ID, OrgID: old.OrgID, ExpectedUpdatedAt: old.UpdatedAt, Locale: locale})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != old.ID || row.OrgID != old.OrgID || row.SenderID != old.SenderID || row.Status != "draft" || row.DefaultLocale != locale || row.SentAt.Valid || row.DeletedAt.Valid {
		return nil, ErrBlocksWriterV1
	}
	expected := *old
	expected.DefaultLocale, expected.UpdatedAt = locale, row.UpdatedAt
	if !applicationStampV1(row.UpdatedAt) || !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	return row, nil
}

func (w *ApplicationBlocksCreationWriterV1) RecordDefaultLocaleV1(ctx context.Context, locale string) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.doc == nil {
		return nil, ErrBlocksWriterV1
	}
	if locale == "" || locale == s.doc.DefaultLocale {
		return s.doc, nil
	}
	row, err := freshDocumentLocaleV1(ctx, s.queries, s.doc, locale, s.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	return row, nil
}

func (w *ApplicationPlainPDFCreationWriterV1) RecordDefaultLocaleV1(ctx context.Context, locale string) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured || s.doc == nil {
		return nil, ErrPlainPDFWriterV1
	}
	if locale == "" || locale == s.doc.DefaultLocale {
		return s.doc, nil
	}
	row, err := freshDocumentLocaleV1(ctx, s.queries, s.doc, locale, s.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	return row, nil
}

func (w *ApplicationHTMLCreationWriterV1) RecordDefaultLocaleV1(ctx context.Context, locale string) (*generated.Document, error) {
	if w == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.created || w.doc == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	if locale == "" || locale == w.doc.DefaultLocale {
		return w.doc, nil
	}
	reader, err := w.session.NewHTMLAuthoringReaderV1(ctx)
	if err != nil {
		return nil, err
	}
	w.purposeCloses = append(w.purposeCloses, reader.CloseConsumerV1)
	hold := func(call context.Context, raw, wire int64) error {
		close, err := reader.acquireOwnedRetainedBodyV1(call, raw, wire)
		if err == nil {
			w.purposeCloses = append(w.purposeCloses, close)
		}
		return err
	}
	row, err := freshDocumentLocaleV1(ctx, w.queries, w.doc, locale, hold)
	if err != nil {
		return nil, err
	}
	w.doc = row
	return row, nil
}
