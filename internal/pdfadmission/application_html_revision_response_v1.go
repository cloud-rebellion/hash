// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type HTMLRevisionResultModelsV1 struct {
	Document                *generated.Document
	MaterializationRevision int32
	PageCount               int
}

// Borrow the one actual response INSIDE the final callback, before Commit.
// The caller publishes it only after genuine Commit acknowledgement and keeps
// this once-release until response encoding/writing has actually returned.
// Concurrent route/factory close cannot credit this in-flight result use.
func (w *ApplicationHTMLRevisionWriterV1) BorrowResultV1(call context.Context) (*HTMLRevisionResultModelsV1, func(), error) {
	done, err := w.beginV1(call)
	if err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	if !w.appended || !w.fieldsWritten || !w.measured || !w.versionWritten || w.responseBorrowed || w.updated == nil || w.row == nil {
		w.mu.Unlock()
		done()
		return nil, nil, ErrHTMLRevisionWriterV1
	}
	w.responseBorrowed = true
	doc, row := w.updated, w.row
	w.mu.Unlock()
	copy := htmlRevisionCloneDocumentV1(doc)
	var once sync.Once
	return &HTMLRevisionResultModelsV1{Document: copy, MaterializationRevision: row.Sequence, PageCount: int(row.PageCount)}, func() { once.Do(done) }, nil
}

// This returns only the actual already-owned opaque session handle, INSIDE its
// real callback. The existing ownedaudit bridge still validates that native
// callback/scope and derives its own fixed payload/cache loan before Marshal.
func (h *ApplicationHTMLRevisionSQLV1) AuditSessionV1(call context.Context) (*ApplicationSessionV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrHTMLRevisionWriterV1
	}
	h.state.mu.Lock()
	session, closed := h.state.session, h.state.consumerClosed
	h.state.mu.Unlock()
	if closed || !htmlRevisionCollectionSessionV1(call, session) {
		return nil, ErrHTMLRevisionWriterV1
	}
	return session, nil
}
