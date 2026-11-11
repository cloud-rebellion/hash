// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/jackc/pgx/v5/pgtype"
)

// This narrow handle exposes only a metadata merge. It borrows the SAME genuine
// reader's complete locked body; no caller Document, UUID, missing cache or
// arbitrary transaction can become fresh-source authority.
type ApplicationDocumentMetadataWriterV1 struct {
	state *applicationBlocksMutationStateV1
}

func (h *ApplicationSessionV1) NewDocumentMetadataWriterV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1) (*ApplicationDocumentMetadataWriterV1, error) {
	writer, err := h.newBlocksMutationWriterWithCRMV1(ctx, reader, true, true)
	if err != nil {
		return nil, err
	}
	return &ApplicationDocumentMetadataWriterV1{writer.state}, nil
}

func (w *ApplicationDocumentMetadataWriterV1) AttachV1(ctx context.Context, key, value string) (*generated.Document, error) {
	if w == nil || w.state == nil || key == "" || documentpurpose.IsReservedKey(key) {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, ErrBlocksWriterV1
	}
	s.attempted = true
	old := s.snapshot.document
	n, err := htmlAuthoringSumV1(int64(len(old.Metadata)), int64(len(key)), int64(len(value)))
	if err != nil || n > (math.MaxInt64-(256<<10))/128 {
		return nil, ErrBlocksWriterV1
	}
	// Fund lexical maps, strings and serialization before parsing/merging. The
	// native source registry retains this loan through real response last use.
	if err = s.sourceWork.holdV1(ctx, n*128+(256<<10), 0); err != nil {
		return nil, err
	}
	metadata := map[string]any{}
	if len(old.Metadata) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(old.Metadata))
		decoder.UseNumber()
		if err = decoder.Decode(&metadata); err != nil {
			return nil, errors.New("stored metadata invalid")
		}
	}
	if metadata == nil {
		return nil, errors.New("stored metadata must be an object")
	}
	metadata[key] = value
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil, err
	}
	row, err := applyDocumentMetadataBytesV1(ctx, &applicationOwnedDBTXV1{session: s.session.state}, s.sourceWork.queries, old, raw, s.sourceWork.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	s.measured = true
	return row, nil
}

func (w *ApplicationDocumentMetadataWriterV1) CloseConsumerV1() {
	if w != nil {
		(&ApplicationBlocksMutationWriterV1{state: w.state}).CloseConsumerV1()
	}
}

// SetExpiryV1 changes only the details tuple. Clearing remains an explicit
// empty string, and existing source/metadata measurement caches stay intact.
func (w *ApplicationDocumentMetadataWriterV1) SetExpiryV1(ctx context.Context, value string) (*generated.Document, error) {
	if w == nil || w.state == nil || len(value) > 40 {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, ErrBlocksWriterV1
	}
	s.attempted = true
	expires := pgtype.Timestamptz{}
	if value != "" {
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil || !parsed.After(time.Now()) {
			return nil, errors.New("expires_at must be a future RFC3339 timestamp")
		}
		expires = pgtype.Timestamptz{Time: parsed, Valid: true}
	}
	old := s.snapshot.document
	if err := s.fundPlainReturnV1(ctx, old, 0); err != nil {
		return nil, err
	}
	row, err := s.sourceWork.queries.UpdateDraftDocumentDetailsV1(ctx, generated.UpdateDraftDocumentDetailsV1Params{ID: old.ID, OrgID: old.OrgID, Name: old.Name, ExpiresAt: expires})
	if err != nil {
		return nil, err
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) || !plainDraftExpiryEqualV1(expires, row.ExpiresAt) {
		return nil, ErrBlocksWriterV1
	}
	expected := *old
	expected.UpdatedAt, expected.ExpiresAt = row.UpdatedAt, row.ExpiresAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	if err = s.retainPlainRowV1(row); err != nil {
		return nil, err
	}
	s.measured = true
	return row, nil
}
