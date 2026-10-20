// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/jackc/pgx/v5/pgtype"
	"time"
	"unsafe"
)

var ErrPlainDraftSourceKindV1 = errors.New("pdfadmission: draft source is not an ordinary PDF or block document")
var ErrPlainDraftBlockInputV1 = errors.New("blocks_json and variables_json require a block-source document")

type PlainDraftInputErrorV1 struct {
	Field string
	Cause error
}

func (e PlainDraftInputErrorV1) Error() string { return e.Cause.Error() }
func (e PlainDraftInputErrorV1) Unwrap() error { return e.Cause }

type PlainDraftPatchV1 struct {
	Name, ExpiresAt, DefaultLocale string
	BlocksJSON, VariablesJSON      json.RawMessage
	RequiresSignature              *bool
}
type ApplicationPlainDraftMutationWriterV1 struct {
	state *applicationBlocksMutationStateV1
}

func (h *ApplicationSessionV1) NewPlainDraftMutationWriterV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1) (*ApplicationPlainDraftMutationWriterV1, error) {
	writer, err := h.newBlocksMutationWriterV1(ctx, reader, true)
	if err != nil {
		return nil, err
	}
	s := writer.state
	if err = s.sourceWork.holdV1(ctx, 2*int64(unsafe.Sizeof(ApplicationPlainDraftMutationWriterV1{}))+2*int64(unsafe.Sizeof(PlainDraftPatchV1{})), 0); err != nil {
		writer.CloseConsumerV1()
		return nil, err
	}
	return &ApplicationPlainDraftMutationWriterV1{state: s}, nil
}

// Each original RETURNING owns both the actual model and its private detached
// tuple through final response/hooks. At most four writes occur in this fixed
// original operation: source, details, optional locale, optional signature mode.
func (s *applicationBlocksMutationStateV1) fundPlainReturnV1(ctx context.Context, old *generated.Document, extraRaw int64) error {
	if old == nil || s.retainedRows > 6 {
		return ErrBlocksWriterV1
	}
	raw := signerDocumentRawBytesV1(old)
	wire, err := htmlAuthoringSumV1(int64(len(old.HtmlSourceJson)), int64(len(old.HtmlCurrentSourceJson)), int64(len(old.BlocksJson)), int64(len(old.VariablesJson)), int64(len(old.Metadata)), int64(len(old.MetadataRedactionReport)))
	if err != nil {
		return err
	}
	raw, err = htmlAuthoringSumV1(raw, extraRaw, 2*int64(unsafe.Sizeof(generated.Document{})), 2*int64(unsafe.Sizeof(generated.UpdateDocumentBlocksParams{})), 2*int64(unsafe.Sizeof(generated.UpdateDraftDocumentDetailsV1Params{})), 2*int64(unsafe.Sizeof(generated.SetDocumentDefaultLocaleParams{})), 2*int64(unsafe.Sizeof(generated.SetDocumentRequiresSignatureParams{})))
	if err != nil {
		return err
	}
	return s.sourceWork.holdV1(ctx, raw, wire)
}
func (s *applicationBlocksMutationStateV1) retainPlainRowV1(row *generated.Document) error {
	if row == nil || s.retainedRows > 6 {
		return ErrBlocksWriterV1
	}
	s.intermediate[s.retainedRows] = row
	s.intermediate[s.retainedRows+1] = htmlRevisionCloneDocumentV1(row)
	s.doc = s.intermediate[s.retainedRows+1]
	s.retainedRows += 2
	return nil
}
func (s *applicationBlocksMutationStateV1) writePlainSourceV1(ctx context.Context, old *generated.Document, raw, variables []byte, bw, vw int64) (*generated.Document, error) {
	if err := s.fundPlainReturnV1(ctx, old, int64(len(raw))+int64(len(variables))); err != nil {
		return nil, err
	}
	if err := s.sourceWork.holdV1(ctx, 0, bw+vw); err != nil {
		return nil, err
	}
	row, err := s.sourceWork.queries.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: old.ID, OrgID: old.OrgID, BlocksJson: raw, VariablesJson: variables})
	if err != nil {
		return nil, err
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) || int64(len(row.BlocksJson)) > bw || int64(len(row.VariablesJson)) > vw {
		return nil, ErrBlocksWriterV1
	}
	expected := *old
	expected.UpdatedAt = row.UpdatedAt
	expected.BlocksJson = row.BlocksJson
	expected.VariablesJson = row.VariablesJson
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	if err = s.retainPlainRowV1(row); err != nil {
		return nil, err
	}
	s.sourceWritten = true
	s.blocksWire = int64(len(row.BlocksJson))
	s.variablesWire = int64(len(row.VariablesJson))
	return row, nil
}

// set_variables historically leaves the existing block bytes untouched. It
// must not normalize/re-ID a legacy tree while replacing only its variable map.
func (w *ApplicationPlainDraftMutationWriterV1) SetVariablesV1(ctx context.Context, variables json.RawMessage) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted || s.snapshot.document.SourceKind != "blocks" {
		return nil, ErrBlocksWriterV1
	}
	s.attempted = true
	old := s.snapshot.document
	raw, err := plainSendBlockLexicalWorkV1(ctx, variables)
	if err != nil {
		return nil, err
	}
	if err = s.sourceWork.holdV1(ctx, raw, 0); err != nil {
		return nil, err
	}
	if _, err = blocks.ParseVariableValues(variables); err != nil {
		return nil, PlainDraftInputErrorV1{Field: "variables", Cause: err}
	}
	vw, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, variables)
	if err != nil {
		return nil, err
	}
	return s.writePlainSourceV1(ctx, old, old.BlocksJson, variables, int64(len(old.BlocksJson)), vw)
}
func (w *ApplicationPlainDraftMutationWriterV1) PatchV1(ctx context.Context, p PlainDraftPatchV1) (*generated.Document, error) {
	if w == nil || w.state == nil {
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
	current := old
	if old.SourceKind != "blocks" && (len(p.BlocksJSON) > 0 || len(p.VariablesJSON) > 0) {
		return nil, ErrPlainDraftBlockInputV1
	}
	if old.SourceKind == "blocks" && (len(p.BlocksJSON) > 0 || len(p.VariablesJSON) > 0) {
		raw, variables := p.BlocksJSON, p.VariablesJSON
		if len(raw) == 0 {
			raw = old.BlocksJson
		}
		if len(variables) == 0 {
			variables = old.VariablesJson
		}
		if err := (&ApplicationBlocksCreationWriterV1{state: s.sourceWork}).PrepareSourceV1(ctx, raw, variables); err != nil {
			return nil, err
		}
		var err error
		current, err = s.writePlainSourceV1(ctx, old, s.sourceWork.blocks, s.sourceWork.variables, s.sourceWork.blocksWire, s.sourceWork.variablesWire)
		if err != nil {
			return nil, err
		}
	}
	name := old.Name
	if p.Name != "" {
		name = p.Name
	}
	expires := old.ExpiresAt
	if p.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, p.ExpiresAt)
		if err != nil {
			return nil, PlainDraftInputErrorV1{Field: "expires_at", Cause: err}
		}
		expires = pgtype.Timestamptz{Time: parsed, Valid: true}
	}
	if err := s.fundPlainReturnV1(ctx, current, int64(len(name))); err != nil {
		return nil, err
	}
	row, err := s.sourceWork.queries.UpdateDraftDocumentDetailsV1(ctx, generated.UpdateDraftDocumentDetailsV1Params{ID: old.ID, OrgID: old.OrgID, Name: name, ExpiresAt: expires})
	if err != nil {
		return nil, err
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) {
		return nil, ErrBlocksWriterV1
	}
	expected := *current
	expected.UpdatedAt = row.UpdatedAt
	expected.Name = name
	if !plainDraftExpiryEqualV1(expires, row.ExpiresAt) {
		return nil, ErrBlocksWriterV1
	}
	expected.ExpiresAt = row.ExpiresAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	if err = s.retainPlainRowV1(row); err != nil {
		return nil, err
	}
	current = row
	if p.DefaultLocale != "" && p.DefaultLocale != current.DefaultLocale {
		if err = s.fundPlainReturnV1(ctx, current, int64(len(p.DefaultLocale))); err != nil {
			return nil, err
		}
		row, err = s.sourceWork.queries.SetDocumentDefaultLocale(ctx, generated.SetDocumentDefaultLocaleParams{ID: old.ID, OrgID: old.OrgID, DefaultLocale: p.DefaultLocale})
		if err != nil {
			return nil, err
		}
		if row == nil || !applicationStampV1(row.UpdatedAt) {
			return nil, ErrBlocksWriterV1
		}
		expected = *current
		expected.UpdatedAt = row.UpdatedAt
		expected.DefaultLocale = p.DefaultLocale
		if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
			return nil, ErrBlocksWriterV1
		}
		if err = s.retainPlainRowV1(row); err != nil {
			return nil, err
		}
		current = row
	}
	if p.RequiresSignature != nil && *p.RequiresSignature != current.RequiresSignature {
		if err = s.fundPlainReturnV1(ctx, current, 0); err != nil {
			return nil, err
		}
		row, err = s.sourceWork.queries.SetDocumentRequiresSignature(ctx, generated.SetDocumentRequiresSignatureParams{ID: old.ID, OrgID: old.OrgID, RequiresSignature: *p.RequiresSignature})
		if err != nil {
			return nil, err
		}
		if row == nil || !applicationStampV1(row.UpdatedAt) {
			return nil, ErrBlocksWriterV1
		}
		expected = *current
		expected.UpdatedAt = row.UpdatedAt
		expected.RequiresSignature = *p.RequiresSignature
		if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
			return nil, ErrBlocksWriterV1
		}
		if err = s.retainPlainRowV1(row); err != nil {
			return nil, err
		}
		current = row
	}
	return current, nil
}
func (w *ApplicationPlainDraftMutationWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || !s.attempted || s.doc == nil {
		s.mu.Unlock()
		return ErrBlocksWriterV1
	}
	written := s.sourceWritten
	s.mu.Unlock()
	if !written {
		return nil
	}
	return (&ApplicationBlocksMutationWriterV1{state: s}).MeasureFreshPolicyV1(ctx)
}
func (w *ApplicationPlainDraftMutationWriterV1) CloseConsumerV1() {
	if w != nil && w.state != nil {
		(&ApplicationBlocksMutationWriterV1{state: w.state}).CloseConsumerV1()
	}
}

func plainDraftExpiryEqualV1(expected, actual pgtype.Timestamptz) bool {
	if expected.Valid != actual.Valid || expected.InfinityModifier != actual.InfinityModifier {
		return false
	}
	if !expected.Valid || expected.InfinityModifier != pgtype.Finite {
		return true
	}
	return actual.Time.Equal(expected.Time.Truncate(time.Microsecond))
}
