// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"unsafe"
)

var ErrTemplateListSourceV1 = errors.New("pdfadmission: native template list source unavailable")

type ApplicationTemplateListSourceV1 struct {
	state *applicationTemplateListSourceStateV1
}
type applicationTemplateListSourceStateV1 struct {
	mu            sync.Mutex
	session       *ApplicationSessionV1
	reader        *ApplicationHTMLAuthoringReaderV1
	queries       *generated.Queries
	closes        []func()
	normalizer    *ApplicationBlocksCreationWriterV1
	limit, offset int32
	bound         int
	read, closed  bool
	headers       []*generated.ListNativeTemplatePageHeadersV1Row
	rows          []*generated.ReadNativeTemplateListProjectionV1Row
	contents      []templatepin.Content
	digests       []string
}

// Existing REST/MCP page policies remain 500/200. Header and all private
// expected-array storage are funded before their bounded scalar roster query.
func (h *ApplicationSessionV1) NewTemplateListSourceV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1, limit, offset int32) (*ApplicationTemplateListSourceV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) || limit > 500 {
		return nil, ErrTemplateListSourceV1
	}
	bound := int(limit)
	if bound < 0 {
		bound = 500
	}
	typed := 2*int64(unsafe.Sizeof(applicationTemplateListSourceStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationTemplateListSourceV1{})) + int64(unsafe.Sizeof(generated.ListNativeTemplatePageHeadersV1Params{})) + int64(unsafe.Sizeof(generated.ReadNativeTemplateListProjectionV1Params{}))
	per := 2*int64(unsafe.Sizeof(generated.ListNativeTemplatePageHeadersV1Row{})) + 2*int64(unsafe.Sizeof(generated.ReadNativeTemplateListProjectionV1Row{})) + 2*int64(unsafe.Sizeof(templatepin.Content{})) + 4*int64(unsafe.Sizeof(uuid.UUID{})) + 4*int64(unsafe.Sizeof(pgtype.Timestamptz{})) + 12*int64(unsafe.Sizeof(int64(0))) + 8*int64(unsafe.Sizeof("")) + 128
	if !htmlInputAddV1(&typed, int64(bound), per) {
		return nil, ErrTemplateListSourceV1
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, typed, 0)
	if err != nil {
		return nil, errors.Join(ErrTemplateListSourceV1, err)
	}
	return &ApplicationTemplateListSourceV1{state: &applicationTemplateListSourceStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}, limit: limit, offset: offset, bound: bound}}, nil
}
func (s *applicationTemplateListSourceStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationTemplateListSourceStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrTemplateListSourceV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}

// The original live reader credential runs under the actual selected parent
// locks before a missing cache can authorize/refuse any cold body operation.
func (h *ApplicationTemplateListSourceV1) ReadPageAfterHeaderV1(ctx context.Context, guard func(context.Context) error) ([]*generated.ReadNativeTemplateListProjectionV1Row, []string, error) {
	if h == nil || h.state == nil || guard == nil {
		return nil, nil, ErrTemplateListSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.read {
		return nil, nil, ErrTemplateListSourceV1
	}
	s.read = true
	headers, err := s.queries.ListNativeTemplatePageHeadersV1(ctx, generated.ListNativeTemplatePageHeadersV1Params{OrgID: s.session.state.org, PageLimit: s.limit, PageOffset: s.offset})
	if err != nil {
		return nil, nil, err
	}
	if len(headers) > s.bound {
		return nil, nil, ErrTemplateListSourceV1
	}
	s.headers = headers
	for i, row := range headers {
		if row == nil || row.ID == uuid.Nil || row.OrgID != s.session.state.org || row.Version < 1 || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || row.RawTextBytes < 0 || (row.SourceKind != "html" && row.SourceKind != "pdf" && row.SourceKind != "blocks") {
			return nil, nil, ErrTemplateListSourceV1
		}
		for j := 0; j < i; j++ {
			if headers[j].ID == row.ID {
				return nil, nil, ErrTemplateListSourceV1
			}
		}
	}
	if err = guard(ctx); err != nil {
		return nil, nil, err
	}
	params := generated.ReadNativeTemplateListProjectionV1Params{OrgID: s.session.state.org, TemplateIds: make([]uuid.UUID, len(headers)), ExpectedVersions: make([]int32, len(headers)), ExpectedCreatedAts: make([]pgtype.Timestamptz, len(headers)), ExpectedUpdatedAts: make([]pgtype.Timestamptz, len(headers)), ExpectedSourceKinds: make([]string, len(headers)), ExpectedRawTextBytes: make([]int64, len(headers)), ExpectedBlocksWireBytes: make([]int64, len(headers)), ExpectedVariablesWireBytes: make([]int64, len(headers)), ExpectedFieldsWireBytes: make([]int64, len(headers))}
	raw, wire := int64(0), int64(0)
	for i, row := range headers {
		if row.MasterWireBytes < 0 || row.VariablesWireBytes < 0 || row.BlocksWireBytes < 0 || row.FieldsWireBytes < 0 || row.SanitizationWireBytes < 0 || row.MeasurementServerVersionNum < 1 || row.MeasurementServerVersionNum != row.ServerVersionNum {
			return nil, nil, ErrTemplateListSourceV1
		}
		raw, err = htmlAuthoringSumV1(raw, row.RawTextBytes)
		if err != nil {
			return nil, nil, err
		}
		wire, err = htmlAuthoringSumV1(wire, row.VariablesWireBytes, row.BlocksWireBytes, row.FieldsWireBytes)
		if err != nil {
			return nil, nil, err
		}
		params.TemplateIds[i] = row.ID
		params.ExpectedVersions[i] = row.Version
		params.ExpectedCreatedAts[i] = row.CreatedAt
		params.ExpectedUpdatedAts[i] = row.UpdatedAt
		params.ExpectedSourceKinds[i] = row.SourceKind
		params.ExpectedRawTextBytes[i] = row.RawTextBytes
		params.ExpectedBlocksWireBytes[i] = row.BlocksWireBytes
		params.ExpectedVariablesWireBytes[i] = row.VariablesWireBytes
		params.ExpectedFieldsWireBytes[i] = row.FieldsWireBytes
	}
	if err = s.holdV1(ctx, raw, wire); err != nil {
		return nil, nil, err
	}
	rows, err := s.queries.ReadNativeTemplateListProjectionV1(ctx, params)
	if err != nil {
		return nil, nil, err
	}
	if len(rows) != len(headers) {
		return nil, nil, ErrTemplateListSourceV1
	}
	s.rows = rows
	lexical, output := int64(0), int64(0)
	for i, row := range rows {
		header := headers[i]
		if row == nil || row.ID != header.ID || row.OrgID != header.OrgID || row.SourceKind != header.SourceKind || row.Version != header.Version || row.CreatedAt != header.CreatedAt || row.UpdatedAt != header.UpdatedAt || row.ArchivedAt.Valid || len(row.HtmlMasterJson) != 0 || len(row.PdfSanitizationReport) != 0 || int64(len(row.BlocksJson)) != header.BlocksWireBytes || int64(len(row.VariablesJson)) != header.VariablesWireBytes || int64(len(row.FieldsJson)) != header.FieldsWireBytes {
			return nil, nil, ErrTemplateListSourceV1
		}
		actualRaw, e := htmlAuthoringSumV1(int64(len(row.Name)), int64(len(row.SourceKind)), int64(len(row.PdfStorageKey.String)), int64(len(row.PdfStorageVersionID.String)), int64(len(row.PdfSha256)), int64(len(row.HtmlContentSha256)))
		if e != nil || actualRaw != header.RawTextBytes {
			return nil, nil, ErrTemplateListSourceV1
		}
		if row.SourceKind != "blocks" {
			continue
		}
		for _, value := range [][]byte{row.BlocksJson, row.VariablesJson} {
			cost, e := plainSendBlockLexicalWorkV1(ctx, value)
			if e != nil {
				return nil, nil, e
			}
			if !htmlInputAddV1(&lexical, cost, 1) {
				return nil, nil, ErrTemplateListSourceV1
			}
		}
		// Fixed bound for the existing blocksCanonicalOutputUpperV1 inventory:
		// each block consumes at least2 source bytes and contributes160 fixed;
		// string headers consume2 quote bytes for8 output bytes, data at most6x;
		// scalar attrs contribute at most32 per nonempty source byte, array/row
		// headers at most8 per2 delimiters. Their sum is below256x raw, plus128
		// per root. This is source work, not a grammar/cap/physical heap claim;
		// the unchanged typed parser and real pre-Marshal callback still verify it.
		if !htmlInputAddV1(&output, int64(len(row.BlocksJson)), 256) || !htmlInputAddV1(&output, int64(len(row.VariablesJson)), 6) || !htmlInputAddV1(&output, 1, 128) {
			return nil, nil, ErrTemplateListSourceV1
		}
	}
	combined, err := htmlAuthoringSumV1(lexical, output)
	if err != nil {
		return nil, nil, err
	}
	if err = s.holdV1(ctx, combined, 0); err != nil {
		return nil, nil, err
	}
	s.normalizer, err = s.session.NewBlocksCreationWriterV1(ctx, s.reader)
	if err != nil {
		return nil, nil, err
	}
	work := s.normalizer.state
	work.processing = true
	defer func() { work.processing = false }()
	admission := blocksCreationDecimalAdmissionV1{state: work, ctx: ctx}
	s.contents = make([]templatepin.Content, len(rows))
	s.digests = make([]string, len(rows))
	for i, row := range rows {
		if row.SourceKind != "blocks" {
			continue
		}
		upper := int64(128)
		if !htmlInputAddV1(&upper, int64(len(row.BlocksJson)), 256) || !htmlInputAddV1(&upper, int64(len(row.VariablesJson)), 6) {
			return nil, nil, ErrTemplateListSourceV1
		}
		content, e := templatepin.CanonicalizeWithAdmissionV1(ctx, row.BlocksJson, row.VariablesJson, admission, func(tree *blocks.Tree) error {
			actual, e := blocksCanonicalOutputUpperV1(ctx, tree)
			if e != nil {
				return e
			}
			if !htmlInputAddV1(&actual, int64(len(row.VariablesJson)), 6) || actual > upper {
				return ErrTemplateListSourceV1
			}
			return ctx.Err()
		})
		if work.admissionFailure != nil {
			return nil, nil, work.admissionFailure
		}
		if e != nil {
			return nil, nil, e
		}
		s.contents[i] = content
		s.digests[i] = content.SHA256Hex()
	}
	return rows, s.digests, nil
}
func (h *ApplicationTemplateListSourceV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.headers = nil
	s.rows = nil
	s.contents = nil
	s.digests = nil
	if s.normalizer != nil {
		s.normalizer.CloseConsumerV1()
		s.normalizer = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
