// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrPDFTemplateSourceV1 = errors.New("pdfadmission: owned PDF template source unavailable")
var ErrPDFTemplateSourceKindV1 = errors.New("pdfadmission: target is not a PDF template")

// Real full template reads use the separate M97 source cache. This owner
// never calls a measurement, borrows a Pool/Tx or adopts a caller Template.
// Both the response consumer and original native client/backend must retire.
type ApplicationPDFTemplateSourceV1 struct {
	state *applicationPDFTemplateSourceStateV1
}
type applicationPDFTemplateSourceStateV1 struct {
	mu                 sync.Mutex
	session            *ApplicationSessionV1
	reader             *ApplicationHTMLAuthoringReaderV1
	queries            *generated.Queries
	closes             []func()
	closed             bool
	reads              int
	template           *generated.Template
	updateLocked       bool
	lockedUpdateHeader *generated.GetPDFTemplateSourceHeaderForUpdateV1Row
	lockedShareHeader  *generated.GetPDFTemplateSourceHeaderForShareV1Row
}

func (h *ApplicationSessionV1) NewPDFTemplateSourceV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationPDFTemplateSourceV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrPDFTemplateSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationPDFTemplateSourceStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationPDFTemplateSourceV1{})) + 2*int64(unsafe.Sizeof(generated.GetPDFTemplateSourceHeaderForShareV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetPDFTemplateSourceHeaderForUpdateV1Row{}))
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrPDFTemplateSourceV1, err)
	}
	return &ApplicationPDFTemplateSourceV1{state: &applicationPDFTemplateSourceStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationPDFTemplateSourceStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (h *ApplicationPDFTemplateSourceV1) GetTemplateForShare(ctx context.Context, p generated.GetTemplateForShareParams) (*generated.Template, error) {
	return h.readV1(ctx, p.ID, p.OrgID, false)
}
func (h *ApplicationPDFTemplateSourceV1) GetTemplateForUpdate(ctx context.Context, p generated.GetTemplateForUpdateParams) (*generated.Template, error) {
	return h.readV1(ctx, p.ID, p.OrgID, true)
}
func (h *ApplicationPDFTemplateSourceV1) readV1(ctx context.Context, id, org uuid.UUID, update bool) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || id == uuid.Nil || org != s.session.state.org || s.reads >= htmlAuthoringMaxReadsV1 {
		return nil, ErrPDFTemplateSourceV1
	}
	s.reads++
	var actualID, actualOrg uuid.UUID
	var kind string
	var version int32
	var created, updated pgtype.Timestamptz
	var raw, master, variables, blocks, fields, sanitization int64
	var measured, server int32
	if update {
		header, err := s.readFreshUpdateHeaderV1(ctx, id, org)
		if err != nil {
			return nil, err
		}
		actualID, actualOrg, kind, version, created, updated, raw, master, variables, blocks, fields, sanitization, measured, server = header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum
	} else {
		header, err := s.readFreshShareHeaderV1(ctx, id, org)
		if err != nil {
			return nil, err
		}
		actualID, actualOrg, kind, version, created, updated, raw, master, variables, blocks, fields, sanitization, measured, server = header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum
	}
	return s.readBodyV1(ctx, id, org, update, actualID, actualOrg, kind, version, created, updated, raw, master, variables, blocks, fields, sanitization, measured, server)
}
func (s *applicationPDFTemplateSourceStateV1) readBodyV1(ctx context.Context, id, org uuid.UUID, update bool, actualID, actualOrg uuid.UUID, kind string, version int32, created, updated pgtype.Timestamptz, raw, master, variables, blocks, fields, sanitization int64, measured, server int32) (*generated.Template, error) {
	if actualID != id || actualOrg != org || version < 1 || !applicationStampV1(created) || !applicationStampV1(updated) || raw < 0 {
		return nil, ErrPDFTemplateSourceV1
	}
	// The original caller maps this cheap real kind observation to its existing
	// source-kind refusal before any missing-cache/full-body admission failure.
	if kind != "pdf" {
		return nil, ErrPDFTemplateSourceKindV1
	}
	wire, err := htmlAuthoringSumV1(master, variables, blocks, fields, sanitization)
	if err != nil || measured < 1 || server < 1 || measured != server {
		return nil, ErrPDFTemplateSourceV1
	}
	typed := 2*int64(unsafe.Sizeof(generated.Template{})) + int64(unsafe.Sizeof(generated.PdfTemplateSourceSizesV1{})) + int64(unsafe.Sizeof(generated.ReadPDFTemplateSourceV1Params{}))
	rawWithHeaders, err := htmlAuthoringSumV1(raw, typed)
	if err != nil {
		return nil, err
	}
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, rawWithHeaders, wire)
	if err != nil {
		return nil, errors.Join(ErrPDFTemplateSourceV1, err)
	}
	s.closes = append(s.closes, close)
	tpl, err := s.queries.ReadPDFTemplateSourceV1(ctx, generated.ReadPDFTemplateSourceV1Params{TemplateID: id, OrgID: org, ExpectedCreatedAt: created, ExpectedUpdatedAt: updated, ExpectedVersion: version, ExpectedRawTextBytes: raw, ExpectedMasterWireBytes: master, ExpectedVariablesWireBytes: variables, ExpectedBlocksWireBytes: blocks, ExpectedFieldsWireBytes: fields, ExpectedSanitizationWireBytes: sanitization})
	if err != nil {
		return nil, err
	}
	if tpl == nil || tpl.ID != id || tpl.OrgID != org || tpl.SourceKind != "pdf" || tpl.Version != version || tpl.CreatedAt != created || tpl.UpdatedAt != updated {
		return nil, ErrPDFTemplateSourceV1
	}
	actualRaw, actualWire := htmlAuthoringTemplateBodyBytesV1(tpl)
	if actualRaw != raw || actualWire != wire || int64(len(tpl.HtmlMasterJson)) != master || int64(len(tpl.VariablesJson)) != variables || int64(len(tpl.BlocksJson)) != blocks || int64(len(tpl.FieldsJson)) != fields || int64(len(tpl.PdfSanitizationReport)) != sanitization {
		return nil, ErrPDFTemplateSourceV1
	}
	s.template = plainPDFCloneTemplateV1(tpl)
	s.updateLocked = update
	return tpl, nil
}
func (h *ApplicationPDFTemplateSourceV1) CloseConsumerV1() {
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
	s.template = nil
	s.lockedUpdateHeader = nil
	s.lockedShareHeader = nil
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}

// Full current Template detach helper for genuine native fresh/update owners.
// It grants neither old-source work nor template/actor/credential authority.
func plainPDFCloneTemplateV1(in *generated.Template) *generated.Template {
	if in == nil {
		return nil
	}
	out := *in
	out.Name = strings.Clone(in.Name)
	out.SourceKind = strings.Clone(in.SourceKind)
	out.PdfStorageKey.String = strings.Clone(in.PdfStorageKey.String)
	out.PdfStorageVersionID.String = strings.Clone(in.PdfStorageVersionID.String)
	out.PdfSha256 = bytes.Clone(in.PdfSha256)
	out.HtmlContentSha256 = bytes.Clone(in.HtmlContentSha256)
	out.HtmlMasterJson = bytes.Clone(in.HtmlMasterJson)
	out.BlocksJson = bytes.Clone(in.BlocksJson)
	out.VariablesJson = bytes.Clone(in.VariablesJson)
	out.FieldsJson = bytes.Clone(in.FieldsJson)
	out.PdfSanitizationReport = bytes.Clone(in.PdfSanitizationReport)
	return &out
}

// Two fixed steps preserve the original parent-lock then live-author/credential
// order while refusing missing/stale source measurements only before full body.
// The second step consumes solely this same native owner's genuine locked header.
func (h *ApplicationPDFTemplateSourceV1) LockUpdateHeaderV1(ctx context.Context, id uuid.UUID) error {
	if h == nil || h.state == nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || id == uuid.Nil || s.lockedUpdateHeader != nil || s.reads >= htmlAuthoringMaxReadsV1 {
		return ErrPDFTemplateSourceV1
	}
	s.reads++
	header, err := s.readFreshUpdateHeaderV1(ctx, id, s.session.state.org)
	if err != nil {
		return err
	}
	if header == nil || header.ID != id || header.OrgID != s.session.state.org {
		return ErrPDFTemplateSourceV1
	}
	if header.SourceKind != "pdf" {
		return ErrPDFTemplateSourceKindV1
	}
	s.lockedUpdateHeader = header
	return nil
}
func (h *ApplicationPDFTemplateSourceV1) ReadLockedUpdateV1(ctx context.Context) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	header := s.lockedUpdateHeader
	if !s.validV1(ctx) || header == nil || s.template != nil {
		return nil, ErrPDFTemplateSourceV1
	}
	return s.readBodyV1(ctx, header.ID, header.OrgID, true, header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum)
}

func (h *ApplicationPDFTemplateSourceV1) LockShareHeaderV1(ctx context.Context, id uuid.UUID) error {
	if h == nil || h.state == nil {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || id == uuid.Nil || s.lockedShareHeader != nil || s.reads >= htmlAuthoringMaxReadsV1 {
		return ErrPDFTemplateSourceV1
	}
	s.reads++
	header, err := s.readFreshShareHeaderV1(ctx, id, s.session.state.org)
	if err != nil {
		return err
	}
	if header == nil || header.ID != id || header.OrgID != s.session.state.org {
		return ErrPDFTemplateSourceV1
	}
	if header.SourceKind != "pdf" {
		return ErrPDFTemplateSourceKindV1
	}
	s.lockedShareHeader = header
	return nil
}
func (h *ApplicationPDFTemplateSourceV1) ReadLockedShareV1(ctx context.Context) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrPDFTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	header := s.lockedShareHeader
	if !s.validV1(ctx) || header == nil || s.template != nil {
		return nil, ErrPDFTemplateSourceV1
	}
	return s.readBodyV1(ctx, header.ID, header.OrgID, false, header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum)
}

// A READ COMMITTED locking statement can wait for a writer and return the new
// parent while its cache join still uses the statement's pre-wait snapshot.
// The first scalar read acquires the real parent lock. Exactly one fresh
// scalar read in that same transaction then sees the committed intrinsic cache
// before any body. This never measures, repairs, retries mutation or uses Pool.
func (s *applicationPDFTemplateSourceStateV1) readFreshShareHeaderV1(ctx context.Context, id, org uuid.UUID) (*generated.GetPDFTemplateSourceHeaderForShareV1Row, error) {
	p := generated.GetPDFTemplateSourceHeaderForShareV1Params{TemplateID: id, OrgID: org}
	locked, err := s.queries.GetPDFTemplateSourceHeaderForShareV1(ctx, p)
	if err != nil {
		return nil, err
	}
	if locked == nil || locked.ID != id || locked.OrgID != org {
		return nil, ErrPDFTemplateSourceV1
	}
	if locked.SourceKind != "pdf" {
		return nil, ErrPDFTemplateSourceKindV1
	}
	return s.queries.GetPDFTemplateSourceHeaderForShareV1(ctx, p)
}
func (s *applicationPDFTemplateSourceStateV1) readFreshUpdateHeaderV1(ctx context.Context, id, org uuid.UUID) (*generated.GetPDFTemplateSourceHeaderForUpdateV1Row, error) {
	p := generated.GetPDFTemplateSourceHeaderForUpdateV1Params{TemplateID: id, OrgID: org}
	locked, err := s.queries.GetPDFTemplateSourceHeaderForUpdateV1(ctx, p)
	if err != nil {
		return nil, err
	}
	if locked == nil || locked.ID != id || locked.OrgID != org {
		return nil, ErrPDFTemplateSourceV1
	}
	if locked.SourceKind != "pdf" {
		return nil, ErrPDFTemplateSourceKindV1
	}
	return s.queries.GetPDFTemplateSourceHeaderForUpdateV1(ctx, p)
}
