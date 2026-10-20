// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrBlocksTemplateSourceV1 = errors.New("pdfadmission: owned block template source unavailable")
var ErrBlocksTemplateSourceKindV1 = errors.New("pdfadmission: target is not a block template")

// Real full template reads use the separate M97 source cache. This owner
// never calls a measurement, borrows a Pool/Tx or adopts a caller Template.
// Both the response consumer and original native client/backend must retire.
type ApplicationBlocksTemplateSourceV1 struct {
	state *applicationBlocksTemplateSourceStateV1
}
type applicationBlocksTemplateSourceStateV1 struct {
	mu                     sync.Mutex
	session                *ApplicationSessionV1
	reader                 *ApplicationHTMLAuthoringReaderV1
	queries                *generated.Queries
	closes                 []func()
	closed, consumerClosed bool
	borrowers              int
	digestWork             *ApplicationBlocksCreationWriterV1
	automationSeed         *AutomationBlockSeedV1
	automationVariables    map[string]string
	content                *templatepin.Content
	template               *generated.Template
	update                 bool
	reads                  int
}

func (h *ApplicationSessionV1) NewBlocksTemplateSourceV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationBlocksTemplateSourceV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrBlocksTemplateSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationBlocksTemplateSourceStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationBlocksTemplateSourceV1{})) + 2*int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForShareV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForShareV1Params{})) + 2*int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{}))
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrBlocksTemplateSourceV1, err)
	}
	return &ApplicationBlocksTemplateSourceV1{state: &applicationBlocksTemplateSourceStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationBlocksTemplateSourceStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && !s.consumerClosed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (h *ApplicationBlocksTemplateSourceV1) GetTemplateForShare(ctx context.Context, p generated.GetTemplateForShareParams) (*generated.Template, error) {
	return h.readV1(ctx, p.ID, p.OrgID, false, nil)
}
func (h *ApplicationBlocksTemplateSourceV1) GetTemplateForUpdate(ctx context.Context, p generated.GetTemplateForUpdateParams) (*generated.Template, error) {
	return h.readV1(ctx, p.ID, p.OrgID, true, nil)
}
func (h *ApplicationBlocksTemplateSourceV1) readV1(ctx context.Context, id, org uuid.UUID, update bool, afterHeader func(context.Context) error) (*generated.Template, error) {
	if h == nil || h.state == nil {
		return nil, ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || id == uuid.Nil || org != s.session.state.org || s.reads != 0 {
		return nil, ErrBlocksTemplateSourceV1
	}
	s.reads++
	var actualID, actualOrg uuid.UUID
	var kind string
	var version int32
	var created, updated pgtype.Timestamptz
	var raw, master, variables, blocks, fields, sanitization int64
	var measured, server int32
	if update {
		header, err := s.queries.GetNonHTMLTemplateSourceHeaderForUpdateV1(ctx, generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return nil, err
		}
		actualID, actualOrg, kind, version, created, updated, raw, master, variables, blocks, fields, sanitization, measured, server = header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum
	} else {
		header, err := s.queries.GetNonHTMLTemplateSourceHeaderForShareV1(ctx, generated.GetNonHTMLTemplateSourceHeaderForShareV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return nil, err
		}
		actualID, actualOrg, kind, version, created, updated, raw, master, variables, blocks, fields, sanitization, measured, server = header.ID, header.OrgID, header.SourceKind, header.Version, header.CreatedAt, header.UpdatedAt, header.RawTextBytes, header.MasterWireBytes, header.VariablesWireBytes, header.BlocksWireBytes, header.FieldsWireBytes, header.SanitizationWireBytes, header.MeasurementServerVersionNum, header.ServerVersionNum
	}
	if actualID != id || actualOrg != org || version < 1 || !applicationStampV1(created) || !applicationStampV1(updated) || raw < 0 {
		return nil, ErrBlocksTemplateSourceV1
	}
	// The original caller maps this cheap real kind observation to its existing
	// source-kind refusal before any missing-cache/full-body admission failure.
	if kind != "blocks" {
		return nil, ErrBlocksTemplateSourceKindV1
	}
	if afterHeader != nil {
		if err := afterHeader(ctx); err != nil {
			return nil, err
		}
	}
	wire, err := htmlAuthoringSumV1(master, variables, blocks, fields, sanitization)
	if err != nil || measured < 1 || server < 1 || measured != server {
		return nil, ErrBlocksTemplateSourceV1
	}
	typed := 2*int64(unsafe.Sizeof(generated.Template{})) + int64(unsafe.Sizeof(generated.PdfTemplateSourceSizesV1{})) + int64(unsafe.Sizeof(generated.ReadNonHTMLTemplateSourceV1Params{}))
	rawWithHeaders, err := htmlAuthoringSumV1(raw, typed)
	if err != nil {
		return nil, err
	}
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, rawWithHeaders, wire)
	if err != nil {
		return nil, errors.Join(ErrBlocksTemplateSourceV1, err)
	}
	s.closes = append(s.closes, close)
	tpl, err := s.queries.ReadNonHTMLTemplateSourceV1(ctx, generated.ReadNonHTMLTemplateSourceV1Params{TemplateID: id, OrgID: org, ExpectedSourceKind: "blocks", ExpectedCreatedAt: created, ExpectedUpdatedAt: updated, ExpectedVersion: version, ExpectedRawTextBytes: raw, ExpectedMasterWireBytes: master, ExpectedVariablesWireBytes: variables, ExpectedBlocksWireBytes: blocks, ExpectedFieldsWireBytes: fields, ExpectedSanitizationWireBytes: sanitization})
	if err != nil {
		return nil, err
	}
	if tpl == nil || tpl.ID != id || tpl.OrgID != org || tpl.SourceKind != "blocks" || tpl.Version != version || tpl.CreatedAt != created || tpl.UpdatedAt != updated {
		return nil, ErrBlocksTemplateSourceV1
	}
	actualRaw, actualWire := htmlAuthoringTemplateBodyBytesV1(tpl)
	if actualRaw != raw || actualWire != wire || int64(len(tpl.HtmlMasterJson)) != master || int64(len(tpl.VariablesJson)) != variables || int64(len(tpl.BlocksJson)) != blocks || int64(len(tpl.FieldsJson)) != fields || int64(len(tpl.PdfSanitizationReport)) != sanitization {
		return nil, ErrBlocksTemplateSourceV1
	}
	s.template = plainPDFCloneTemplateV1(tpl)
	s.update = update
	return tpl, nil
}
func (s *applicationBlocksTemplateSourceStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || s.borrowers != 0 {
		return
	}
	s.closed = true
	s.template = nil
	s.content = nil
	s.automationSeed = nil
	s.automationVariables = nil
	if s.digestWork != nil {
		s.digestWork.CloseConsumerV1()
		s.digestWork = nil
	}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func (h *ApplicationBlocksTemplateSourceV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}
func (s *applicationBlocksTemplateSourceStateV1) borrowV1(ctx context.Context, session *ApplicationSessionV1, reader *ApplicationHTMLAuthoringReaderV1) (*generated.Template, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.consumerClosed || s.session != session || s.reader != reader || s.template == nil {
		return nil, nil, ErrBlocksTemplateSourceV1
	}
	s.borrowers++
	snapshot := s.template
	var once sync.Once
	release := func() { once.Do(func() { s.mu.Lock(); s.borrowers--; s.releaseIfCompleteV1(); s.mu.Unlock() }) }
	return snapshot, release, nil
}

func (h *ApplicationBlocksTemplateSourceV1) CanonicalContentV1(ctx context.Context) (templatepin.Content, error) {
	if h == nil || h.state == nil {
		return templatepin.Content{}, ErrBlocksTemplateSourceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.template == nil {
		return templatepin.Content{}, ErrBlocksTemplateSourceV1
	}
	if s.content != nil {
		return *s.content, nil
	}
	var err error
	if s.digestWork == nil {
		s.digestWork, err = s.session.NewBlocksCreationWriterV1(ctx, s.reader)
		if err != nil {
			return templatepin.Content{}, err
		}
	}
	content, err := s.digestWork.state.canonicalContentV1(ctx, s.template)
	if err != nil {
		return templatepin.Content{}, err
	}
	s.content = &content
	return content, nil
}

func (s *applicationBlocksTemplateSourceStateV1) borrowUpdateV1(ctx context.Context, session *ApplicationSessionV1, reader *ApplicationHTMLAuthoringReaderV1) (*generated.Template, func(), error) {
	tpl, release, err := s.borrowV1(ctx, session, reader)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	update := s.update
	s.mu.Unlock()
	if !update {
		release()
		return nil, nil, ErrBlocksTemplateSourceV1
	}
	return tpl, release, nil
}

// The actual parent lock precedes the caller's original live member/credential
// guard; protected cache/body admission follows that guard without a lock gap.
func (h *ApplicationBlocksTemplateSourceV1) GetTemplateForUpdateAfterHeaderV1(ctx context.Context, p generated.GetTemplateForUpdateParams, guard func(context.Context) error) (*generated.Template, error) {
	if guard == nil {
		return nil, ErrBlocksTemplateSourceV1
	}
	return h.readV1(ctx, p.ID, p.OrgID, true, guard)
}
func (h *ApplicationBlocksTemplateSourceV1) GetTemplateForShareAfterHeaderV1(ctx context.Context, p generated.GetTemplateForShareParams, guard func(context.Context) error) (*generated.Template, error) {
	if guard == nil {
		return nil, ErrBlocksTemplateSourceV1
	}
	return h.readV1(ctx, p.ID, p.OrgID, false, guard)
}

type AutomationBlockSeedV1 struct {
	BlocksJSON, VariablesJSON json.RawMessage
	ContentSHA256             string
	TemplateVersion           int32
}

// This concrete automation source stage preserves the actual pinned template's
// prose and merges variable values into that approved template. It clones defaults before
// overrides, funds original map/output/preflight work before allocation, and
// lends the SAME actual numeric admission through the unchanged pure validator.
func (h *ApplicationBlocksTemplateSourceV1) WithAutomationSeedV1(ctx context.Context, overrides map[string]string, values []recipients.Values, preflight func([]byte, []byte, []recipients.Values, blocks.ConditionalSendAdmissionV1) error) (AutomationBlockSeedV1, error) {
	if h == nil || h.state == nil || preflight == nil || len(values) < 1 || len(values) > 50 {
		return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
	}
	content, err := h.CanonicalContentV1(ctx)
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.template == nil || s.automationSeed != nil || s.digestWork == nil {
		return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
	}
	pairs := int64(len(content.DefaultVariables)) + int64(len(overrides))
	raw := int64(unsafe.Sizeof(AutomationBlockSeedV1{})) + 4*int64(unsafe.Sizeof(map[string]string{}))
	upper := int64(2)
	for _, variables := range []map[string]string{content.DefaultVariables, overrides} {
		for name, value := range variables {
			n, e := htmlAuthoringSumV1(int64(len(name)), int64(len(value)))
			if e != nil || !htmlInputAddV1(&raw, n, 2) || !htmlInputAddV1(&upper, n, 6) || !htmlInputAddV1(&upper, 1, 8) {
				return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
			}
		}
	}
	if !htmlInputAddV1(&raw, pairs, 8*int64(unsafe.Sizeof(""))+8*int64(unsafe.Sizeof(uintptr(0)))) || !htmlInputAddV1(&raw, int64(len(values)), 4*int64(unsafe.Sizeof(recipients.Values{}))+4*int64(unsafe.Sizeof(generated.Recipient{}))) || !htmlInputAddV1(&raw, upper, 1) {
		return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
	}
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	s.closes = append(s.closes, close)
	merged := make(map[string]string, len(content.DefaultVariables)+len(overrides))
	for name, value := range content.DefaultVariables {
		merged[strings.Clone(name)] = strings.Clone(value)
	}
	for name, value := range overrides {
		merged[strings.Clone(name)] = strings.Clone(value)
	}
	s.automationVariables = merged
	variablesJSON, err := json.Marshal(merged)
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	if int64(len(variablesJSON)) > upper {
		return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
	}
	lexical, err := plainSendBlockLexicalWorkV1(ctx, content.BlocksJSON)
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	vars, e := plainSendBlockLexicalWorkV1(ctx, variablesJSON)
	if e != nil {
		return AutomationBlockSeedV1{}, e
	}
	if !htmlInputAddV1(&lexical, vars, 1) || lexical > int64(^uint64(0)>>1)/4 {
		return AutomationBlockSeedV1{}, ErrBlocksTemplateSourceV1
	}
	close, err = s.reader.acquireOwnedRetainedBodyV1(ctx, 4*lexical, 0)
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	s.closes = append(s.closes, close)
	work := s.digestWork.state
	work.mu.Lock()
	defer work.mu.Unlock()
	work.processing = true
	work.decimalPeak = 0
	defer func() { work.processing = false }()
	if err = preflight(content.BlocksJSON, variablesJSON, values, blocksCreationDecimalAdmissionV1{state: work, ctx: ctx}); work.admissionFailure != nil {
		return AutomationBlockSeedV1{}, work.admissionFailure
	}
	if err != nil {
		return AutomationBlockSeedV1{}, err
	}
	seed := AutomationBlockSeedV1{BlocksJSON: content.BlocksJSON, VariablesJSON: variablesJSON, ContentSHA256: content.SHA256Hex(), TemplateVersion: s.template.Version}
	s.automationSeed = &seed
	return seed, nil
}
