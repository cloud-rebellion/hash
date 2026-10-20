// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrHTMLAuthoringKindV1 = errors.New("pdfadmission: authoring target is not HTML")
var ErrHTMLAuthoringReadV1 = errors.New("pdfadmission: owned HTML authoring read unavailable")
var ErrHTMLAuthoringChangedV1 = errors.New("pdfadmission: expected HTML authoring pins changed")

const htmlAuthoringOtherWorkV1 int64 = 32 << 20
const htmlAuthoringMaxReadsV1 = 32

// A fixed native transaction owns every header, body projection and work loan.
// This object accepts neither cached length declarations nor external DBTXs.
// Original actor/credential/approval/CRM checks remain with the fixed handler.
// CloseConsumerV1 ends only buffer consumption; the original physical fence
// and the factory's retained registry govern real coordinator release.
type ApplicationHTMLAuthoringReaderV1 struct {
	self                                                       *ApplicationHTMLAuthoringReaderV1
	bodyHeader                                                 *applicationHTMLAuthoringBodyHeaderV1
	canonicalSources                                           [htmlAuthoringMaxReadsV1]htmlAuthoringCanonicalSourceV1
	canonicalCount                                             int
	mu                                                         sync.Mutex
	session                                                    *ApplicationSessionV1
	queries                                                    *generated.Queries
	closeConsumers                                             []func()
	reads                                                      int
	updateID                                                   uuid.UUID
	updateVersion                                              int32
	updateBlocksWire, updateFieldsWire, updateSanitizationWire int64
	closed                                                     bool
}

func htmlAuthoringResourcesV1(raw, wire int64) (ApplicationRequestPayloadResourcesV1, error) {
	if raw < 0 || wire < 0 || wire > (math.MaxInt64-htmlAuthoringOtherWorkV1)/16 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	db := 16*wire + htmlAuthoringOtherWorkV1
	if raw > (math.MaxInt64-db)/8 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: 8*raw + db, DBStagingBytes: db}, nil
}

// Registration precedes admission, atomically with factory shutdown snapshots.
// Its private identity prevents stale empty-registry removal, not retirement.
func (h *ApplicationSessionV1) acquireHTMLAuthoringV1(ctx context.Context, phase string, raw, wire int64) (func(), error) {
	return h.acquireHTMLAuthoringCoreV1(ctx, phase, raw, wire, nil)
}

// Caller is the actual one-shot WithModelsV1 owner, already holding reader.mu.
// Never acquire that mutex again beneath factory/session locks.
func (h *ApplicationSessionV1) acquireSignerReadModelsV1(ctx context.Context, phase string, raw, wire int64, reader *ApplicationSignerReaderV1) (func(), error) {
	if reader == nil || (phase != "locked-signer-read-header" && phase != "locked-signer-read-body") {
		return nil, ErrHTMLAuthoringReadV1
	}
	return h.acquireHTMLAuthoringCoreV1(ctx, phase, raw, wire, reader)
}

func (h *ApplicationSessionV1) acquireHTMLAuthoringCoreV1(ctx context.Context, phase string, raw, wire int64, reader *ApplicationSignerReaderV1) (func(), error) {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLAuthoringReadV1
	}
	r, err := htmlAuthoringResourcesV1(raw, wire)
	if err != nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	s := h.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer ||
		s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil ||
		!s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) ||
		a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone ||
		!s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s ||
		(p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLAuthoringReadV1
	}
	if reader != nil {
		_, registered := p.signerReaders[reader]
		if !registered || reader.self != reader || reader.factory == nil || reader.factory.state != p ||
			reader.creating || !reader.read || reader.consumerClosed || reader.released || reader.finishScope == nil ||
			reader.session != h || reader.admission != a || reader.scope.org != s.org || reader.scope.document != s.document {
			s.mu.Unlock()
			p.mu.Unlock()
			return nil, ErrHTMLAuthoringReadV1
		}
	}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	budget := ApplicationBudgetV1{Phase: phase, OrgID: s.org, DocumentID: s.document,
		HTMLAuthoringRawBytes: raw, HTMLAuthoringWireBytes: wire, WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes}
	var closeConsumer func()
	if reader == nil {
		closeConsumer, err = a.admit(ctx, budget)
	} else {
		var denial workguard.AdmissionDenialV1
		closeConsumer, err = a.admitCoreV1(ctx, budget, p.work, &denial)
		if denial != (workguard.AdmissionDenialV1{}) && !reader.diagnostic.captured {
			reader.diagnostic.denial, reader.diagnostic.captured = denial, true
		}
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrHTMLAuthoringReadV1, err)
	}
	return closeConsumer, nil
}

func (h *ApplicationSessionV1) NewHTMLAuthoringReaderV1(ctx context.Context) (*ApplicationHTMLAuthoringReaderV1, error) {
	closeConsumer, err := h.acquireHTMLAuthoringV1(ctx, "locked-html-authoring-header", 0, 0)
	if err != nil {
		return nil, err
	}
	reader := &ApplicationHTMLAuthoringReaderV1{session: h, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closeConsumers: []func(){closeConsumer}}
	reader.self = reader
	header := &applicationHTMLAuthoringBodyHeaderV1{reader: reader, session: h, admission: h.state.admission, fence: h.state.fence, loanClose: closeConsumer}
	header.self = header
	reader.bodyHeader = header
	return reader, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) valid(ctx context.Context) bool {
	if r == nil || r.self != r || r.session == nil || r.session.state == nil || r.queries == nil || r.closed || !applicationContextV1(ctx) {
		return false
	}
	s := r.session.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.unknown && !s.ended && !s.retired && s.callbackActive && !s.sqlActive && ctx.Value(applicationSessionCallbackKeyV1{}) == s
}
func (r *ApplicationHTMLAuthoringReaderV1) acquire(ctx context.Context, raw, wire int64) error {
	if !r.valid(ctx) || r.reads >= htmlAuthoringMaxReadsV1 {
		return ErrHTMLAuthoringReadV1
	}
	closeConsumer, err := r.acquireRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	r.closeConsumers = append(r.closeConsumers, closeConsumer)
	r.reads++
	return nil
}
func htmlAuthoringSumV1(values ...int64) (int64, error) {
	var total int64
	for _, n := range values {
		if n < 0 || n > math.MaxInt64-total {
			return 0, ErrHTMLAuthoringReadV1
		}
		total += n
	}
	return total, nil
}
func htmlAuthoringTemplateBodyBytesV1(t *generated.Template) (raw, wire int64) {
	if t == nil {
		return -1, -1
	}
	var err error
	raw, err = htmlAuthoringSumV1(int64(len(t.Name)), int64(len(t.SourceKind)), int64(len(t.PdfStorageKey.String)), int64(len(t.PdfStorageVersionID.String)), int64(len(t.PdfSha256)), int64(len(t.HtmlContentSha256)))
	if err != nil {
		return -1, -1
	}
	wire, err = htmlAuthoringSumV1(int64(len(t.HtmlMasterJson)), int64(len(t.VariablesJson)), int64(len(t.BlocksJson)), int64(len(t.FieldsJson)), int64(len(t.PdfSanitizationReport)))
	if err != nil {
		return -1, -1
	}
	return raw, wire
}

type htmlAuthoringExpectedTemplatePinsV1 struct {
	version     int32
	digest      [32]byte
	matchDigest bool
}

func (r *ApplicationHTMLAuthoringReaderV1) readTemplate(ctx context.Context, id uuid.UUID, update bool) (*generated.Template, error) {
	return r.readTemplateExpectedV1(ctx, id, update, nil)
}

func (r *ApplicationHTMLAuthoringReaderV1) readTemplateExpectedV1(ctx context.Context, id uuid.UUID, update bool, expected *htmlAuthoringExpectedTemplatePinsV1) (*generated.Template, error) {
	if !r.valid(ctx) || id == uuid.Nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	org := r.session.state.org
	// Parent and cache locks are taken by the actual cheap header query. Every
	// subsequent body is read in this same native transaction under those locks.
	var version int32
	var content []byte
	var raw, master, variables, blocks, fields, sanitization int64
	var measured, server int32
	if update {
		h, err := r.queries.GetHTMLAuthoringTemplateHeaderForUpdateV1(ctx, generated.GetHTMLAuthoringTemplateHeaderForUpdateV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return nil, err
		}
		content = h.ContentSha256
		version, raw, master, variables, blocks, fields, sanitization, measured, server = h.Version, h.RawTextBytes, h.MasterWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.FieldsWireBytes, h.SanitizationWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum
	} else {
		h, err := r.queries.GetHTMLAuthoringTemplateHeaderV1(ctx, generated.GetHTMLAuthoringTemplateHeaderV1Params{TemplateID: id, OrgID: org})
		if err != nil {
			return nil, err
		}
		content = h.ContentSha256
		version, raw, master, variables, blocks, fields, sanitization, measured, server = h.Version, h.RawTextBytes, h.MasterWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.FieldsWireBytes, h.SanitizationWireBytes, h.MeasurementServerVersionNum, h.ServerVersionNum
	}
	// Expected observations are checked against this SAME locked scalar header
	// before cache/body admission. A real changed revision is a conflict even
	// when its genuine update invalidated the cache; unchanged missing caches
	// remain unavailable and never cause an expanded body read or refresh.
	if expected != nil {
		if version <= 0 {
			return nil, ErrHTMLAuthoringReadV1
		}
		if version != expected.version {
			return nil, ErrHTMLAuthoringChangedV1
		}
		if len(content) != 32 {
			return nil, ErrHTMLAuthoringReadV1
		}
		if expected.matchDigest && !bytes.Equal(content, expected.digest[:]) {
			return nil, ErrHTMLAuthoringChangedV1
		}
	}
	wire, err := htmlAuthoringSumV1(master, variables, blocks, fields, sanitization)
	if err != nil || measured <= 0 || measured != server || version <= 0 || raw < 0 {
		return nil, ErrHTMLAuthoringReadV1
	}
	if err = r.acquire(ctx, raw, wire); err != nil {
		return nil, err
	}
	// The whole actual model is charged; no fabricated or NULL source sentinel.
	t, err := r.queries.ReadHTMLAuthoringTemplateV1(ctx, generated.ReadHTMLAuthoringTemplateV1Params{TemplateID: id, OrgID: org, ExpectedVersion: version, ExpectedContentSha256: content, ExpectedMasterWireBytes: master, ExpectedVariablesWireBytes: variables, ExpectedBlocksWireBytes: blocks, ExpectedFieldsWireBytes: fields, ExpectedSanitizationWireBytes: sanitization})
	if err != nil {
		return nil, err
	}
	actualRaw, actualWire := htmlAuthoringTemplateBodyBytesV1(t)
	if t.ID != id || t.OrgID != org || t.Version != version || actualRaw != raw || actualWire != wire ||
		int64(len(t.HtmlMasterJson)) != master || int64(len(t.VariablesJson)) != variables || int64(len(t.BlocksJson)) != blocks ||
		int64(len(t.FieldsJson)) != fields || int64(len(t.PdfSanitizationReport)) != sanitization {
		return nil, ErrHTMLAuthoringReadV1
	}
	if !update {
		if err = r.rememberCanonicalSourceV1(t.ID, t.Version, false, t.HtmlMasterJson, t.VariablesJson, t.HtmlContentSha256); err != nil {
			return nil, err
		}
	}
	if update {
		r.updateID, r.updateVersion, r.updateBlocksWire, r.updateFieldsWire, r.updateSanitizationWire = id, version, blocks, fields, sanitization
	}
	return t, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) ReadTemplateForUpdateV1(ctx context.Context, id uuid.UUID) (*generated.Template, error) {
	return r.readTemplateForUpdateExpectedV1(ctx, id, nil)
}

// UPDATE carries the original public expected_version pin; comparison occurs
// under the actual parent UPDATE lock before any expanded model/cache grant.
func (r *ApplicationHTMLAuthoringReaderV1) ReadTemplateForUpdateExpectedV1(ctx context.Context, id uuid.UUID, version int32) (*generated.Template, error) {
	if version <= 0 {
		return nil, ErrHTMLAuthoringReadV1
	}
	return r.readTemplateForUpdateExpectedV1(ctx, id, &htmlAuthoringExpectedTemplatePinsV1{version: version})
}

func (r *ApplicationHTMLAuthoringReaderV1) readTemplateForUpdateExpectedV1(ctx context.Context, id uuid.UUID, expected *htmlAuthoringExpectedTemplatePinsV1) (*generated.Template, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t, err := r.readTemplateExpectedV1(ctx, id, true, expected)
	if errors.Is(err, pgx.ErrNoRows) && r.valid(ctx) {
		isHTML, kindErr := r.queries.GetHTMLAuthoringTargetKindForUpdateV1(ctx, generated.GetHTMLAuthoringTargetKindForUpdateV1Params{TemplateID: id, OrgID: r.session.state.org})
		if kindErr != nil {
			return nil, kindErr
		}
		if !isHTML {
			return nil, ErrHTMLAuthoringKindV1
		}
	}
	return t, err
}
func (r *ApplicationHTMLAuthoringReaderV1) ReadTemplateRevisionV1(ctx context.Context, id uuid.UUID, version int32) (*generated.Template, *generated.HtmlTemplateRevision, error) {
	return r.readTemplateRevisionExpectedV1(ctx, id, version, nil)
}

// This fixed path binds caller expectations only to actual locked M92 scalar
// pins. Expectations confer no body size, cache validity or work authority.
func (r *ApplicationHTMLAuthoringReaderV1) ReadTemplateRevisionExpectedV1(ctx context.Context, id uuid.UUID, version int32, contentSHA256 string) (*generated.Template, *generated.HtmlTemplateRevision, error) {
	if version <= 0 || len(contentSHA256) != 64 {
		return nil, nil, ErrHTMLAuthoringReadV1
	}
	decoded, err := hex.DecodeString(contentSHA256)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != contentSHA256 {
		return nil, nil, ErrHTMLAuthoringReadV1
	}
	expected := htmlAuthoringExpectedTemplatePinsV1{version: version, matchDigest: true}
	copy(expected.digest[:], decoded)
	return r.readTemplateRevisionExpectedV1(ctx, id, version, &expected)
}

func (r *ApplicationHTMLAuthoringReaderV1) readTemplateRevisionExpectedV1(ctx context.Context, id uuid.UUID, version int32, expected *htmlAuthoringExpectedTemplatePinsV1) (*generated.Template, *generated.HtmlTemplateRevision, error) {
	if r == nil || r.self != r {
		return nil, nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t, err := r.readTemplateExpectedV1(ctx, id, false, expected)
	if err != nil {
		return nil, nil, err
	}
	h, err := r.queries.GetHTMLAuthoringRevisionHeaderV1(ctx, generated.GetHTMLAuthoringRevisionHeaderV1Params{TemplateID: id, OrgID: t.OrgID, Version: version})
	if err != nil {
		return nil, nil, err
	}
	if expected != nil {
		if len(h.ContentSha256) != 32 {
			return nil, nil, ErrHTMLAuthoringReadV1
		}
		if !bytes.Equal(h.ContentSha256, expected.digest[:]) {
			return nil, nil, ErrHTMLAuthoringChangedV1
		}
	}
	wire, err := htmlAuthoringSumV1(h.MasterWireBytes, h.VariablesWireBytes)
	if err != nil || h.MeasurementServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum {
		return nil, nil, ErrHTMLAuthoringReadV1
	}
	if err = r.acquire(ctx, 32, wire); err != nil {
		return nil, nil, err
	}
	revision, err := r.queries.ReadHTMLAuthoringRevisionV1(ctx, generated.ReadHTMLAuthoringRevisionV1Params{TemplateID: id, OrgID: t.OrgID, Version: version, ExpectedContentSha256: h.ContentSha256, ExpectedMasterWireBytes: h.MasterWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes})
	if err != nil {
		return nil, nil, err
	}
	if revision.TemplateID != id || revision.OrgID != t.OrgID || revision.Version != version || len(revision.ContentSha256) != 32 ||
		int64(len(revision.HtmlMasterJson)) != h.MasterWireBytes || int64(len(revision.VariablesJson)) != h.VariablesWireBytes {
		return nil, nil, ErrHTMLAuthoringReadV1
	}
	if err = r.rememberCanonicalSourceV1(id, version, true, revision.HtmlMasterJson, revision.VariablesJson, revision.ContentSha256); err != nil {
		return nil, nil, err
	}
	return t, revision, nil
}

// Input maps are actual typed string maps. Count strings without Marshal or
// copies before the native loan; 6x is valid here only because every token is
// a string. It is never applied to unrestricted JSON numbers or RawMessage.
func htmlAuthoringStringMapCostV1(ctx context.Context, m map[string]string) (raw, wire int64, err error) {
	if !applicationContextV1(ctx) {
		return 0, 0, ErrHTMLAuthoringReadV1
	}
	wire = 2
	for k, v := range m {
		if !htmlAuthoringUTF8V1(ctx, k) || !htmlAuthoringUTF8V1(ctx, v) {
			return 0, 0, ErrHTMLAuthoringReadV1
		}
		n, err := htmlAuthoringSumV1(int64(len(k)), int64(len(v)))
		if err != nil || n > (math.MaxInt64-8)/6 {
			return 0, 0, ErrHTMLAuthoringReadV1
		}
		raw, err = htmlAuthoringSumV1(raw, n)
		if err != nil {
			return 0, 0, err
		}
		wire, err = htmlAuthoringSumV1(wire, 6*n+8)
		if err != nil {
			return 0, 0, err
		}
	}
	return raw, wire, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) AcquireStringMapsV1(ctx context.Context, values, sections map[string]string) error {
	if r == nil || r.self != r {
		return ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw1, wire1, err := htmlAuthoringStringMapCostV1(ctx, values)
	if err != nil {
		return err
	}
	raw2, wire2, err := htmlAuthoringStringMapCostV1(ctx, sections)
	if err != nil {
		return err
	}
	raw, err := htmlAuthoringSumV1(raw1, raw2)
	if err != nil {
		return err
	}
	wire, err := htmlAuthoringSumV1(wire1, wire2)
	if err != nil {
		return err
	}
	return r.acquire(ctx, raw, wire)
}
func (r *ApplicationHTMLAuthoringReaderV1) CloseConsumerV1() {
	if r == nil || r.self != r {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	r.closed = true
	if r.bodyHeader != nil {
		r.bodyHeader.closed.Store(true)
	}
	// Final source use has ended. Drop retained source/canonical references before
	// releasing their component loans; shutdown never closes these consumers.
	r.canonicalSources = [htmlAuthoringMaxReadsV1]htmlAuthoringCanonicalSourceV1{}
	r.canonicalCount = 0
	for _, closeConsumer := range r.closeConsumers {
		closeConsumer()
	}
	r.closeConsumers = nil
}

// Only this actual locked header may size the current authorized replay view.
// Source presence/review facts are projected as booleans, never source sentinels.
func (r *ApplicationHTMLAuthoringReaderV1) ReadCreationResponseV1(ctx context.Context, id uuid.UUID) (*generated.ReadHTMLCreationResponseV1Row, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || id == uuid.Nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	h, err := r.queries.GetHTMLCreationResponseHeaderV1(ctx, generated.GetHTMLCreationResponseHeaderV1Params{DocumentID: id, OrgID: r.session.state.org})
	if err != nil {
		return nil, err
	}
	wire, err := htmlAuthoringSumV1(h.BlocksWireBytes, h.VariablesWireBytes, h.MetadataWireBytes)
	if err != nil || h.RawTextBytes < 0 || h.MeasurementServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum || h.PolicyMeasurementServerVersionNum != h.ServerVersionNum {
		return nil, ErrHTMLAuthoringReadV1
	}
	if err = r.acquire(ctx, h.RawTextBytes, wire); err != nil {
		return nil, err
	}
	row, err := r.queries.ReadHTMLCreationResponseV1(ctx, generated.ReadHTMLCreationResponseV1Params{DocumentID: id, OrgID: r.session.state.org, ExpectedUpdatedAt: h.UpdatedAt,
		ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes})
	if err != nil {
		return nil, err
	}
	raw, err := htmlAuthoringSumV1(int64(len(row.Name)), int64(len(row.Status)), int64(len(row.RoutingMode)), int64(len(row.SourceKind)), int64(len(row.PdfStorageKey.String)), int64(len(row.PdfSha256)), int64(len(row.FinalPdfKey.String)), int64(len(row.AuditCertKey.String)), int64(len(row.DefaultLocale)), int64(len(row.HtmlEffectiveSourceCommitment.String)))
	if err != nil {
		return nil, err
	}
	if row.ID != id || row.OrgID != r.session.state.org || raw != h.RawTextBytes || int64(len(row.BlocksJson)) != h.BlocksWireBytes || int64(len(row.VariablesJson)) != h.VariablesWireBytes || int64(len(row.Metadata)) != h.MetadataWireBytes {
		return nil, ErrHTMLAuthoringReadV1
	}
	return row, nil
}

// Actor/org TEXT lengths come from actual row-locking scalar projections; a
// copied user, cookie or caller size hint cannot supply the working-set loan.
func (r *ApplicationHTMLAuthoringReaderV1) AcquireActorV1(ctx context.Context, org, user uuid.UUID, owner bool) error {
	if r == nil || r.self != r {
		return ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || user == uuid.Nil || org != r.session.state.org {
		return ErrHTMLAuthoringReadV1
	}
	var raw int64
	if owner {
		h, err := r.queries.GetHTMLAuthoringOwnerHeaderV1(ctx, generated.GetHTMLAuthoringOwnerHeaderV1Params{UserID: user, OrgID: r.session.state.org})
		if err != nil {
			return err
		}
		if h.UserID != user || h.OrgID != org {
			return ErrHTMLAuthoringReadV1
		}
		raw = h.RawTextBytes
	} else {
		h, err := r.queries.GetHTMLAuthoringActorHeaderV1(ctx, generated.GetHTMLAuthoringActorHeaderV1Params{UserID: user, OrgID: r.session.state.org})
		if err != nil {
			return err
		}
		if h.UserID != user || h.OrgID != org {
			return ErrHTMLAuthoringReadV1
		}
		raw = h.RawTextBytes
	}
	return r.acquire(ctx, raw, 0)
}

func (r *ApplicationHTMLAuthoringReaderV1) ReadCRMConnectionV1(ctx context.Context) (*generated.CrmConnection, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return nil, ErrHTMLAuthoringReadV1
	}
	h, err := r.queries.GetHTMLAuthoringCRMConnectionHeaderV1(ctx, r.session.state.org)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = r.acquire(ctx, h.RawTextBytes, 0); err != nil {
		return nil, err
	}
	row, err := r.queries.GetCRMConnectionByOrgForShare(ctx, r.session.state.org)
	if err != nil {
		return nil, err
	}
	raw, err := htmlAuthoringSumV1(int64(len(row.Status)), int64(len(row.Origin)), int64(len(row.CrmTeamID)), int64(len(row.CrmUserID)), int64(len(row.CredentialCiphertext)))
	if err != nil {
		return nil, err
	}
	if row.ID != h.ID || row.OrgID != h.OrgID || row.OrgID != r.session.state.org || raw != h.RawTextBytes {
		return nil, ErrHTMLAuthoringReadV1
	}
	return row, nil
}

func htmlAuthoringUTF8V1(ctx context.Context, text string) bool {
	next := 0
	for offset := 0; offset < len(text); {
		if offset >= next {
			if ctx.Err() != nil {
				return false
			}
			next = offset + 4096
		}
		runeValue, width := utf8.DecodeRuneInString(text[offset:])
		if runeValue == utf8.RuneError && width == 1 {
			return false
		}
		offset += width
	}
	return ctx.Err() == nil
}
