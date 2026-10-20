// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
)

// This private store is born only inside a genuine final Send callback. Every
// original policy read still executes at its original point, under this native
// document/collection lock scope. The scalar controls grant bodies; none of
// their observations are substituted for an original policy decision.
type htmlSendCRMPolicyReadsV1 struct {
	work *ApplicationHTMLSendWorkV1
	ctx  context.Context
}

func (r *htmlSendCRMPolicyReadsV1) validV1(ctx context.Context) bool {
	return r != nil && r.work != nil && r.work.self == r.work && ctx == r.ctx
}
func (r *htmlSendCRMPolicyReadsV1) GetDocumentCRMMappingReviewForShare(ctx context.Context, a generated.GetDocumentCRMMappingReviewForShareParams) (*generated.DocumentCrmMappingReview, error) {
	if !r.validV1(ctx) {
		return nil, ErrHTMLSendWorkV1
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || a.DocumentID != w.logicalDocumentV1() || a.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	h, err := w.queries.GetHTMLSendCRMReviewReadHeaderV1(ctx, generated.GetHTMLSendCRMReviewReadHeaderV1Params{DocumentID: a.DocumentID, OrgID: a.OrgID})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != a.DocumentID || h.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.ReadHTMLSendCRMReviewV1(ctx, generated.ReadHTMLSendCRMReviewV1Params{DocumentID: a.DocumentID, OrgID: a.OrgID, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != a.DocumentID || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || int64(len(row.BindingDigest)+len(row.ContentCommitment)+len(row.Origin)+len(row.CrmTeamID)+len(row.CrmUserID)) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	return row, nil
}
func (r *htmlSendCRMPolicyReadsV1) DocumentHasCRMBindings(ctx context.Context, a generated.DocumentHasCRMBindingsParams) (bool, error) {
	if !r.validV1(ctx) {
		return false, ErrHTMLSendWorkV1
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || a.DocumentID != w.logicalDocumentV1() || a.OrgID != w.session.state.org {
		return false, ErrHTMLSendWorkV1
	}
	return w.queries.DocumentHasCRMBindings(ctx, a)
}
func (r *htmlSendCRMPolicyReadsV1) ListCRMMappingBindingsForShare(ctx context.Context, a generated.ListCRMMappingBindingsForShareParams) ([]*generated.DocumentVariableBinding, error) {
	if !r.validV1(ctx) {
		return nil, ErrHTMLSendWorkV1
	}
	w := r.work
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || a.DocumentID != w.logicalDocumentV1() || a.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	// Original bounded129 query remains the policy source. Its raw upper is the
	// genuine current complete ledger, freshly observed after any own observation
	// writes; empty/manual rows do not gain a new legal member limit.
	h, err := w.queries.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: a.DocumentID, OrgID: a.OrgID})
	if err != nil {
		return nil, err
	}
	if h == nil || h.BindingCount < 0 || h.BindingRawBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.BindingRawBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	rows, err := w.queries.ListCRMMappingBindingsForShare(ctx, a)
	if err != nil {
		return nil, err
	}
	if len(rows) > crmreview.MaxBindings+1 {
		return nil, ErrHTMLSendWorkV1
	}
	raw := int64(0)
	for _, b := range rows {
		if b == nil || b.DocumentID != a.DocumentID {
			return nil, ErrHTMLSendWorkV1
		}
		if !htmlInputAddV1(&raw, int64(len(b.VariableName)+len(b.SourceKind)+len(b.SourceRef)+len(b.SourcePath)+len(b.Fallback)+len(b.LastValue)+len(b.LastError)), 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if raw > h.BindingRawBytes {
		return nil, ErrHTMLSendWorkV1
	}
	return rows, nil
}
func (r *htmlSendCRMPolicyReadsV1) GetCRMConnectionByOrgForShare(ctx context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	if !r.validV1(ctx) || r.work.session == nil || org != r.work.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	return r.work.readCRMSourceV1(ctx)
}

// CheckCRMReviewV1 is called at each of the TWO original final-transaction
// check points. Reports can only come from this SAME operation's actual opaque
// resolver, while original source/doc pins remain this locked native Work.
func (w *ApplicationHTMLSendWorkV1) CheckCRMReviewV1(call context.Context, h *ApplicationHTMLSendSourceV1, resolution *ApplicationHTMLSendResolutionV1) error {
	if w == nil || w.self != w || h == nil || h.state == nil || h.state.work != w || h.state.candidate {
		return ErrHTMLSendWorkV1
	}
	state := h.state
	if !state.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.owner == nil {
		return ErrHTMLSendWorkV1
	}
	owner := state.owner
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	w.mu.Lock()
	if !w.valid(call) || w.sourceOwner != owner || w.sourceDocument == nil || w.crmReviewChecks >= 2 {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.crmReviewChecks++
	doc := w.sourceDocument
	w.mu.Unlock()
	var reports []resolver.ResolveReport
	if resolution != nil {
		p := resolution.state
		if p == nil {
			return ErrHTMLSendWorkV1
		}
		p.mu.Lock()
		if !p.liveV1() || !p.attempted || p.failure != nil || p.active != 0 || p.work.stage.operation != w.stage.operation || p.document.ID != doc.ID || p.document.OrgID != doc.OrgID {
			p.mu.Unlock()
			return ErrHTMLSendWorkV1
		}
		p.active++
		reports = p.crmReports
		p.mu.Unlock()
		defer func() { p.mu.Lock(); p.active--; p.retireV1(); p.mu.Unlock() }()
	}
	// A fixed continuation clone is funded before Begin allocates it. Native
	// body grants separately cover each actual review/connection/ledger result.
	retained, err := htmlSendCRMContinuationLogicalV1(owner.binding.ctx, doc, reports)
	if err != nil {
		return err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, 0, retained); err != nil {
		return err
	}
	store := &htmlSendCRMPolicyReadsV1{work: w, ctx: call}
	check, err := crmreview.BeginPreparedHTMLSendCheckV1(call, store, doc, reports)
	if err != nil {
		return err
	}
	defer check.CloseV1()
	needed, err := check.NeedsContentV1()
	if err != nil {
		return err
	}
	if !needed {
		return check.ResumeV1(nil)
	}
	v, err := state.prepareValidationV1()
	if err != nil {
		if errors.Is(err, htmlsource.ErrInvalid) || errors.Is(err, htmlsource.ErrReviewRequired) {
			return crmreview.ErrReviewRequired
		}
		return err
	}
	if doc.SourceKind == "blocks" && len(doc.HtmlSourceJson) == 0 {
		state.blockProcessing = true
		defer func() { state.blockProcessing = false }()
		result := check.ResumeBlocksV1(v, plainSendBlockDecimalAdmissionV1{source: state})
		if state.blockAdmissionFailure != nil {
			return state.blockAdmissionFailure
		}
		return result
	}
	return check.ResumeV1(v)
}
func htmlSendCRMContinuationLogicalV1(ctx context.Context, doc *generated.Document, reports []resolver.ResolveReport) (int64, error) {
	if doc == nil {
		return 0, ErrHTMLSendWorkV1
	}
	n, err := htmlRevisionPreparedDocumentCloneV1(doc)
	if err != nil {
		return 0, err
	}
	// At most129 complete original query rows are cloned by the continuation;
	// their dynamic strings remain covered by the separately retained native
	// full-ledger body result. Two independent clones need two logical copies.
	if !htmlInputAddV1(&n, crmreview.MaxBindings+1, 2*(int64(unsafe.Sizeof(generated.DocumentVariableBinding{}))+16)) {
		return 0, ErrHTMLSendWorkV1
	}
	for _, r := range reports {
		// Public/private CRM report proof has the exact original bounded source
		// metadata topology; value copies are priced from the actual produced value.
		v, err := htmlSendResolverValueLogicalV1(r.Value)
		if err != nil || !htmlInputAddV1(&n, v, 1) || !htmlInputAddV1(&n, 1, 16*(2048+2*256+20+128+64)+int64(unsafe.Sizeof(resolver.ResolveReport{}))+256) {
			return 0, ErrHTMLSendWorkV1
		}
	}
	if doc.SourceKind == "blocks" {
		rawWork, e := plainSendBlockLexicalWorkV1(ctx, doc.BlocksJson)
		if e != nil || !htmlInputAddV1(&n, rawWork, 2) || !htmlInputAddV1(&n, int64(len(doc.BlocksJson)), 64) {
			return 0, ErrHTMLSendWorkV1
		}
	}
	parse, err := htmlSendResolverParseLogicalV1(int64(len(doc.VariablesJson)), 2)
	if err != nil || !htmlInputAddV1(&n, parse, 1) || !htmlInputAddV1(&n, 1, 4096) {
		return 0, ErrHTMLSendWorkV1
	}
	return n, nil
}

var _ crmreview.PreparedHTMLSendReadsV1 = (*htmlSendCRMPolicyReadsV1)(nil)
