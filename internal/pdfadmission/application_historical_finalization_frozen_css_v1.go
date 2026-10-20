// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// The output grant is independent of the short native metadata Work. Closing
// SQL/that Work cannot credit a CSS string which is still being rendered.
type ApplicationHistoricalFinalizationCSSV1 struct {
	mu             sync.Mutex
	self           *ApplicationHistoricalFinalizationCSSV1
	closeRequested atomic.Bool
	css            string
	grant          *workguard.GrantV1
	borrowers      int
	org, document  uuid.UUID
}

func (h *ApplicationHistoricalFinalizationCSSV1) clearLockedV1() {
	if !h.closeRequested.Load() || h.borrowers != 0 {
		return
	}
	h.css = ""
	grant := h.grant
	h.grant = nil
	if grant != nil {
		grant.Close()
	}
}
func (h *ApplicationHistoricalFinalizationCSSV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.closeRequested.Store(true)
	h.mu.Lock()
	h.clearLockedV1()
	h.mu.Unlock()
}

// The returned view has one explicit consumer. A concurrent genuine Close,
// copied handle, or context cancellation cannot release it before finish.
func (h *ApplicationHistoricalFinalizationCSSV1) BorrowCSSV1() (string, func(), error) {
	if h == nil || h.self != h {
		return "", nil, ErrHTMLSendWorkV1
	}
	h.mu.Lock()
	if h.closeRequested.Load() || h.grant == nil {
		h.mu.Unlock()
		return "", nil, ErrHTMLSendWorkV1
	}
	h.borrowers++
	value := h.css
	h.mu.Unlock()
	var once sync.Once
	return value, func() { once.Do(func() { h.mu.Lock(); h.borrowers--; h.clearLockedV1(); h.mu.Unlock() }) }, nil
}

// Canonical frozen fonts are <=256 bytes each. CSSVariables emits two quoted
// font lists, six input colors, three seven-byte contrasts, and fixed labels.
// Each canonical one-byte font name can add at most two quote bytes. This is
// a closed output bound for the original generator, not a caller-provided cap.
func historicalFrozenCSSOutputBytesV1() int64 {
	const fixed = "<style>:root{}</style>" +
		"--hash-primary:;--hash-accent:;--hash-surface:;--hash-text:;--hash-muted:;--hash-signature:;" +
		"--hash-on-primary:;--hash-on-accent:;--hash-on-surface:;--hash-font-heading:;--hash-font-body:;"
	return int64(len(fixed)) + 9*7 + 2*(3*256+2)
}

// Price the actual locked row before reading it. NormaliseFontFamily can make
// Split/Fields/canonical lists (at most raw+2 entries across the two fonts),
// their joined strings and quote lists. URL parsing, row/view copies and the
// original CSS builder/formatting output are retained separately in this sum.
// These are logical owned-object bounds; they do not claim allocator/RSS proof.
func historicalFrozenCSSResourcesV1(raw int64) (int64, error) {
	if raw < 0 {
		return 0, ErrHTMLSendWorkV1
	}
	n := 2*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationCSSV1{})) +
		4*int64(unsafe.Sizeof(generated.DocumentBrandingOverride{})) +
		4*int64(unsafe.Sizeof(branding.Branding{})) +
		4*int64(unsafe.Sizeof(sync.Once{})) + 32*int64(unsafe.Sizeof(uintptr(0)))
	if !htmlInputAddV1(&n, raw, 8) ||
		!htmlInputAddV1(&n, raw, 6*int64(unsafe.Sizeof(""))) ||
		!htmlInputAddV1(&n, 4, 6*int64(unsafe.Sizeof(""))) ||
		!htmlInputAddV1(&n, historicalFrozenCSSOutputBytesV1(), 8) {
		return 0, ErrHTMLSendWorkV1
	}
	return n, nil
}

func (w *ApplicationHTMLSendWorkV1) NewHistoricalFinalizationFrozenCSSV1(call context.Context, reference *ApplicationHistoricalFinalizationStageReferenceV1) (output *ApplicationHistoricalFinalizationCSSV1, failure error) {
	if w == nil || w.self != w || reference == nil || w.stage == nil || w.stage.operation == nil {
		return nil, ErrHTMLSendWorkV1
	}
	owner, err := reference.ownerV1(w.stage.operation.factory)
	if err != nil {
		return nil, err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if owner.closed || !owner.stagePrepared || !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationCertificateRenderV1 ||
		w.familyRoot != nil || w.state == nil || w.state.ID != owner.document || w.state.OrgID != owner.org ||
		w.state.BoundedStatus != "finalizing" || w.state.ParentEnvelopeID.Valid || w.state.RequiresSignature != owner.stageCommitment.requiresSignature {
		return nil, ErrHTMLSendWorkV1
	}
	fixed := 4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationFrozenBrandingReadHeaderV1Params{})) +
		4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationFrozenBrandingReadHeaderV1Row{}))
	closeHeader, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeHeader)
	params := generated.GetHistoricalFinalizationFrozenBrandingReadHeaderV1Params{DocumentID: owner.document, OrgID: owner.org}
	header, err := w.queries.GetHistoricalFinalizationFrozenBrandingReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != owner.document || header.OrgID != owner.org || header.SourceUpdatedAt != w.state.UpdatedAt ||
		!applicationStampV1(header.SourceUpdatedAt) || header.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	if !header.HasFrozenBranding {
		return nil, branding.ErrFrozenBrandingUnavailable
	}
	if !applicationStampV1(header.BrandingUpdatedAt) {
		return nil, ErrHTMLSendWorkV1
	}
	resources, err := historicalFrozenCSSResourcesV1(header.RawTextBytes)
	if err != nil {
		return nil, err
	}
	factory := w.session.state.factory
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHTMLSendWorkV1
	}
	grant, err := coordinator.TryAcquireV1(w.stage.operation.original, owner.org, workguard.VectorV1{ParentBytes: resources})
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			grant.Close()
		}
	}()
	row, err := w.queries.GetDocumentBrandingOverride(call, owner.document)
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != owner.document || row.UpdatedAt != header.BrandingUpdatedAt {
		return nil, ErrHTMLSendWorkV1
	}
	actual := int64(0)
	for _, value := range []string{row.PrimaryHex.String, row.AccentHex.String, row.SurfaceHex.String, row.TextHex.String, row.MutedHex.String, row.LogoUrl.String, row.LogoAlt.String, row.FontHeading.String, row.FontBody.String, row.SignatureColor.String} {
		if !htmlInputAddV1(&actual, int64(len(value)), 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if actual != header.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	fresh, err := w.queries.GetHistoricalFinalizationFrozenBrandingReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *header {
		return nil, ErrHTMLSendWorkV1
	}
	resolved, err := branding.ResolveFrozenRowV1(owner.document, row)
	if err != nil {
		return nil, err
	}
	css := resolved.CSSVariables()
	if int64(len(css)) > historicalFrozenCSSOutputBytesV1() {
		return nil, ErrHTMLSendWorkV1
	}
	output = &ApplicationHistoricalFinalizationCSSV1{css: strings.Clone(css), grant: grant, org: owner.org, document: owner.document}
	output.self = output
	keep = true
	return output, nil
}
