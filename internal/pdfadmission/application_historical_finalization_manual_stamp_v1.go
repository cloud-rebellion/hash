// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// A fixed manual-stamp input is created only by the genuine checked Source24
// SDK-body callback. It accepts no caller bytes/row/hash/cost as provenance.
// The source callback's mutex joins an actual producer and original-alias PDF
// consumer before the SDK clears its raw response and closes its Parent grant.
type ApplicationHistoricalManualPDFSourceV1 struct {
	mu               sync.Mutex
	self             *ApplicationHistoricalManualPDFSourceV1
	evidence         *ApplicationHistoricalFinalizationSourceEvidenceV1
	raw              []byte
	originalGeometry *sanitize.PDFManualGeometry
	active, used     bool
	result           *ApplicationHistoricalFinalizationManualPDFV1
}

func historicalManualCoordinatorV1(w *ApplicationHTMLSendWorkV1) (*workguard.CoordinatorV1, error) {
	if w == nil || w.self != w || w.stage == nil || w.stage.operation == nil || w.stage.operation.factory == nil || w.stage.operation.factory.state == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	p := w.stage.operation.factory.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	return p.work.coordinator, nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) WithManualPDFSourceV1(consume func(*ApplicationHistoricalManualPDFSourceV1) error) error {
	if e == nil || e.self != e || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	return e.withManualCompositionPDFV1(func(raw []byte, originalGeometry *sanitize.PDFManualGeometry) error {
		if !e.lockV1() {
			return ErrHistoricalFinalizationSourceV1
		}
		if !e.validV1() || !e.sourceChecked || e.document.SourceKind != "pdf" {
			e.unlockV1()
			return ErrHistoricalFinalizationSourceV1
		}
		w, ctx, org := e.work, e.ctx, e.document.OrgID
		e.unlockV1()
		coordinator, err := historicalManualCoordinatorV1(w)
		if err != nil {
			return err
		}
		fixed := 4*int64(unsafe.Sizeof(ApplicationHistoricalManualPDFSourceV1{})) + 4*int64(unsafe.Sizeof(sync.Once{})) + 4096
		grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: fixed})
		if err != nil {
			return err
		}
		defer grant.Close()
		input := &ApplicationHistoricalManualPDFSourceV1{evidence: e, raw: raw, originalGeometry: originalGeometry, active: true}
		input.self = input
		defer input.finishSourceCallbackV1()
		return consume(input)
	})
}

// This is the actual SDK callback exit. It joins the fixed producer and
// original-alias PDF borrower; cancellation alone never clears a live body.
func (input *ApplicationHistoricalManualPDFSourceV1) finishSourceCallbackV1() {
	input.mu.Lock()
	defer input.mu.Unlock()
	input.active = false
	input.raw = nil
	input.originalGeometry = nil
	input.evidence = nil
	if input.result != nil {
		m := input.result
		input.result = nil
		if m.lockV1() {
			if m.originalAlias {
				m.pdf = nil
			}
			m.unlockV1()
		}
	}
}

// Only original restricted sanitize-worker calls execute customer PDF work.
// These private grants fund actual PARENT frames, decoded geometry, overlays,
// formatter results, composed bytes and error consumers. They mint no worker
// slot/address/process authority or remote renderer termination claim.
type ApplicationHistoricalFinalizationManualPDFV1 struct {
	activityMutex             sync.Mutex
	activity                  applicationJoinedActivityV1
	self                      *ApplicationHistoricalFinalizationManualPDFV1
	closeRequested            atomic.Bool
	input                     *ApplicationHistoricalManualPDFSourceV1 // immutable lock-order root
	originalAlias             bool
	geometry                  sanitize.PDFManualGeometry
	inspected, stampAttempted bool
	pdf                       []byte
	localError                *render.HTMLLocalPDFV1
	grants                    [7]*workguard.GrantV1 // control,geometry,inspect,items,batch,compose,PDF
	coordinator               *workguard.CoordinatorV1
	ctx                       context.Context
	org                       uuid.UUID
}

func (m *ApplicationHistoricalFinalizationManualPDFV1) retireClosedV1() {
	m.pdf = nil
	m.geometry = sanitize.PDFManualGeometry{}
	m.ctx = nil
	m.coordinator = nil
	local := m.localError
	m.localError = nil
	if local != nil {
		local.CloseConsumerV1()
	}
	for i, g := range m.grants {
		m.grants[i] = nil
		if g != nil {
			g.Close()
		}
	}
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) lockV1() bool {
	if !m.activity.enterV1() {
		return false
	}
	m.activityMutex.Lock()
	return true
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) unlockV1() {
	m.activityMutex.Unlock()
	if m.activity.leaveV1() {
		m.retireClosedV1()
	}
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) CloseConsumerV1() {
	if m == nil || m.self != m {
		return
	}
	m.closeRequested.Store(true)
	if m.activity.closeV1() {
		m.retireClosedV1()
	}
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) WithPDFV1(consume func([]byte) error) error {
	if m == nil || m.self != m || m.input == nil || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	m.input.mu.Lock()
	defer m.input.mu.Unlock()
	if !m.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer m.unlockV1()
	if m.closeRequested.Load() || m.grants[0] == nil || len(m.pdf) == 0 || (m.originalAlias && !m.input.active) {
		return ErrHistoricalFinalizationSourceV1
	}
	return consume(m.pdf)
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) acquireV1(index int, raw int64) error {
	if raw <= 0 || index < 0 || index >= len(m.grants) || m.grants[index] != nil {
		return ErrHistoricalFinalizationSourceV1
	}
	grant, err := m.coordinator.TryAcquireV1(m.ctx, m.org, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return err
	}
	m.grants[index] = grant
	return nil
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) dropV1(index int) {
	g := m.grants[index]
	m.grants[index] = nil
	if g != nil {
		g.Close()
	}
}

// Inspect precedes every new SQL header/field read at the original stamp
// policy point. The only body is this native input's genuine SDK response.
func (input *ApplicationHistoricalManualPDFSourceV1) InspectManualPDFV1() (output *ApplicationHistoricalFinalizationManualPDFV1, failure error) {
	if input == nil || input.self != input {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	input.mu.Lock()
	defer input.mu.Unlock()
	if !input.active || input.used || input.evidence == nil || len(input.raw) == 0 {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	evidence := input.evidence
	if !evidence.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !evidence.validV1() || !evidence.sourceChecked || !evidence.signaturesChecked {
		evidence.unlockV1()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if (input.originalGeometry == nil) != (evidence.delegated == nil) {
		evidence.unlockV1()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	old, ctx, org := evidence.work, evidence.ctx, evidence.document.OrgID
	evidence.unlockV1()
	coordinator, err := historicalManualCoordinatorV1(old)
	if err != nil {
		return nil, err
	}
	m := &ApplicationHistoricalFinalizationManualPDFV1{input: input, coordinator: coordinator, ctx: ctx, org: org}
	m.self = m
	if !m.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer m.unlockV1()
	if err = m.acquireV1(0, 4*int64(unsafe.Sizeof(*m))+4*int64(unsafe.Sizeof(ApplicationHistoricalManualPDFSourceV1{}))+4*int64(unsafe.Sizeof(workguard.GrantV1{}))+4096); err != nil {
		return nil, err
	}
	input.used = true
	input.result = m
	output = m
	inspectWork, geometryWork, err := sanitize.ManualPDFInspectionParentWorkV1(int64(len(input.raw)))
	if err != nil {
		return output, fmt.Errorf("inspect manual PDF in isolated worker: %w", err)
	}
	if err = m.acquireV1(1, geometryWork); err != nil {
		return output, err
	}
	if err = m.acquireV1(2, inspectWork); err != nil {
		return output, err
	}
	geometry, err := sanitize.InspectManualPDFWithContext(ctx, input.raw)
	if err != nil {
		return output, fmt.Errorf("inspect manual PDF in isolated worker: %w", err)
	}
	if original := input.originalGeometry; original != nil {
		if evidence.delegated == nil || !sameDelegatedManualGeometryV1(geometry, *original, evidence.delegated.Execution().Snapshot().VisiblePDF.Artifact) {
			return output, ErrHistoricalFinalizationSourceV1
		}
	}
	m.geometry = geometry
	m.inspected = true
	// Original cmd.Run and its IPC-copy goroutines have joined. The already
	// independent geometry grant retains the decoded output for later rows.
	m.dropV1(2)
	return output, nil
}
func (w *ApplicationHTMLSendWorkV1) CompleteHistoricalManualStampV1(call context.Context, input *ApplicationHistoricalManualPDFSourceV1, m *ApplicationHistoricalFinalizationManualPDFV1, evidence *ApplicationHistoricalFinalizationSourceEvidenceV1, renderer *render.Gotenberg) error {
	if w == nil || w.self != w || input == nil || input.self != input || m == nil || m.self != m || evidence == nil || renderer == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	input.mu.Lock()
	defer input.mu.Unlock()
	if !m.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer m.unlockV1()
	if !input.active || !input.used || input.result != m || m.input != input || input.evidence != evidence || len(input.raw) == 0 || !m.inspected || m.stampAttempted || m.grants[0] == nil || m.closeRequested.Load() {
		return ErrHistoricalFinalizationSourceV1
	}
	m.stampAttempted = true
	if !evidence.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !evidence.validV1() || !evidence.sourceChecked || !evidence.signaturesChecked {
		evidence.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	old, private := evidence.work, evidence.document
	evidence.unlockV1()
	w.mu.Lock()
	valid := w.valid(call) && w.stage.purpose == HTMLHistoricalFinalizationSourceV1 && w.familyRoot == nil && w.sourceDocument == private && private.SourceKind == "pdf" && w.stage.operation == old.stage.operation
	var ctx context.Context
	if valid {
		ctx = w.stage.operation.original
	}
	w.mu.Unlock()
	if !valid {
		return ErrHistoricalFinalizationSourceV1
	}
	geometry := m.geometry
	var err error
	if _, err = w.ReadFieldsV1(call); err != nil {
		return err
	}
	if _, err = w.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
		return err
	}
	if _, err = w.ReadRecipientsV1(call); err != nil {
		return err
	}
	w.mu.Lock()
	fields, signatures, recipients := w.sourceFields, w.finalization.signatures, w.sourceRecipients
	w.mu.Unlock()
	for _, signature := range signatures {
		if signature != nil && signature.SignatureKind == "manual_pdf_fit_v1" {
			return ErrHistoricalFittedPublicationV1
		}
	}
	if err = pdflayout.ValidateSignatureRows(private, recipients, fields, signatures, len(geometry.Pages)); err != nil {
		return fmt.Errorf("stamp PDF parties: %w", err)
	}
	provider, err := delegatedProviderRecipientV1(evidence.delegated, fields, signatures)
	if err != nil {
		return err
	}
	resources := int64(4096)
	if !htmlInputAddV1(&resources, int64(len(signatures)+1), 8*render.MaxArchivedSignatureSpanBytes+1024) || !htmlInputAddV1(&resources, int64(len(fields)+1), 8*render.MaxArchivedSignatureSpanBytes+4096) {
		return ErrHistoricalFinalizationSourceV1
	}
	for _, field := range fields {
		if field != nil && !htmlInputAddV1(&resources, int64(len(field.Value.String)), 48) {
			return ErrHistoricalFinalizationSourceV1
		}
	}
	if err = m.acquireV1(3, resources); err != nil {
		return err
	}
	spans := map[string]render.ArchivedSignatureSpan{}
	for _, signature := range signatures {
		if provider != uuid.Nil && signature != nil && signature.RecipientID == provider {
			continue
		}
		if !evidence.privateArchiveSignatureMatchesV1(signature, w) {
			return ErrHistoricalFinalizationSourceV1
		}
		span, err := historicalArchiveSpanV1(evidence, signature)
		if err != nil {
			return fmt.Errorf("stamp stored signature: %w", err)
		}
		spans[signature.RecipientID.String()] = span
	}
	byPage := map[int][]render.PDFStampItemV1{}
	for _, field := range fields {
		if provider != uuid.Nil && field != nil && field.Type == "signature" && field.RecipientID.Valid && uuid.UUID(field.RecipientID.Bytes) == provider {
			continue
		}
		inner, err := historicalStampInnerHTMLV1(field, spans)
		if err != nil {
			return err
		}
		if inner == "" {
			continue
		}
		if field == nil {
			return errors.New("stamp pdf: nil field")
		}
		if len(geometry.Pages) < 1 || field.Page < 1 || int(field.Page) > len(geometry.Pages) {
			return fmt.Errorf("stamp pdf: field %s targets page %d outside source page range 1..%d", field.ID, field.Page, len(geometry.Pages))
		}
		page := int(field.Page)
		byPage[page] = append(byPage[page], render.PDFStampItemV1{XPct: historicalStampNumericPctV1(field.XPct), YPct: historicalStampNumericPctV1(field.YPct), WPct: historicalStampClampWidthV1(historicalStampNumericPctV1(field.WPct)), HPct: historicalStampClampWidthV1(historicalStampNumericPctV1(field.HPct)), HTML: inner})
	}
	if len(byPage) == 0 {
		// Original no-overlay behavior: preserve this same authentic original
		// alias inside the genuine source callback until its actual final consumer.
		if err = m.acquireV1(6, 4*int64(len(input.raw))+4096); err != nil {
			return err
		}
		m.pdf = input.raw
		m.originalAlias = true
		geometry = sanitize.PDFManualGeometry{}
		m.geometry = sanitize.PDFManualGeometry{}
		spans = nil
		byPage = nil
		m.dropV1(1)
		m.dropV1(3)
		return nil
	}
	if len(input.raw) < 1 || len(input.raw) > sanitize.MaxPDFBytes || geometry.SourceBytes != int64(len(input.raw)) {
		return sanitize.ErrPDFTooLarge
	}
	batchControl := int64(4096)
	if !htmlInputAddV1(&batchControl, int64(len(byPage)), 1024) {
		return ErrHistoricalFinalizationSourceV1
	}
	if err = m.acquireV1(4, batchControl); err != nil {
		return err
	}
	overlays := map[int][]byte{}
	pages := make([]int, 0, len(byPage))
	for page := range byPage {
		pages = append(pages, page)
	}
	sort.Ints(pages)
	total := len(input.raw)
	for _, page := range pages {
		remaining := sanitize.MaxPDFBytes - total
		if remaining < 1 {
			return sanitize.ErrPDFTooLarge
		}
		width, height, err := geometry.Pages[page-1].ViewportPoints()
		if err != nil {
			return err
		}
		htmlWork := int64(32768) + 8*int64(len(render.SignatureCSSV1()))
		for _, item := range byPage[page] {
			if !htmlInputAddV1(&htmlWork, int64(len(item.HTML)), 8) || !htmlInputAddV1(&htmlWork, 1, 4096) {
				return ErrHistoricalFinalizationSourceV1
			}
		}
		html, err := w.newHistoricalHTMLV1(call, htmlWork)
		if err != nil {
			return err
		}
		html.html = render.BuildSizedPageOverlayHTMLV1(byPage[page], width, height)
		local, renderErr := html.RenderPDFV1(renderer, render.PDFOptions{MaxResponseBytes: remaining, ExactPaperPoints: [2]float64{width, height}, Margins: [4]float32{0, 0, 0, 0}, PreferCSSPageSize: true, WaitDelay: "500ms"})
		html.CloseConsumerV1()
		if renderErr != nil {
			m.localError = local
			return fmt.Errorf("render overlay page %d: %w", page, renderErr)
		}
		if local == nil {
			return ErrHistoricalFinalizationSourceV1
		}
		copyErr := local.WithPDFV1(func(raw []byte) error {
			if len(raw) < 1 || len(raw) > remaining {
				return sanitize.ErrPDFTooLarge
			}
			if err := m.grants[4].TryGrowParentV1(ctx, 4*int64(len(raw))); err != nil {
				return err
			}
			overlays[page] = bytes.Clone(raw)
			total += len(raw)
			return nil
		})
		local.CloseConsumerV1()
		if copyErr != nil {
			return copyErr
		}
	}
	composeWork, pdfWork, err := sanitize.ManualPDFCompositionParentWorkV1(int64(len(input.raw)), int64(total-len(input.raw)))
	if err != nil {
		return fmt.Errorf("compose manual PDF in isolated worker: %w", err)
	}
	if err = m.acquireV1(5, composeWork); err != nil {
		return err
	}
	if err = m.acquireV1(6, pdfWork); err != nil {
		return err
	}
	composed, err := sanitize.ApplyManualPDFOverlaysWithContext(ctx, input.raw, geometry, overlays)
	if err != nil {
		return fmt.Errorf("compose manual PDF in isolated worker: %w", err)
	}
	m.pdf = composed.Bytes
	composed = sanitize.PDFManualOverlayResult{}
	// Original restricted worker, validation and all synchronous producers have
	// joined. Drop actual transient aliases before their independent grants.
	geometry = sanitize.PDFManualGeometry{}
	m.geometry = sanitize.PDFManualGeometry{}
	overlays = nil
	pages = nil
	spans = nil
	byPage = nil
	m.dropV1(1)
	m.dropV1(3)
	m.dropV1(4)
	m.dropV1(5)
	return nil
}
func historicalStampInnerHTMLV1(field *generated.DocumentField, spans map[string]render.ArchivedSignatureSpan) (string, error) {
	if field == nil {
		return "", errors.New("stamp pdf: nil field")
	}
	if field.Type == "signature" {
		if !field.RecipientID.Valid {
			return "", nil
		}
		span, ok := spans[uuid.UUID(field.RecipientID.Bytes).String()]
		if !ok {
			return "", nil
		}
		if span.HTML() == "" {
			return "", errors.New("stamp stored signature: validated archive is empty")
		}
		return span.HTML(), nil
	}
	if !field.Value.Valid || strings.TrimSpace(field.Value.String) == "" {
		return "", nil
	}
	value := field.Value.String
	if field.Type == "checkbox" {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "true", "1", "yes", "on", "checked", "x":
			return "&#10003;", nil
		}
		return "", nil
	}
	return historicalFinalHTMLEscapeV1(value), nil
}
func historicalStampNumericPctV1(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	exp := int(n.Exp)
	for ; exp < 0; exp++ {
		f /= 10
	}
	for ; exp > 0; exp-- {
		f *= 10
	}
	return f
}
func historicalStampClampWidthV1(v float64) float64 {
	if v <= 0 {
		return 12
	}
	return v
}
