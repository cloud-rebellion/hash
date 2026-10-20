// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/i18n"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Independently funded real formatter output. Its fixed private factory and
// native scope are captured before formatting, never supplied as caller cost,
// coordinator, SQL handle, body or row authority. The public handle is opaque.
type ApplicationHistoricalFinalizationHTMLV1 struct {
	mu             sync.Mutex
	self           *ApplicationHistoricalFinalizationHTMLV1
	closeRequested atomic.Bool
	html           string
	grant          *workguard.GrantV1
	factory        *ApplicationSessionFactoryV1
	ctx            context.Context
	org, document  uuid.UUID
	borrowers      int
}

func (h *ApplicationHistoricalFinalizationHTMLV1) clearLockedV1() {
	if !h.closeRequested.Load() || h.borrowers != 0 {
		return
	}
	h.html = ""
	h.ctx = nil
	h.factory = nil
	grant := h.grant
	h.grant = nil
	if grant != nil {
		grant.Close()
	}
}
func (h *ApplicationHistoricalFinalizationHTMLV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.closeRequested.Store(true)
	h.mu.Lock()
	h.clearLockedV1()
	h.mu.Unlock()
}
func (h *ApplicationHistoricalFinalizationHTMLV1) BorrowHTMLV1() (string, func(), error) {
	if h == nil || h.self != h {
		return "", nil, ErrHistoricalFinalizationSourceV1
	}
	h.mu.Lock()
	if h.closeRequested.Load() || h.grant == nil {
		h.mu.Unlock()
		return "", nil, ErrHistoricalFinalizationSourceV1
	}
	h.borrowers++
	view := h.html
	h.mu.Unlock()
	var once sync.Once
	return view, func() { once.Do(func() { h.mu.Lock(); h.borrowers--; h.clearLockedV1(); h.mu.Unlock() }) }, nil
}
func (w *ApplicationHTMLSendWorkV1) newHistoricalHTMLV1(call context.Context, resource int64) (*ApplicationHistoricalFinalizationHTMLV1, error) {
	if w == nil || w.self != w || resource <= 0 {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.sourceDocument == nil {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	root := w
	if w.familyRoot != nil {
		root = w.familyRoot
	}
	op := w.stage.operation
	w.mu.Unlock()
	root.mu.Lock()
	d := root.sourceDocument
	if d == nil || d.Status != "finalizing" {
		root.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	org, document := d.OrgID, d.ID
	root.mu.Unlock()
	p := op.factory.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	fixed := 4*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationHTMLV1{})) + 4*int64(unsafe.Sizeof(workguard.GrantV1{})) + 4*int64(unsafe.Sizeof(sync.Once{}))
	total, err := htmlAuthoringSumV1(resource, fixed)
	if err != nil {
		return nil, err
	}
	grant, err := coordinator.TryAcquireV1(op.original, org, workguard.VectorV1{ParentBytes: total})
	if err != nil {
		return nil, err
	}
	h := &ApplicationHistoricalFinalizationHTMLV1{grant: grant, factory: op.factory, ctx: op.original, org: org, document: document}
	h.self = h
	return h, nil
}

// The actual original formatter emits <1024 fixed bytes per block/cell, at
// most six escaped bytes per source/substitution byte, unchanged validated
// archive bytes per signature slot and bounded sanitizer tag attributes.
// Count ALL branches before rendering; selected conditional branches cannot
// increase this bound. Parser/typed tree/decimal CPU has its separate owner.
// This is retained logical object pricing, not physical allocator/RSS proof.
func historicalBlocksHTMLResourcesV1(doc *generated.Document, tree *blocks.Tree, vars map[string]string, signatures int, pending string) (int64, int64, error) {
	if doc == nil || tree == nil || signatures < 0 {
		return 0, 0, ErrHistoricalFinalizationSourceV1
	}
	var nodes, cells, tokens, dynamic, slots, rawTags int64
	var walk func([]blocks.Block)
	walk = func(items []blocks.Block) {
		for i := range items {
			b := &items[i]
			nodes++
			tokens += int64(strings.Count(b.Text, "{{"))
			if b.Type == blocks.TypeDynamicVar {
				dynamic++
			}
			if b.Type == blocks.TypeSignatureField {
				slots++
			}
			if b.Type == blocks.TypeRawHTML {
				rawTags += int64(strings.Count(b.Text, "<"))
			}
			for _, row := range b.Rows {
				for _, cell := range row {
					cells++
					tokens += int64(strings.Count(cell, "{{"))
				}
			}
			walk(b.Content)
		}
	}
	walk(tree.Blocks)
	maxValue := int64(0)
	for _, value := range vars {
		maxValue = max(maxValue, int64(len(value)))
	}
	upper := int64(0)
	for _, part := range [][2]int64{{int64(len(doc.BlocksJson)), 32}, {nodes + cells + 1, 1024}, {rawTags, 256}, {slots, render.MaxArchivedSignatureSpanBytes + 6*int64(len(pending)) + 128}} {
		if !htmlInputAddV1(&upper, part[0], part[1]) {
			return 0, 0, ErrHistoricalFinalizationSourceV1
		}
	}
	if maxValue > 0 {
		if tokens+dynamic < 0 || tokens+dynamic > (int64(^uint64(0)>>1))/6 {
			return 0, 0, ErrHistoricalFinalizationSourceV1
		}
		if !htmlInputAddV1(&upper, maxValue, 6*(tokens+dynamic)) {
			return 0, 0, ErrHistoricalFinalizationSourceV1
		}
	}
	resource := int64(0)
	if !htmlInputAddV1(&resource, upper, 8) || !htmlInputAddV1(&resource, int64(signatures)+nodes+1, 8*render.MaxArchivedSignatureSpanBytes+1024) {
		return 0, 0, ErrHistoricalFinalizationSourceV1
	}
	return resource, upper, nil
}

func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) privateArchiveSignatureMatchesV1(row *generated.Signature, root *ApplicationHTMLSendWorkV1) bool {
	if e == nil || e.self != e || row == nil || root == nil {
		return false
	}
	if !e.lockV1() {
		return false
	}
	defer e.unlockV1()
	if !e.validV1() || !e.signaturesChecked || e.document.ID != root.logicalDocumentV1() || e.work.stage.operation != root.stage.operation {
		return false
	}
	for _, actual := range e.signatures {
		if actual.ID == row.ID {
			return historicalInputSignatureExactV1(actual, row)
		}
	}
	return false
}
func historicalArchiveSpanV1(e *ApplicationHistoricalFinalizationSourceEvidenceV1, signature *generated.Signature) (span render.ArchivedSignatureSpan, failure error) {
	if signature == nil || signature.ID == uuid.Nil || signature.RecipientID == uuid.Nil || strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size {
		return span, errors.New("signature archive: incomplete evidence commitment")
	}
	if err := render.ValidateSignatureName(signature.TypedName); err != nil {
		return span, fmt.Errorf("signature archive: %w", err)
	}
	var validationFailure error
	err := e.WithSignatureBodyV1(signature.ID, func(raw []byte) error {
		if len(raw) == 0 || len(raw) > render.MaxArchivedSignatureSpanBytes {
			validationFailure = errors.New("signature archive: invalid byte count")
			return validationFailure
		}
		sum := sha256.Sum256(raw)
		if subtle.ConstantTimeCompare(sum[:], signature.ImageSha256) != 1 {
			validationFailure = errors.New("signature archive: digest mismatch")
			return validationFailure
		}
		var err error
		span, err = render.ValidateArchivedSignatureSpan(raw, signature.TypedName, signature.Font)
		if err != nil {
			validationFailure = fmt.Errorf("validate signature archive %s: %w", signature.ID, err)
		}
		return validationFailure
	})
	if validationFailure != nil {
		return render.ArchivedSignatureSpan{}, validationFailure
	}
	if err != nil {
		return render.ArchivedSignatureSpan{}, fmt.Errorf("read signature archive %s: %w", signature.ID, err)
	}
	return span, nil
}

func (w *ApplicationHTMLSendWorkV1) newHistoricalSingleBlocksHTMLV1(call context.Context, ceremony *ApplicationHTMLSendWorkV1, evidence *ApplicationHistoricalFinalizationSourceEvidenceV1, locale string) (output *ApplicationHistoricalFinalizationHTMLV1, failure error) {
	source, err := w.historicalFinalizationSourceV1(call)
	if err != nil {
		return nil, err
	}
	s := source.state
	if !s.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if err = s.owner.beginV1(); err != nil {
		return nil, err
	}
	defer s.owner.finishV1()
	if err = s.blockSigningValuesV1(); err != nil {
		return nil, err
	}
	if _, err = ceremony.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
		return nil, err
	}
	ceremony.mu.Lock()
	state, err := ceremony.historicalFinalizationStateV1(call)
	if err != nil {
		ceremony.mu.Unlock()
		return nil, err
	}
	sigs := state.signatures
	ceremony.mu.Unlock()
	for _, signature := range sigs {
		if !evidence.privateArchiveSignatureMatchesV1(signature, ceremony) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	pending := i18n.T(i18n.Normalize(locale), "sign.signaturePending", nil)
	resources, upper, err := historicalBlocksHTMLResourcesV1(s.owner.snapshot.document, s.blockTree, s.blockValues, len(sigs), pending)
	if err != nil {
		return nil, err
	}
	output, err = w.newHistoricalHTMLV1(call, resources)
	if err != nil {
		return nil, err
	}
	owned := output
	keep := false
	defer func() {
		if !keep {
			owned.CloseConsumerV1()
		}
	}()
	spanBySigner := map[string]render.ArchivedSignatureSpan{}
	for _, signature := range sigs {
		span, err := historicalArchiveSpanV1(evidence, signature)
		if err != nil {
			return nil, fmt.Errorf("render stored signature: %w", err)
		}
		key := signature.RecipientID.String()
		if _, duplicate := spanBySigner[key]; duplicate {
			return nil, errors.New("render stored signature: duplicate recipient")
		}
		spanBySigner[key] = span
	}
	if _, err = ceremony.ReadRecipientsV1(call); err != nil {
		return nil, err
	}
	ceremony.mu.Lock()
	recipients := ceremony.sourceRecipients
	ceremony.mu.Unlock()
	spanByField := map[string]render.ArchivedSignatureSpan{}
	var bind func([]blocks.Block)
	bind = func(items []blocks.Block) {
		for i := range items {
			b := &items[i]
			if b.Type == blocks.TypeSignatureField {
				role := b.AttrString("recipient_role", "")
				if role == "" {
					role = "signer"
				}
				for _, rec := range recipients {
					if rec.Role != role {
						continue
					}
					if span, ok := spanBySigner[rec.ID.String()]; ok {
						spanByField[b.ID] = span
						break
					}
				}
			}
			bind(b.Content)
		}
	}
	bind(s.blockTree.Blocks)
	was := s.blockProcessing
	s.blockProcessing = true
	defer func() { s.blockProcessing = was }()
	result, err := blocks.RenderHTMLWithSignaturesForSendV1(s.blockTree, s.blockValues, spanByField, pending, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		return nil, err
	}
	if int64(len(result)) > upper {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	output.html = result
	keep = true
	return output, nil
}

func historicalFinalHTMLEscapeV1(value string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(value)
}
func (w *ApplicationHTMLSendWorkV1) NewHistoricalFinalBlocksHTMLV1(call context.Context, evidence *ApplicationHistoricalFinalizationSourceEvidenceV1, family *ApplicationHistoricalFinalizationSourceFamilyV1, css *ApplicationHistoricalFinalizationCSSV1, locale string) (output *ApplicationHistoricalFinalizationHTMLV1, failure error) {
	if w == nil || w.self != w || evidence == nil || css == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.sourceDocument == nil || w.familyRoot != nil || w.sourceDocument.SourceKind != "blocks" {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	doc := w.sourceDocument
	w.mu.Unlock()
	var body *ApplicationHistoricalFinalizationHTMLV1
	defer func() {
		if body != nil {
			body.CloseConsumerV1()
		}
	}()
	if !doc.IsEnvelope {
		var err error
		body, err = w.newHistoricalSingleBlocksHTMLV1(call, w, evidence, locale)
		if err != nil {
			return nil, err
		}
	} else {
		if family == nil {
			return nil, errors.New("render envelope body: envelope children unavailable")
		}
		members, err := w.ReadEnvelopeMembersV1(call)
		if err != nil {
			return nil, fmt.Errorf("render envelope body: list children: %w", err)
		}
		if len(members) == 0 {
			return nil, errors.New("render envelope body: envelope has no children")
		}
		price := int64(4096)
		if !htmlInputAddV1(&price, int64(len(doc.Name)), 48) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		body, err = w.newHistoricalHTMLV1(call, price)
		if err != nil {
			return nil, err
		}
		body.html = fmt.Sprintf(`<section class="hash-envelope-banner"><h1>%s</h1><p class="hash-envelope-note">This envelope bundles %d documents that are signed together as a single legal instrument.</p></section>`, historicalFinalHTMLEscapeV1(doc.Name), len(members))
		for index, member := range members {
			if member == nil {
				return nil, fmt.Errorf("render envelope body: child %d is nil", index+1)
			}
			if _, err = family.NewHistoricalRenderMemberContinuationV1(call, member); err != nil {
				return nil, err
			}
			member.mu.Lock()
			child := member.sourceDocument
			member.mu.Unlock()
			if child == nil {
				return nil, fmt.Errorf("render envelope body: child %d is nil", index+1)
			}
			if !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != doc.ID {
				return nil, fmt.Errorf("render envelope body: child %s is not attached", child.ID)
			}
			if child.IsEnvelope {
				return nil, fmt.Errorf("render envelope body: child %s is itself an envelope", child.ID)
			}
			if !historicalSourceChildStatusMatchesV1(doc.Status, child.Status) {
				return nil, fmt.Errorf("render envelope body: child %s status %s does not match envelope status %s", child.ID, child.Status, doc.Status)
			}
			if child.SourceKind != "blocks" {
				return nil, fmt.Errorf("render envelope body: child %s is not a blocks document", child.ID)
			}
			childSource, err := member.historicalFinalizationSourceV1(call)
			if err != nil {
				return nil, fmt.Errorf("render envelope body: child %s: %w", child.ID, err)
			}
			if err = childSource.prepareHistoricalFinalBlocksV1(); err != nil {
				return nil, fmt.Errorf("render envelope body: child %s: %w", child.ID, err)
			}
			childHTML, err := member.newHistoricalSingleBlocksHTMLV1(call, w, evidence, locale)
			if err != nil {
				return nil, fmt.Errorf("render envelope body: render child %s: %w", child.ID, err)
			}
			next, appendErr := w.appendHistoricalEnvelopeHTMLV1(call, body, childHTML, child, index)
			childHTML.CloseConsumerV1()
			if appendErr != nil {
				return nil, appendErr
			}
			body.CloseConsumerV1()
			body = next
		}
	}
	return w.wrapHistoricalFinalHTMLV1(call, body, css)
}
func (w *ApplicationHTMLSendWorkV1) appendHistoricalEnvelopeHTMLV1(call context.Context, prefix, childHTML *ApplicationHistoricalFinalizationHTMLV1, child *generated.Document, index int) (*ApplicationHistoricalFinalizationHTMLV1, error) {
	before, finishBefore, err := prefix.BorrowHTMLV1()
	if err != nil {
		return nil, err
	}
	defer finishBefore()
	childBody, finishChild, err := childHTML.BorrowHTMLV1()
	if err != nil {
		return nil, err
	}
	defer finishChild()
	resource := int64(8192)
	for _, part := range [][2]int64{{int64(len(before)), 8}, {int64(len(childBody)), 8}, {int64(len(child.Name)), 48}} {
		if !htmlInputAddV1(&resource, part[0], part[1]) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	out, err := w.newHistoricalHTMLV1(call, resource)
	if err != nil {
		return nil, err
	}
	var builder strings.Builder
	builder.WriteString(before)
	if index > 0 {
		builder.WriteString(`<div class="hash-envelope-pagebreak" style="page-break-before:always;"></div>`)
	}
	fmt.Fprintf(&builder, `<section class="hash-envelope-child" data-child-id="%s"><h2>%d. %s</h2>`, child.ID, index+1, historicalFinalHTMLEscapeV1(child.Name))
	builder.WriteString(childBody)
	builder.WriteString(`</section>`)
	out.html = builder.String()
	return out, nil
}
func (w *ApplicationHTMLSendWorkV1) wrapHistoricalFinalHTMLV1(call context.Context, body *ApplicationHistoricalFinalizationHTMLV1, css *ApplicationHistoricalFinalizationCSSV1) (*ApplicationHistoricalFinalizationHTMLV1, error) {
	if body == nil || body.self != body || css == nil || css.self != css || body.org != css.org || body.document != css.document {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	bodyHTML, finishBody, err := body.BorrowHTMLV1()
	if err != nil {
		return nil, err
	}
	defer finishBody()
	brand, finishCSS, err := css.BorrowCSSV1()
	if err != nil {
		return nil, err
	}
	defer finishCSS()
	resource := int64(0)
	if !htmlInputAddV1(&resource, render.FinalDocumentHTMLFixedBytesV1(), 8) || !htmlInputAddV1(&resource, int64(len(bodyHTML)), 8) || !htmlInputAddV1(&resource, int64(len(brand)), 8) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	out, err := w.newHistoricalHTMLV1(call, resource)
	if err != nil {
		return nil, err
	}
	out.html = render.BuildHTMLDocumentV1(brand, bodyHTML, "")
	return out, nil
}

// The actual factory/org are the private native output provenance. No caller
// coordinator or externally closable Grant may back this renderer route.
func (h *ApplicationHistoricalFinalizationHTMLV1) RenderPDFV1(renderer *render.Gotenberg, options render.PDFOptions) (*render.HTMLLocalPDFV1, error) {
	value, finish, err := h.BorrowHTMLV1()
	if err != nil {
		return nil, err
	}
	defer finish()
	h.mu.Lock()
	factory, ctx, org := h.factory, h.ctx, h.org
	h.mu.Unlock()
	if factory == nil || factory.state == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	p := factory.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	return renderer.HTMLToPDFLocalOwnedV1(ctx, value, options, coordinator, org)
}

func (h *ApplicationHTMLSendSourceV1) prepareHistoricalFinalBlocksV1() error {
	if h == nil || h.state == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	return s.blockSigningValuesV1()
}
