// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

var ErrHTMLRevisionCollectionsV1 = errors.New("pdfadmission: owned HTML revision collections unavailable")

// This fixed collection owner derives all sizes from its genuine M94 scalar
// header and original reader snapshot. It accepts no counts, size declarations,
// external DBTX or mutable application Document. Its SQL owner retains parent,
// subject and orgchain until capture/clear/project finish. Logical staging
// credit is not a PostgreSQL executor heap/RSS measurement.
type ApplicationHTMLRevisionCollectionsV1 struct {
	mu                      sync.Mutex
	self                    *ApplicationHTMLRevisionCollectionsV1
	reader                  *ApplicationHTMLRevisionReaderV1
	snapshot                *applicationHTMLRevisionSourceSnapshotV1
	session                 *ApplicationSessionV1
	queries                 *generated.Queries
	header                  generated.GetHTMLRevisionSnapshotSizeHeaderV1Row
	components              htmlRevisionSnapshotCollectionComponentsV1
	closeConsumers          []func()
	releaseBody             func()
	active                  int
	validationSource        *applicationHTMLRevisionSourceOwnerV1
	stageAttempted          [5]bool
	closed, resourcesClosed bool
}

// The reader's original fixed32MiB header loan precedes the numeric aggregate.
// Full complete-set logical JSON/row credit precedes every scalable cache pin
// or native collection body. A fresh statement must reproduce the entire
// scalar header after pins; the initial orgchain wait is not a snapshot proof.
func (r *ApplicationHTMLRevisionReaderV1) NewCollectionsV1(ctx context.Context) (out *ApplicationHTMLRevisionCollectionsV1, failure error) {
	snapshot, release, err := r.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			release()
		}
	}()
	if r == nil || r.self != r || snapshot == nil || snapshot.document == nil {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	r.mu.Lock()
	session := r.session
	r.mu.Unlock()
	if session == nil || !htmlRevisionCollectionSessionV1(ctx, session) {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	q := generated.New(&applicationOwnedDBTXV1{session: session.state})
	doc := snapshot.document
	h, err := q.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	components, err := htmlRevisionSnapshotCollectionComponentsForV1(h, doc, snapshot.current)
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionCollectionsV1, err)
	}
	// These are actual complete JSON-text envelopes, including empty-row fixed
	// schema work, all six historical JSON values and full native recipient raw
	// credentials/decline text. No history count is capped or truncated.
	wire, err := htmlRevisionSnapshotSumV1(components.contextJSONBytes, components.historyRowJSONBytes)
	if err != nil {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	if err = htmlRevisionCollectionTypedEnvelopeV1(h, components, wire); err != nil {
		return nil, err
	}
	closeCollection, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, 0, wire)
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionCollectionsV1, err)
	}
	o := &ApplicationHTMLRevisionCollectionsV1{reader: r, snapshot: snapshot, session: session, queries: q, header: *h, components: components, closeConsumers: []func(){closeCollection}, releaseBody: release}
	o.self = o
	// Once installed, even refusal retains its loan until actual consumer close
	// and original physical session/registry reconciliation. No inferred refund.
	keep = true
	defer func() {
		if failure != nil {
			o.CloseConsumerV1()
		}
	}()
	locked, err := q.LockHTMLRevisionSnapshotSizeCachesV1(ctx, generated.LockHTMLRevisionSnapshotSizeCachesV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if locked == nil || locked.LockedFieldCacheCount != h.FieldCount || locked.LockedEventCacheCount != h.EventCount || locked.LockedHistoryCacheCount != h.HistoryCount {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	current, err := q.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if current == nil || *current != *h || !htmlRevisionCollectionSessionV1(ctx, session) {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	return o, nil
}
func htmlRevisionCollectionSessionV1(ctx context.Context, h *ApplicationSessionV1) bool {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.factory != nil && !s.closed && !s.unknown && !s.ended && !s.retired && s.callbackActive && !s.sqlActive && s.tx != nil && s.admission != nil && s.admission.valid() && s.admission.fence == s.fence && ctx.Value(applicationSessionCallbackKeyV1{}) == s
}
func (o *ApplicationHTMLRevisionCollectionsV1) beginV1(ctx context.Context, id uuid.UUID) (func(), error) {
	if o == nil || o.self != o {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	o.mu.Lock()
	if o.closed || o.resourcesClosed || o.snapshot == nil || o.snapshot.document == nil || o.snapshot.document.ID != id || !htmlRevisionCollectionSessionV1(ctx, o.session) {
		o.mu.Unlock()
		return nil, ErrHTMLRevisionCollectionsV1
	}
	o.active++
	o.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			o.mu.Lock()
			o.active--
			closes, release := o.retireV1()
			o.mu.Unlock()
			htmlRevisionCollectionReleaseV1(closes, release)
		})
	}, nil
}

// These exact methods satisfy the original htmlsource signing-state query
// interface. Body reads keep their original call order/error masking inside
// that validator; this owner does not eagerly fetch later policy inputs.
func (o *ApplicationHTMLRevisionCollectionsV1) ListRecipientsByDocument(ctx context.Context, id uuid.UUID) ([]*generated.Recipient, error) {
	done, err := o.beginV1(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := o.queries.ListRecipientsByDocument(ctx, id)
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != o.header.RecipientCount {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	raw := int64(0)
	for _, r := range rows {
		if r == nil || r.DocumentID != id || r.ID == uuid.Nil {
			return nil, ErrHTMLRevisionCollectionsV1
		}
		n, err := htmlRevisionSnapshotSumV1(int64(len(r.Email)), int64(len(r.Name)), int64(len(r.Role)), int64(len(r.Status)), int64(len(r.Locale)), int64(len(r.MagicTokenHash)), signerTextBytesV1(r.DeclinedReason))
		if err != nil || !htmlRevisionSnapshotAddV1(&raw, n, 1) {
			return nil, ErrHTMLRevisionCollectionsV1
		}
	}
	if raw != o.header.RecipientRawTextBytes {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	return rows, nil
}
func (o *ApplicationHTMLRevisionCollectionsV1) ListFieldsByDocument(ctx context.Context, id uuid.UUID) ([]*generated.DocumentField, error) {
	done, err := o.beginV1(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	rows, err := o.queries.ListFieldsByDocument(ctx, id)
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != o.header.FieldCount {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	raw, wire := int64(0), int64(0)
	for _, f := range rows {
		if f == nil || f.DocumentID != id || f.ID == uuid.Nil {
			return nil, ErrHTMLRevisionCollectionsV1
		}
		n, err := htmlRevisionSnapshotSumV1(int64(len(f.Type)), signerTextBytesV1(f.Label), signerTextBytesV1(f.Value))
		if err != nil || !htmlRevisionSnapshotAddV1(&raw, n, 1) || !htmlRevisionSnapshotAddV1(&wire, int64(len(f.OptionsJson)), 1) {
			return nil, ErrHTMLRevisionCollectionsV1
		}
	}
	if raw != o.header.FieldRawTextBytes || wire != o.header.FieldOptionsWireBytes {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	o.mu.Lock()
	source := o.validationSource
	o.mu.Unlock()
	if source != nil {
		if err := source.fieldOptionsComponentsV1(rows); err != nil {
			return nil, err
		}
	}
	return rows, nil
}
func (o *ApplicationHTMLRevisionCollectionsV1) GetDocumentBrandingOverride(ctx context.Context, id uuid.UUID) (*generated.DocumentBrandingOverride, error) {
	done, err := o.beginV1(ctx, id)
	if err != nil {
		return nil, err
	}
	defer done()
	row, err := o.queries.GetDocumentBrandingOverride(ctx, id)
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != id || o.header.BrandingCount != 1 {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	raw, err := htmlRevisionSnapshotSumV1(signerTextBytesV1(row.PrimaryHex), signerTextBytesV1(row.AccentHex), signerTextBytesV1(row.SurfaceHex), signerTextBytesV1(row.TextHex), signerTextBytesV1(row.MutedHex), signerTextBytesV1(row.LogoUrl), signerTextBytesV1(row.LogoAlt), signerTextBytesV1(row.FontHeading), signerTextBytesV1(row.FontBody), signerTextBytesV1(row.SignatureColor))
	if err != nil || raw != o.header.BrandingRawTextBytes {
		return nil, ErrHTMLRevisionCollectionsV1
	}
	return row, nil
}

// The complete original policy callback remains active until its last source
// and row use joins. Closing the route during one nested query cannot release
// the model/body loan before the remaining original checks finish.
func (o *ApplicationHTMLRevisionCollectionsV1) validateSigningPageStateWithSourceV1(ctx context.Context, validation *htmlsource.RevisionValidationV1, pages int, source *applicationHTMLRevisionSourceOwnerV1) error {
	if o == nil || o.self != o {
		return ErrHTMLRevisionCollectionsV1
	}
	done, err := o.beginV1(ctx, o.header.ID)
	if err != nil {
		return err
	}
	defer done()
	if validation == nil || !validation.MatchesDocumentV1(o.snapshot.document) || source == nil || source.self != source || source.snapshot != o.snapshot {
		return ErrHTMLRevisionCollectionsV1
	}
	o.mu.Lock()
	if o.validationSource != nil {
		o.mu.Unlock()
		return ErrHTMLRevisionCollectionsV1
	}
	o.validationSource = source
	o.mu.Unlock()
	defer func() { o.mu.Lock(); o.validationSource = nil; o.mu.Unlock() }()
	return validation.ValidateSigningPageStateV1(ctx, o, pages)
}

// Each fixed statement reserves its complete logical staging mass before SQL.
// The original snapshot/collection inputs and every preceding stage's credit
// remain retained through actual operation/response consumption. This applies
// the existing staging class; it asserts neither work_mem nor RSS containment.
type htmlRevisionSnapshotStageV1 uint8

const (
	htmlRevisionSnapshotCaptureStageV1 htmlRevisionSnapshotStageV1 = iota + 1
	htmlRevisionSnapshotMeasureStageV1
	htmlRevisionSnapshotClearStageV1
	htmlRevisionSnapshotProjectStageV1
	htmlRevisionSnapshotOriginProjectStageV1
)

func (o *ApplicationHTMLRevisionCollectionsV1) acquireStatementV1(ctx context.Context, stage htmlRevisionSnapshotStageV1) error {
	if o == nil || o.self != o {
		return ErrHTMLRevisionCollectionsV1
	}
	done, err := o.beginV1(ctx, o.header.ID)
	if err != nil {
		return err
	}
	defer done()
	if stage < htmlRevisionSnapshotCaptureStageV1 || stage > htmlRevisionSnapshotOriginProjectStageV1 {
		return ErrHTMLRevisionCollectionsV1
	}
	o.mu.Lock()
	index := int(stage - htmlRevisionSnapshotCaptureStageV1)
	if o.stageAttempted[index] {
		o.mu.Unlock()
		return ErrHTMLRevisionCollectionsV1
	}
	o.stageAttempted[index] = true
	o.mu.Unlock()
	var c htmlRevisionSnapshotStatementComponentsV1
	switch stage {
	case htmlRevisionSnapshotCaptureStageV1:
		c = o.components.capture
	case htmlRevisionSnapshotMeasureStageV1:
		c = o.components.measureFresh
	case htmlRevisionSnapshotClearStageV1:
		c = o.components.clear
	case htmlRevisionSnapshotProjectStageV1, htmlRevisionSnapshotOriginProjectStageV1:
		c = o.components.project
	default:
		return ErrHTMLRevisionCollectionsV1
	}
	closeStage, err := o.reader.authoring.acquireOwnedRetainedBodyV1(ctx, 0, c.logicalRowJSONBytes)
	if err != nil {
		return errors.Join(ErrHTMLRevisionCollectionsV1, err)
	}
	o.mu.Lock()
	o.closeConsumers = append(o.closeConsumers, closeStage)
	o.mu.Unlock()
	return nil
}

// Caller holds o.mu. This closes consumption only: the same admission registry
// and actual original client/backend fence must still settle physical debt.
func (o *ApplicationHTMLRevisionCollectionsV1) retireV1() ([]func(), func()) {
	if !o.closed || o.resourcesClosed || o.active != 0 {
		return nil, nil
	}
	o.resourcesClosed = true
	o.snapshot = nil
	o.reader = nil
	o.queries = nil
	o.session = nil
	closes, release := o.closeConsumers, o.releaseBody
	o.closeConsumers = nil
	o.releaseBody = nil
	return closes, release
}
func htmlRevisionCollectionReleaseV1(closes []func(), release func()) {
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
}
func (o *ApplicationHTMLRevisionCollectionsV1) CloseConsumerV1() {
	if o == nil || o.self != o {
		return
	}
	o.mu.Lock()
	o.closed = true
	closes, release := o.retireV1()
	o.mu.Unlock()
	htmlRevisionCollectionReleaseV1(closes, release)
}

// The complete JSON row envelopes already include every empty row and every
// fixed schema key/UUID/time value. Verify explicitly that their16x logical
// staging component dominates each scalable native row, pointer/slice growth
// and old/new row storage; no fixed union substitutes for arbitrary counts.
func htmlRevisionCollectionTypedEnvelopeV1(h *generated.GetHTMLRevisionSnapshotSizeHeaderV1Row, c htmlRevisionSnapshotCollectionComponentsV1, wire int64) error {
	if h == nil || wire < 0 {
		return ErrHTMLRevisionCollectionsV1
	}
	typed := int64(0)
	for _, row := range []struct{ count, size int64 }{
		{h.FieldCount, int64(unsafe.Sizeof(generated.DocumentField{}))},
		{h.RecipientCount, int64(unsafe.Sizeof(generated.Recipient{}))},
		{h.BrandingCount, int64(unsafe.Sizeof(generated.DocumentBrandingOverride{}))},
		{h.EventCount, int64(unsafe.Sizeof(generated.Event{}))},
		{h.HistoryCount, int64(unsafe.Sizeof(generated.HtmlDocumentMaterializationSnapshot{}))},
	} {
		if row.count < 0 || !htmlInputAddV1(&typed, row.count, 4*(row.size+16)) {
			return ErrHTMLRevisionCollectionsV1
		}
	}
	staging := int64(0)
	if !htmlInputAddV1(&staging, wire, 16) || typed > staging {
		return ErrHTMLRevisionCollectionsV1
	}
	// c is the same checked complete context+history projection used for grant.
	expected, err := htmlRevisionSnapshotSumV1(c.contextJSONBytes, c.historyRowJSONBytes)
	if err != nil || expected != wire {
		return ErrHTMLRevisionCollectionsV1
	}
	return nil
}
