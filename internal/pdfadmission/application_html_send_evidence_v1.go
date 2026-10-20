// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrHTMLSendEvidenceV1 = errors.New("pdfadmission: owned HTML send evidence unavailable")
var ErrHTMLSendPDFMissingV1 = errors.New("pdfadmission: owned HTML send source PDF commitment unavailable")

// Only an actual Work can create this fixed provider owner. Its source, pins,
// storage limit and original deadline come from genuine private owners. There
// is no caller body/key/digest/cost or arbitrary EvidenceRetainer callback.
// Every SDK call is synchronous, and storage's bounded response Close joins
// its actual reads. A provider stream closes only after that call returns.
type ApplicationHTMLSendEvidenceV1 struct {
	activityMutex                                                           sync.Mutex
	activity                                                                applicationJoinedActivityV1
	self                                                                    *ApplicationHTMLSendEvidenceV1
	closeRequested                                                          atomic.Bool
	work                                                                    *ApplicationHTMLSendWorkV1
	source                                                                  *applicationHTMLSendSourceStateV1
	client                                                                  *storage.Client
	limits                                                                  storage.SendEvidenceLimitsV1
	original                                                                *generated.Document
	releaseSource                                                           func()
	pdfVersion, renderedVersion                                             pgtype.Text
	draft                                                                   bool
	prepareAttempted, bound, fieldsBound, inspectAttempted, retainAttempted bool
	prepareError, inspectError, retainError                                 error
	pages                                                                   int
	retainUntil                                                             time.Time
}

func (w *ApplicationHTMLSendWorkV1) NewEvidenceV1(call context.Context, source *ApplicationHTMLSendSourceV1, client *storage.Client) (*ApplicationHTMLSendEvidenceV1, error) {
	if w == nil || w.self != w || source == nil || source.state == nil {
		return nil, ErrHTMLSendEvidenceV1
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return nil, errors.Join(ErrHTMLSendEvidenceV1, err)
	}
	w.mu.Lock()
	valid := w.valid(call) && w.evidence == nil && w.stage != nil && (w.stage.purpose == HTMLSendSnapshotV1 || (w.stage.purpose == HTMLSendPinV1 && w.familyRoot != nil)) && w.sourceDocument != nil && w.sourceState == source.state
	w.mu.Unlock()
	if !valid {
		return nil, ErrHTMLSendEvidenceV1
	}
	s := source.state
	if !s.lockV1() {
		return nil, ErrHTMLSendEvidenceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.work != w || s.owner == nil || !s.attempted || s.failure != nil || s.candidate {
		return nil, ErrHTMLSendEvidenceV1
	}
	if err = s.owner.beginV1(); err != nil {
		return nil, err
	}
	defer s.owner.finishV1()
	if err = s.owner.holdV1(htmlRevisionSourceStateV1, 0, int64(unsafe.Sizeof(ApplicationHTMLSendEvidenceV1{}))+int64(unsafe.Sizeof(sync.Once{}))+2*int64(unsafe.Sizeof(uintptr(0)))); err != nil {
		return nil, err
	}
	e := &ApplicationHTMLSendEvidenceV1{work: w, source: s, client: client, limits: limits, original: s.owner.snapshot.document}
	e.self = e
	if err = s.owner.beginV1(); err != nil {
		return nil, err
	}
	var once sync.Once
	e.releaseSource = func() { once.Do(s.owner.finishV1) }
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.evidence != nil {
		e.CloseConsumerV1()
		return nil, ErrHTMLSendEvidenceV1
	}
	w.evidence = e
	return e, nil
}

// Draft inspection is born from the retained ORIGINAL preparation source after
// its original resolver/review policy, outside the retired SQL callback. The
// real source binding supplies the original context and immutable body; no
// later caller ctx or model can create work. It permits inspection ONLY.
func (w *ApplicationHTMLSendWorkV1) NewDraftEvidenceV1(source *ApplicationHTMLSendSourceV1, client *storage.Client) (*ApplicationHTMLSendEvidenceV1, error) {
	if w == nil || w.self != w || source == nil || source.state == nil {
		return nil, ErrHTMLSendEvidenceV1
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return nil, errors.Join(ErrHTMLSendEvidenceV1, err)
	}
	s := source.state
	if !s.lockV1() {
		return nil, ErrHTMLSendEvidenceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.work != w || s.owner == nil || !s.attempted || s.failure != nil {
		return nil, ErrHTMLSendEvidenceV1
	}
	owner := s.owner
	if err = owner.beginV1(); err != nil {
		return nil, err
	}
	defer owner.finishV1()
	w.mu.Lock()
	valid := !w.closed && !w.resourcesClosed && w.evidence == nil && w.stage != nil && w.stage.purpose == HTMLSendPreparationV1 && w.stage.operation != nil && w.stage.operation.original.Err() == nil &&
		((s.candidate && w.resolvedState == s && w.resolvedOwner == owner) || (!s.candidate && w.sourceState == s && w.sourceOwner == owner))
	w.mu.Unlock()
	if !valid {
		return nil, ErrHTMLSendEvidenceV1
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, 0, int64(unsafe.Sizeof(ApplicationHTMLSendEvidenceV1{}))+int64(unsafe.Sizeof(sync.Once{}))+2*int64(unsafe.Sizeof(uintptr(0)))); err != nil {
		return nil, err
	}
	e := &ApplicationHTMLSendEvidenceV1{draft: true, work: w, source: s, client: client, limits: limits, original: owner.snapshot.document}
	e.self = e
	if err = s.owner.beginV1(); err != nil {
		return nil, err
	}
	var once sync.Once
	e.releaseSource = func() { once.Do(s.owner.finishV1) }
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.resourcesClosed || w.evidence != nil {
		e.CloseConsumerV1()
		return nil, ErrHTMLSendEvidenceV1
	}
	w.evidence = e
	return e, nil
}

// Registration precedes mutex wait and lasts through all captured source and
// provider completions. Only the actual final admitted release may retire.
func (e *ApplicationHTMLSendEvidenceV1) lockV1() bool {
	if !e.activity.enterV1() {
		return false
	}
	e.activityMutex.Lock()
	return true
}
func (e *ApplicationHTMLSendEvidenceV1) unlockV1() {
	e.activityMutex.Unlock()
	if e.activity.leaveV1() {
		e.retireClosedV1()
	}
}
func (e *ApplicationHTMLSendEvidenceV1) retireClosedV1() {
	release := e.releaseSource
	e.releaseSource = nil
	e.original = nil
	e.source = nil
	e.work = nil
	e.client = nil
	e.prepareError = nil
	e.inspectError = nil
	e.retainError = nil
	e.pdfVersion = pgtype.Text{}
	e.renderedVersion = pgtype.Text{}
	if release != nil {
		release()
	}
}
func (e *ApplicationHTMLSendEvidenceV1) CloseConsumerV1() {
	if e == nil || e.self != e {
		return
	}
	e.closeRequested.Store(true)
	if e.activity.closeV1() {
		e.retireClosedV1()
	}
}

// Caller holds the registered evidence mutex; this is a fixed internal source/provider entry, never a
// public supplied callback. The returned release closes the source use only
// after every helper-local body/reference has gone out of scope.
func (e *ApplicationHTMLSendEvidenceV1) beginV1() (context.Context, *applicationHTMLSendSourceStateV1, func(), error) {
	if e.closeRequested.Load() || e.source == nil || e.work == nil || e.client == nil {
		return nil, nil, nil, ErrHTMLSendEvidenceV1
	}
	s := e.source
	if !s.lockV1() {
		return nil, nil, nil, ErrHTMLSendEvidenceV1
	}
	if s.closeRequested.Load() || s.owner == nil || !s.attempted || s.failure != nil || s.owner.purpose != htmlSendSourcePurposeV1 {
		s.unlockV1()
		return nil, nil, nil, ErrHTMLSendEvidenceV1
	}
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		s.unlockV1()
		return nil, nil, nil, err
	}
	release := func() { owner.finishV1(); s.unlockV1() }
	return owner.binding.ctx, s, release, nil
}
func (e *ApplicationHTMLSendEvidenceV1) providerV1(ctx context.Context) (*workguard.GrantV1, error) {
	if e.source == nil || e.source.owner == nil || e.source.owner.binding == nil {
		return nil, ErrHTMLSendEvidenceV1
	}
	b := e.source.owner.binding
	p := b.factory
	p.mu.Lock()
	available := !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return nil, ErrHTMLSendEvidenceV1
	}
	// One synchronous provider call owns its raw/body/parser staging until every
	// response Close and caller PDF/body use has actually joined. The separately
	// retained immutable source/pins never borrow this transient credit.
	scratch := int64(0)
	if !htmlInputAddV1(&scratch, e.limits.ObjectBytes+1, 4) || !htmlInputAddV1(&scratch, e.limits.MetadataBytes, 4) || !htmlInputAddV1(&scratch, e.limits.HeaderBytes, 4) || !htmlInputAddV1(&scratch, e.limits.VersionIDBytes, 2) {
		return nil, ErrHTMLSendEvidenceV1
	}
	g, err := coordinator.TryAcquireV1(ctx, b.org, workguard.VectorV1{ParentBytes: scratch, ProviderStreams: 1})
	if err != nil {
		return nil, errors.Join(ErrHTMLSendEvidenceV1, err)
	}
	return g, nil
}

// The caller still owns the per-call provider grant. Charge every escaping
// VersionId/error before that grant ends. On credit refusal only a fixed
// admission sentinel escapes; no uncharged provider error is retained. SDK
// XML/allocator/GC/process effects remain explicit capacity qualification.
func (e *ApplicationHTMLSendEvidenceV1) retainProviderResultV1(cause error, version string) error {
	if e.source == nil || e.source.owner == nil {
		return ErrHTMLSendEvidenceV1
	}
	retained := int64(unsafe.Sizeof(pgtype.Text{})) + 4*int64(unsafe.Sizeof(uintptr(0)))
	if !htmlInputAddV1(&retained, int64(len(version)), 2) {
		return ErrHTMLSendEvidenceV1
	}
	if cause != nil {
		// Concrete bounded metadata/error/header decoders and wrapping text remain
		// reachable through the returned error chain, independently of raw bodies.
		if !htmlInputAddV1(&retained, e.limits.MetadataBytes, 4) || !htmlInputAddV1(&retained, e.limits.HeaderBytes, 4) || !htmlInputAddV1(&retained, int64(len(cause.Error())), 4) {
			return ErrHTMLSendEvidenceV1
		}
		d := e.source.owner.snapshot.document
		if !htmlInputAddV1(&retained, int64(len(d.PdfStorageKey.String)+len(d.RenderedPdfKey.String)), 4) {
			return ErrHTMLSendEvidenceV1
		}
	}
	if err := e.source.owner.holdV1(htmlRevisionSourceStateV1, 0, retained); err != nil {
		return err
	}
	return cause
}
func (e *ApplicationHTMLSendEvidenceV1) resolveV1(ctx context.Context, d *generated.Document, key pgtype.Text, digest []byte, current pgtype.Text) (pgtype.Text, error) {
	if !key.Valid || strings.TrimSpace(key.String) == "" {
		return pgtype.Text{}, nil
	}
	if len(digest) != sha256.Size {
		return pgtype.Text{}, fmt.Errorf("evidence %q has no valid SHA-256", key.String)
	}
	if current.Valid && strings.TrimSpace(current.String) != "" {
		g, err := e.providerV1(ctx)
		if err != nil {
			return pgtype.Text{}, err
		}
		body, err := e.client.GetVerifiedVersionForSendV1(ctx, key.String, current.String, digest)
		clear(body)
		body = nil
		err = e.retainProviderResultV1(err, "")
		g.Close()
		if err != nil {
			return pgtype.Text{}, err
		}
		return current, nil
	}
	if d.EvidenceVersionPinsRequired {
		return pgtype.Text{}, fmt.Errorf("evidence %q is missing its required VersionId", key.String)
	}
	g, err := e.providerV1(ctx)
	if err != nil {
		return pgtype.Text{}, err
	}
	body, stored, err := e.client.ResolveVerifiedLegacyForSendV1(ctx, key.String, digest)
	clear(body)
	body = nil
	err = e.retainProviderResultV1(err, stored.VersionID)
	if err != nil {
		stored = storage.StoredObject{}
	}
	g.Close()
	if err != nil {
		return pgtype.Text{}, err
	}
	if strings.TrimSpace(stored.VersionID) == "" {
		return pgtype.Text{}, fmt.Errorf("evidence %q resolved without a VersionId", key.String)
	}
	return pgtype.Text{String: stored.VersionID, Valid: true}, nil
}
func (e *ApplicationHTMLSendEvidenceV1) PreparePinsV1() error {
	if e == nil || e.self != e {
		return ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.draft || e.bound {
		return ErrHTMLSendEvidenceV1
	}
	ctx, _, done, err := e.beginV1()
	if err != nil {
		return err
	}
	defer done()
	if e.prepareAttempted {
		return e.prepareError
	}
	e.prepareAttempted = true
	e.prepareError = ErrHTMLSendEvidenceV1
	d := e.original
	pdf, err := e.resolveV1(ctx, d, d.PdfStorageKey, d.PdfSha256, d.PdfStorageVersionID)
	if err != nil {
		e.prepareError = fmt.Errorf("resume send sealing: pin source PDF VersionId: %w", err)
		return e.prepareError
	}
	rendered, err := e.resolveV1(ctx, d, d.RenderedPdfKey, d.RenderedPdfSha, d.RenderedPdfVersionID)
	if err != nil {
		e.prepareError = fmt.Errorf("resume send sealing: pin rendered PDF VersionId: %w", err)
		return e.prepareError
	}
	e.pdfVersion, e.renderedVersion = pdf, rendered
	e.prepareError = nil
	return nil
}

// Compare ONLY actual private DB snapshots. The four permitted pin mutations
// are removed from temporary local comparison values; no caller Document is
// adopted or normalized and all other81-column legal/source identity remains.
func htmlSendEvidenceSameTupleV1(a, b *generated.Document) bool {
	return htmlSendEvidencePinnedTupleEqualV1(a, b)
}

// Caller holds e.mu and both actual source borrowers through tuple validation.
// Move the fixed evidence consumer to its new Work before the old Work can
// retire. Closing a superseded SQL phase must not close the current evidence.
func (e *ApplicationHTMLSendEvidenceV1) transferWorkRegistrationV1(next *ApplicationHTMLSendWorkV1) error {
	previous := e.work
	if previous == nil || next == nil {
		return ErrHTMLSendEvidenceV1
	}
	if previous == next {
		previous.mu.Lock()
		defer previous.mu.Unlock()
		if previous.familyRoot == nil || previous.closed || previous.resourcesClosed || previous.evidence != e || e.closeRequested.Load() {
			return ErrHTMLSendEvidenceV1
		}
		return nil
	}
	previous.mu.Lock()
	defer previous.mu.Unlock()
	next.mu.Lock()
	defer next.mu.Unlock()
	if previous.closed || previous.resourcesClosed || previous.evidence != e || next.closed || next.resourcesClosed || next.evidence != nil || previous.stage == nil || next.stage == nil || previous.stage.operation != next.stage.operation || e.closeRequested.Load() {
		return ErrHTMLSendEvidenceV1
	}
	previous.evidence = nil
	next.evidence = e
	return nil
}

// The pin SQL's idempotent winner may already have installed THESE exact pins.
// It may not change source, keys/digests/legal tuple, or substitute other pins.
func (e *ApplicationHTMLSendEvidenceV1) pinsForWorkV1(w *ApplicationHTMLSendWorkV1) (pgtype.Text, pgtype.Text, error) {
	if e == nil || e.self != e || w == nil || w.self != w {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.closeRequested.Load() || e.draft || e.bound || !e.prepareAttempted || e.prepareError != nil || e.work == nil || e.original == nil || e.source == nil {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	s := e.source
	if !s.lockV1() {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return pgtype.Text{}, pgtype.Text{}, err
	}
	defer s.owner.finishV1()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.resourcesClosed || w.stage == nil || e.work.stage == nil || w.stage.operation != e.work.stage.operation || w.stage.purpose != HTMLSendPinV1 || (w.sourceStarted && !(w == e.work && w.familyRoot != nil && w.sourceState == s && w.sourceOwner == s.owner)) || w.sourceDocument == nil || !htmlSendEvidenceSameTupleV1(e.original, w.sourceDocument) {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	d := w.sourceDocument
	// An unchanged originally malformed/empty version still reaches original
	// pin SQL/error semantics. A concurrent installed value must be OUR resolved
	// exact pin; no unrelated version may be adopted through this idempotency.
	if (d.PdfStorageVersionID != e.original.PdfStorageVersionID && d.PdfStorageVersionID != e.pdfVersion) || (d.RenderedPdfVersionID != e.original.RenderedPdfVersionID && d.RenderedPdfVersionID != e.renderedVersion) {
		return pgtype.Text{}, pgtype.Text{}, ErrHTMLSendEvidenceV1
	}
	return e.pdfVersion, e.renderedVersion, nil
}

// Bind only a fresh native source minted AFTER actual pin SQL installation.
// Original source credit remains with its original Work through last use.
func (e *ApplicationHTMLSendEvidenceV1) BindPinnedV1(source *ApplicationHTMLSendSourceV1) error {
	if e == nil || e.self != e || source == nil || source.state == nil {
		return ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.closeRequested.Load() || e.draft || e.bound || e.work == nil || e.work.stage == nil || !e.prepareAttempted || e.prepareError != nil || e.source == nil {
		return ErrHTMLSendEvidenceV1
	}
	old := e.source
	if !old.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer old.unlockV1()
	if old.closeRequested.Load() || old.owner == nil {
		return ErrHTMLSendEvidenceV1
	}
	if err := old.owner.beginV1(); err != nil {
		return err
	}
	defer old.owner.finishV1()
	s := source.state
	if s == old {
		return ErrHTMLSendEvidenceV1
	}
	if !s.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer s.unlockV1()
	w := s.work
	if s.closeRequested.Load() || s.owner == nil || !s.attempted || s.failure != nil || s.candidate || w == nil || w.stage == nil || w.stage.operation != e.work.stage.operation || w.stage.purpose != HTMLSendPinV1 || !w.pinsCompleted || s.owner.snapshot == nil {
		return ErrHTMLSendEvidenceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	d := s.owner.snapshot.document
	if !htmlSendEvidenceSameTupleV1(e.original, d) || !d.EvidenceVersionPinsRequired || d.PdfStorageVersionID != e.pdfVersion || d.RenderedPdfVersionID != e.renderedVersion {
		return ErrHTMLSendEvidenceV1
	}
	// Last actual old-tuple use ends under its OWN active/source/body borrower.
	// Nothing from that variable backing survives into methods pinned only to s.
	w.mu.Lock()
	installed := !w.closed && !w.resourcesClosed && w.pinsCompleted && w.sourceState == s && w.sourceOwner == s.owner
	w.mu.Unlock()
	if !installed || e.closeRequested.Load() {
		return ErrHTMLSendEvidenceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	if err := e.transferWorkRegistrationV1(w); err != nil {
		s.owner.finishV1()
		return err
	}
	newOwner := s.owner
	var once sync.Once
	nextRelease := func() { once.Do(newOwner.finishV1) }
	oldRelease := e.releaseSource
	e.original = nil
	e.pdfVersion = pgtype.Text{}
	e.renderedVersion = pgtype.Text{}
	e.work = w
	e.source = s
	e.releaseSource = nextRelease
	e.bound = true
	if oldRelease != nil {
		oldRelease()
	}
	return nil
}

// Field collection expansion belongs AFTER the original source PDF inspection.
// Transfer only between actual private snapshots in the SAME operation. Both
// source owners remain active through the complete 81-column comparison. The
// fields phase may observe a different UpdatedAt, but every legal/source field,
// including EvidenceVersionPinsRequired and exact pins, must remain identical.
func htmlSendEvidenceFieldTupleEqualV1(a, b *generated.Document) bool {
	if a == nil || b == nil {
		return false
	}
	before := *a
	before.UpdatedAt = b.UpdatedAt
	return htmlSendDocumentExactTupleEqualV1(&before, b)
}
func (e *ApplicationHTMLSendEvidenceV1) BindFieldsV1(source *ApplicationHTMLSendSourceV1) error {
	if e == nil || e.self != e || source == nil || source.state == nil {
		return ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.closeRequested.Load() || e.draft || !e.bound || e.fieldsBound || !e.inspectAttempted || e.inspectError != nil || e.retainAttempted || e.work == nil || e.work.stage == nil || e.source == nil {
		return ErrHTMLSendEvidenceV1
	}
	old := e.source
	if !old.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer old.unlockV1()
	if old.closeRequested.Load() || old.owner == nil || old.owner.snapshot == nil || old.owner.snapshot.document == nil {
		return ErrHTMLSendEvidenceV1
	}
	if err := old.owner.beginV1(); err != nil {
		return err
	}
	defer old.owner.finishV1()
	s := source.state
	if s == old {
		return ErrHTMLSendEvidenceV1
	}
	if !s.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer s.unlockV1()
	w := s.work
	if s.closeRequested.Load() || s.owner == nil || s.owner.snapshot == nil || s.owner.snapshot.document == nil || !s.attempted || s.failure != nil || !s.currentAttempted || s.currentFailure != nil || s.candidate || w == nil || w.stage == nil || w.stage.operation != e.work.stage.operation || w.stage.purpose != HTMLSendSnapshotFieldsV1 {
		return ErrHTMLSendEvidenceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if !htmlSendEvidenceFieldTupleEqualV1(old.owner.snapshot.document, s.owner.snapshot.document) {
		return ErrHTMLSendEvidenceV1
	}
	// Both collections were read under this new phase's actual scoped locks and
	// the original party policy has already consumed its private recipient copy.
	w.mu.Lock()
	member := w.familyRoot != nil
	installed := !w.closed && !w.resourcesClosed && (s.owner.snapshot.document.SourceKind != "pdf" || w.fieldsRead) && w.sourceState == s && w.sourceOwner == s.owner && (member || (w.recipientsRead && s.partiesAttempted && s.partiesFailure == nil))
	w.mu.Unlock()
	if member && !w.memberRootPartiesReadyV1() {
		return ErrHTMLSendEvidenceV1
	}
	if !installed || e.closeRequested.Load() {
		return ErrHTMLSendEvidenceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	if err := e.transferWorkRegistrationV1(w); err != nil {
		s.owner.finishV1()
		return err
	}
	newOwner := s.owner
	var once sync.Once
	nextRelease := func() { once.Do(newOwner.finishV1) }
	oldRelease := e.releaseSource
	e.work = w
	e.source = s
	e.releaseSource = nextRelease
	e.fieldsBound = true
	if oldRelease != nil {
		oldRelease()
	}
	return nil
}
func (e *ApplicationHTMLSendEvidenceV1) InspectPDFV1() (int, error) {
	if e == nil || e.self != e {
		return 0, ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return 0, ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if !e.draft && !e.bound {
		return 0, ErrHTMLSendEvidenceV1
	}
	ctx, s, done, err := e.beginV1()
	if err != nil {
		return 0, err
	}
	defer done()
	if e.inspectAttempted {
		return e.pages, e.inspectError
	}
	e.inspectAttempted = true
	e.inspectError = ErrHTMLSendEvidenceV1
	d := s.owner.snapshot.document
	if d.SourceKind != "pdf" {
		e.inspectError = nil
		return 0, nil
	}
	if !d.PdfStorageKey.Valid || strings.TrimSpace(d.PdfStorageKey.String) == "" || len(d.PdfSha256) != sha256.Size {
		e.inspectError = ErrHTMLSendPDFMissingV1
		return 0, e.inspectError
	}
	g, err := e.providerV1(ctx)
	if err != nil {
		e.inspectError = err
		return 0, err
	}
	var body []byte
	if d.PdfStorageVersionID.Valid && strings.TrimSpace(d.PdfStorageVersionID.String) != "" {
		body, err = e.client.GetVerifiedVersionForSendV1(ctx, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256)
	} else if d.EvidenceVersionPinsRequired {
		err = errors.New("send evidence VersionId is required")
	} else {
		body, _, err = e.client.ResolveVerifiedLegacyForSendV1(ctx, d.PdfStorageKey.String, d.PdfSha256)
	}
	defer func() { clear(body); body = nil; g.Close() }()
	if err != nil {
		err = e.retainProviderResultV1(err, "")
		e.inspectError = fmt.Errorf("send PDF: load retained source: %w", err)
		return 0, e.inspectError
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], d.PdfSha256) != 1 {
		e.inspectError = errors.New("send PDF: source digest does not match recorded intake hash")
		return 0, e.inspectError
	}
	// Preserve original configured isolated-worker/development policy. Logical
	// source credit asserts no PDF child-address/allocator/RSS capacity proof.
	pages, err := sanitize.PageCountWithContext(ctx, body)
	if err != nil || pages < 1 {
		if err == nil {
			err = errors.New("PDF has no pages")
		}
		err = e.retainProviderResultV1(err, "")
		e.inspectError = fmt.Errorf("send PDF: inspect retained source: %w", err)
		return 0, e.inspectError
	}
	e.pages = pages
	e.inspectError = nil
	return pages, nil
}

// Original ready/party/field policy runs at fixed Send points. This helper
// requires the SAME pinned source and successful actual role/field observation.
func (e *ApplicationHTMLSendEvidenceV1) RetainReadyV1(retainUntil time.Time) error {
	if e == nil || e.self != e {
		return ErrHTMLSendEvidenceV1
	}
	if !e.lockV1() {
		return ErrHTMLSendEvidenceV1
	}
	defer e.unlockV1()
	if e.draft || !e.bound || !e.fieldsBound || !e.inspectAttempted || e.inspectError != nil {
		return ErrHTMLSendEvidenceV1
	}
	ctx, s, done, err := e.beginV1()
	if err != nil {
		return err
	}
	defer done()
	if e.retainAttempted {
		if !e.retainUntil.Equal(retainUntil) {
			return ErrHTMLSendEvidenceV1
		}
		return e.retainError
	}
	e.retainAttempted = true
	e.retainUntil = retainUntil
	e.retainError = ErrHTMLSendEvidenceV1
	d := s.owner.snapshot.document
	if ((s.work.familyRoot == nil && (!s.partiesAttempted || s.partiesFailure != nil)) || (s.work.familyRoot != nil && !s.work.memberRootPartiesReadyV1())) || (d.SourceKind == "pdf" && ((!d.RequiresSignature && len(s.work.sourceFields) != 0) || (d.RequiresSignature && (!s.rolesAttempted || s.rolesFailure != nil || s.rolesPages != e.pages)))) || (d.SourceKind == "blocks" && (!s.blockAttempted || s.blockFailure != nil || (!d.IsEnvelope && (!s.blockRolesAttempted || s.blockRolesFailure != nil)))) {
		return e.retainError
	}
	type artifact struct {
		key, version string
		digest       []byte
	}
	var artifacts [2]artifact
	n := 0
	if d.PdfStorageKey.Valid && d.PdfStorageKey.String != "" {
		artifacts[n] = artifact{d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256}
		n++
	}
	if d.RenderedPdfKey.Valid && d.RenderedPdfKey.String != "" && (!d.PdfStorageKey.Valid || d.RenderedPdfKey.String != d.PdfStorageKey.String) {
		artifacts[n] = artifact{d.RenderedPdfKey.String, d.RenderedPdfVersionID.String, d.RenderedPdfSha}
		n++
	}
	for _, a := range artifacts[:n] {
		if strings.TrimSpace(a.key) == "" || strings.TrimSpace(a.version) == "" || len(a.digest) != sha256.Size {
			e.retainError = fmt.Errorf("retain send evidence %q: committed SHA-256 or VersionId is unavailable", a.key)
			return e.retainError
		}
		g, err := e.providerV1(ctx)
		if err != nil {
			e.retainError = err
			return err
		}
		err = e.client.RetainEvidenceVersionForSendV1(ctx, a.key, a.version, a.digest, retainUntil)
		err = e.retainProviderResultV1(err, "")
		g.Close()
		if err != nil {
			e.retainError = fmt.Errorf("retain send evidence %q: %w", a.key, err)
			return e.retainError
		}
	}
	e.retainError = nil
	return nil
}
