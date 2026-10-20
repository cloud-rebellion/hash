// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// Source24 follows the two separately owned finite certificate purposes.
const HTMLHistoricalFinalizationSourceV1 HTMLSendSQLPurposeV1 = HTMLHistoricalFinalizationCertificateRenderV1 + 1

var ErrHistoricalFinalizationSourceV1 = errors.New("pdfadmission: native finalization source evidence unavailable")

type ApplicationHistoricalFinalizationSourceEvidenceV1 struct {
	activityMutex                                                                                                    sync.Mutex
	activity                                                                                                         applicationJoinedActivityV1
	self                                                                                                             *ApplicationHistoricalFinalizationSourceEvidenceV1
	closeRequested                                                                                                   atomic.Bool
	work                                                                                                             *ApplicationHTMLSendWorkV1
	client                                                                                                           *storage.Client
	limits                                                                                                           storage.SendEvidenceLimitsV1
	ctx                                                                                                              context.Context
	document                                                                                                         *generated.Document
	view                                                                                                             *generated.Document
	signatures, signatureViews                                                                                       []*generated.Signature
	sourceAttempted, sourceChecked, signaturesAttempted, signaturesChecked, familyAttempted, intentVersionsAttempted bool
	intentVersionOriginal, intentVersionPinned                                                                       *generated.DocumentFinalizationIntent
	resumePredecessor                                                                                                *ApplicationHistoricalFinalizationSourceEvidenceV1
	releaseBody                                                                                                      func()
	bodyBorrowers                                                                                                    int
}

func (w *ApplicationHTMLSendWorkV1) NewHistoricalFinalizationSourceEvidenceV1(call context.Context, client *storage.Client) (*ApplicationHistoricalFinalizationSourceEvidenceV1, error) {
	if w == nil || w.self != w || client == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return nil, errors.Join(ErrHistoricalFinalizationSourceV1, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.sourceDocument == nil || w.sourceDocument.Status != "finalizing" || w.models == nil || w.historicalSourceEvidence != nil || w.stage.operation == nil || w.stage.operation.factory == nil || w.stage.operation.factory.state != w.session.state.factory {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	raw := 2*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationSourceEvidenceV1{})) + 2*int64(unsafe.Sizeof(sync.Once{})) + 8*int64(unsafe.Sizeof(uintptr(0)))
	for _, n := range []int64{limits.MetadataBytes, limits.HeaderBytes, limits.VersionIDBytes} {
		if !htmlInputAddV1(&raw, n, 4) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	closeOwner, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeOwner)
	w.sourceBorrowers++
	e := &ApplicationHistoricalFinalizationSourceEvidenceV1{work: w, client: client, limits: limits, ctx: w.stage.operation.original, document: w.sourceDocument, view: w.models.Document}
	e.self = e
	var once sync.Once
	e.releaseBody = func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			w.releaseFamilyRootIfRetiredV1()
		})
	}
	w.historicalSourceEvidence = e
	return e, nil
}

// Activity is admitted before waiting and remains owned through every actual
// callback/consumer completion. Closed admission never discards a prior finish.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) lockV1() bool {
	if !e.activity.enterV1() {
		return false
	}
	e.activityMutex.Lock()
	return true
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) finishActivityV1() {
	if e.activity.leaveV1() {
		e.retireClosedV1()
	}
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) unlockV1() {
	e.activityMutex.Unlock()
	e.finishActivityV1()
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) retireClosedV1() {
	if !e.closeRequested.Load() || e.bodyBorrowers != 0 {
		return
	}
	release := e.releaseBody
	e.releaseBody = nil
	e.work = nil
	e.client = nil
	e.ctx = nil
	e.document = nil
	e.view = nil
	e.signatures = nil
	e.signatureViews = nil
	e.intentVersionOriginal = nil
	e.intentVersionPinned = nil
	e.resumePredecessor = nil
	if release != nil {
		release()
	}
}

// Every actual metadata/refusal exit joins a pending copied Close. The real
// body count still prevents clearing or credit before the last callback joins.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) CloseConsumerV1() {
	if e == nil || e.self != e {
		return
	}
	e.closeRequested.Store(true)
	if e.activity.closeV1() {
		e.retireClosedV1()
	}
}

func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) validV1() bool {
	if e == nil || e.self != e || e.closeRequested.Load() || e.work == nil || e.client == nil || e.ctx == nil || e.ctx.Err() != nil || e.document == nil {
		return false
	}
	w := e.work
	w.mu.Lock()
	defer w.mu.Unlock()
	return !w.closed && !w.resourcesClosed && w.historicalSourceEvidence == e && w.sourceBorrowers > 0 && w.session != nil && w.session.state != nil && w.stage != nil && w.stage.operation != nil && w.stage.purpose == HTMLHistoricalFinalizationSourceV1 && w.session.state.org == e.document.OrgID && w.logicalDocumentV1() == e.document.ID
}

// The concrete first-party limit is priced before its SDK expands a response.
// A distinct stream grant joins the synchronous SDK Read/Close; raw-body work
// stays through the actual callback even when that callback makes other reads.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) providerV1() (*workguard.GrantV1, *workguard.GrantV1, error) {
	if !e.validV1() {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	p := e.work.session.state.factory
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	raw := int64(0)
	if !htmlInputAddV1(&raw, e.limits.ObjectBytes+1, 4) || !htmlInputAddV1(&raw, e.limits.MetadataBytes, 4) || !htmlInputAddV1(&raw, e.limits.HeaderBytes, 4) || !htmlInputAddV1(&raw, e.limits.VersionIDBytes, 2) {
		return nil, nil, ErrHistoricalFinalizationSourceV1
	}
	body, err := coordinator.TryAcquireV1(e.ctx, e.document.OrgID, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return nil, nil, errors.Join(ErrHistoricalFinalizationSourceV1, err)
	}
	stream, err := coordinator.TryAcquireV1(e.ctx, e.document.OrgID, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		body.Close()
		return nil, nil, errors.Join(ErrHistoricalFinalizationSourceV1, err)
	}
	return body, stream, nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) readV1(key, version string, digest []byte, legacy bool, consume func([]byte) error) (stored storage.StoredObject, failure error) {
	bodyGrant, stream, err := e.providerV1()
	if err != nil {
		return stored, err
	}
	defer bodyGrant.Close()
	var body []byte
	if legacy {
		body, stored, err = e.client.ResolveVerifiedLegacyForSendV1(e.ctx, key, digest)
	} else {
		body, err = e.client.GetVerifiedVersionForSendV1(e.ctx, key, version, digest)
		stored.VersionID = version
	}
	stream.Close()
	defer func() { clear(body); body = nil }()
	if err != nil {
		return stored, err
	}
	if int64(len(body)) > e.limits.ObjectBytes || int64(len(stored.VersionID)) > e.limits.VersionIDBytes {
		return stored, ErrHistoricalFinalizationSourceV1
	}
	if consume != nil {
		err = consume(body)
	}
	return stored, err
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) resolveSourceV1(key pgtype.Text, digest []byte, current pgtype.Text) (pgtype.Text, error) {
	if !key.Valid || strings.TrimSpace(key.String) == "" {
		return pgtype.Text{}, nil
	}
	if len(digest) != sha256.Size {
		return pgtype.Text{}, fmt.Errorf("finalization: source %q has no valid storage commitment", key.String)
	}
	if current.Valid && strings.TrimSpace(current.String) != "" {
		_, err := e.readV1(key.String, current.String, digest, false, nil)
		if err != nil {
			return pgtype.Text{}, fmt.Errorf("finalization: verify source %q VersionId: %w", key.String, err)
		}
		return current, nil
	}
	if e.document.EvidenceVersionPinsRequired {
		return pgtype.Text{}, fmt.Errorf("finalization: source %q is missing its required VersionId", key.String)
	}
	stored, err := e.readV1(key.String, "", digest, true, nil)
	if err != nil {
		return pgtype.Text{}, fmt.Errorf("finalization: resolve legacy source %q: %w", key.String, err)
	}
	if strings.TrimSpace(stored.VersionID) == "" {
		return pgtype.Text{}, fmt.Errorf("finalization: resolve legacy source %q returned no VersionId", key.String)
	}
	return pgtype.Text{String: stored.VersionID, Valid: true}, nil
}

// Preserve PDF-source then rendered-source resolution order. The old SQL CAS
// and exact unchanged returned source are validated before private replacement.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) EnsureSourceVersionsV1(call context.Context) (*generated.Document, error) {
	if e == nil || e.self != e {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer func() { e.unlockV1() }()
	if !e.validV1() || e.sourceAttempted {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	e.sourceAttempted = true
	w := e.work
	w.mu.Lock()
	valid := w.valid(call)
	w.mu.Unlock()
	if !valid {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	before := e.document
	pdf, err := e.resolveSourceV1(before.PdfStorageKey, before.PdfSha256, before.PdfStorageVersionID)
	if err != nil {
		return nil, err
	}
	rendered, err := e.resolveSourceV1(before.RenderedPdfKey, before.RenderedPdfSha, before.RenderedPdfVersionID)
	if err != nil {
		return nil, err
	}
	if before.EvidenceVersionPinsRequired {
		e.sourceChecked = true
		return e.view, nil
	}
	w.mu.Lock()
	extra := int64(0)
	if !htmlInputAddV1(&extra, e.limits.VersionIDBytes, 2) {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	raw, _, err := w.admitDocumentReturnV1(call, extra)
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	row, err := w.queries.PinDocumentSendEvidenceVersions(call, generated.PinDocumentSendEvidenceVersionsParams{ID: before.ID, OrgID: before.OrgID, PdfStorageVersionID: pdf, RenderedPdfVersionID: rendered})
	if err != nil {
		return nil, fmt.Errorf("finalization: persist source VersionIds: %w", err)
	}
	if row == nil || !row.EvidenceVersionPinsRequired || (row.PdfStorageKey.Valid && !row.PdfStorageVersionID.Valid) || (row.RenderedPdfKey.Valid && !row.RenderedPdfVersionID.Valid) {
		return nil, errors.New("finalization: persisted source VersionIds are incomplete")
	}
	expected := *before
	expected.PdfStorageVersionID = pdf
	expected.RenderedPdfVersionID = rendered
	expected.EvidenceVersionPinsRequired = true
	expected.UpdatedAt = row.UpdatedAt
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || !w.verifyDocumentReturnV1(row, raw) || !htmlSendDocumentExactTupleEqualV1(&expected, row) || !applicationStampV1(row.UpdatedAt) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	e.document = htmlSendCloneDocumentV1(row)
	e.view = row
	w.sourceDocument = e.document
	w.models.Document = row
	w.state.UpdatedAt = row.UpdatedAt
	e.sourceChecked = true
	return row, nil
}
func historicalInputSignatureExactV1(a, b *generated.Signature) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if (a.SignerIp == nil) != (b.SignerIp == nil) {
		return false
	}
	if a.SignerIp != nil && *a.SignerIp != *b.SignerIp {
		return false
	}
	return a.ID == b.ID && a.DocumentID == b.DocumentID && a.RecipientID == b.RecipientID && a.FieldID == b.FieldID && a.Font == b.Font && a.TypedName == b.TypedName && a.ImageStorageKey == b.ImageStorageKey && bytes.Equal(a.ImageSha256, b.ImageSha256) && a.SignerUa == b.SignerUa && a.SignedAt == b.SignedAt && a.ImageVersionID == b.ImageVersionID && a.ImageVersionPinRequired == b.ImageVersionPinRequired && a.SignatureKind == b.SignatureKind && a.PresignExecutionID == b.PresignExecutionID
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) EnsureSignatureVersionsV1(call context.Context) error {
	if e == nil || e.self != e {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer func() { e.unlockV1() }()
	if !e.validV1() || e.signaturesAttempted {
		return ErrHistoricalFinalizationSourceV1
	}
	e.signaturesAttempted = true
	w := e.work
	if _, err := w.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
		return fmt.Errorf("finalization: list signature evidence: %w", err)
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	source := state.signatures
	raw := int64(0)
	for _, s := range source {
		n, err := historicalFinalizationSignatureRawV1(s)
		if err != nil || !htmlInputAddV1(&raw, n, 2) || !htmlInputAddV1(&raw, e.limits.VersionIDBytes, 4) || !htmlInputAddV1(&raw, 1, 8*int64(unsafe.Sizeof(generated.Signature{}))+8*int64(unsafe.Sizeof((*generated.Signature)(nil)))+2*int64(unsafe.Sizeof(generated.PinLegacySignatureVersionParams{}))) {
			w.mu.Unlock()
			return ErrHistoricalFinalizationSourceV1
		}
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.closes = append(w.closes, closeRows)
	w.mu.Unlock()
	e.signatures = make([]*generated.Signature, len(source))
	e.signatureViews = make([]*generated.Signature, len(source))
	for index, signature := range source {
		if signature == nil || strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size {
			return errors.New("finalization: signature evidence commitment is incomplete")
		}
		if signature.ImageVersionPinRequired {
			if !signature.ImageVersionID.Valid || strings.TrimSpace(signature.ImageVersionID.String) == "" {
				return errors.New("finalization: signature evidence is missing its required VersionId")
			}
			if _, err = e.readV1(signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256, false, nil); err != nil {
				return fmt.Errorf("finalization: verify signature evidence %s: %w", signature.ID, err)
			}
			e.signatures[index] = historicalFinalizationCloneSignatureV1(signature)
			e.signatureViews[index] = historicalFinalizationCloneSignatureV1(signature)
			continue
		}
		if signature.ImageVersionID.Valid {
			return errors.New("finalization: legacy signature evidence has a partial VersionId commitment")
		}
		stored, err := e.readV1(signature.ImageStorageKey, "", signature.ImageSha256, true, nil)
		if err != nil {
			return fmt.Errorf("finalization: resolve legacy signature evidence %s: %w", signature.ID, err)
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return fmt.Errorf("finalization: resolve legacy signature evidence %s returned no VersionId", signature.ID)
		}
		pinned, err := w.queries.PinLegacySignatureVersion(call, generated.PinLegacySignatureVersionParams{ID: signature.ID, DocumentID: e.document.ID, ImageVersionID: pgtype.Text{String: stored.VersionID, Valid: true}})
		if errors.Is(err, pgx.ErrNoRows) {
			refreshed, listErr := w.queries.ListSignaturesByDocument(call, e.document.ID)
			if listErr != nil {
				return fmt.Errorf("finalization: reload signature evidence: %w", listErr)
			}
			if len(refreshed) != len(source) {
				return ErrHistoricalFinalizationSourceV1
			}
			for i, candidate := range refreshed {
				if candidate == nil || candidate.ID != source[i].ID {
					return ErrHistoricalFinalizationSourceV1
				}
				n, nerr := historicalFinalizationSignatureRawV1(candidate)
				old, oerr := historicalFinalizationSignatureRawV1(source[i])
				if nerr != nil || oerr != nil || n > old+e.limits.VersionIDBytes {
					return ErrHistoricalFinalizationSourceV1
				}
				if candidate.ID == signature.ID {
					pinned = candidate
				}
			}
			err = nil
		}
		if err != nil {
			return fmt.Errorf("finalization: persist signature VersionId %s: %w", signature.ID, err)
		}
		if pinned == nil || !pinned.ImageVersionPinRequired || !pinned.ImageVersionID.Valid || pinned.ImageVersionID.String != stored.VersionID {
			return fmt.Errorf("finalization: persisted signature VersionId %s does not match resolved object", signature.ID)
		}
		expected := *signature
		expected.ImageVersionPinRequired = true
		expected.ImageVersionID = pinned.ImageVersionID
		if !historicalInputSignatureExactV1(&expected, pinned) {
			return ErrHistoricalFinalizationSourceV1
		}
		if _, err = e.readV1(pinned.ImageStorageKey, pinned.ImageVersionID.String, pinned.ImageSha256, false, nil); err != nil {
			return fmt.Errorf("finalization: verify pinned signature evidence %s: %w", signature.ID, err)
		}
		e.signatures[index] = historicalFinalizationCloneSignatureV1(pinned)
		e.signatureViews[index] = pinned
	}
	e.signaturesChecked = true
	return nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) MatchesDocumentV1(row *generated.Document) bool {
	if e == nil || e.self != e {
		return false
	}
	if !e.lockV1() {
		return false
	}
	defer e.unlockV1()
	return e.validV1() && htmlSendDocumentExactTupleEqualV1(e.document, row)
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) SignatureRowsV1() ([]*generated.Signature, error) {
	if e == nil || e.self != e {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.signaturesChecked {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	return e.signatureViews, nil
}

// The callback is a synchronous local body consumer, not SQL/provider authority.
// Copied Close and cancellation cannot clear its bytes before it has joined.
// Each real body read owns a private active consumer before releasing the
// metadata mutex. The synchronous provider frame/body grant spans its whole
// callback. This permits the PDF stamp's original nested signature read while
// preserving independent stream closure and the original source last-use loan.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) beginBodyBorrowLockedV1() bool {
	if !e.activity.enterV1() {
		return false
	}
	e.bodyBorrowers++
	return true
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) finishBodyBorrowV1() {
	e.activityMutex.Lock()
	e.bodyBorrowers--
	e.unlockV1()
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) WithSourcePDFV1(consume func([]byte) error) error {
	if e == nil || e.self != e || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.validV1() || !e.sourceChecked {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	d := e.document
	if !d.PdfStorageKey.Valid || d.PdfStorageKey.String == "" {
		e.unlockV1()
		return errors.New("pdf-source document has no stored pdf")
	}
	if len(d.PdfSha256) != sha256.Size {
		e.unlockV1()
		return errors.New("pdf-source document has no valid SHA-256 commitment")
	}
	if !d.PdfStorageVersionID.Valid || strings.TrimSpace(d.PdfStorageVersionID.String) == "" {
		e.unlockV1()
		return errors.New("pdf-source document is missing its required object VersionId")
	}
	if !e.beginBodyBorrowLockedV1() {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	e.unlockV1()
	defer e.finishBodyBorrowV1()
	_, err := e.readV1(d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256, false, consume)
	return err
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) WithSignatureBodyV1(id uuid.UUID, consume func([]byte) error) error {
	if e == nil || e.self != e || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if !e.validV1() || !e.signaturesChecked {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	var selected *generated.Signature
	for _, signature := range e.signatures {
		if signature.ID == id {
			selected = signature
			break
		}
	}
	if selected == nil {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	if selected.SignatureKind == "manual_pdf_fit_v1" {
		e.unlockV1()
		return ErrHistoricalFittedPublicationV1
	}
	if !e.beginBodyBorrowLockedV1() {
		e.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	e.unlockV1()
	defer e.finishBodyBorrowV1()
	_, err := e.readV1(selected.ImageStorageKey, selected.ImageVersionID.String, selected.ImageSha256, false, consume)
	return err
}

// Only the actual root/intent and registered native member rows can establish
// this retention target. No caller timestamp, document slice or object pin is
// accepted, and actual fitted packages remain on their separate closed route.
func (w *ApplicationHTMLSendWorkV1) RetainHistoricalFinalizationSignatureInputsV1(call context.Context, client *storage.Client) error {
	if w == nil || w.self != w || client == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	intent, err := w.ReadHistoricalFinalizationIntentV1(call)
	if err != nil {
		return err
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil || state.intent == nil || w.familyRoot != nil {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	private := state.intent
	doc := w.sourceDocument
	if doc == nil || !doc.CompletionEffectiveAtBound || doc.CompletionEffectiveAt != private.CompletionEffectiveAt || doc.FinalizationRetainUntil != private.RetainUntil || private.OrgID != doc.OrgID || private.DocumentID != doc.ID {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	until := private.RetainUntil.Time.UTC()
	if !applicationStampV1(private.CompletionEffectiveAt) || !applicationStampV1(private.RetainUntil) || until.Nanosecond() != 0 || !until.Equal(storage.EvidenceRetentionDeadline(private.CompletionEffectiveAt.Time, article13.RetentionYearsV1)) {
		w.mu.Unlock()
		return errors.New("resume finalization: finalization retention deadline does not match completion commitment")
	}
	w.mu.Unlock()
	_ = intent
	children, err := w.HistoricalFinalizationMembersV1(call)
	if err != nil {
		return err
	}
	w.mu.Lock()
	memberCost := int64(0)
	if !htmlInputAddV1(&memberCost, int64(len(children)+1), 4*int64(unsafe.Sizeof((*ApplicationHTMLSendWorkV1)(nil)))) {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	closeMembers, err := w.actor.acquireOwnedRetainedBodyV1(call, memberCost, 0)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.closes = append(w.closes, closeMembers)
	w.mu.Unlock()
	members := make([]*ApplicationHTMLSendWorkV1, 0, len(children)+1)
	members = append(members, w)
	for _, child := range children {
		member := w.EnvelopeMemberForAuditV1(call, child.ID)
		if member == nil || child.CompletionEffectiveAt != doc.CompletionEffectiveAt || child.FinalizationRetainUntil != doc.FinalizationRetainUntil {
			return ErrHistoricalFinalizationSourceV1
		}
		members = append(members, member)
	}
	for _, member := range members {
		member.mu.Lock()
		actual := member.sourceDocument
		requires := actual != nil && actual.RequiresSignature
		member.mu.Unlock()
		if !requires {
			continue
		}
		if _, err = member.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
			return fmt.Errorf("resume finalization: list signature evidence for %s: %w", actual.ID, err)
		}
		member.mu.Lock()
		e := member.historicalSourceEvidence
		member.mu.Unlock()
		owned := false
		if e == nil {
			e, err = member.NewHistoricalFinalizationSourceEvidenceV1(call, client)
			if err != nil {
				return err
			}
			owned = true
		}
		err = e.retainPrivateSignaturesV1(call, until)
		if owned {
			e.CloseConsumerV1()
		}
		if err != nil {
			return err
		}
	}
	return nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) retainPrivateSignaturesV1(call context.Context, until time.Time) error {
	if !e.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer func() { e.unlockV1() }()
	if !e.validV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	w := e.work
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil || !state.signatureRead {
		w.mu.Unlock()
		return ErrHistoricalFinalizationSourceV1
	}
	signatures := state.signatures
	w.mu.Unlock()
	for _, signature := range signatures {
		if signature != nil && signature.SignatureKind == "manual_pdf_fit_v1" {
			return ErrHistoricalFittedPublicationV1
		}
	}
	for _, signature := range signatures {
		if signature == nil || signature.DocumentID != e.document.ID || strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size || !signature.ImageVersionPinRequired || !signature.ImageVersionID.Valid || strings.TrimSpace(signature.ImageVersionID.String) == "" {
			return fmt.Errorf("resume finalization: signature evidence for %s is incomplete", e.document.ID)
		}
		body, stream, err := e.providerV1()
		if err != nil {
			return err
		}
		err = e.client.RetainEvidenceVersionForSendV1(e.ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256, until)
		stream.Close()
		body.Close()
		if err != nil {
			return fmt.Errorf("resume finalization: retain signature evidence %s: %w", signature.ID, err)
		}
	}
	return nil
}
