// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package fitprepare stages an immutable all-page manual-signature archive.
// It does not publish signatures, apply Object Lock, select a ceremony or
// authorize a recipient. Those effects belong to the locked signing saga.
package fitprepare

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

var (
	ErrPreparationV1     = errors.New("fit preparation unavailable")
	ErrIdentityV1        = errors.New("fit preparation identity mismatch")
	ErrBudgetV1          = errors.New("fit preparation budget not admitted")
	ErrLeaseV1           = errors.New("fit preparation current owner lease required")
	ErrUncertainIOV1     = errors.New("fit preparation outcome requires positive reconciliation")
	ErrOriginalPayloadV1 = errors.New("fit preparation requires the original reserved payload")
)

// BudgetV1 is the caller's conservative, locked whole-document admission.
// EvidenceOtherBytes includes source/final/certificate/index/ZIP framing and ALL
// other selected, unpublished and uncertain reservations. ProcessingOtherBytes
// includes the exact source, base/other-party PDF layers and complete composition
// metadata. These are not inferred from the fitted-artifact SQL counter.
// Selection and final Sign MUST recheck this proof under document/recipient locks.
type BudgetV1 struct {
	FitBytes             int64
	EvidenceOtherBytes   int64
	ProcessingOtherBytes int64
}

func (b BudgetV1) validate(sourceBytes int64) error {
	if b.FitBytes < 3 || b.EvidenceOtherBytes < sourceBytes || b.EvidenceOtherBytes > manualfit.MaxEvidenceBytesV1 || b.FitBytes > manualfit.MaxEvidenceBytesV1-b.EvidenceOtherBytes ||
		b.ProcessingOtherBytes < sourceBytes || b.ProcessingOtherBytes >= sanitize.MaxPDFBytes {
		return ErrBudgetV1
	}
	return nil
}

// AdmissionV1 must establish permission and budget from current application
// authority under its original document -> recipient locks, including credential,
// notice, source and ALL targets. It must not treat AuthorityV1 as authorization.
// Called on EVERY resume, before any renderer, storage or worker I/O. Returned
// proof is a bounded reservation; publication still needs a fresh locked rebind.
type AdmissionV1 func(context.Context, *manualfit.AuthorityV1) (BudgetV1, error)

type ObjectIDV1 struct {
	Kind string
	Page int32
}

// RequestV1 must use a stable OperationID after an uncertain database/object
// outcome. Takeover is explicit and only legal after the old lease expires.
// OriginalPayloads optionally supplies exact captured bytes for a reserved but
// never-attempted page after interruption. It can never replace a committed hash
// or permit a second PUT after an attempted upload. Names/font/target arrays come
// from the original captured authority, not redacted/current recipient rows.
type RequestV1 struct {
	OperationID          uuid.UUID
	OwnerID              uuid.UUID
	Authority            *manualfit.AuthorityV1
	Span                 []byte // Original inert span; optional when durable original/upload recovery supplies it.
	LeaseUntil           time.Time
	TakeoverExpiredLease bool
	Admission            AdmissionV1
	OriginalPayloads     map[ObjectIDV1][]byte
}

// JournalV1 methods are committed checkpoints, never operations within the
// caller's uncommitted transaction. Ambiguous errors refuse further effects.
// SQLJournalV1 is the production adapter and intentionally accepts only a pool.
type JournalV1 interface {
	Get(context.Context, generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error)
	Reserve(context.Context, generated.ReserveSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error)
	Claim(context.Context, generated.ClaimSignatureFitPreparationLeaseParams) (*generated.SignatureFitPreparation, error)
	Objects(context.Context, generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error)
	ReserveObject(context.Context, generated.ReserveSignatureFitObjectParams) (*generated.SignatureFitObject, error)
	Attempt(context.Context, generated.MarkSignatureFitUploadAttemptedParams) (*generated.SignatureFitObject, error)
	Pin(context.Context, generated.PinSignatureFitObjectVersionParams) (*generated.SignatureFitObject, error)
	Verified(context.Context, generated.MarkSignatureFitObjectReadbackVerifiedParams) (*generated.SignatureFitObject, error)
	Prepared(context.Context, generated.MarkSignatureFitPreparationPreparedParams) (*generated.SignatureFitPreparation, error)
}

// OriginalJournalV1 is an optional request-scoped durable-original adapter.
// Reserve commits the 85 preparation, exact immutable authority and original span
// atomically. Capture commits an exact identity-idempotent body BEFORE 85 object
// reservation; a late/unknown acknowledgment refuses further effects. Authority
// and Load read authenticated frozen originals, never hot fields/names or QA data.
// Only bare pgx.ErrNoRows from Load denotes a definitive, physically reconciled
// absence; wrapped/joined errors refuse further effects. Fresh rendering is
// allowed only for that sentinel AND no existing object reservation.
// The adapter must admit aggregate resource/storage quotas before body retrieval,
// decoding or copying. Returned leases own their resource hold through consumer
// Close AND any outstanding physical SQL CleanupDone. A lease is not permission
// to sign, replay an attempted PUT, delete originals or infer safe cleanup.
// The caller also owns whole-Prepare concurrency/memory admission; these bounded
// producer/read contracts do not establish a whole-process memory guarantee.
type OriginalJournalV1 interface {
	Reserve(context.Context, generated.ReserveSignatureFitPreparationParams, *manualfit.AuthorityV1, []byte) (*generated.SignatureFitPreparation, error)
	Authority(context.Context, *generated.SignatureFitPreparation) (*OriginalAuthorityV1, error)
	Capture(context.Context, *generated.SignatureFitPreparation, ObjectIDV1, string, string, []byte) error
	Load(context.Context, *generated.SignatureFitPreparation, ObjectIDV1) (*OriginalPayloadV1, error)
}

// OriginalPayloadV1 owns a bounded original-body/resource lease. Bytes returns
// a borrowed view: use it from one consumer, do not mutate/retain it, and do not
// call Bytes concurrently with Close. It is valid only until Close.
type OriginalPayloadV1 struct {
	body    []byte
	release func()
	once    sync.Once
}

func (p *OriginalPayloadV1) Bytes() []byte {
	if p == nil {
		return nil
	}
	return p.body
}
func (p *OriginalPayloadV1) Close() {
	if p == nil {
		return
	}
	p.once.Do(func() {
		clear(p.body)
		p.body = nil
		if p.release != nil {
			p.release()
			p.release = nil
		}
	})
}

// OriginalAuthorityV1 holds an immutable authority/resource lease. Authority
// returns a borrowed immutable pointer valid only until Close; use one consumer.
type OriginalAuthorityV1 struct {
	authority *manualfit.AuthorityV1
	release   func()
	once      sync.Once
}

func (a *OriginalAuthorityV1) Authority() *manualfit.AuthorityV1 {
	if a == nil {
		return nil
	}
	return a.authority
}
func (a *OriginalAuthorityV1) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() {
		a.authority = nil
		if a.release != nil {
			a.release()
			a.release = nil
		}
	})
}

type ObjectsV1 interface {
	manualfit.BoundedReaderV1
	ResolveFitTransientVersion(context.Context, storage.FitTransientReservation) (storage.StoredObject, bool, error)
	PutFitTransientReserved(context.Context, storage.FitTransientReservation, []byte) (storage.StoredObject, error)
}
type RendererV1 interface {
	PrepareManualSignaturePageV1(context.Context, signaturefit.Plan) (*signaturefit.Package, error)
}
type InspectorV1 interface {
	Source(context.Context, []byte) (sanitize.PDFManualGeometry, error)
	Fragment(context.Context, []byte, float64, float64) (sanitize.PDFManualFragmentAdmission, error)
}

// IsolatedInspectorV1 never parses a PDF in the application process.
type IsolatedInspectorV1 struct{}

func (IsolatedInspectorV1) Source(ctx context.Context, raw []byte) (sanitize.PDFManualGeometry, error) {
	return sanitize.InspectManualPDFWithContext(ctx, raw)
}
func (IsolatedInspectorV1) Fragment(ctx context.Context, raw []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
	return sanitize.InspectManualPDFFragmentWithContext(ctx, raw, w, h)
}

type PreparerV1 struct {
	Journal   JournalV1
	Originals OriginalJournalV1 // Nil preserves historical caller-supplied recovery.
	Objects   ObjectsV1
	Renderer  RendererV1 // May be nil when recovering a complete original archive.
	Inspector InspectorV1
}

// PreparedV1 can only be returned after complete original-byte verification,
// isolated fragment admission and the committed prepared checkpoint. This is a
// transient archive, not a WORM receipt or signing credential.
type PreparedV1 struct {
	manifest *manualfit.ManifestV1
	pin      manualfit.ObjectPinV1
}

func (p *PreparedV1) Binding() manualfit.BindingV1 {
	if p == nil {
		return manualfit.BindingV1{}
	}
	return p.manifest.Binding()
}
func (p *PreparedV1) ManifestObject() manualfit.ObjectPinV1 {
	if p == nil {
		return manualfit.ObjectPinV1{}
	}
	return p.pin
}
func (p *PreparedV1) Manifest() *manualfit.ManifestV1 {
	if p == nil {
		return nil
	}
	m, _ := manualfit.DecodeManifestV1(p.manifest.CanonicalJSON(), p.manifest.Binding())
	return m
}
