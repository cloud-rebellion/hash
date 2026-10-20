// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"
)

// Fixed21 follows Resume19 and the concurrently owned Publication20 stage.
// This purpose reads only an actual root/intent; it grants no source policy.
const htmlHistoricalFinalizationPublicationPurposeV1 HTMLSendSQLPurposeV1 = HTMLHistoricalFinalizationResumeV1 + 1
const HTMLHistoricalFinalizationEvidenceV1 HTMLSendSQLPurposeV1 = htmlHistoricalFinalizationPublicationPurposeV1 + 1

var ErrHistoricalFinalizationEvidenceV1 = errors.New("pdfadmission: native finalization evidence unavailable")

type ApplicationHistoricalFinalizationEvidenceV1 struct {
	activityMutex     sync.Mutex
	activity          applicationJoinedActivityV1
	self              *ApplicationHistoricalFinalizationEvidenceV1
	closeRequested    atomic.Bool
	work              *ApplicationHTMLSendWorkV1
	client            *storage.Client
	limits            storage.SendEvidenceLimitsV1
	intent            *generated.DocumentFinalizationIntent
	ctx               context.Context
	verificationError *storage.EvidenceLocalVerificationV1
	retentionError    *storage.EvidenceLocalRetentionV1
	releaseBody       func()
}

func (w *ApplicationHTMLSendWorkV1) NewHistoricalFinalizationEvidenceV1(call context.Context, client *storage.Client) (*ApplicationHistoricalFinalizationEvidenceV1, error) {
	if w == nil || w.self != w || client == nil {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return nil, errors.Join(ErrHistoricalFinalizationEvidenceV1, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLHistoricalFinalizationResumeV1 && w.stage.purpose != HTMLHistoricalFinalizationEvidenceV1 && w.stage.purpose != htmlHistoricalFinalizationPublicationPurposeV1 && w.stage.purpose != HTMLHistoricalFinalizationSourceV1) || w.finalization == nil || !w.finalization.intentRead || w.finalization.intent == nil || w.finalizationEvidence != nil || w.state == nil || w.state.BoundedStatus != "finalizing" || w.stage.operation == nil || w.stage.operation.factory == nil || w.stage.operation.factory.state != w.session.state.factory {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	intent := w.finalization.intent
	if intent.DocumentID != w.logicalDocumentV1() || intent.OrgID != w.session.state.org {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	raw := 2*int64(unsafe.Sizeof(HistoricalFinalizationEvidenceCapacityErrorV1{})) + 2*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationEvidenceV1{})) + 2*int64(unsafe.Sizeof(sync.Once{})) + 8*int64(unsafe.Sizeof(uintptr(0)))
	// Concrete bounded provider errors/headers and four actual key/version texts
	// stay owned independently of each transient raw response/stream grant.
	if !htmlInputAddV1(&raw, limits.MetadataBytes, 4) || !htmlInputAddV1(&raw, limits.HeaderBytes, 4) || !htmlInputAddV1(&raw, limits.VersionIDBytes, 4) {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	keys := int64(len(intent.FinalPdfKey) + len(intent.AuditCertKey) + len(intent.AuditPayloadKey) + len(intent.AuditSignatureKey))
	if !htmlInputAddV1(&raw, keys, 8) {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	closeOwner, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeOwner)
	w.sourceBorrowers++
	e := &ApplicationHistoricalFinalizationEvidenceV1{work: w, client: client, limits: limits, intent: intent, ctx: w.stage.operation.original}
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
	w.finalizationEvidence = e
	return e, nil
}

// Activity is admitted before waiting and remains owned through every actual
// callback/consumer completion. Closed admission never discards a prior finish.
func (e *ApplicationHistoricalFinalizationEvidenceV1) lockV1() bool {
	if !e.activity.enterV1() {
		return false
	}
	e.activityMutex.Lock()
	return true
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) finishActivityV1() {
	if e.activity.leaveV1() {
		e.retireClosedV1()
	}
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) unlockV1() {
	e.activityMutex.Unlock()
	e.finishActivityV1()
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) retireClosedV1() {
	if !e.closeRequested.Load() {
		return
	}
	if e.verificationError != nil {
		owned := e.verificationError
		e.verificationError = nil
		owned.CloseConsumerV1()
	}
	if e.retentionError != nil {
		owned := e.retentionError
		e.retentionError = nil
		owned.CloseConsumerV1()
	}
	release := e.releaseBody
	e.releaseBody = nil
	e.intent = nil
	e.work = nil
	e.client = nil
	e.ctx = nil
	if release != nil {
		release()
	}
}

// Every metadata/provider exit joins a pending copied Close, including the
// narrow clear-check to Unlock interval. Actual synchronous provider callbacks
// retain the mutex, body grant and native borrower until their own return.
func (e *ApplicationHistoricalFinalizationEvidenceV1) CloseConsumerV1() {
	if e == nil || e.self != e {
		return
	}
	e.closeRequested.Store(true)
	if e.activity.closeV1() {
		e.retireClosedV1()
	}
}

// The same genuine Work/factory/org supplies only the private actual runtime.
// Concrete storage now owns its private Parent frame and local IO stream; no
// outer Provider1 grant or max128MiB body exists. The admitted evidence frame and Work borrower
// still span actual verification/retention and returned error consumer joins.
func (e *ApplicationHistoricalFinalizationEvidenceV1) coordinatorV1() (*workguard.CoordinatorV1, error) {
	if e.closeRequested.Load() || e.work == nil || e.intent == nil || e.client == nil || e.ctx == nil || e.ctx.Err() != nil {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	w := e.work
	w.mu.Lock()
	stage := w.stage
	session := w.session
	valid := !w.closed && !w.resourcesClosed && stage != nil && stage.operation != nil && session != nil && session.state != nil && w.finalizationEvidence == e && w.finalization != nil && w.finalization.intent == e.intent && w.sourceBorrowers > 0
	w.mu.Unlock()
	if !valid {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	factory := session.state.factory
	factory.mu.Lock()
	available := !factory.closing && factory.work != nil && factory.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if !available {
		return nil, ErrHistoricalFinalizationEvidenceV1
	}
	return coordinator, nil
}

func (e *ApplicationHistoricalFinalizationEvidenceV1) artifactV1(i int) (key, version string, digest []byte) {
	p := e.intent
	switch i {
	case 0:
		return p.FinalPdfKey, p.FinalPdfVersionID.String, p.FinalPdfSha256
	case 1:
		return p.AuditCertKey, p.AuditCertVersionID.String, p.AuditCertSha256
	case 2:
		return p.AuditPayloadKey, p.AuditPayloadVersionID.String, p.AuditPayloadSha256
	default:
		return p.AuditSignatureKey, p.AuditSignatureVersionID.String, p.AuditSignatureSha256
	}
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) verifyLockedV1() error {
	if e.intent == nil || !e.intent.EvidenceVersionPinsRequired {
		return ErrHistoricalFinalizationEvidenceV1
	}
	for i := 0; i < 4; i++ {
		key, version, digest := e.artifactV1(i)
		if strings.TrimSpace(key) == "" || strings.TrimSpace(version) == "" || len(digest) != sha256.Size {
			return errors.New("resume finalization: artifact commitment is incomplete")
		}
		coordinator, err := e.coordinatorV1()
		if err != nil {
			return err
		}
		// The original exact HEAD/version/ETag/full128MiB maximum/EOF/SHA
		// policy now hashes through a private fixed64KiB frame. No full body
		// is returned only to hash it again and immediately clear it.
		owned, denial, err := e.client.VerifyFinalizationEvidenceLocalOwnedV1(e.ctx, key, version, digest, coordinator, e.intent.OrgID)
		if err != nil {
			e.verificationError = owned
			if denial.CapacityV1() {
				return errors.Join(ErrHistoricalFinalizationEvidenceV1, &HistoricalFinalizationEvidenceCapacityErrorV1{cause: err, denial: denial})
			}
			return fmt.Errorf("resume finalization: read %q: %w", key, err)
		}
		if owned == nil {
			return ErrHistoricalFinalizationEvidenceV1
		}
		err = owned.WithVerifiedV1(func() error { return nil })
		if err != nil {
			e.verificationError = owned
			return fmt.Errorf("resume finalization: read %q: %w", key, err)
		}
		owned.CloseConsumerV1()
	}
	return nil
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) VerifyIntentArtifactsV1() error {
	if e == nil || e.self != e {
		return ErrHistoricalFinalizationEvidenceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationEvidenceV1
	}
	defer func() { e.unlockV1() }()
	if e.closeRequested.Load() || e.verificationError != nil || e.retentionError != nil {
		return ErrHistoricalFinalizationEvidenceV1
	}
	return e.verifyLockedV1()
}
func (e *ApplicationHistoricalFinalizationEvidenceV1) RetainIntentArtifactsV1() error {
	if e == nil || e.self != e {
		return ErrHistoricalFinalizationEvidenceV1
	}
	if !e.lockV1() {
		return ErrHistoricalFinalizationEvidenceV1
	}
	defer func() { e.unlockV1() }()
	if e.closeRequested.Load() || e.verificationError != nil || e.retentionError != nil || e.intent == nil || !e.intent.EvidenceVersionPinsRequired {
		return ErrHistoricalFinalizationEvidenceV1
	}
	p := e.intent
	if !p.CompletionEffectiveAt.Valid || p.CompletionEffectiveAt.Time.IsZero() || !p.RetainUntil.Valid || p.RetainUntil.Time.IsZero() {
		return errors.New("resume finalization: finalization retention deadline is unavailable")
	}
	until := p.RetainUntil.Time.UTC()
	if until.Nanosecond() != 0 || !until.Equal(storage.EvidenceRetentionDeadline(p.CompletionEffectiveAt.Time, article13.RetentionYearsV1)) {
		return errors.New("resume finalization: finalization retention deadline does not match completion commitment")
	}
	for i := 0; i < 4; i++ {
		key, version, digest := e.artifactV1(i)
		coordinator, err := e.coordinatorV1()
		if err != nil {
			return err
		}
		// Original canonical deadline, COMPLIANCE no-shortening/read-before-
		// extension/fresh-error verification policy stays in the concrete lane.
		// Its digest read has the same full safety maximum and fixed frame.
		owned, denial, err := e.client.RetainFinalizationEvidenceLocalOwnedV1(e.ctx, key, version, digest, until, coordinator, e.intent.OrgID)
		if err != nil {
			e.retentionError = owned
			if denial.CapacityV1() {
				return errors.Join(ErrHistoricalFinalizationEvidenceV1, &HistoricalFinalizationEvidenceCapacityErrorV1{cause: err, denial: denial})
			}
			return fmt.Errorf("resume finalization: retain %q: %w", key, err)
		}
		if owned == nil {
			return ErrHistoricalFinalizationEvidenceV1
		}
		err = owned.WithRetainedV1(func() error { return nil })
		if err != nil {
			e.retentionError = owned
			return fmt.Errorf("resume finalization: retain %q: %w", key, err)
		}
		owned.CloseConsumerV1()
	}
	return e.verifyLockedV1()
}

// Compares a caller view against this privately read actual legal tuple only;
// it cannot adopt caller rows, counts, pins or an alternate physical owner.
func (e *ApplicationHistoricalFinalizationEvidenceV1) MatchesIntentV1(expected *generated.DocumentFinalizationIntent) bool {
	if e == nil || e.self != e {
		return false
	}
	if !e.lockV1() {
		return false
	}
	defer e.unlockV1()
	return !e.closeRequested.Load() && historicalFinalizationSameIntentV1(e.intent, expected)
}
