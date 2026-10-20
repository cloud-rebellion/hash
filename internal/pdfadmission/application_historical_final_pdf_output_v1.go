// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// A finite contract-body output is issued only by a genuine native canonical
// renderer, manual-stamp result or original acknowledgement SDK callback.
// Caller bytes/digest/pins/grants cannot issue this opaque body provenance.
// Source-derived scalar metadata is independently retained; its real source
// borrower also prevents an outer copied Close from retiring private source
// references while claims/actual PUT consume them.
type ApplicationHistoricalFinalizationPDFV1 struct {
	activityMutex          sync.Mutex
	activity               applicationJoinedActivityV1
	self                   *ApplicationHistoricalFinalizationPDFV1
	closeRequested         atomic.Bool
	grant                  *workguard.GrantV1
	source                 *ApplicationHistoricalFinalizationSourceEvidenceV1
	factory                *ApplicationSessionFactoryV1
	coordinator            *workguard.CoordinatorV1
	ctx                    context.Context
	org, document          uuid.UUID
	retainUntil            time.Time
	local                  *render.HTMLLocalPDFV1
	manual                 *ApplicationHistoricalFinalizationManualPDFV1
	raw                    []byte
	rawActive, bodyRetired bool
	metadataBorrowers      int
	hashAttempted, stored  bool
	hashFailure            error
	sum                    [sha256.Size]byte
	key                    string
	pin                    storage.StoredObject
	putError               *storage.EvidenceLocalPutV1
	releaseSource          func()
}

// Activity is admitted before waiting and remains owned through every actual
// callback/consumer completion. Closed admission never discards a prior finish.
func (f *ApplicationHistoricalFinalizationPDFV1) lockV1() bool {
	if !f.activity.enterV1() {
		return false
	}
	f.activityMutex.Lock()
	return true
}
func (f *ApplicationHistoricalFinalizationPDFV1) finishActivityV1() {
	if f.activity.leaveV1() {
		f.retireClosedV1()
	}
}
func (f *ApplicationHistoricalFinalizationPDFV1) unlockV1() {
	f.activityMutex.Unlock()
	f.finishActivityV1()
}
func (f *ApplicationHistoricalFinalizationPDFV1) clearClosedV1() []func() {
	if !f.closeRequested.Load() || f.metadataBorrowers != 0 {
		return nil
	}
	f.raw = nil
	f.rawActive = false
	f.source = nil
	f.factory = nil
	f.coordinator = nil
	f.ctx = nil
	f.key = ""
	f.pin = storage.StoredObject{}
	f.hashFailure = nil
	var closes []func()
	if f.local != nil {
		local := f.local
		f.local = nil
		closes = append(closes, local.CloseConsumerV1)
	}
	if f.manual != nil {
		manual := f.manual
		f.manual = nil
		closes = append(closes, manual.CloseConsumerV1)
	}
	if f.putError != nil {
		put := f.putError
		f.putError = nil
		closes = append(closes, put.CloseConsumerV1)
	}
	if f.releaseSource != nil {
		release := f.releaseSource
		f.releaseSource = nil
		closes = append(closes, release)
	}
	// The actual source-release once/closure is priced by this fixed control.
	// It may block on the source mutex; credit only after that callback joins.
	if f.grant != nil {
		grant := f.grant
		f.grant = nil
		closes = append(closes, grant.Close)
	}
	return closes
}
func (f *ApplicationHistoricalFinalizationPDFV1) retireClosedV1() {
	historicalFinalPDFClosesV1(f.clearClosedV1())
}
func (f *ApplicationHistoricalFinalizationPDFV1) CloseConsumerV1() {
	if f == nil || f.self != f {
		return
	}
	f.closeRequested.Store(true)
	if f.activity.closeV1() {
		f.retireClosedV1()
	}
}

// Both producer mutexes are released before final activity retirement can
// call releaseSource, whose already-admitted completion reenters source.
func (f *ApplicationHistoricalFinalizationPDFV1) unlockSourceConsumerV1(source *ApplicationHistoricalFinalizationSourceEvidenceV1) {
	f.activityMutex.Unlock()
	source.unlockV1()
	f.finishActivityV1()
}
func historicalFinalPDFClosesV1(closes []func()) {
	for _, close := range closes {
		close()
	}
}
func (f *ApplicationHistoricalFinalizationPDFV1) validScopeLockedV1(source *ApplicationHistoricalFinalizationSourceEvidenceV1) bool {
	return f != nil && f.self == f && !f.closeRequested.Load() && f.grant != nil && f.source == source && source != nil && source.document != nil && f.factory == source.work.stage.operation.factory && f.org == source.document.OrgID && f.document == source.document.ID && f.ctx != nil && f.ctx.Err() == nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) newHistoricalFinalPDFV1() (*ApplicationHistoricalFinalizationPDFV1, error) {
	if e == nil || e.self != e {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.sourceChecked || e.document == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w := e.work
	factory := w.stage.operation.factory
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
	// Existing document/retention guards ran at their original earlier adapter
	// point. Capture only these actual private scalars, never a caller timestamp.
	if !e.document.FinalizationRetainUntil.Valid || e.document.FinalizationRetainUntil.Time.IsZero() {
		return nil, errors.New("finalization retention deadline is unavailable")
	}
	control := int64(65536) + 8*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationPDFV1{})) + 4*int64(unsafe.Sizeof(sync.Once{}))
	grant, err := coordinator.TryAcquireV1(e.ctx, e.document.OrgID, workguard.VectorV1{ParentBytes: control})
	if err != nil {
		return nil, err
	}
	f := &ApplicationHistoricalFinalizationPDFV1{grant: grant, source: e, factory: factory, coordinator: coordinator, ctx: w.stage.operation.original, org: e.document.OrgID, document: e.document.ID, retainUntil: e.document.FinalizationRetainUntil.Time.UTC()}
	f.self = f
	if !e.beginBodyBorrowLockedV1() {
		grant.Close()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	var once sync.Once
	f.releaseSource = func() { once.Do(e.finishBodyBorrowV1) }
	return f, nil
}
func (h *ApplicationHistoricalFinalizationHTMLV1) RenderFinalPDFV1(renderer *render.Gotenberg, options render.PDFOptions, evidence *ApplicationHistoricalFinalizationSourceEvidenceV1) (*ApplicationHistoricalFinalizationPDFV1, error) {
	if h == nil || h.self != h || evidence == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	h.mu.Lock()
	factory, org, document, live := h.factory, h.org, h.document, !h.closeRequested.Load() && h.grant != nil
	h.mu.Unlock()
	if !live {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	final, err := evidence.newHistoricalFinalPDFV1()
	if err != nil {
		return nil, err
	}
	if final.factory != factory || final.org != org || final.document != document {
		final.CloseConsumerV1()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	local, err := h.RenderPDFV1(renderer, options)
	final.local = local
	return final, err
}
func (m *ApplicationHistoricalFinalizationManualPDFV1) FinalPDFV1() (*ApplicationHistoricalFinalizationPDFV1, error) {
	if m == nil || m.self != m || m.input == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	m.input.mu.Lock()
	defer m.input.mu.Unlock()
	if !m.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !m.input.active || m.closeRequested.Load() || m.grants[0] == nil || len(m.pdf) == 0 || m.input.evidence == nil {
		m.unlockV1()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	evidence := m.input.evidence
	// Keep the admitted producer registration through actual final-owner
	// construction/binding, but release the mutex before its evidence locks.
	m.activityMutex.Unlock()
	defer func() {
		if m.activity.leaveV1() {
			m.retireClosedV1()
		}
	}()
	final, err := evidence.newHistoricalFinalPDFV1()
	if err != nil {
		return nil, err
	}
	if m.closeRequested.Load() {
		final.CloseConsumerV1()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	final.manual = m
	return final, nil
}
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) WithAcknowledgementFinalPDFV1(consume func(*ApplicationHistoricalFinalizationPDFV1) error) error {
	if e == nil || e.self != e || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	return e.WithSourcePDFV1(func(raw []byte) error {
		if !e.lockV1() {
			return ErrHistoricalFinalizationSourceV1
		}
		ack := e.validV1() && e.document != nil && !e.document.RequiresSignature
		e.unlockV1()
		if !ack {
			return ErrHistoricalFinalizationSourceV1
		}
		final, err := e.newHistoricalFinalPDFV1()
		if err != nil {
			return err
		}
		if !final.lockV1() {
			final.CloseConsumerV1()
			return ErrHistoricalFinalizationSourceV1
		}
		final.raw = raw
		final.rawActive = true
		final.activityMutex.Unlock() // Keep original raw consumer registration through mandatory completion.
		defer func() {
			final.activityMutex.Lock()
			final.raw = nil
			final.rawActive = false
			final.bodyRetired = true
			final.unlockV1()
		}()
		return consume(final)
	})
}
func (f *ApplicationHistoricalFinalizationPDFV1) withBodyLockedV1(consume func([]byte) error) error {
	if f.closeRequested.Load() || f.grant == nil || f.bodyRetired {
		return ErrHistoricalFinalizationSourceV1
	}
	if f.local != nil {
		return f.local.WithPDFV1(consume)
	}
	if f.manual != nil {
		return f.manual.WithPDFV1(consume)
	}
	if f.rawActive && len(f.raw) > 0 {
		return consume(f.raw)
	}
	return ErrHistoricalFinalizationSourceV1
}
func (f *ApplicationHistoricalFinalizationPDFV1) CalculateSHA256V1() ([sha256.Size]byte, error) {
	if f == nil || f.self != f {
		return [sha256.Size]byte{}, ErrHistoricalFinalizationSourceV1
	}
	if !f.lockV1() {
		return [sha256.Size]byte{}, ErrHistoricalFinalizationSourceV1
	}
	defer f.unlockV1()
	if f.closeRequested.Load() || f.grant == nil {
		return [sha256.Size]byte{}, ErrHistoricalFinalizationSourceV1
	}
	if f.hashAttempted {
		return f.sum, f.hashFailure
	}
	f.hashAttempted = true
	err := f.withBodyLockedV1(func(raw []byte) error {
		f.sum = sha256.Sum256(raw)
		f.key = path.Join("org", f.org.String(), "documents", f.document.String(), "final-"+hex.EncodeToString(f.sum[:])+".pdf")
		return nil
	})
	f.hashFailure = err
	return f.sum, err
}
func (f *ApplicationHistoricalFinalizationPDFV1) StoreFinalV1(client *storage.Client) error {
	if f == nil || f.self != f || client == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !f.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer f.unlockV1()
	if !f.hashAttempted || f.hashFailure != nil || f.stored || f.putError != nil {
		return ErrHistoricalFinalizationSourceV1
	}
	err := f.withBodyLockedV1(func(raw []byte) error {
		put, err := client.PutEvidenceVersionedLocalOwnedV1(f.ctx, f.key, "application/pdf", raw, f.retainUntil, f.coordinator, f.org)
		if err != nil {
			f.putError = put
			return err
		}
		if put == nil {
			return ErrHistoricalFinalizationSourceV1
		}
		err = put.WithStoredV1(func(stored storage.StoredObject) error {
			if stored.SHA256 != f.sum || strings.TrimSpace(stored.VersionID) == "" {
				return errors.New("storage digest mismatch")
			}
			f.pin = storage.StoredObject{SHA256: stored.SHA256, VersionID: strings.Clone(stored.VersionID)}
			f.stored = true
			return nil
		})
		if err != nil {
			f.putError = put
		} else {
			put.CloseConsumerV1()
		}
		return err
	})
	return err
}

// Actual final bytes have no remaining consumer after joined PUT returns.
// The independently owned digest/version scalars remain for claims and Stage.
// Clear source SDK aliases at their callback exit; a native local/manual body
// is closed only outside this metadata mutex after its actual borrower joined.
func (f *ApplicationHistoricalFinalizationPDFV1) RetireBodyV1() {
	if f == nil || f.self != f {
		return
	}
	if !f.lockV1() {
		return
	}
	local, manual := f.local, f.manual
	f.local = nil
	f.manual = nil
	f.raw = nil
	f.rawActive = false
	f.bodyRetired = true
	f.activityMutex.Unlock()
	defer f.finishActivityV1()
	if local != nil {
		local.CloseConsumerV1()
	}
	if manual != nil {
		manual.CloseConsumerV1()
	}
}

// These exact string views are consumed synchronously under a real metadata
// borrower. A copied Close cannot credit their fixed control until the actual
// Stage/intent consumer returns; the callback supplies no source authority.
func (f *ApplicationHistoricalFinalizationPDFV1) WithStoredFinalV1(consume func(string, [sha256.Size]byte, string) error) error {
	if f == nil || f.self != f || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !f.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if f.closeRequested.Load() || f.grant == nil || !f.stored {
		f.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	f.metadataBorrowers++
	key, sum, version := f.key, f.sum, f.pin.VersionID
	f.activityMutex.Unlock() // Keep original metadata consumer admitted while unlocked.
	defer func() { f.activityMutex.Lock(); f.metadataBorrowers--; f.unlockV1() }()
	return consume(key, sum, version)
}

// Only metadata remains after the real PDF/claims consumers. No later body or
// claims method can use this detached handle as original source authority.
// Its own finite pin/key grant remains through the actual Stage/intent caller.
func (f *ApplicationHistoricalFinalizationPDFV1) RetireSourceConsumerV1() {
	if f == nil || f.self != f {
		return
	}
	if !f.lockV1() {
		return
	}
	if !f.stored || !f.bodyRetired {
		f.unlockV1()
		return
	}
	release := f.releaseSource
	f.releaseSource = nil
	f.source = nil
	f.activityMutex.Unlock()
	defer f.finishActivityV1()
	if release != nil {
		release()
	}
}
