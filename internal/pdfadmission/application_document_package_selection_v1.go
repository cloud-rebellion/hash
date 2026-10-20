// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

var ErrDocumentPackageSelectionV1 = errors.New("pdfadmission: owned document package selection unavailable")

// This owner is a separate standalone-document purpose. It never creates a
// legacy envelope family pin, changes physical session scope, accepts caller
// Documents/DBTXs, or treats a source validation as staff mutation authority.
// The fixed application adapter retains original credential, role, sender,
// draft/evidence/privacy/CAS policy and rechecks it through audit and COMMIT.
type ApplicationDocumentPackageSelectionV1 struct {
	state *applicationDocumentPackageSelectionStateV1
}
type applicationDocumentPackageSelectionStateV1 struct {
	mu                  sync.Mutex
	session             *ApplicationSessionV1
	actor               *ApplicationHTMLAuthoringReaderV1
	call                context.Context
	sourceContext       context.Context
	cancel              context.CancelFunc
	ids                 [2]uuid.UUID // root, selected standalone source; immutable
	headers             [2]*generated.GetHTMLRevisionDocumentReadHeaderV1Row
	readers             [2]*ApplicationHTMLRevisionReaderV1
	sources             [2]*applicationHTMLRevisionSourceOwnerV1
	closes              []func()
	active              int
	attempted           bool
	validationAttempted bool
	sourcesValidated    bool
	readActor           uuid.UUID
	draftAttempted      bool
	draft               *applicationDocumentPackageDraftSnapshotV1
	retired             bool
	closed              atomic.Bool
}
type applicationDocumentPackageReadBindingV1 struct {
	owner    *applicationDocumentPackageSelectionStateV1
	document uuid.UUID
	header   *generated.GetHTMLRevisionDocumentReadHeaderV1Row
	slot     int
}

func (b *applicationDocumentPackageReadBindingV1) validV1(call context.Context, r *ApplicationHTMLRevisionReaderV1) bool {
	if b == nil || b.owner == nil || b.owner.session == nil || b.owner.session.state == nil || b.slot < 0 || b.slot >= 2 || r == nil {
		return false
	}
	s := b.owner
	return !s.closed.Load() && call == s.call && b.document == s.ids[b.slot] && b.header == s.headers[b.slot] && b.header != nil &&
		b.header.ID == b.document && b.header.OrgID == s.session.state.org && r.session == s.session && s.readers[b.slot] == r
}
func (h *ApplicationSessionV1) NewDocumentPackageSelectionV1(call context.Context, source uuid.UUID) (out *ApplicationDocumentPackageSelectionV1, failure error) {
	if h == nil || h.state == nil || source == uuid.Nil || source == h.state.document || !applicationContextV1(call) {
		return nil, ErrDocumentPackageSelectionV1
	}
	actor, err := h.NewHTMLAuthoringReaderV1(call)
	if err != nil {
		return nil, errors.Join(ErrDocumentPackageSelectionV1, err)
	}
	sourceContext, cancel := context.WithCancel(call)
	s := &applicationDocumentPackageSelectionStateV1{session: h, actor: actor, call: call, sourceContext: sourceContext, cancel: cancel, ids: [2]uuid.UUID{h.state.document, source}, active: 1}
	out = &ApplicationDocumentPackageSelectionV1{state: s}
	defer func() {
		s.finishV1()
		if failure != nil {
			out.CloseConsumerV1()
			out = nil
		}
	}()
	// Independent typed/container credit precedes the two genuine fixed headers,
	// readers, bindings and returned owner shell. Dynamic bodies remain additive.
	typed := 2*int64(unsafe.Sizeof(applicationDocumentPackageSelectionStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationDocumentPackageSelectionV1{})) +
		4*int64(unsafe.Sizeof(generated.GetHTMLRevisionDocumentReadHeaderV1Row{})) + 4*int64(unsafe.Sizeof(ApplicationHTMLRevisionReaderV1{})) +
		4*int64(unsafe.Sizeof(applicationDocumentPackageReadBindingV1{}))
	close, err := actor.acquireOwnedRetainedBodyV1(call, typed, 0)
	if err != nil {
		return out, errors.Join(ErrDocumentPackageSelectionV1, err)
	}
	s.closes = append(s.closes, close)
	ordered := s.ids
	if bytes.Compare(ordered[0][:], ordered[1][:]) > 0 {
		ordered[0], ordered[1] = ordered[1], ordered[0]
	}
	q := generated.New(&applicationOwnedDBTXV1{session: h.state})
	for _, id := range ordered {
		header, err := q.GetHTMLRevisionDocumentReadHeaderV1(call, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: id, OrgID: h.state.org})
		if err != nil {
			return out, err
		}
		if header == nil || header.ID != id || header.OrgID != h.state.org || !applicationStampV1(header.UpdatedAt) {
			return out, ErrDocumentPackageSelectionV1
		}
		slot := 0
		if id == source {
			slot = 1
		}
		s.headers[slot] = header
	}
	for slot := range s.ids {
		reader, err := h.NewHTMLRevisionReaderV1(call)
		if err != nil {
			return out, err
		}
		s.readers[slot] = reader
		reader.packageBinding = &applicationDocumentPackageReadBindingV1{owner: s, document: s.ids[slot], header: s.headers[slot], slot: slot}
	}
	return out, nil
}
func (s *applicationDocumentPackageSelectionStateV1) beginV1(call context.Context) error {
	if s == nil {
		return ErrDocumentPackageSelectionV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() || s.retired || call != s.call || !applicationContextV1(call) || s.session == nil || s.actor == nil || !s.actor.valid(call) {
		return ErrDocumentPackageSelectionV1
	}
	s.active++
	return nil
}
func (s *applicationDocumentPackageSelectionStateV1) finishV1() {
	s.mu.Lock()
	s.active--
	retire := s.closed.Load() && !s.retired && s.active == 0
	if retire {
		s.retired = true
	}
	s.mu.Unlock()
	if retire {
		s.retireV1()
	}
}
func (s *applicationDocumentPackageSelectionStateV1) retireV1() {
	for _, source := range s.sources {
		if source != nil {
			(&ApplicationHTMLRevisionSourceV1{state: source}).CloseConsumerV1()
		}
	}
	for _, reader := range s.readers {
		if reader != nil {
			reader.CloseConsumerV1()
		}
	}
	if s.actor != nil {
		s.actor.CloseConsumerV1()
	}
	for _, close := range s.closes {
		close()
	}
	s.sources = [2]*applicationHTMLRevisionSourceOwnerV1{}
	s.readers = [2]*ApplicationHTMLRevisionReaderV1{}
	s.headers = [2]*generated.GetHTMLRevisionDocumentReadHeaderV1Row{}
	s.closes = nil
	s.actor = nil
	s.draft = nil
}
func (w *ApplicationDocumentPackageSelectionV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	s.closed.Store(true)
	retire := !s.retired && s.active == 0
	if retire {
		s.retired = true
	}
	s.mu.Unlock()
	s.cancel()
	if retire {
		s.retireV1()
	}
}

// ReadDocumentsV1 runs the original fixed application policy gate for BOTH
// actual locked documents before each complete body. Callback return is only a
// policy decision; callers cannot supply sizes, source rows or resource grants.
func (w *ApplicationDocumentPackageSelectionV1) ReadDocumentsV1(call context.Context, actor uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, gate func(HTMLRevisionReadAccessV1, *generated.User) error) ([2]*HTMLRevisionReadModelsV1, error) {
	var result [2]*HTMLRevisionReadModelsV1
	if w == nil || w.state == nil || actor == uuid.Nil || preflight == nil || gate == nil {
		return result, ErrDocumentPackageSelectionV1
	}
	s := w.state
	if err := s.beginV1(call); err != nil {
		return result, err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.attempted {
		s.mu.Unlock()
		return result, ErrDocumentPackageSelectionV1
	}
	s.attempted = true
	s.readActor = actor
	s.mu.Unlock()
	for i, r := range s.readers {
		m, err := r.ReadDocumentWithActorV1(call, actor, preflight, gate)
		if err != nil {
			return result, err
		}
		if m == nil || m.Document == nil || m.Document.ID != s.ids[i] || m.Document.OrgID != s.session.state.org {
			return result, ErrDocumentPackageSelectionV1
		}
		result[i] = m
	}
	if s.closed.Load() {
		return [2]*HTMLRevisionReadModelsV1{}, ErrDocumentPackageSelectionV1
	}
	return result, nil
}

// ValidateSourcesV1 owns real staged source validation on both private native
// snapshots. It validates exact reviewed HTML/current materialization state;
// imported PDFs retain their existing no-HTML semantics. No render/revision,
// retention, Sign, invitation or finalization authority is created.
func (w *ApplicationDocumentPackageSelectionV1) ValidateSourcesV1(call context.Context) error {
	if w == nil || w.state == nil {
		return ErrDocumentPackageSelectionV1
	}
	s := w.state
	if err := s.beginV1(call); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.validationAttempted {
		s.mu.Unlock()
		return ErrDocumentPackageSelectionV1
	}
	s.validationAttempted = true
	s.mu.Unlock()
	for i, r := range s.readers {
		if s.sources[i] != nil {
			return ErrDocumentPackageSelectionV1
		}
		snapshot, release, err := r.borrowHTMLRevisionSourceV1(call)
		if err != nil {
			return err
		}
		physical := s.session.state
		p := physical.factory
		p.mu.Lock()
		physical.mu.Lock()
		a := physical.admission
		registration := p.htmlAdmissions[a]
		valid := !p.closing && !physical.observer && !physical.closed && !physical.retired && !physical.unknown && !physical.ended &&
			physical.callbackActive && !physical.sqlActive && call.Value(applicationSessionCallbackKeyV1{}) == physical && a != nil && a.valid() &&
			physical.fence != nil && a.fence == physical.fence && a.cleanupDone == physical.fence.clientDone && registration != nil
		original, cancel := context.WithCancel(s.sourceContext)
		deadline, _ := original.Deadline()
		binding := &applicationHTMLRevisionSourceBindingV1{factory: p, session: s.session, admission: a, registration: registration, org: physical.org, document: s.ids[i], ctx: original, deadline: deadline}
		physical.mu.Unlock()
		p.mu.Unlock()
		if !valid {
			cancel()
			release()
			return ErrDocumentPackageSelectionV1
		}
		owner := &applicationHTMLRevisionSourceOwnerV1{purpose: htmlPackageSelectionSourcePurposeV1, binding: binding, snapshot: snapshot, releaseBorrower: release, cancel: cancel}
		owner.self = owner
		// Register before first parser/grant. Close waits for this real active call;
		// source CPU's own active counter joins its original native borrower.
		s.sources[i] = owner
		handle := &ApplicationHTMLRevisionSourceV1{state: owner}
		if err = owner.beginV1(); err != nil {
			return err
		}
		initial, e := owner.initialComponentsV1()
		if e == nil {
			e = owner.holdV1(htmlRevisionSourceInitialV1, 0, initial)
		}
		owner.finishV1()
		if e != nil {
			return e
		}
		if err = handle.ValidateV1(); err != nil {
			return err
		}
		if err = owner.validation.ValidateV1(true); err != nil {
			return err
		}
		if len(snapshot.document.HtmlSourceJson) == 0 {
			// The staged builder already rejects every orphan HTML projection.
			// Imported PDFs have no HTML commitment or current materialization.
			if snapshot.current != nil {
				return ErrDocumentPackageSelectionV1
			}
		} else if err = handle.ValidateCurrentV1(); err != nil {
			return err
		}
	}
	if s.closed.Load() {
		return ErrDocumentPackageSelectionV1
	}
	s.mu.Lock()
	if s.closed.Load() || call.Err() != nil {
		s.mu.Unlock()
		return ErrDocumentPackageSelectionV1
	}
	s.sourcesValidated = true
	s.mu.Unlock()
	return nil
}
