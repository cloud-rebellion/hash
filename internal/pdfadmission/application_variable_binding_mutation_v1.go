// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"strings"
	"sync"
	"unsafe"
)

var ErrVariableBindingMutationV1 = errors.New("pdfadmission: owned variable binding mutation unavailable")
var ErrVariableBindingRootChangedV1 = errors.New("document family changed; reload before editing bindings")

// No caller Document, body length or mutation callback is accepted. The real
// reader supplies its private source and borrower; root scope is read from SQL.
type ApplicationVariableBindingMutationV1 struct {
	state *applicationVariableBindingMutationStateV1
}
type applicationVariableBindingMutationStateV1 struct {
	mu                            sync.Mutex
	session                       *ApplicationSessionV1
	reader                        *ApplicationHTMLRevisionReaderV1
	queries                       *generated.Queries
	snapshot                      *applicationHTMLRevisionSourceSnapshotV1
	release                       func()
	closes                        []func()
	root                          uuid.UUID
	row                           *generated.DocumentVariableBinding
	rootLocked, attempted, closed bool
}

func (h *ApplicationSessionV1) NewVariableBindingMutationV1(ctx context.Context, r *ApplicationHTMLRevisionReaderV1) (*ApplicationVariableBindingMutationV1, error) {
	if h == nil || h.state == nil || r == nil || r.self != r || r.session != h || !r.valid(ctx) {
		return nil, ErrVariableBindingMutationV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationVariableBindingMutationStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationVariableBindingMutationV1{})) + 4*int64(unsafe.Sizeof(generated.DocumentVariableBinding{})) + 2*int64(unsafe.Sizeof(generated.GetVariableBindingMutationHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetVariableBindingMutationHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.ReadVariableBindingMutationSourceV1Params{})) + 2*int64(unsafe.Sizeof(generated.UpsertVariableBindingParams{})) + 2*int64(unsafe.Sizeof(generated.LockVariableBindingMutationRootV1Row{})) + 4096
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrVariableBindingMutationV1, err)
	}
	return &ApplicationVariableBindingMutationV1{state: &applicationVariableBindingMutationStateV1{session: h, reader: r, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationVariableBindingMutationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationVariableBindingMutationStateV1) holdV1(ctx context.Context, raw int64) error {
	close, err := s.reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return errors.Join(ErrVariableBindingMutationV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}

// A false result is an actual frozen/non-draft family root. No parent supplied
// by the caller is used, and a stale discovery is never retried automatically.
func (w *ApplicationVariableBindingMutationV1) LockRootV1(ctx context.Context) (bool, error) {
	if w == nil || w.state == nil {
		return false, ErrVariableBindingMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.rootLocked {
		return false, ErrVariableBindingMutationV1
	}
	p := s.session.state
	root, err := s.queries.GetVariableBindingMutationRootV1(ctx, generated.GetVariableBindingMutationRootV1Params{DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return false, err
	}
	locked, err := s.queries.LockVariableBindingMutationRootV1(ctx, generated.LockVariableBindingMutationRootV1Params{DocumentID: p.document, OrgID: p.org, RootDocumentID: root})
	if err != nil {
		return false, err
	}
	if locked == nil || locked.RootDocumentID != root || root == uuid.Nil {
		return false, ErrVariableBindingMutationV1
	}
	if !locked.IsDraft {
		return false, nil
	}
	matches, err := s.queries.VariableBindingMutationRootMatchesV1(ctx, generated.VariableBindingMutationRootMatchesV1Params{DocumentID: p.document, OrgID: p.org, RootDocumentID: root})
	if err != nil {
		return false, err
	}
	if !matches {
		return false, ErrVariableBindingRootChangedV1
	}
	s.root = root
	s.rootLocked = true
	return true, nil
}
func (w *ApplicationVariableBindingMutationV1) AcceptActualDocumentV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrVariableBindingMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.rootLocked || s.snapshot != nil {
		return ErrVariableBindingMutationV1
	}
	snapshot, release, err := s.reader.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return err
	}
	d := snapshot.document
	p := s.session.state
	if d == nil || d.ID != p.document || d.OrgID != p.org || d.DeletedAt.Valid || d.Status != "draft" || (d.ParentEnvelopeID.Valid && (uuid.UUID(d.ParentEnvelopeID.Bytes) != s.root || d.IsEnvelope)) || (!d.ParentEnvelopeID.Valid && d.ID != s.root) {
		release()
		return ErrVariableBindingRootChangedV1
	}
	matches, err := s.queries.VariableBindingMutationRootMatchesV1(ctx, generated.VariableBindingMutationRootMatchesV1Params{DocumentID: p.document, OrgID: p.org, RootDocumentID: s.root})
	if err != nil || !matches {
		release()
		return errors.Join(ErrVariableBindingRootChangedV1, err)
	}
	s.snapshot = snapshot
	s.release = release
	return nil
}
func variableBindingRawV1(b *generated.DocumentVariableBinding) int64 {
	if b == nil {
		return 0
	}
	return int64(len(b.VariableName) + len(b.SourceKind) + len(b.SourceRef) + len(b.SourcePath) + len(b.Fallback) + len(b.LastValue) + len(b.LastError))
}
func cloneVariableBindingV1(b *generated.DocumentVariableBinding) *generated.DocumentVariableBinding {
	if b == nil {
		return nil
	}
	v := *b
	v.VariableName = strings.Clone(b.VariableName)
	v.SourceKind = strings.Clone(b.SourceKind)
	v.SourceRef = strings.Clone(b.SourceRef)
	v.SourcePath = strings.Clone(b.SourcePath)
	v.Fallback = strings.Clone(b.Fallback)
	v.LastValue = strings.Clone(b.LastValue)
	v.LastError = strings.Clone(b.LastError)
	return &v
}
func (w *ApplicationVariableBindingMutationV1) UpsertV1(ctx context.Context, name, kind, ref, path, fallback string) (*generated.DocumentVariableBinding, error) {
	if w == nil || w.state == nil {
		return nil, ErrVariableBindingMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.snapshot == nil || s.snapshot.owner != s.reader || s.attempted {
		return nil, ErrVariableBindingMutationV1
	}
	s.attempted = true
	if err := resolver.ValidateBinding(name, resolver.SourceKind(kind), ref, path, fallback); err != nil {
		return nil, err
	}
	p := s.session.state
	h, err := s.queries.GetVariableBindingMutationHeaderV1(ctx, generated.GetVariableBindingMutationHeaderV1Params{DocumentID: p.document, OrgID: p.org, VariableName: name})
	if err != nil {
		return nil, err
	}
	if h == nil || h.RawTextBytes < 0 {
		return nil, ErrVariableBindingMutationV1
	}
	var old *generated.DocumentVariableBinding
	if h.Present {
		if !applicationStampV1(h.CreatedAt) || !applicationStampV1(h.UpdatedAt) {
			return nil, ErrVariableBindingMutationV1
		}
		if err = s.holdV1(ctx, h.RawTextBytes); err != nil {
			return nil, err
		}
		old, err = s.queries.ReadVariableBindingMutationSourceV1(ctx, generated.ReadVariableBindingMutationSourceV1Params{DocumentID: p.document, OrgID: p.org, VariableName: name, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
		if err != nil {
			return nil, err
		}
		if old == nil || old.DocumentID != p.document || old.VariableName != name || old.CreatedAt != h.CreatedAt || old.UpdatedAt != h.UpdatedAt || old.LastResolved != h.LastResolved || variableBindingRawV1(old) != h.RawTextBytes {
			return nil, ErrVariableBindingMutationV1
		}
	} else if h.RawTextBytes != 0 {
		return nil, ErrVariableBindingMutationV1
	}
	raw := int64(len(name) + len(kind) + len(ref) + len(path) + len(fallback))
	if old != nil {
		var e error
		raw, e = htmlAuthoringSumV1(raw, int64(len(old.LastValue)), int64(len(old.LastError)))
		if e != nil {
			return nil, e
		}
	}
	// Returned/native/private result and both REST or nested MCP JSON encoders.
	output := int64(0)
	if !htmlInputAddV1(&output, raw, 4) {
		return nil, ErrVariableBindingMutationV1
	}
	if err = s.holdV1(ctx, output); err != nil {
		return nil, err
	}
	row, err := s.queries.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{DocumentID: p.document, VariableName: name, SourceKind: kind, SourceRef: ref, SourcePath: path, Fallback: fallback})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != p.document || row.VariableName != name || row.SourceKind != kind || row.SourceRef != ref || row.SourcePath != path || row.Fallback != fallback || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) {
		return nil, ErrVariableBindingMutationV1
	}
	if old == nil {
		if row.LastValue != "" || row.LastError != "" || row.LastResolved.Valid {
			return nil, ErrVariableBindingMutationV1
		}
	} else if row.CreatedAt != old.CreatedAt || row.LastValue != old.LastValue || row.LastError != old.LastError || row.LastResolved != old.LastResolved {
		return nil, ErrVariableBindingMutationV1
	}
	s.row = cloneVariableBindingV1(row)
	return row, nil
}
func (w *ApplicationVariableBindingMutationV1) DeleteV1(ctx context.Context, name string) error {
	if w == nil || w.state == nil {
		return ErrVariableBindingMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.snapshot == nil || s.snapshot.owner != s.reader || s.attempted {
		return ErrVariableBindingMutationV1
	}
	s.attempted = true
	if err := resolver.ValidateBindingName(name); err != nil {
		return err
	}
	if err := s.holdV1(ctx, int64(len(name))); err != nil {
		return err
	}
	return s.queries.DeleteVariableBinding(ctx, generated.DeleteVariableBindingParams{DocumentID: s.session.state.document, VariableName: name})
}
func (w *ApplicationVariableBindingMutationV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.row = nil
	s.snapshot = nil
	closes, release := s.closes, s.release
	s.closes = nil
	s.release = nil
	s.mu.Unlock()
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
}
