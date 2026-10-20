// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"unsafe"
)

var ErrEnvelopeTopologyV1 = errors.New("pdfadmission: owned envelope topology unavailable")

type ApplicationEnvelopeTopologyV1 struct {
	state *applicationEnvelopeTopologyStateV1
}
type applicationEnvelopeTopologyStateV1 struct {
	mu      sync.Mutex
	session *ApplicationSessionV1
	reader  *ApplicationHTMLAuthoringReaderV1
	queries *generated.Queries
	docs    map[uuid.UUID]*generated.Document
	member  *generated.User
	closes  []func()
	closed  bool
}

func (h *ApplicationSessionV1) NewEnvelopeTopologyV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationEnvelopeTopologyV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrEnvelopeTopologyV1
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, 2*int64(unsafe.Sizeof(applicationEnvelopeTopologyStateV1{}))+2*int64(unsafe.Sizeof(ApplicationEnvelopeTopologyV1{}))+2*int64(unsafe.Sizeof(map[uuid.UUID]*generated.Document{})), 0)
	if err != nil {
		return nil, errors.Join(ErrEnvelopeTopologyV1, err)
	}
	return &ApplicationEnvelopeTopologyV1{state: &applicationEnvelopeTopologyStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), docs: make(map[uuid.UUID]*generated.Document), closes: []func(){close}}}, nil
}
func (s *applicationEnvelopeTopologyStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationEnvelopeTopologyStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrEnvelopeTopologyV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}
func (s *applicationEnvelopeTopologyStateV1) memberV1(ctx context.Context, user uuid.UUID, gate func(*generated.User) error) error {
	if user == uuid.Nil || gate == nil {
		return ErrEnvelopeTopologyV1
	}
	if s.member == nil {
		if err := s.reader.AcquireActorV1(ctx, s.session.state.org, user, false); err != nil {
			return err
		}
		member, err := s.queries.GetUserForShare(ctx, generated.GetUserForShareParams{ID: user, OrgID: s.session.state.org})
		if err != nil {
			return err
		}
		if member == nil || member.ID != user || member.OrgID != s.session.state.org {
			return ErrEnvelopeTopologyV1
		}
		value := *member
		s.member = &value
	}
	if s.member.ID != user {
		return ErrEnvelopeTopologyV1
	}
	value := *s.member
	return gate(&value)
}

// Original root then sorted-child lock order is selected by the fixed shared
// envelope producer. Each requested/full family row comes from a real protected
// scalar cache header, then actual live actor/credential, then complete body.
// Every old/new body remains in this same root operation's retained loan.
func (w *ApplicationEnvelopeTopologyV1) ReadDocumentV1(ctx context.Context, id, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, gate func(*generated.User) error) (*generated.Document, error) {
	if w == nil || w.state == nil || id == uuid.Nil || preflight == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) {
		return nil, ErrEnvelopeTopologyV1
	}
	if doc := s.docs[id]; doc != nil {
		return doc, nil
	}
	h, err := s.queries.GetHTMLRevisionDocumentReadHeaderV1(ctx, generated.GetHTMLRevisionDocumentReadHeaderV1Params{DocumentID: id, OrgID: s.session.state.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != id || h.OrgID != s.session.state.org || h.ServerVersionNum < 1 || !applicationStampV1(h.UpdatedAt) {
		return nil, ErrEnvelopeTopologyV1
	}
	if err = preflight(HTMLRevisionReadAccessV1{DocumentID: h.ID, OrgID: h.OrgID, SenderID: h.SenderID, UpdatedAt: h.UpdatedAt, ExpiresAt: h.ExpiresAt, Draft: h.IsDraft, ChangesRequested: h.IsChangesRequested, HasHTMLSource: h.HasHtmlSource}); err != nil {
		return nil, err
	}
	if err = s.memberV1(ctx, user, gate); err != nil {
		return nil, err
	}
	if h.PolicyMeasurementServerVersionNum != h.ServerVersionNum || h.ResponseMeasurementServerVersionNum != h.ServerVersionNum || h.ReportMeasurementServerVersionNum != h.ServerVersionNum {
		return nil, ErrEnvelopeTopologyV1
	}
	wire, err := htmlAuthoringSumV1(h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.BlocksWireBytes, h.MetadataWireBytes, h.ReportWireBytes)
	if err != nil {
		return nil, err
	}
	// Distinct old exposed/private and new returned/private headers and the map
	// entry coexist. Dynamic raw/JSON backing is independently additive below.
	raw, err := htmlAuthoringSumV1(h.RawTextBytes, 8*int64(unsafe.Sizeof(generated.Document{})), 8*(int64(unsafe.Sizeof(uuid.UUID{}))+int64(unsafe.Sizeof((*generated.Document)(nil)))+8))
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	doc, err := s.queries.ReadSignerDocumentV1(ctx, generated.ReadSignerDocumentV1Params{DocumentID: id, OrgID: s.session.state.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedHtmlOriginWireBytes: h.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: h.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: h.VariablesWireBytes, ExpectedBlocksWireBytes: h.BlocksWireBytes, ExpectedMetadataWireBytes: h.MetadataWireBytes, ExpectedReportWireBytes: h.ReportWireBytes})
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.ID != id || doc.OrgID != s.session.state.org || doc.UpdatedAt != h.UpdatedAt || signerDocumentRawBytesV1(doc) != h.RawTextBytes || int64(len(doc.HtmlSourceJson)) != h.HtmlOriginWireBytes || int64(len(doc.HtmlCurrentSourceJson)) != h.HtmlCurrentWireBytes || int64(len(doc.VariablesJson)) != h.VariablesWireBytes || int64(len(doc.BlocksJson)) != h.BlocksWireBytes || int64(len(doc.Metadata)) != h.MetadataWireBytes || int64(len(doc.MetadataRedactionReport)) != h.ReportWireBytes {
		return nil, ErrEnvelopeTopologyV1
	}
	s.docs[id] = htmlRevisionCloneDocumentV1(doc)
	return doc, nil
}
func (w *ApplicationEnvelopeTopologyV1) ReadMemberV1(ctx context.Context, user uuid.UUID, gate func(*generated.User) error) error {
	if w == nil || w.state == nil {
		return ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) {
		return ErrEnvelopeTopologyV1
	}
	return s.memberV1(ctx, user, gate)
}
func (w *ApplicationEnvelopeTopologyV1) ChildIDsV1(ctx context.Context, root uuid.UUID) ([]uuid.UUID, error) {
	if w == nil || w.state == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || root != s.session.state.document || s.docs[root] == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	n, err := s.queries.CountEnvelopeTopologyChildrenV1(ctx, generated.CountEnvelopeTopologyChildrenV1Params{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: s.session.state.org})
	if err != nil {
		return nil, err
	}
	cost := int64(0)
	if !htmlInputAddV1(&cost, n, 8*int64(unsafe.Sizeof(uuid.UUID{}))+4*int64(unsafe.Sizeof((*generated.Document)(nil)))+4*int64(unsafe.Sizeof(""))+32) {
		return nil, ErrEnvelopeTopologyV1
	}
	if err = s.holdV1(ctx, cost, 0); err != nil {
		return nil, err
	}
	ids, err := s.queries.ListEnvelopeTopologyChildIDsV1(ctx, generated.ListEnvelopeTopologyChildIDsV1Params{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: s.session.state.org})
	if err != nil {
		return nil, err
	}
	if int64(len(ids)) != n {
		return nil, ErrEnvelopeTopologyV1
	}
	return ids, nil
}
func (w *ApplicationEnvelopeTopologyV1) RegisterFreshRootV1(ctx context.Context, writer *ApplicationBlocksCreationWriterV1) error {
	if w == nil || w.state == nil || writer == nil || writer.state == nil {
		return ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	p := writer.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if !s.validV1(ctx) || p.session != s.session || p.reader != s.reader || !p.validV1(ctx) || !p.created || !p.measured || p.doc == nil || p.doc.ID != s.session.state.document || s.docs[p.doc.ID] != nil {
		return ErrEnvelopeTopologyV1
	}
	s.docs[p.doc.ID] = htmlRevisionCloneDocumentV1(p.doc)
	return nil
}
func (s *applicationEnvelopeTopologyStateV1) acceptV1(old, next *generated.Document, expected generated.Document) error {
	if next == nil || !applicationStampV1(next.UpdatedAt) {
		return ErrEnvelopeTopologyV1
	}
	expected.UpdatedAt = next.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, next) {
		return ErrEnvelopeTopologyV1
	}
	s.docs[old.ID] = htmlRevisionCloneDocumentV1(next)
	return nil
}
func (w *ApplicationEnvelopeTopologyV1) PromoteV1(ctx context.Context, id uuid.UUID) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || id != s.session.state.document {
		return nil, ErrEnvelopeTopologyV1
	}
	old := s.docs[id]
	if old == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	next, err := s.queries.MarkAsEnvelope(ctx, generated.MarkAsEnvelopeParams{ID: id, OrgID: s.session.state.org})
	if err != nil {
		return nil, err
	}
	expected := *old
	expected.IsEnvelope = true
	if err = s.acceptV1(old, next, expected); err != nil {
		return nil, err
	}
	return next, nil
}
func (w *ApplicationEnvelopeTopologyV1) AttachV1(ctx context.Context, root, child uuid.UUID, position int32) (*generated.Document, error) {
	if root == child {
		return nil, errors.New("attach: envelope cannot contain itself")
	}
	if w == nil || w.state == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || root != s.session.state.document {
		return nil, ErrEnvelopeTopologyV1
	}
	parent, old := s.docs[root], s.docs[child]
	if parent == nil || old == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	if !parent.IsEnvelope {
		return nil, errors.New("attach: parent document is not an envelope (call promote first)")
	}
	if position <= 0 {
		maxPos, err := s.queries.MaxEnvelopePosition(ctx, pgtype.UUID{Bytes: root, Valid: true})
		if err != nil {
			return nil, fmt.Errorf("attach: max position: %w", err)
		}
		position = maxPos + 1
	}
	next, err := s.queries.AttachToEnvelope(ctx, generated.AttachToEnvelopeParams{ID: child, ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, EnvelopePosition: pgtype.Int4{Int32: position, Valid: true}, OrgID: s.session.state.org})
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}
	expected := *old
	expected.ParentEnvelopeID = pgtype.UUID{Bytes: root, Valid: true}
	expected.EnvelopePosition = pgtype.Int4{Int32: position, Valid: true}
	if err = s.acceptV1(old, next, expected); err != nil {
		return nil, err
	}
	return next, nil
}
func (w *ApplicationEnvelopeTopologyV1) DetachV1(ctx context.Context, child uuid.UUID) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) {
		return nil, ErrEnvelopeTopologyV1
	}
	old := s.docs[child]
	if old == nil || !old.ParentEnvelopeID.Valid || uuid.UUID(old.ParentEnvelopeID.Bytes) != s.session.state.document {
		return nil, pgx.ErrNoRows
	}
	next, err := s.queries.DetachFromEnvelope(ctx, generated.DetachFromEnvelopeParams{ID: child, OrgID: s.session.state.org})
	if err != nil {
		return nil, fmt.Errorf("detach: %w", err)
	}
	expected := *old
	expected.ParentEnvelopeID = pgtype.UUID{}
	expected.EnvelopePosition = pgtype.Int4{}
	if err = s.acceptV1(old, next, expected); err != nil {
		return nil, err
	}
	return next, nil
}
func (w *ApplicationEnvelopeTopologyV1) ReorderV1(ctx context.Context, root uuid.UUID, ids []uuid.UUID) error {
	if w == nil || w.state == nil {
		return ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || root != s.session.state.document {
		return ErrEnvelopeTopologyV1
	}
	for i, id := range ids {
		old := s.docs[id]
		if old == nil {
			return ErrEnvelopeTopologyV1
		}
		position := pgtype.Int4{Int32: int32(i + 1), Valid: true}
		next, err := s.queries.ReorderEnvelopeTopologyChildV1(ctx, generated.ReorderEnvelopeTopologyChildV1Params{ID: id, ParentEnvelopeID: root, OrgID: s.session.state.org, EnvelopePosition: position})
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("reorder child %d (%s): child is not in this draft envelope", i, id)
		}
		if err != nil {
			return fmt.Errorf("reorder child %d (%s): %w", i, id, err)
		}
		expected := *old
		expected.EnvelopePosition = position
		if err = s.acceptV1(old, next, expected); err != nil {
			return err
		}
	}
	return nil
}
func (w *ApplicationEnvelopeTopologyV1) MetadataV1(ctx context.Context, root uuid.UUID) ([]*generated.ListEnvelopeChildMetadataForReadRow, error) {
	if w == nil || w.state == nil {
		return nil, ErrEnvelopeTopologyV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || root != s.session.state.document {
		return nil, ErrEnvelopeTopologyV1
	}
	count := int64(0)
	for _, doc := range s.docs {
		if doc.ParentEnvelopeID.Valid && uuid.UUID(doc.ParentEnvelopeID.Bytes) == root {
			count++
		}
	}
	cost := int64(0)
	if !htmlInputAddV1(&cost, count, 2*int64(unsafe.Sizeof(generated.ListEnvelopeChildMetadataForReadRow{}))+4*int64(unsafe.Sizeof((*generated.Document)(nil)))) {
		return nil, ErrEnvelopeTopologyV1
	}
	if err := s.holdV1(ctx, cost, 0); err != nil {
		return nil, err
	}
	rows, err := s.queries.ListEnvelopeChildMetadataForRead(ctx, generated.ListEnvelopeChildMetadataForReadParams{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: s.session.state.org})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != count {
		return nil, ErrEnvelopeTopologyV1
	}
	for _, row := range rows {
		old := s.docs[row.ID]
		if old == nil || old.OrgID != row.OrgID || old.ParentEnvelopeID != row.ParentEnvelopeID || old.EnvelopePosition != row.EnvelopePosition || old.UpdatedAt != row.UpdatedAt {
			return nil, ErrEnvelopeTopologyV1
		}
	}
	return rows, nil
}
func (w *ApplicationEnvelopeTopologyV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.docs = nil
	s.member = nil
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
