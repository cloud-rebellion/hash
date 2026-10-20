// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrManualNegotiationMutationV1 = errors.New("pdfadmission: owned manual negotiation mutation unavailable")

type ManualNegotiationOperationV1 uint8

const (
	ManualProposalCreateV1 ManualNegotiationOperationV1 = iota + 1
	ManualProposalStatusV1
	ManualNegotiationSettingV1
	ManualBilingualTargetV1
)

type ManualNegotiationInputV1 struct {
	Operation                                                    ManualNegotiationOperationV1
	ProposalID                                                   uuid.UUID
	ParentID                                                     pgtype.UUID
	BlockID, ProposalKind, ProposedText, Rationale, Status, Lang string
	AIAssisted, Enabled                                          bool
}
type ManualNegotiationPolicyV1 struct {
	RootDocumentID, DocumentID                             uuid.UUID
	RootDraft, DocumentDraft, RootAllowed, DocumentAllowed bool
}
type ApplicationManualNegotiationMutationV1 struct {
	state *applicationManualNegotiationStateV1
}
type applicationManualNegotiationStateV1 struct {
	mu                                        sync.Mutex
	session                                   *ApplicationSessionV1
	reader                                    *ApplicationHTMLRevisionReaderV1
	queries                                   *generated.Queries
	root                                      uuid.UUID
	snapshot                                  *applicationHTMLRevisionSourceSnapshotV1
	sourceWork                                *applicationBlocksCreationStateV1
	release                                   func()
	closes                                    []func()
	row                                       *generated.DocumentProposal
	policy                                    *generated.GetManualNegotiationPolicyV1Row
	rootLocked, policyRead, attempted, closed bool
}

func (h *ApplicationSessionV1) NewManualNegotiationMutationV1(ctx context.Context, r *ApplicationHTMLRevisionReaderV1) (*ApplicationManualNegotiationMutationV1, error) {
	if h == nil || h.state == nil || r == nil || r.self != r || r.session != h || !r.valid(ctx) {
		return nil, ErrManualNegotiationMutationV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationManualNegotiationStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationManualNegotiationMutationV1{})) + 4*int64(unsafe.Sizeof(generated.DocumentProposal{})) + 2*int64(unsafe.Sizeof(generated.GetManualProposalHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetManualProposalHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.ReadManualProposalSourceV1Params{})) + 2*int64(unsafe.Sizeof(generated.InsertProposalParams{})) + 2*int64(unsafe.Sizeof(generated.SetProposalStatusParams{})) + 2*int64(unsafe.Sizeof(generated.GetManualNegotiationPolicyV1Row{})) + 2*int64(unsafe.Sizeof(applicationBlocksCreationStateV1{})) + 2*int64(unsafe.Sizeof(generated.ManualProposalWireSizesV1{})) + 2*int64(unsafe.Sizeof(generated.MeasureManualProposalWireV1Params{})) + 4096
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrManualNegotiationMutationV1, err)
	}
	work := &applicationBlocksCreationStateV1{session: h, reader: r.authoring, queries: generated.New(&applicationOwnedDBTXV1{session: h.state})}
	return &ApplicationManualNegotiationMutationV1{state: &applicationManualNegotiationStateV1{sourceWork: work, session: h, reader: r, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationManualNegotiationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationManualNegotiationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return errors.Join(ErrManualNegotiationMutationV1, err)
	}
	s.closes = append(s.closes, close)
	return nil
}
func (w *ApplicationManualNegotiationMutationV1) LockRootV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrManualNegotiationMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.rootLocked {
		return ErrManualNegotiationMutationV1
	}
	p := s.session.state
	root, err := s.queries.GetManualNegotiationRootV1(ctx, generated.GetManualNegotiationRootV1Params{DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return err
	}
	row, err := s.queries.LockManualNegotiationRootV1(ctx, generated.LockManualNegotiationRootV1Params{RootDocumentID: root, OrgID: p.org})
	if err != nil {
		return err
	}
	if row == nil || root == uuid.Nil || row.RootDocumentID != root {
		return ErrManualNegotiationMutationV1
	}
	if row.RootHasParent || (root != p.document && !row.IsEnvelope) {
		return authoring.ErrAIAppDocumentClosed
	}
	matches, err := s.queries.ManualNegotiationRootMatchesV1(ctx, generated.ManualNegotiationRootMatchesV1Params{RootDocumentID: root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return err
	}
	if !matches {
		return authoring.ErrAIAppDocumentClosed
	}
	s.root = root
	s.rootLocked = true
	return nil
}

// These are actual locked scalar facts, not an authorization receipt. The fixed
// service preserves the original member/privacy/status order before body reads.
func (w *ApplicationManualNegotiationMutationV1) PolicyV1(ctx context.Context) (ManualNegotiationPolicyV1, error) {
	var out ManualNegotiationPolicyV1
	if w == nil || w.state == nil {
		return out, ErrManualNegotiationMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.rootLocked || s.policyRead {
		return out, ErrManualNegotiationMutationV1
	}
	p := s.session.state
	row, err := s.queries.GetManualNegotiationPolicyV1(ctx, generated.GetManualNegotiationPolicyV1Params{RootDocumentID: s.root, DocumentID: p.document, OrgID: p.org})
	if err != nil {
		return out, err
	}
	if row == nil || row.RootDocumentID != s.root || row.DocumentID != p.document {
		return out, ErrManualNegotiationMutationV1
	}
	copy := *row
	s.policy = &copy
	s.policyRead = true
	return ManualNegotiationPolicyV1{RootDocumentID: row.RootDocumentID, DocumentID: row.DocumentID, RootDraft: row.RootDraft, DocumentDraft: row.DocumentDraft, RootAllowed: row.RootAllowed, DocumentAllowed: row.DocumentAllowed}, nil
}
func (w *ApplicationManualNegotiationMutationV1) AcceptActualDocumentV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrManualNegotiationMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.rootLocked || !s.policyRead || s.policy == nil || s.snapshot != nil {
		return ErrManualNegotiationMutationV1
	}
	snapshot, release, err := s.reader.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return err
	}
	d := snapshot.document
	p := s.session.state
	if d == nil || d.ID != p.document || d.OrgID != p.org || d.DeletedAt.Valid || (d.ParentEnvelopeID.Valid && (uuid.UUID(d.ParentEnvelopeID.Bytes) != s.root)) || (!d.ParentEnvelopeID.Valid && d.ID != s.root) {
		release()
		return authoring.ErrAIAppDocumentClosed
	}
	if !s.policy.RootAllowed || !s.policy.DocumentAllowed {
		release()
		return authoring.ErrAIAppDocumentClosed
	}
	switch d.Status {
	case "draft", "sent", "in_progress", "changes_requested":
	default:
		release()
		return authoring.ErrAIAppDocumentClosed
	}
	matches, err := s.queries.ManualNegotiationRootMatchesV1(ctx, generated.ManualNegotiationRootMatchesV1Params{RootDocumentID: s.root, DocumentID: p.document, OrgID: p.org})
	if err != nil || !matches {
		release()
		return errors.Join(authoring.ErrAIAppDocumentClosed, err)
	}
	s.snapshot = snapshot
	s.release = release
	return nil
}
func (s *applicationManualNegotiationStateV1) blockV1(ctx context.Context, id string) error {
	// Preserve the original authoring ParseTree grammar (including omitted IDs),
	// top-level search and errors. Actual lexical and decimal work are owned by
	// this same session's concrete block-source owner before either allocation.
	cost, err := plainSendBlockLexicalWorkV1(ctx, s.snapshot.document.BlocksJson)
	if err != nil {
		return err
	}
	work := s.sourceWork
	if work == nil || !work.validV1(ctx) {
		return ErrManualNegotiationMutationV1
	}
	if err = work.holdV1(ctx, cost, 0); err != nil {
		return err
	}
	work.processing = true
	defer func() { work.processing = false }()
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, s.snapshot.document.BlocksJson, blocksCreationDecimalAdmissionV1{state: work, ctx: ctx})
	if work.admissionFailure != nil {
		return work.admissionFailure
	}
	if err != nil {
		return err
	}
	for i := range tree.Blocks {
		if tree.Blocks[i].ID == id {
			return nil
		}
	}
	return authoring.ErrAIBlockNotFound
}
func manualProposalRawV1(p *generated.DocumentProposal) int64 {
	if p == nil {
		return 0
	}
	return int64(len(p.BlockID) + len(p.ProposalKind) + len(p.ProposedText) + len(p.Rationale) + len(p.Status))
}
func cloneManualProposalV1(p *generated.DocumentProposal) *generated.DocumentProposal {
	if p == nil {
		return nil
	}
	v := *p
	v.BlockID = strings.Clone(p.BlockID)
	v.ProposalKind = strings.Clone(p.ProposalKind)
	v.ProposedText = strings.Clone(p.ProposedText)
	v.Rationale = strings.Clone(p.Rationale)
	v.Status = strings.Clone(p.Status)
	v.DiffJson = bytes.Clone(p.DiffJson)
	return &v
}
func (w *ApplicationManualNegotiationMutationV1) MutateV1(ctx context.Context, actor uuid.UUID, in ManualNegotiationInputV1) (*generated.DocumentProposal, error) {
	if w == nil || w.state == nil {
		return nil, ErrManualNegotiationMutationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.snapshot == nil || s.snapshot.owner != s.reader || s.attempted || actor == uuid.Nil {
		return nil, ErrManualNegotiationMutationV1
	}
	s.attempted = true
	p := s.session.state
	switch in.Operation {
	case ManualProposalCreateV1:
		switch in.ProposalKind {
		case "edit", "reject", "counter", "block_lock":
		default:
			return nil, ErrManualNegotiationMutationV1
		}
		if err := s.blockV1(ctx, in.BlockID); err != nil {
			return nil, err
		}
		if in.ParentID.Valid {
			if err := s.holdV1(ctx, int64(len(in.BlockID)), 0); err != nil {
				return nil, err
			}
			matches, err := s.queries.LockManualProposalParentV1(ctx, generated.LockManualProposalParentV1Params{ProposalID: uuid.UUID(in.ParentID.Bytes), DocumentID: p.document, OrgID: p.org, BlockID: in.BlockID})
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, authoring.ErrAIProposalNotFound
			}
			if err != nil {
				return nil, err
			}
			if !matches {
				return nil, authoring.ErrAIProposalBlockMismatch
			}
		}
		raw, err := htmlAuthoringSumV1(int64(len(in.BlockID)), int64(len(in.ProposalKind)), int64(len(in.ProposedText)), int64(len(in.Rationale)), int64(len("pending")))
		if err != nil {
			return nil, err
		}
		output := int64(0)
		if !htmlInputAddV1(&output, raw, 4) {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.holdV1(ctx, output, 8); err != nil {
			return nil, err
		}
		row, err := s.queries.InsertProposal(ctx, generated.InsertProposalParams{DocumentID: p.document, OrgID: p.org, ProposedBy: pgtype.UUID{Bytes: actor, Valid: true}, BlockID: in.BlockID, ProposalKind: in.ProposalKind, ProposedText: in.ProposedText, Rationale: in.Rationale, DiffJson: []byte("{}"), AiAssisted: in.AIAssisted, ParentID: in.ParentID})
		if err != nil {
			return nil, err
		}
		if row == nil || row.ID == uuid.Nil || row.DocumentID != p.document || row.OrgID != p.org || row.RecipientID.Valid || row.ProposedBy != (pgtype.UUID{Bytes: actor, Valid: true}) || row.BlockID != in.BlockID || row.ProposalKind != in.ProposalKind || row.ProposedText != in.ProposedText || row.Rationale != in.Rationale || row.Status != "pending" || row.AiAssisted != in.AIAssisted || row.ParentID != in.ParentID || !bytes.Equal(row.DiffJson, []byte("{}")) || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.measureProposalV1(ctx, row); err != nil {
			return nil, err
		}
		s.row = cloneManualProposalV1(row)
		return row, nil
	case ManualProposalStatusV1:
		switch in.Status {
		case "pending", "accepted", "rejected", "superseded":
		default:
			return nil, ErrManualNegotiationMutationV1
		}
		h, err := s.queries.GetManualProposalHeaderV1(ctx, generated.GetManualProposalHeaderV1Params{ProposalID: in.ProposalID, DocumentID: p.document, OrgID: p.org})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, authoring.ErrAIProposalNotFound
		}
		if err != nil {
			return nil, err
		}
		if h == nil || h.ID != in.ProposalID || h.DocumentID != p.document || h.OrgID != p.org || h.RawTextBytes < 0 || h.DiffWireBytes < 0 || h.MeasurementServerVersionNum != h.ServerVersionNum || h.ServerVersionNum < 1 || !applicationStampV1(h.CreatedAt) || !applicationStampV1(h.UpdatedAt) {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.holdV1(ctx, h.RawTextBytes, h.DiffWireBytes); err != nil {
			return nil, err
		}
		old, err := s.queries.ReadManualProposalSourceV1(ctx, generated.ReadManualProposalSourceV1Params{ProposalID: in.ProposalID, DocumentID: p.document, OrgID: p.org, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes, ExpectedDiffWireBytes: h.DiffWireBytes})
		if err != nil {
			return nil, err
		}
		if old == nil || old.ID != in.ProposalID || old.DocumentID != p.document || old.OrgID != p.org || old.CreatedAt != h.CreatedAt || old.UpdatedAt != h.UpdatedAt || manualProposalRawV1(old) != h.RawTextBytes || int64(len(old.DiffJson)) != h.DiffWireBytes {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.blockV1(ctx, old.BlockID); err != nil {
			return nil, err
		}
		raw, err := htmlAuthoringSumV1(h.RawTextBytes, int64(len(in.Status)))
		if err != nil {
			return nil, err
		}
		output, wire := int64(0), int64(0)
		if !htmlInputAddV1(&output, raw, 4) || !htmlInputAddV1(&wire, h.DiffWireBytes, 4) {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.holdV1(ctx, output, wire); err != nil {
			return nil, err
		}
		row, err := s.queries.SetProposalStatus(ctx, generated.SetProposalStatusParams{ID: in.ProposalID, OrgID: p.org, Status: in.Status})
		if err != nil {
			return nil, err
		}
		if row == nil || row.ID != old.ID || row.DocumentID != old.DocumentID || row.OrgID != old.OrgID || row.RecipientID != old.RecipientID || row.ProposedBy != old.ProposedBy || row.ParentID != old.ParentID || row.CreatedAt != old.CreatedAt || row.BlockID != old.BlockID || row.ProposalKind != old.ProposalKind || row.ProposedText != old.ProposedText || row.Rationale != old.Rationale || row.AiAssisted != old.AiAssisted || row.Status != in.Status || !bytes.Equal(row.DiffJson, old.DiffJson) || !applicationStampV1(row.UpdatedAt) {
			return nil, ErrManualNegotiationMutationV1
		}
		if err = s.measureProposalV1(ctx, row); err != nil {
			return nil, err
		}
		s.row = cloneManualProposalV1(row)
		return row, nil
	case ManualNegotiationSettingV1:
		return nil, s.queries.SetDocumentNegotiationEnabled(ctx, generated.SetDocumentNegotiationEnabledParams{ID: p.document, OrgID: p.org, NegotiationEnabled: in.Enabled})
	case ManualBilingualTargetV1:
		if err := s.holdV1(ctx, int64(len(in.Lang)), 0); err != nil {
			return nil, err
		}
		return nil, s.queries.SetDocumentBilingualTarget(ctx, generated.SetDocumentBilingualTargetParams{ID: p.document, OrgID: p.org, BilingualTargetLang: in.Lang})
	}
	return nil, ErrManualNegotiationMutationV1
}

// Both callers already retain the actual known birth or old/status body loan.
// This fresh measurement is not exposed as a legacy cache-repair operation.
func (s *applicationManualNegotiationStateV1) measureProposalV1(ctx context.Context, row *generated.DocumentProposal) error {
	p := s.session.state
	m, err := s.queries.MeasureManualProposalWireV1(ctx, generated.MeasureManualProposalWireV1Params{ProposalID: row.ID, DocumentID: p.document, OrgID: p.org, ExpectedCreatedAt: row.CreatedAt, ExpectedUpdatedAt: row.UpdatedAt})
	if err != nil {
		return err
	}
	if m == nil || m.ProposalID != row.ID || m.DocumentID != p.document || m.OrgID != p.org || m.ProposalCreatedAt != row.CreatedAt || m.ProposalUpdatedAt != row.UpdatedAt || m.DiffWireBytes != int64(len(row.DiffJson)) || m.MeasurementServerVersionNum < 1 || !applicationStampV1(m.MeasuredAt) {
		return ErrManualNegotiationMutationV1
	}
	return nil
}

func (w *ApplicationManualNegotiationMutationV1) CloseConsumerV1() {
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
	s.policy = nil
	work := s.sourceWork
	s.sourceWork = nil
	closes, release := s.closes, s.release
	s.closes = nil
	s.release = nil
	s.mu.Unlock()
	if work != nil {
		(&ApplicationBlocksCreationWriterV1{state: work}).CloseConsumerV1()
	}
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
}
