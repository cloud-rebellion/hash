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

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

var ErrPlainRecipientWriterV1 = errors.New("pdfadmission: owned ordinary recipient writer unavailable")
var ErrPlainRecipientSourceKindV1 = errors.New("pdfadmission: recipient parent requires original HTML policy")

// This is a real existing-source mutation owner, never a fresh-document owner.
// Scalar source kind and both HTML absence checks precede full6JSON/actor work;
// the real revision reader subsequently supplies its private source snapshot.
// Original author/credential/evidence/contract/privacy/quota policy stays in the
// one fixed recipient service. Source/cache/input sizes supply no permission.
type ApplicationPlainRecipientMutationV1 struct {
	state *applicationPlainRecipientMutationStateV1
}
type applicationPlainRecipientMutationStateV1 struct {
	mu                                      sync.Mutex
	session                                 *ApplicationSessionV1
	reader                                  *ApplicationHTMLRevisionReaderV1
	queries                                 *generated.Queries
	closes                                  []func()
	sourceKind                              string
	document                                *generated.Document
	recipient                               *generated.Recipient
	sourceChecked, created, mutated, closed bool
}

func (h *ApplicationSessionV1) NewPlainRecipientMutationV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1) (*ApplicationPlainRecipientMutationV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrPlainRecipientWriterV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationPlainRecipientMutationStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationPlainRecipientMutationV1{})) + 2*int64(unsafe.Sizeof(generated.Recipient{})) + int64(unsafe.Sizeof(generated.GetRecipientMutationSourceHeaderV1Row{})) + int64(unsafe.Sizeof(generated.GetPlainFieldRecipientReadHeaderV1Row{})) + int64(unsafe.Sizeof(plainRecipientQuotaSourceReadsV1{})) + int64(unsafe.Sizeof(generated.CreateRecipientParams{})) + int64(unsafe.Sizeof(generated.UpdateRecipientParams{}))
	close, err := reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	return &ApplicationPlainRecipientMutationV1{state: &applicationPlainRecipientMutationStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationPlainRecipientMutationStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.self == s.reader && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func (s *applicationPlainRecipientMutationStateV1) holdV1(ctx context.Context, raw, wire int64) error {
	close, err := s.reader.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	return nil
}
func (w *ApplicationPlainRecipientMutationV1) LockOrdinaryParentV1(ctx context.Context) (bool, error) {
	if w == nil || w.state == nil {
		return false, ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.sourceChecked {
		return false, ErrPlainRecipientWriterV1
	}
	s.sourceChecked = true
	h, err := s.queries.GetRecipientMutationSourceHeaderV1(ctx, generated.GetRecipientMutationSourceHeaderV1Params{DocumentID: s.session.state.document, OrgID: s.session.state.org})
	if err != nil {
		return false, err
	}
	if h == nil || h.ID != s.session.state.document || h.OrgID != s.session.state.org {
		return false, ErrPlainRecipientWriterV1
	}
	if h.Status != "draft" {
		return false, nil
	}
	if (h.SourceKind != "pdf" && h.SourceKind != "blocks") || h.HasHtmlOrigin || h.HasHtmlCurrent || h.HasHtmlMaterialization {
		return true, ErrPlainRecipientSourceKindV1
	}
	s.sourceKind = h.SourceKind
	return true, nil
}
func (w *ApplicationPlainRecipientMutationV1) AcceptActualDocumentV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.sourceChecked || s.sourceKind == "" || s.created {
		return ErrPlainRecipientWriterV1
	}
	snapshot := s.reader.snapshot
	if snapshot == nil || snapshot.owner != s.reader || snapshot.document == nil {
		return ErrPlainRecipientWriterV1
	}
	d := snapshot.document
	if d.ID != s.session.state.document || d.OrgID != s.session.state.org || d.SourceKind != s.sourceKind || d.Status != "draft" || len(d.HtmlSourceJson) != 0 || len(d.HtmlCurrentSourceJson) != 0 || d.HtmlCurrentMaterializationID.Valid {
		return ErrPlainRecipientWriterV1
	}
	s.document = d
	s.created = true
	return nil
}

// Four concrete original recipient text inputs are priced before normalization
// copies. Optional patch presence/order is fixed typed control storage above.
func (w *ApplicationPlainRecipientMutationV1) RetainRecipientInputV1(ctx context.Context, email, name, role, locale string) error {
	if w == nil || w.state == nil {
		return ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.mutated {
		return ErrPlainRecipientWriterV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(email)), int64(len(name)), int64(len(role)), int64(len(locale)))
	if err != nil {
		return err
	}
	return s.holdV1(ctx, raw, 0)
}
func (w *ApplicationPlainRecipientMutationV1) ReadRecipientV1(ctx context.Context, id uuid.UUID) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.mutated || s.recipient != nil || id == uuid.Nil {
		return nil, ErrPlainRecipientWriterV1
	}
	row, err := s.reader.ReadPlainFieldRecipientV1(ctx, id)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.DocumentID != s.session.state.document {
		return nil, ErrPlainRecipientWriterV1
	}
	s.recipient = plainCloneRecipientV1(row)
	return row, nil
}
func (w *ApplicationPlainRecipientMutationV1) CreateRecipientV1(ctx context.Context, p generated.CreateRecipientParams) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.mutated || s.recipient != nil || p.DocumentID != s.session.state.document {
		return nil, ErrPlainRecipientWriterV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(p.Email)), int64(len(p.Name)), int64(len(p.Role)), int64(len(p.Locale)), int64(len(p.MagicTokenHash)), 2*int64(unsafe.Sizeof(generated.CreateRecipientParams{})))
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, raw, 0); err != nil {
		return nil, err
	}
	p.Email = strings.Clone(p.Email)
	p.Name = strings.Clone(p.Name)
	p.Role = strings.Clone(p.Role)
	p.Locale = strings.Clone(p.Locale)
	p.MagicTokenHash = bytes.Clone(p.MagicTokenHash)
	s.mutated = true
	row, err := s.queries.CreateRecipient(ctx, p)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != p.DocumentID || row.Email != p.Email || row.Name != p.Name || row.Role != p.Role || row.Locale != p.Locale || row.OrderIndex != p.OrderIndex || !bytes.Equal(row.MagicTokenHash, p.MagicTokenHash) || row.DeclinedReason.Valid || row.Status != "pending" {
		return nil, ErrPlainRecipientWriterV1
	}
	s.recipient = plainCloneRecipientV1(row)
	return row, nil
}
func (w *ApplicationPlainRecipientMutationV1) UpdateRecipientV1(ctx context.Context, p generated.UpdateRecipientParams) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.mutated || s.recipient == nil || p.DocumentID != s.session.state.document || p.ID != s.recipient.ID {
		return nil, ErrPlainRecipientWriterV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(p.Email)), int64(len(p.Name)), int64(len(p.Role)), int64(len(p.Locale)), 2*int64(unsafe.Sizeof(generated.UpdateRecipientParams{})))
	if err != nil {
		return nil, err
	}
	if err = s.holdV1(ctx, raw, 0); err != nil {
		return nil, err
	}
	p.Email = strings.Clone(p.Email)
	p.Name = strings.Clone(p.Name)
	p.Role = strings.Clone(p.Role)
	p.Locale = strings.Clone(p.Locale)
	s.mutated = true
	row, err := s.queries.UpdateRecipient(ctx, p)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != p.ID || row.DocumentID != p.DocumentID || row.Email != p.Email || row.Name != p.Name || row.Role != p.Role || row.Locale != p.Locale || row.OrderIndex != p.OrderIndex || !bytes.Equal(row.MagicTokenHash, s.recipient.MagicTokenHash) || row.MagicTokenExpiresAt != s.recipient.MagicTokenExpiresAt || row.Status != s.recipient.Status || row.DeclinedReason != s.recipient.DeclinedReason {
		return nil, ErrPlainRecipientWriterV1
	}
	s.recipient = plainCloneRecipientV1(row)
	return row, nil
}
func (w *ApplicationPlainRecipientMutationV1) DeleteRecipientV1(ctx context.Context, id uuid.UUID) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainRecipientWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.mutated || s.recipient == nil || id != s.recipient.ID {
		return nil, ErrPlainRecipientWriterV1
	}
	s.mutated = true
	deleted, err := s.queries.DeleteRecipient(ctx, generated.DeleteRecipientParams{ID: id, DocumentID: s.session.state.document})
	if err != nil {
		return nil, err
	}
	if deleted != id {
		return nil, ErrPlainRecipientWriterV1
	}
	return plainCloneRecipientV1(s.recipient), nil
}
func (w *ApplicationPlainRecipientMutationV1) CloseConsumerV1() {
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
	s.document = nil
	s.recipient = nil
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func plainCloneRecipientV1(in *generated.Recipient) *generated.Recipient {
	if in == nil {
		return nil
	}
	out := *in
	out.Role = strings.Clone(in.Role)
	out.Email = strings.Clone(in.Email)
	out.Name = strings.Clone(in.Name)
	out.Status = strings.Clone(in.Status)
	out.Locale = strings.Clone(in.Locale)
	out.DeclinedReason.String = strings.Clone(in.DeclinedReason.String)
	out.MagicTokenHash = bytes.Clone(in.MagicTokenHash)
	return &out
}
