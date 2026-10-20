// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fixed original-policy bridge class, checked against its actual Go types by sign.
const SignerAIBridgeControlBytesV1 uintptr = 4096

var ErrSignerAIExpiredV1 = errors.New("pdfadmission: original signer AI credential expired")
var ErrSignerAINoticeV1 = errors.New("pdfadmission: original signer AI notice changed")

// Only an actual registered active reader can issue this request. It owns the
// original token, expiry and notice pins; exported document/recipient IDs or an
// old audit row cannot construct it. It grants no staff actor authority.
type ApplicationSignerAIRequestV1 struct{ state *applicationSignerAIRequestV1 }
type applicationSignerAIRequestV1 struct {
	mu                                                   sync.Mutex
	self                                                 *applicationSignerAIRequestV1
	factory                                              *ApplicationSessionFactoryV1
	reader                                               *ApplicationSignerReaderV1
	org, document, recipient                             uuid.UUID
	hash                                                 [32]byte
	parent                                               pgtype.UUID
	recipientExpiry, documentExpiry, sentAt, noticeEpoch pgtype.Timestamptz
	noticeCommitted                                      bool
	name, basis, schema, role                            string
	notice                                               article13.Evidence
	ctx                                                  context.Context
	grant                                                *workguard.GrantV1
	input                                                *ApplicationDocumentAIInputV1
	ip, ua, block, locale, selection, question           string
	active                                               int
	inputStarted, captured, closed, retired              bool
}

func (f *ApplicationSessionFactoryV1) NewSignerAIRequestV1(ctx context.Context, r *ApplicationSignerReaderV1, notice article13.Evidence, ip, ua string) (*ApplicationSignerAIRequestV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) {
		return nil, ErrDocumentAIAuditV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrDocumentAIAuditV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.finishScope == nil || r.models == nil || r.models.Document == nil || r.models.Recipient == nil {
		return nil, ErrDocumentAIAuditV1
	}
	d, rec := r.models.Document, r.models.Recipient
	if d.ID != r.scope.document || d.OrgID != r.scope.org || rec.ID != r.scope.recipient || rec.DocumentID != d.ID || rec.DocOrgID != d.OrgID || !bytes.Equal(rec.MagicTokenHash, r.scope.hash[:]) {
		return nil, ErrDocumentAIAuditV1
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	available := registered && !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return nil, ErrDocumentAIAuditV1
	}
	raw, err := signerViewRequestParentBytesV1(ctx, ip, ua, notice)
	if err != nil {
		return nil, err
	}
	if !htmlInputAddV1(&raw, 4*int64(unsafe.Sizeof(applicationSignerAIRequestV1{}))+int64(SignerAIBridgeControlBytesV1), 1) {
		return nil, ErrDocumentAIAuditV1
	}
	for _, s := range []string{d.Name, d.LawfulBasis, d.Article13NoticeSchema, rec.Role} {
		if !htmlInputAddV1(&raw, int64(len(s)), 8) {
			return nil, ErrDocumentAIAuditV1
		}
	}
	grant, err := coordinator.TryAcquireV1(ctx, d.OrgID, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return nil, err
	}
	h := &applicationSignerAIRequestV1{factory: f, reader: r, org: d.OrgID, document: d.ID, recipient: rec.ID, hash: r.scope.hash, parent: d.ParentEnvelopeID, recipientExpiry: rec.MagicTokenExpiresAt, documentExpiry: d.ExpiresAt, sentAt: d.SentAt, noticeEpoch: d.Article13NoticeEpochAt, noticeCommitted: d.Article13NoticeEpochV61Committed, name: strings.Clone(d.Name), basis: strings.Clone(d.LawfulBasis), schema: strings.Clone(d.Article13NoticeSchema), role: strings.Clone(rec.Role), notice: notice, ctx: ctx, grant: grant, ip: strings.Clone(ip), ua: strings.Clone(ua)}
	h.self = h
	if err = notice.Validate(); err != nil {
		grant.Close()
		return nil, ErrSignerAINoticeV1
	}
	if err = h.checkDocumentV1(d, signerAIRecipientModelV1(rec), time.Now()); err != nil {
		grant.Close()
		return nil, err
	}
	r.blockSigningBorrowers++
	return &ApplicationSignerAIRequestV1{state: h}, nil
}
func signerAIRecipientModelV1(r *generated.GetRecipientByTokenHashRow) *generated.Recipient {
	if r == nil {
		return nil
	}
	return &generated.Recipient{ID: r.ID, DocumentID: r.DocumentID, Role: r.Role, Email: r.Email, Name: r.Name, OrderIndex: r.OrderIndex, Status: r.Status, MagicTokenHash: r.MagicTokenHash, SentAt: r.SentAt, FirstViewedAt: r.FirstViewedAt, SignedAt: r.SignedAt, DeclinedReason: r.DeclinedReason, CreatedAt: r.CreatedAt, MagicTokenExpiresAt: r.MagicTokenExpiresAt, Locale: r.Locale}
}
func (h *applicationSignerAIRequestV1) checkDocumentV1(d *generated.Document, r *generated.Recipient, now time.Time) error {
	if h == nil || d == nil || r == nil || d.ID != h.document || d.OrgID != h.org || d.ParentEnvelopeID != h.parent || r.ID != h.recipient || r.DocumentID != h.document || r.Role != h.role || len(r.MagicTokenHash) != 32 || subtle.ConstantTimeCompare(r.MagicTokenHash, h.hash[:]) != 1 {
		return ErrSignerAIExpiredV1
	}
	for _, t := range []pgtype.Timestamptz{h.recipientExpiry, h.documentExpiry, r.MagicTokenExpiresAt, d.ExpiresAt} {
		if t.Valid && now.After(t.Time) {
			return ErrSignerAIExpiredV1
		}
	}
	if d.SentAt != h.sentAt || d.Article13NoticeEpochAt != h.noticeEpoch || d.Article13NoticeSchema != h.schema || d.Article13NoticeEpochV61Committed != h.noticeCommitted || d.Name != h.name || d.LawfulBasis != h.basis {
		return ErrSignerAINoticeV1
	}
	n := h.notice.Snapshot
	if !d.SentAt.Valid || !d.Article13NoticeEpochAt.Valid || !d.SentAt.Time.Equal(d.Article13NoticeEpochAt.Time) || n.DocumentID != h.document || n.OrgID != h.org || n.RecipientID != h.recipient || n.Schema != h.schema || n.SentAt != d.SentAt.Time.UTC().Format(time.RFC3339Nano) {
		return ErrSignerAINoticeV1
	}
	return nil
}
func (h *applicationSignerAIRequestV1) beginV1(ctx context.Context) error {
	if h == nil {
		return ErrDocumentAIAuditV1
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.self != h || h.closed || h.retired || h.ctx == nil || h.ctx.Err() != nil || ctx == nil || ctx.Err() != nil {
		return ErrDocumentAIAuditV1
	}
	deadline, ok := ctx.Deadline()
	original, originalOK := h.ctx.Deadline()
	if !ok || !originalOK || deadline.After(original) {
		return ErrDocumentAIAuditV1
	}
	h.active++
	return nil
}
func (h *applicationSignerAIRequestV1) finishV1() {
	h.mu.Lock()
	h.active--
	r, g, input := h.retireV1()
	h.mu.Unlock()
	retireSignerAIRequestV1(r, g, input)
}
func (h *applicationSignerAIRequestV1) retireV1() (*ApplicationSignerReaderV1, *workguard.GrantV1, *ApplicationDocumentAIInputV1) {
	if !h.closed || h.retired || h.active != 0 {
		return nil, nil, nil
	}
	h.retired = true
	r, g, in := h.reader, h.grant, h.input
	h.reader = nil
	h.grant = nil
	h.input = nil
	h.factory = nil
	h.ctx = nil
	h.notice = article13.Evidence{}
	h.name, h.basis, h.schema, h.role, h.ip, h.ua, h.block, h.locale, h.selection, h.question = "", "", "", "", "", "", "", "", "", ""
	h.hash = [32]byte{}
	return r, g, in
}
func retireSignerAIRequestV1(r *ApplicationSignerReaderV1, g *workguard.GrantV1, in *ApplicationDocumentAIInputV1) {
	if in != nil {
		in.CloseConsumerV1()
	}
	retireSignerViewRequestV1(r, g)
}
func (h *ApplicationSignerAIRequestV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	r, g, in := s.retireV1()
	s.mu.Unlock()
	retireSignerAIRequestV1(r, g, in)
}
func (h *ApplicationSignerAIRequestV1) ScopeV1(ctx context.Context, f *ApplicationSessionFactoryV1) (uuid.UUID, uuid.UUID, error) {
	if h == nil || h.state == nil {
		return uuid.Nil, uuid.Nil, ErrDocumentAIAuditV1
	}
	s := h.state
	if err := s.beginV1(ctx); err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	defer s.finishV1()
	if s.factory != f {
		return uuid.Nil, uuid.Nil, ErrDocumentAIAuditV1
	}
	return s.org, s.document, nil
}

// Before the unchanged single Decode. Actual prefix growth and decoder buffers
// use the same retained original parser loan as staff ingress, not a post hoc bill.
func (h *ApplicationSignerAIRequestV1) WithBodyV1(ctx context.Context, body io.Reader, decode func(io.Reader) error) error {
	if h == nil || h.state == nil {
		return ErrDocumentAIAuditV1
	}
	s := h.state
	if err := s.beginV1(ctx); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.inputStarted {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	s.inputStarted = true
	s.mu.Unlock()
	input, err := s.factory.newAIInputV1(ctx, s.org, aiHTTPInputProfileV1, 32*1024, nil)
	s.mu.Lock()
	s.input = input
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return input.WithBodyV1(ctx, body, decode)
}
func (h *ApplicationSignerAIRequestV1) CaptureInputV1(ctx context.Context, block, locale, selection, question string) error {
	if h == nil || h.state == nil {
		return ErrDocumentAIAuditV1
	}
	s := h.state
	if err := s.beginV1(ctx); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.inputStarted || s.input == nil || s.captured {
		return ErrDocumentAIAuditV1
	}
	raw := int64(4096)
	if !htmlInputAddV1(&raw, int64(len(block)), 16) || !htmlInputAddV1(&raw, int64(len(locale)), 16) || !htmlInputAddV1(&raw, int64(len(selection)), 16) || !htmlInputAddV1(&raw, int64(len(question)), 16) {
		return ErrDocumentAIAuditV1
	}
	if err := s.grant.TryGrowParentV1(ctx, raw); err != nil {
		return err
	}
	s.block, s.locale, s.selection, s.question = strings.Clone(block), strings.Clone(locale), strings.Clone(selection), strings.Clone(question)
	s.captured = true
	return nil
}

func (h *ApplicationSignerAIRequestV1) VerifyInputV1(ctx context.Context, block, locale, selection, question string) error {
	if h == nil || h.state == nil {
		return ErrDocumentAIAuditV1
	}
	s := h.state
	if err := s.beginV1(ctx); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.captured || s.block != block || s.locale != locale || s.selection != selection || s.question != question {
		return ErrDocumentAIAuditV1
	}
	return nil
}
