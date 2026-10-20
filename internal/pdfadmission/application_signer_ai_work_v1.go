// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (h *ApplicationSessionV1) NewSignerAIWorkV1(ctx context.Context, request *ApplicationSignerAIRequestV1) (*ApplicationDocumentAIWorkV1, error) {
	if h == nil || h.state == nil || request == nil || request.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := request.state
	if err := s.beginV1(ctx); err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			s.finishV1()
		}
	}()
	s.mu.Lock()
	valid := s.captured && s.factory != nil && h.state.factory == s.factory.state && h.state.org == s.org && h.state.document == s.document
	s.mu.Unlock()
	if !valid {
		return nil, ErrDocumentAIAuditV1
	}
	r, err := h.NewHTMLRevisionReaderV1(ctx)
	if err != nil {
		return nil, err
	}
	raw := 4*int64(unsafe.Sizeof(applicationDocumentAIStateV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIRequestReceiptV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIUsageReceiptV1{})) + 4*int64(unsafe.Sizeof(generated.GetDocumentAIPolicyV1Row{})) + 4*int64(unsafe.Sizeof(generated.Recipient{})) + 8192
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		r.CloseConsumerV1()
		return nil, err
	}
	r.documentAIShared = true
	out := &ApplicationDocumentAIWorkV1{state: &applicationDocumentAIStateV1{session: h, reader: r, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), signer: s, via: "signer", action: "clarify_clause", closes: []func(){close}}}
	out.state.self = out
	keep = true
	return out, nil
}
func (s *applicationDocumentAIStateV1) recipientIDV1() uuid.UUID {
	if s != nil && s.signer != nil {
		return s.signer.recipient
	}
	return uuid.Nil
}
func (s *applicationDocumentAIStateV1) auditActorV1() pgtype.UUID {
	if s.signer != nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: s.actor, Valid: true}
}
func (s *applicationDocumentAIStateV1) requestPurposeV1() HTMLAuditPurposeV1 {
	if s.signer != nil {
		return HTMLAuditSignerAIRequestedV1
	}
	return HTMLAuditAIRequestedV1
}
func (s *applicationDocumentAIStateV1) costPurposeV1() HTMLAuditPurposeV1 {
	if s.signer != nil {
		return HTMLAuditSignerAICompletedV1
	}
	return HTMLAuditAICompletedV1
}
func (s *applicationDocumentAIAuditScopeV1) signerRequestV1() *applicationSignerAIRequestV1 {
	return s.signer
}
func (s *applicationDocumentAIAuditScopeV1) attributionV1() (pgtype.UUID, pgtype.UUID) {
	if r := s.signerRequestV1(); r != nil {
		return pgtype.UUID{Bytes: r.recipient, Valid: true}, pgtype.UUID{}
	}
	return pgtype.UUID{}, pgtype.UUID{Bytes: s.actor, Valid: true}
}
func (s *applicationDocumentAIStateV1) checkSignerV1(ctx context.Context) error {
	if s.signer == nil || s.snapshot == nil || s.snapshot.document == nil || s.signerRecipient == nil {
		return ErrDocumentAIAuditV1
	}
	h := s.signer
	h.mu.Lock()
	live := h.self == h && !h.closed && !h.retired && h.ctx != nil && h.ctx.Err() == nil
	h.mu.Unlock()
	if !live || ctx.Err() != nil {
		return ErrDocumentAIAuditV1
	}
	return h.checkDocumentV1(s.snapshot.document, s.signerRecipient, time.Now())
}
func (w *ApplicationDocumentAIWorkV1) CheckSignerCredentialV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	return s.checkSignerV1(ctx)
}

// Same source reader and scalar/body sizing, but the fixed recipient capability
// replaces the staff-user actor gate. No public callback can fabricate it.
func (w *ApplicationDocumentAIWorkV1) ReadSignerDocumentV1(ctx context.Context) (*generated.Document, *generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.signer == nil || s.closeAfterProvider || s.readActive != 0 || s.root == uuid.Nil || s.snapshot != nil {
		s.mu.Unlock()
		return nil, nil, ErrDocumentAIAuditV1
	}
	s.readActive++
	r, request := s.reader, s.signer
	s.mu.Unlock()
	defer s.finishReadV1()
	models, err := r.readDocumentBodyV1(ctx, uuid.Nil, func(a HTMLRevisionReadAccessV1) error {
		if a.DocumentID != request.document || a.OrgID != request.org {
			return ErrDocumentAIAuditV1
		}
		q := s.queries
		if (request.parent.Valid && uuid.UUID(request.parent.Bytes) != s.root) || (!request.parent.Valid && s.root != request.document) {
			return authoring.ErrAIAppDocumentClosed
		}
		matches, err := q.DocumentAIRootMatchesV1(ctx, generated.DocumentAIRootMatchesV1Params{RootDocumentID: s.root, DocumentID: request.document, OrgID: request.org})
		if err != nil {
			return err
		}
		if !matches {
			return authoring.ErrAIAppDocumentClosed
		}
		h, err := q.GetSignerRecipientReadHeaderV1(ctx, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: request.document, OrgID: request.org, RecipientID: request.recipient, TokenHash: request.hash[:]})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSignerAIExpiredV1
		}
		if err != nil {
			return err
		}
		if h == nil || h.RawTextBytes < 0 {
			return ErrDocumentAIAuditV1
		}
		raw := int64(8192)
		for _, v := range []string{request.name, request.basis, request.schema, request.role} {
			if !htmlInputAddV1(&raw, int64(len(v)), 8) {
				return ErrDocumentAIAuditV1
			}
		}
		s.mu.Lock()
		err = func() error {
			total, sumErr := htmlAuthoringSumV1(raw, h.RawTextBytes)
			if sumErr != nil {
				return sumErr
			}
			return s.holdV1(ctx, total, h.RawTextBytes)
		}()
		s.mu.Unlock()
		if err != nil {
			return err
		}
		pins, err := q.GetSignerAICredentialPinsV1(ctx, generated.GetSignerAICredentialPinsV1Params{DocumentID: request.document, OrgID: request.org, RecipientID: request.recipient, TokenHash: request.hash[:], OriginalName: request.name, OriginalBasis: request.basis, OriginalSchema: request.schema, OriginalRole: request.role})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSignerAIExpiredV1
		}
		if err != nil {
			return err
		}
		if pins == nil || !pins.RoleMatches {
			return ErrSignerAIExpiredV1
		}
		now := time.Now()
		for _, v := range []pgtype.Timestamptz{request.documentExpiry, request.recipientExpiry, pins.ExpiresAt, pins.MagicTokenExpiresAt} {
			if v.Valid && now.After(v.Time) {
				return ErrSignerAIExpiredV1
			}
		}
		if !pins.NameMatches || !pins.BasisMatches || !pins.SchemaMatches || pins.SentAt != request.sentAt || pins.Article13NoticeEpochAt != request.noticeEpoch || pins.Article13NoticeEpochV61Committed != request.noticeCommitted {
			return ErrSignerAINoticeV1
		}
		fence, err := q.TryCollabArchivePrivacyFence(ctx, request.org)
		if err != nil {
			return err
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		policy, err := w.PolicyV1(ctx)
		if err != nil {
			return err
		}
		if !policy.RootAllowed || !policy.DocumentAllowed || policy.RootDraft || policy.DocumentDraft {
			return authoring.ErrAIAppDocumentClosed
		}
		for _, id := range []uuid.UUID{s.root, request.document} {
			pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: request.org})
			if err != nil {
				return err
			}
			if pending {
				return authoring.ErrPendingPrivacyReview
			}
			if id == request.document {
				break
			}
		}
		rec, err := q.GetRecipientForShare(ctx, generated.GetRecipientForShareParams{ID: request.recipient, DocumentID: request.document, OrgID: request.org})
		if err != nil {
			return err
		}
		if rec == nil {
			return ErrSignerAIExpiredV1
		}
		// This same locked row cannot grow after its scalar header. Read it before
		// full source; retain it as private credential policy through final commit.
		s.mu.Lock()
		s.signerRecipient = rec
		s.mu.Unlock()
		return nil
	}, nil, true)
	if err != nil {
		return nil, nil, err
	}
	snapshot, release, err := r.borrowHTMLRevisionSourceV1(ctx)
	if err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	if !s.validV1(ctx) || s.closeAfterProvider || s.snapshot != nil {
		s.mu.Unlock()
		release()
		return nil, nil, ErrDocumentAIAuditV1
	}
	s.snapshot, s.release = snapshot, release
	err = s.checkSignerV1(ctx)
	rec := s.signerRecipient
	s.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	// A detached row copy prevents the external original-policy check replacing
	// the actual private source/credential pins retained by the producer.
	copy := *rec
	return models.Document, &copy, nil
}
func (c *ApplicationDocumentAICostV1) usageHeaderV1(ctx context.Context, u *ApplicationDocumentAIUsageReceiptV1) (*generated.GetDocumentAIUsageHeaderV1Row, error) {
	p := c.session.state
	if u.dispatch.signer == nil {
		return c.queries.GetDocumentAIUsageHeaderV1(ctx, generated.GetDocumentAIUsageHeaderV1Params{RequestEventID: u.request.id, OrgID: p.org, DocumentID: p.document, ActorUserID: u.dispatch.actor})
	}
	h, err := c.queries.GetSignerAIUsageHeaderV1(ctx, generated.GetSignerAIUsageHeaderV1Params{RequestEventID: u.request.id, OrgID: p.org, DocumentID: p.document, RecipientID: u.dispatch.signer.recipient})
	return (*generated.GetDocumentAIUsageHeaderV1Row)(h), err
}
func (c *ApplicationDocumentAICostV1) usageBodyV1(ctx context.Context, u *ApplicationDocumentAIUsageReceiptV1, h *generated.GetDocumentAIUsageHeaderV1Row) (*generated.AiCompletionAudit, error) {
	p := c.session.state
	if u.dispatch.signer == nil {
		return c.queries.ReadDocumentAIUsageV1(ctx, generated.ReadDocumentAIUsageV1Params{RequestEventID: u.request.id, OrgID: p.org, DocumentID: p.document, ActorUserID: u.dispatch.actor, ExpectedCreatedAt: h.CreatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	}
	return c.queries.ReadSignerAIUsageV1(ctx, generated.ReadSignerAIUsageV1Params{RequestEventID: u.request.id, OrgID: p.org, DocumentID: p.document, RecipientID: u.dispatch.signer.recipient, ExpectedCreatedAt: h.CreatedAt, ExpectedRawTextBytes: h.RawTextBytes})
}

func (w *ApplicationDocumentAIWorkV1) NewSignerRequestAuditV1(ctx context.Context, clarifier bool) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.signer == nil || s.snapshot == nil || s.policy == nil || s.requested || s.closeAfterProvider {
		s.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	if err := s.checkSignerV1(ctx); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	purpose := HTMLAuditSignerAIRequestedV1
	if clarifier {
		if s.clarifierRequested {
			s.mu.Unlock()
			return nil, ErrDocumentAIAuditV1
		}
		s.clarifierRequested = true
		purpose = HTMLAuditSignerClarifierRequestedV1
	} else {
		if !s.clarifierRequested {
			s.mu.Unlock()
			return nil, ErrDocumentAIAuditV1
		}
		s.requested = true
	}
	s.auditActive++
	scope := &applicationDocumentAIAuditScopeV1{work: s, purpose: purpose, signer: s.signer}
	payload := map[string]any{"via": "signer", "tool": "clarify_clause", "block_id": s.signer.block, "locale": s.signer.locale}
	err := s.signer.notice.BindAuditPayload(payload)
	s.mu.Unlock()
	defer s.finishAuditV1()
	if err != nil {
		return nil, err
	}
	return scope.newEventV1(ctx, s.signer.ip, s.signer.ua, payload)
}
func (w *ApplicationDocumentAIWorkV1) NewSignerAnswerAuditV1(ctx context.Context, r *ApplicationDocumentAIRequestReceiptV1, shield bool, latency, input, output int) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.state == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	if !s.validV1(ctx) || s.signer == nil || s.snapshot == nil || s.result || s.requested || !s.requestMatchesV1(r) {
		s.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	if err := s.checkSignerV1(ctx); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	s.result = true
	s.auditActive++
	scope := &applicationDocumentAIAuditScopeV1{work: s, purpose: HTMLAuditSignerClarifierAnsweredV1, signer: s.signer}
	payload := map[string]any{"via": "signer", "tool": "clarify_clause", "request_event_id": r.id.String(), "block_id": s.signer.block, "locale": s.signer.locale, "shield_active": shield, "latency_ms": latency, "input_tokens": input, "output_tokens": output}
	err := s.signer.notice.BindAuditPayload(payload)
	s.mu.Unlock()
	defer s.finishAuditV1()
	if err != nil {
		return nil, err
	}
	return scope.newEventV1(ctx, s.signer.ip, s.signer.ua, payload)
}

// Clone metadata while its genuine owner remains held; no caller supplied
// payload or arbitrary audit kind can enter the fixed signer producers.
func (h *ApplicationSignerAIRequestV1) MetadataV1() (string, string, error) {
	if h == nil || h.state == nil {
		return "", "", ErrDocumentAIAuditV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired {
		return "", "", ErrDocumentAIAuditV1
	}
	return strings.Clone(s.ip), strings.Clone(s.ua), nil
}
func (s *applicationDocumentAIAuditScopeV1) signerPayloadMatchesV1(p HTMLAuditPurposeV1, m map[string]any) bool {
	h := s.signerRequestV1()
	signerPurpose := p == HTMLAuditSignerAIRequestedV1 || p == HTMLAuditSignerClarifierRequestedV1 || p == HTMLAuditSignerAICompletedV1 || p == HTMLAuditSignerClarifierAnsweredV1
	if h == nil {
		return !signerPurpose
	}
	if !signerPurpose || m["via"] != "signer" || m["tool"] != "clarify_clause" || m["notice_schema"] != h.notice.Schema || m["notice_digest"] != h.notice.Digest {
		return false
	}
	snapshot, ok := m["notice_snapshot"].(article13.Snapshot)
	if !ok || snapshot != h.notice.Snapshot {
		return false
	}
	expected := 7
	if p == HTMLAuditSignerAICompletedV1 {
		expected = 14
	} else {
		if m["block_id"] != h.block || m["locale"] != h.locale {
			return false
		}
		if p == HTMLAuditSignerClarifierAnsweredV1 {
			expected = 12
		}
	}
	return len(m) == expected
}
