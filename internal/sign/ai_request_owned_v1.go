// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgtype"
	"io"
	"sync"
	"unsafe"
)

// Copies share one private original-policy consumer. The fixed native request
// owns its concrete bridge class before either shell/state is allocated.
type SignerAIRequestV1 struct{ state *signerAIRequestStateV1 }
type signerAIRequestStateV1 struct {
	mu       sync.Mutex
	native   *pdfadmission.ApplicationSignerAIRequestV1
	original *RecipientContext
	issuer   *Engine
	notice   Article13NoticeEvidence
	finish   func()
	active   int
	closed   bool
}

func (e *Engine) NewSignerAIRequestV1(ctx context.Context, rc *RecipientContext, notice Article13NoticeEvidence, ip, ua string) (*SignerAIRequestV1, error) {
	if e == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || 4*(unsafe.Sizeof(SignerAIRequestV1{})+unsafe.Sizeof(signerAIRequestStateV1{})) > pdfadmission.SignerAIBridgeControlBytesV1 {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			finish()
		}
	}()
	if original.presentedCredential == nil || !original.presentedCredential.matchesContextV1(original) {
		return nil, ErrMagicLinkExpired
	}
	if err = validateNoticeEvidence(original, notice); err != nil {
		return nil, err
	}
	if err = original.presentedCredential.originalLiveV1(e.now()); err != nil {
		return nil, err
	}
	native, err := e.WorkRuntime.SessionsV1().NewSignerAIRequestV1(ctx, rc.readLease.reader, notice, ip, ua)
	if err != nil {
		return nil, err
	}
	keep = true
	return &SignerAIRequestV1{state: &signerAIRequestStateV1{native: native, original: original, issuer: e, notice: notice, finish: finish}}, nil
}
func (h *SignerAIRequestV1) NativeV1() (*pdfadmission.ApplicationSignerAIRequestV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.native == nil || s.original == nil || s.issuer == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	return s.native, nil
}
func (h *SignerAIRequestV1) WithBodyV1(ctx context.Context, body io.Reader, decode func(io.Reader) error) error {
	n, err := h.NativeV1()
	if err != nil {
		return err
	}
	return n.WithBodyV1(ctx, body, decode)
}
func (h *SignerAIRequestV1) CaptureInputV1(ctx context.Context, block, locale, selection, question string) error {
	n, err := h.NativeV1()
	if err != nil {
		return err
	}
	return n.CaptureInputV1(ctx, block, locale, selection, question)
}
func (s *signerAIRequestStateV1) retireLockedV1() func() {
	if !s.closed || s.active != 0 {
		return nil
	}
	finish := s.finish
	s.finish = nil
	s.original = nil
	s.issuer = nil
	s.notice = Article13NoticeEvidence{}
	return finish
}
func (h *SignerAIRequestV1) RecheckV1(ctx context.Context, doc *generated.Document, rec *generated.Recipient) error {
	if h == nil || h.state == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.original == nil || s.native == nil || s.issuer == nil {
		s.mu.Unlock()
		return ErrSigningAdmissionUnavailableV1
	}
	s.active++
	original, issuer, notice := s.original, s.issuer, s.notice
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		finish := s.retireLockedV1()
		s.mu.Unlock()
		if finish != nil {
			finish()
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	now := issuer.now()
	for _, d := range []pgtype.Timestamptz{original.Recipient.MagicTokenExpiresAt, original.Document.ExpiresAt} {
		if d.Valid && now.After(d.Time) {
			return ErrMagicLinkExpired
		}
	}
	if err := ValidateLockedRecipientCredential(original, rec, doc, now); err != nil {
		return err
	}
	return ValidateLockedNoticeEvidence(original, doc, notice)
}
func (h *SignerAIRequestV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	n := s.native
	s.native = nil
	finish := s.retireLockedV1()
	s.mu.Unlock()
	if n != nil {
		n.CloseConsumerV1()
	}
	if finish != nil {
		finish()
	}
}
