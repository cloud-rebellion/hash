// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
)

var (
	ErrSignerPackagePreconditionV1 = errors.New("recipient package precondition changed")
	ErrSignerPackageAbsentV1       = errors.New("recipient package member unavailable")
)

// Copies retain the same native byte owner and original read lease. The
// original scope cannot close underneath an actual HTTP writer.
type SignerPackageMemberPDFResultV1 struct {
	state *signerPackageMemberPDFResultStateV1
}
type signerPackageMemberPDFResultStateV1 struct {
	mu        sync.Mutex
	self      *signerPackageMemberPDFResultStateV1
	body      *pdfadmission.ApplicationSignerPackageMemberReadV1
	release   func()
	borrowers int
	closed    bool
}

func (s *signerPackageMemberPDFResultStateV1) releaseLockedV1() func() {
	if !s.closed || s.borrowers != 0 {
		return nil
	}
	release := s.release
	s.release = nil
	s.body = nil
	return release
}
func (r *SignerPackageMemberPDFResultV1) WithPDFV1(consume func(pdfadmission.SignerPackageMemberPDFMetadataV1, []byte) error) error {
	if r == nil || r.state == nil || consume == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	s := r.state
	s.mu.Lock()
	if s.self != s || s.closed || s.body == nil {
		s.mu.Unlock()
		return ErrSigningAdmissionUnavailableV1
	}
	s.borrowers++
	body := s.body
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.borrowers--
		release := s.releaseLockedV1()
		s.mu.Unlock()
		if release != nil {
			release()
		}
	}()
	entered := false
	err := body.WithPDFV1(func(metadata pdfadmission.SignerPackageMemberPDFMetadataV1, value []byte) error {
		entered = true
		return consume(metadata, value)
	})
	if err != nil && !entered && (errors.Is(err, pdfadmission.ErrSignerPackageMemberReadV1) || errors.Is(err, storage.ErrPackagePDFLocalReadV1)) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return err
}
func (r *SignerPackageMemberPDFResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	if s.self != s {
		s.mu.Unlock()
		return
	}
	s.closed = true
	release := s.releaseLockedV1()
	s.mu.Unlock()
	if release != nil {
		release()
	}
}

// Expected commitments and position are observations only. Every private pin
// comes from the genuine original recipient reader and completed native Send.
func (e *Engine) SignerPackageMemberPDFV1(ctx context.Context, rc *RecipientContext, expected pdfadmission.SignerPackageMemberExpectedV1) (result *SignerPackageMemberPDFResultV1, failure error) {
	return e.signerPackageMemberPDFV1(ctx, rc, expected, false)
}
func (e *Engine) CompletedSignerPackageMemberPDFV1(ctx context.Context, rc *RecipientContext, expected pdfadmission.SignerPackageMemberExpectedV1) (*SignerPackageMemberPDFResultV1, error) {
	return e.signerPackageMemberPDFV1(ctx, rc, expected, true)
}
func (e *Engine) signerPackageMemberPDFV1(ctx context.Context, rc *RecipientContext, expected pdfadmission.SignerPackageMemberExpectedV1, completed bool) (result *SignerPackageMemberPDFResultV1, failure error) {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || expected.Position < 0 || expected.Position > documentpackage.MaxAnnexesV1 {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	client, ok := e.Storage.(*storage.Client)
	if !ok || client == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	mode := pdfadmission.SignerReadActiveV1
	if completed {
		mode = pdfadmission.SignerReadCompletedV1
	}
	original, _, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, mode)
	if err != nil {
		return nil, err
	}
	var native *pdfadmission.ApplicationSignerPackageMemberReadV1
	transferred := false
	defer func() {
		if !transferred {
			if native != nil {
				native.CloseConsumerV1()
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				failure = errors.Join(failure, native.CloseV1(cleanup))
				stop()
			}
			finishOriginal()
		}
		if failure != nil {
			switch {
			case errors.Is(failure, pdfadmission.ErrSignerPackageMemberPreconditionV1):
				failure = errors.Join(ErrSignerPackagePreconditionV1, failure)
			case errors.Is(failure, pdfadmission.ErrSignerPackageMemberAbsentV1):
				failure = errors.Join(ErrSignerPackageAbsentV1, failure)
			case errors.Is(failure, pdfadmission.ErrSignerReadCredentialV1), errors.Is(failure, ErrMagicLinkExpired):
				failure = errors.Join(ErrMagicLinkExpired, failure)
			default:
				failure = errors.Join(ErrSigningAdmissionUnavailableV1, failure)
			}
		}
	}()
	if completed {
		native, err = e.WorkRuntime.SessionsV1().NewCompletedSignerPackageMemberReadV1(ctx, rc.readLease.reader, client, expected)
	} else {
		native, err = e.WorkRuntime.SessionsV1().NewSignerPackageMemberReadV1(ctx, rc.readLease.reader, client, expected)
	}
	if err != nil {
		return nil, err
	}
	if err = native.LoadV1(); err != nil {
		return nil, err
	}
	observed, err := native.ObservationV1()
	identity := observed.Observation
	if err != nil || !identity.PackagePresent || identity.DocumentID != original.Document.ID || identity.OrgID != original.Document.OrgID || identity.RecipientID != original.Recipient.ID || !presentedStampEqualV1(identity.SentAt, original.Document.SentAt) || !presentedStampEqualV1(identity.NoticeEpoch, original.Document.Article13NoticeEpochAt) || observed.Position != expected.Position || identity.Capture.CanonicalSHA256 != expected.ManifestSHA256 || identity.Capture.CommitmentSHA256 != expected.LegalCommitmentSHA256 {
		return nil, ErrMagicLinkExpired
	}
	if completed {
		err = e.RecheckCompletedPackageByTokenV1(ctx, original.Recipient.MagicTokenHash, rc)
	} else {
		err = e.RecheckRecipientReadV1(ctx, rc, func(fresh *RecipientContext) error {
			if !packageReadSourceEqualV1(original, fresh) {
				return ErrMagicLinkExpired
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	state := &signerPackageMemberPDFResultStateV1{body: native, release: func() {
		native.CloseConsumerV1()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := native.CloseV1(cleanup)
		stop()
		if closeErr != nil {
			slog.Warn("recipient package PDF cleanup remains pending")
		}
		finishOriginal()
	}}
	state.self = state
	result = &SignerPackageMemberPDFResultV1{state: state}
	transferred = true
	return result, nil
}
