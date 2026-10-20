// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

func (e *Engine) LookupSignerPackageByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerPurposeRouteV1(ctx, hash, pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadActiveResponseV1, pdfadmission.SignerReadDiagnosticPackageV1)
}

type SignerPackageReadResultV1 struct {
	state *signerPackageReadResultStateV1
}
type signerPackageReadResultStateV1 struct {
	mu        sync.Mutex
	self      *signerPackageReadResultStateV1
	body      *pdfadmission.ApplicationSignerPackagePresentationV1
	release   func()
	borrowers int
	closed    bool
}

func (s *signerPackageReadResultStateV1) releaseLockedV1() func() {
	if !s.closed || s.borrowers != 0 {
		return nil
	}
	release := s.release
	s.release = nil
	s.body = nil
	return release
}
func (r *SignerPackageReadResultV1) WithJSONV1(consume func([]byte) error) error {
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
	return body.WithJSONV1(consume)
}
func (r *SignerPackageReadResultV1) CloseConsumerV1() {
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
func packageReadSourceEqualV1(original, fresh *RecipientContext) bool {
	if original == nil || fresh == nil || original.Document == nil || fresh.Document == nil {
		return false
	}
	a, b := original.Document, fresh.Document
	return htmlCeremonyDocumentPinsForV1(a) == htmlCeremonyDocumentPinsForV1(b) && a.SourceKind == b.SourceKind && a.RequiresSignature == b.RequiresSignature && a.IsEnvelope == b.IsEnvelope && a.ParentEnvelopeID == b.ParentEnvelopeID && a.RoutingTier == b.RoutingTier && a.EvidenceVersionPinsRequired == b.EvidenceVersionPinsRequired && a.PdfStorageKey == b.PdfStorageKey && a.PdfStorageVersionID == b.PdfStorageVersionID && bytes.Equal(a.PdfSha256, b.PdfSha256) && a.HtmlCurrentMaterializationID == b.HtmlCurrentMaterializationID && a.HtmlCurrentMaterializationSequence == b.HtmlCurrentMaterializationSequence && a.HtmlCurrentPageCount == b.HtmlCurrentPageCount && a.HtmlEffectiveSourceCommitment == b.HtmlEffectiveSourceCommitment && bytes.Equal(a.HtmlSourceJson, b.HtmlSourceJson) && bytes.Equal(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) && bytes.Equal(a.BlocksJson, b.BlocksJson) && bytes.Equal(a.VariablesJson, b.VariablesJson)
}

// This fixed producer accepts only the genuine original token read lease. Its
// result cannot supply a package identity, query callback, policy witness or key.
func (e *Engine) SignerPackagePresentationV1(ctx context.Context, rc *RecipientContext) (result *SignerPackageReadResultV1, failure error) {
	return e.signerPackagePresentationV1(ctx, rc, false)
}
func (e *Engine) CompletedSignerPackagePresentationV1(ctx context.Context, rc *RecipientContext) (*SignerPackageReadResultV1, error) {
	return e.signerPackagePresentationV1(ctx, rc, true)
}
func (e *Engine) signerPackagePresentationV1(ctx context.Context, rc *RecipientContext, completed bool) (result *SignerPackageReadResultV1, failure error) {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
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
	var native *pdfadmission.ApplicationHTMLSendOperationV1
	var input *pdfadmission.ApplicationSignerPackageReadInputV1
	var finishInput func()
	var body *pdfadmission.ApplicationSignerPackagePresentationV1
	transferred := false
	defer func() {
		if native != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			failure = errors.Join(failure, native.CloseV1(cleanup))
			stop()
		}
		if !transferred {
			if body != nil {
				body.CloseConsumerV1()
			}
			if input != nil {
				input.CloseConsumerV1()
			}
			if finishInput != nil {
				finishInput()
			}
			finishOriginal()
		}
		if failure != nil && result != nil {
			result.CloseConsumerV1()
			result = nil
		}
		if failure != nil {
			if completed && (errors.Is(failure, ErrCompletedArtifactUnavailable) || errors.Is(failure, ErrMagicLinkExpired) || errors.Is(failure, pdfadmission.ErrSignerReadCredentialV1) || !time.Now().Before(original.Recipient.MagicTokenExpiresAt.Time)) {
				failure = errors.Join(ErrCompletedArtifactUnavailable, failure)
			} else {
				failure = errors.Join(ErrSigningAdmissionUnavailableV1, failure)
			}
		}
	}()
	factory := e.WorkRuntime.SessionsV1()
	if completed {
		input, err = factory.NewCompletedSignerPackageReadInputV1(ctx, rc.readLease.reader)
	} else {
		input, err = factory.NewSignerPackageReadInputV1(ctx, rc.readLease.reader)
	}
	if err != nil {
		return nil, err
	}
	native, finishInput, err = factory.NewSignerPackageReadOperationV1(input)
	if err != nil {
		return nil, err
	}
	request := input.ContextV1()
	stage, err := native.OpenSQLV1(pdfadmission.HTMLSignerPackageReadV1)
	if err != nil {
		return nil, err
	}
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		return nil, err
	}
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		state, err := w.StateV1(actual)
		if err != nil {
			return err
		}
		if state.ID != original.Document.ID || state.OrgID != original.Document.OrgID || !presentedStampEqualV1(state.SentAt, original.Document.SentAt) || !presentedStampEqualV1(state.Article13NoticeEpochAt, original.Document.Article13NoticeEpochAt) || state.Article13NoticeEpochV61Committed != original.Document.Article13NoticeEpochV61Committed || (!completed && !state.HasSupportedArticle13NoticeSchema) {
			return ErrMagicLinkExpired
		}
		body, err = w.ReadSignerPackagePresentationV1(actual)
		if err != nil {
			return err
		}
		observation, err := body.ObservationV1()
		if err != nil || observation.DocumentID != original.Document.ID || observation.OrgID != original.Document.OrgID || observation.RecipientID != original.Recipient.ID || !presentedStampEqualV1(observation.SentAt, original.Document.SentAt) || !presentedStampEqualV1(observation.NoticeEpoch, original.Document.Article13NoticeEpochAt) {
			return ErrMagicLinkExpired
		}
		if completed {
			return checkCompletedPackageObservationV1(original, original, time.Now())
		}
		return ValidateRecipientReadCredential(original, original, time.Now())
	})
	if err != nil {
		return nil, err
	}
	if err = session.CommitV1(call); err != nil {
		return nil, err
	}
	if err = stage.CloseSQLV1(); err != nil {
		return nil, err
	}
	producer := native
	native = nil
	producer.EndConsumerV1()
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = producer.CloseV1(cleanup)
	stop()
	if err != nil {
		return nil, err
	}
	if completed {
		err = e.RecheckCompletedPackageByTokenV1(request, original.Recipient.MagicTokenHash, rc)
	} else {
		err = e.RecheckRecipientReadV1(request, rc, func(fresh *RecipientContext) error {
			if !packageReadSourceEqualV1(original, fresh) {
				return ErrMagicLinkExpired
			}
			return nil
		})
	}
	if err != nil {
		return nil, err
	}
	if err = request.Err(); err != nil {
		return nil, err
	}
	state := &signerPackageReadResultStateV1{body: body, release: func() {
		body.CloseConsumerV1()
		input.CloseConsumerV1()
		if finishInput != nil {
			finishInput()
		}
		finishOriginal()
	}}
	state.self = state
	result = &SignerPackageReadResultV1{state: state}
	transferred = true
	return result, nil
}
