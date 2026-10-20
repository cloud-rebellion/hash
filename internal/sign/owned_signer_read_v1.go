// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"sync"
	"time"
)

type signerContextQueriesV1 interface {
	GetRecipientByTokenHash(context.Context, []byte) (*generated.GetRecipientByTokenHashRow, error)
	GetDocument(context.Context, generated.GetDocumentParams) (*generated.Document, error)
	GetDocumentLawfulBasisConfirmation(context.Context, generated.GetDocumentLawfulBasisConfirmationParams) (*generated.DocumentLawfulBasisConfirmation, error)
	GetOrg(context.Context, uuid.UUID) (*generated.Org, error)
}

// This adapter contains only the actual charged models returned by the native
// reader. It neither executes SQL nor substitutes an incomplete legal model.
type signerReadQueriesV1 struct {
	models *pdfadmission.ApplicationSignerReadModelsV1
}

func (q signerReadQueriesV1) GetRecipientByTokenHash(_ context.Context, hash []byte) (*generated.GetRecipientByTokenHashRow, error) {
	if q.models == nil || q.models.Recipient == nil || len(hash) != sha256.Size || !bytes.Equal(hash, q.models.Recipient.MagicTokenHash) {
		return nil, ErrMagicLinkExpired
	}
	return q.models.Recipient, nil
}
func (q signerReadQueriesV1) GetDocument(_ context.Context, p generated.GetDocumentParams) (*generated.Document, error) {
	if q.models == nil || q.models.Document == nil || q.models.Document.ID != p.ID || q.models.Document.OrgID != p.OrgID {
		return nil, ErrMagicLinkExpired
	}
	return q.models.Document, nil
}
func (q signerReadQueriesV1) GetDocumentLawfulBasisConfirmation(_ context.Context, p generated.GetDocumentLawfulBasisConfirmationParams) (*generated.DocumentLawfulBasisConfirmation, error) {
	if q.models == nil || q.models.LawfulBasisConfirmation == nil || q.models.LawfulBasisConfirmation.DocumentID != p.DocumentID || q.models.LawfulBasisConfirmation.OrgID != p.OrgID {
		return nil, ErrSignerLawfulBasisUnavailable
	}
	return q.models.LawfulBasisConfirmation, nil
}
func (q signerReadQueriesV1) GetOrg(_ context.Context, org uuid.UUID) (*generated.Org, error) {
	if q.models == nil || q.models.ControllerOrg == nil || q.models.ControllerOrg.ID != org {
		return nil, ErrSignerControllerUnavailable
	}
	return q.models.ControllerOrg, nil
}

type signerReadLeaseV1 struct {
	mu                      sync.Mutex
	issuer                  *Engine
	diagnosticRoute         pdfadmission.SignerReadDiagnosticRouteV1
	scope                   *pdfadmission.ApplicationSignerScopeV1
	reader                  *pdfadmission.ApplicationSignerReaderV1
	mode                    pdfadmission.SignerReadModeV1
	original                *RecipientContext
	blockSignatureRequests  []*pdfadmission.ApplicationBlockSignatureRequestV1
	acknowledgementRequests []*pdfadmission.ApplicationAcknowledgementRequestV1
	packageResponseRequests []*pdfadmission.ApplicationPackageResponseRequestV1
	signerViewRequests      []*pdfadmission.ApplicationSignerViewRequestV1
	signerFieldsRequests    []*pdfadmission.ApplicationSignerFieldsRequestV1
	signerFieldsOperations  []*ownedSignerFieldsOperationV1
	historicalPublication   *ownedHistoricalFinalizationPublicationV1
	finalizationInput       *ownedHistoricalFinalizationSourceV1
	current                 *htmlmaterialization.CurrentReadProjectionV1
	closed                  bool
	borrowers               int
	cleanupRunning          bool
}

func cloneSignerReadContextV1(rc *RecipientContext) *RecipientContext {
	out := *rc
	out.readLease = nil
	if rc.Document != nil {
		d := *rc.Document
		d.BlocksJson = bytes.Clone(d.BlocksJson)
		d.VariablesJson = bytes.Clone(d.VariablesJson)
		d.Metadata = bytes.Clone(d.Metadata)
		d.MetadataRedactionReport = bytes.Clone(d.MetadataRedactionReport)
		d.HtmlSourceJson = bytes.Clone(d.HtmlSourceJson)
		d.HtmlCurrentSourceJson = bytes.Clone(d.HtmlCurrentSourceJson)
		d.RenderedPdfSha = bytes.Clone(d.RenderedPdfSha)
		d.PdfSha256 = bytes.Clone(d.PdfSha256)
		d.FinalPdfSha = bytes.Clone(d.FinalPdfSha)
		d.AuditPayloadSha256 = bytes.Clone(d.AuditPayloadSha256)
		d.AuditSignatureSha256 = bytes.Clone(d.AuditSignatureSha256)
		d.AuditCertSha256 = bytes.Clone(d.AuditCertSha256)
		d.HtmlReviewedPdfSha256 = bytes.Clone(d.HtmlReviewedPdfSha256)
		d.FitsIndexSha256 = bytes.Clone(d.FitsIndexSha256)
		out.Document = &d
	}
	if rc.Recipient != nil {
		r := *rc.Recipient
		r.MagicTokenHash = bytes.Clone(r.MagicTokenHash)
		out.Recipient = &r
	}
	if rc.ControllerOrg != nil {
		o := *rc.ControllerOrg
		out.ControllerOrg = &o
	}
	if rc.LawfulBasisConfirmation != nil {
		c := *rc.LawfulBasisConfirmation
		out.LawfulBasisConfirmation = &c
	}
	return &out
}
func checkSignerReadExpiryV1(recipient, document pgtype.Timestamptz, now time.Time) error {
	if recipient.Valid && !recipient.Time.IsZero() && now.After(recipient.Time) {
		return ErrMagicLinkExpired
	}
	if document.Valid && !document.Time.IsZero() && now.After(document.Time) {
		return ErrMagicLinkExpired
	}
	return nil
}
func signerReadPreflightV1(mode pdfadmission.SignerReadModeV1, now time.Time, a pdfadmission.ApplicationSignerReadAccessV1) error {
	if mode == pdfadmission.SignerReadCompletedV1 {
		if !a.CompletedCeremony || !a.CompletedRecipient || !a.RecipientExpiresAt.Valid || a.RecipientExpiresAt.Time.IsZero() || !now.Before(a.RecipientExpiresAt.Time) {
			return ErrCompletedArtifactUnavailable
		}
		return nil
	}
	if err := checkSignerReadExpiryV1(a.RecipientExpiresAt, a.DocumentExpiresAt, now); err != nil {
		return err
	}
	if !a.ActiveCeremony {
		return ErrDocumentNotSignable
	}
	return nil
}
func signerReadErrorV1(err error) error {
	if errors.Is(err, pdfadmission.ErrSignerReadCredentialV1) {
		return errors.New("invalid magic link")
	}
	if errors.Is(err, pdfadmission.ErrSignerReadLawfulBasisV1) {
		return ErrSignerLawfulBasisUnavailable
	}
	if errors.Is(err, pdfadmission.ErrSignerReadV1) || errors.Is(err, pdfadmission.ErrApplicationSessionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return err
}
func (e *Engine) LookupByToken(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerV1(ctx, hash, pdfadmission.SignerReadActiveV1)
}
func (e *Engine) LookupCompletedArtifactByToken(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerV1(ctx, hash, pdfadmission.SignerReadCompletedV1)
}

func (e *Engine) LookupCompletedAuditCertificateByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	rc, err := e.LookupCompletedArtifactByToken(ctx, hash)
	if err != nil {
		return nil, err
	}
	if !completedAuditCertificatePinsV1(rc.Document) {
		if closeErr := rc.CloseReadV1(); closeErr != nil {
			return nil, errors.Join(ErrCompletedArtifactUnavailable, ErrSigningAdmissionUnavailableV1, closeErr)
		}
		return nil, ErrCompletedArtifactUnavailable
	}
	return rc, nil
}

// Fixed response entrypoints retain ordinary Active authorization and complete
// models, but do not capture mutation-only source copies. Diagnostic routes
// remain observations, separate from this explicit materialization purpose.
func (e *Engine) LookupSignerFieldsByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerPurposeRouteV1(ctx, hash, pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadActiveResponseV1, pdfadmission.SignerReadDiagnosticFieldsV1)
}

// LookupSignerPDFByTokenV1 uses the same active-read policy and original
// reader lifetime, with no unused mutation-only signing snapshot.
func (e *Engine) LookupSignerPDFByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerPurposeRouteV1(ctx, hash, pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadActiveResponseV1, pdfadmission.SignerReadDiagnosticPDFV1)
}

// LookupSignerCommentsByTokenV1 preserves the existing active lookup and
// lifetime; its native response producer owns no mutation-only source snapshot.
func (e *Engine) LookupSignerCommentsByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerPurposeRouteV1(ctx, hash, pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadActiveResponseV1, pdfadmission.SignerReadDiagnosticCommentsV1)
}

// LookupSignerViewByTokenV1 keeps original active authorization and lifetime;
// its fixed route distinguishes the view-confirmation access read only.
func (e *Engine) LookupSignerViewByTokenV1(ctx context.Context, hash []byte) (*RecipientContext, error) {
	return e.lookupOwnedSignerRouteV1(ctx, hash, pdfadmission.SignerReadActiveV1, pdfadmission.SignerReadDiagnosticViewV1)
}

// LogSignerViewRefusalV1 observes an actual failed view mutation while the
// original successful read still owns its frame. It performs no SQL/admission
// and does not claim a particular mutation resource or failure cause.
func (e *Engine) LogSignerViewRefusalV1(ctx context.Context, rc *RecipientContext) {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil {
		return
	}
	lease := rc.readLease
	_, _, finishOriginal, err := lease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return
	}
	defer finishOriginal()
	lease.mu.Lock()
	reader, route := lease.reader, lease.diagnosticRoute
	lease.mu.Unlock()
	if route != pdfadmission.SignerReadDiagnosticViewV1 || reader == nil {
		return
	}
	reader.LogRefusalV1(ctx, route, pdfadmission.SignerReadDiagnosticViewMutationV1, pdfadmission.SignerReadDiagnosticViewMutationPhaseV1)
}

func (e *Engine) lookupOwnedSignerV1(ctx context.Context, hash []byte, mode pdfadmission.SignerReadModeV1) (rc *RecipientContext, retErr error) {
	return e.lookupOwnedSignerRouteV1(ctx, hash, mode, pdfadmission.SignerReadDiagnosticOtherV1)
}
func (e *Engine) lookupOwnedSignerRouteV1(ctx context.Context, hash []byte, mode pdfadmission.SignerReadModeV1, route pdfadmission.SignerReadDiagnosticRouteV1) (rc *RecipientContext, retErr error) {
	return e.lookupOwnedSignerPurposeRouteV1(ctx, hash, mode, mode, route)
}

func (e *Engine) lookupOwnedSignerPurposeRouteV1(ctx context.Context, hash []byte, mode, nativeMode pdfadmission.SignerReadModeV1, route pdfadmission.SignerReadDiagnosticRouteV1) (rc *RecipientContext, retErr error) {
	// A diagnostic label can never select policy or materialization. Rechecks
	// have their own constructor path; unknown and crossed lookup purposes fail
	// before even probing the credential scope.
	if (mode != pdfadmission.SignerReadActiveV1 && mode != pdfadmission.SignerReadCompletedV1) ||
		(nativeMode != mode && !(mode == pdfadmission.SignerReadActiveV1 && nativeMode == pdfadmission.SignerReadActiveResponseV1)) {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, pdfadmission.ErrSignerReadV1)
	}
	if ctx == nil || e == nil || len(hash) != sha256.Size {
		return nil, errors.New("invalid magic link")
	}
	var presentedHash [sha256.Size]byte
	copy(presentedHash[:], hash)
	if e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	owned, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	factory := e.WorkRuntime.SessionsV1()
	scope, err := factory.ProbeSignerScopeForRouteV1(owned, presentedHash[:], route)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid magic link")
		}
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	reader, err := factory.NewSignerReaderV1(owned, scope, nativeMode)
	keep := false
	defer func() {
		if !keep {
			if reader != nil {
				reader.CloseConsumerV1()
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				_ = reader.CloseV1(cleanup)
				stop()
			}
			scope.CloseConsumerV1()
		}
	}()
	phase := pdfadmission.SignerReadDiagnosticOpenV1
	defer func() {
		if errors.Is(retErr, ErrSigningAdmissionUnavailableV1) && reader != nil {
			reader.LogRefusalV1(owned, route, pdfadmission.SignerReadDiagnosticLookupV1, phase)
		} else if errors.Is(retErr, ErrSigningAdmissionUnavailableV1) && reader == nil {
			scope.LogReaderConstructionRefusalV1(owned, route, pdfadmission.SignerReadDiagnosticLookupV1, retErr)
		}
	}()
	if err != nil {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	var current *htmlmaterialization.CurrentReadProjectionV1
	phase = pdfadmission.SignerReadDiagnosticModelsV1
	err = reader.WithModelsV1(owned, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
		return signerReadPreflightV1(mode, e.now(), a)
	}, func(actual context.Context, models *pdfadmission.ApplicationSignerReadModelsV1) error {
		q := signerReadQueriesV1{models: models}
		var err error
		if mode == pdfadmission.SignerReadActiveV1 {
			rc, err = e.lookupByTokenQueriesV1(actual, presentedHash[:], q)
		} else {
			rc, err = e.lookupCompletedArtifactQueriesV1(actual, presentedHash[:], q)
		}
		current = models.Current
		return err
	})
	if err != nil {
		return nil, signerReadErrorV1(err)
	}
	phase = pdfadmission.SignerReadDiagnosticCommitV1
	if err := reader.CommitReadV1(owned); err != nil {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	phase = pdfadmission.SignerReadDiagnosticCloseSQLV1
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = reader.CloseSQLV1(cleanup)
	stop()
	if err != nil {
		return nil, errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if mode == pdfadmission.SignerReadActiveV1 {
		err = ValidateRecipientReadCredential(rc, rc, e.now())
	} else {
		err = checkCompletedArtifactObservation(rc, rc, e.now())
	}
	if err != nil {
		return nil, err
	}
	if err := owned.Err(); err != nil {
		return nil, err
	}
	rc.readLease = &signerReadLeaseV1{issuer: e, diagnosticRoute: route, scope: scope, reader: reader, mode: mode, original: cloneSignerReadContextV1(rc), current: current}
	keep = true
	return rc, nil
}

// CloseReadV1 ends the retained result consumer after its LAST response or
// operation use. Context cancellation alone never closes this ownership. Fresh
// bounded cleanup uses the actual owner/fence/registry; uncertainty stays held.
func (rc *RecipientContext) CloseReadV1() error {
	if rc == nil || rc.readLease == nil {
		return nil
	}
	return rc.readLease.closeV1()
}
func (l *signerReadLeaseV1) closeV1() error {
	l.mu.Lock()
	l.closed = true
	if l.borrowers != 0 || l.cleanupRunning {
		l.mu.Unlock()
		return ErrSigningAdmissionUnavailableV1
	}
	l.cleanupRunning = true
	reader, scope := l.reader, l.scope
	requests := l.blockSignatureRequests
	acknowledgementRequests := l.acknowledgementRequests
	packageResponseRequests := l.packageResponseRequests
	l.packageResponseRequests = nil
	l.acknowledgementRequests = nil
	signerViewRequests := l.signerViewRequests
	l.signerViewRequests = nil
	signerFieldsRequests, signerFieldsOperations := l.signerFieldsRequests, l.signerFieldsOperations
	l.signerFieldsRequests, l.signerFieldsOperations = nil, nil
	publication := l.historicalPublication
	input := l.finalizationInput
	l.finalizationInput = nil
	l.historicalPublication = nil
	l.blockSignatureRequests = nil
	l.original = nil
	l.current = nil
	l.mu.Unlock()
	for _, request := range requests {
		request.CloseConsumerV1()
	}
	for _, request := range packageResponseRequests {
		request.CloseConsumerV1()
	}
	for _, request := range acknowledgementRequests {
		request.CloseConsumerV1()
	}
	for _, request := range signerViewRequests {
		request.CloseConsumerV1()
	}
	for _, request := range signerFieldsRequests {
		request.CloseConsumerV1()
	}
	var fieldsErr error
	for _, operation := range signerFieldsOperations {
		fieldsErr = errors.Join(fieldsErr, operation.closeV1())
	}
	// The logical original consumer ends only after every actual recheck that
	// borrowed its frozen body has joined; cancellation alone cannot end it.
	if reader != nil {
		reader.CloseConsumerV1()
	}
	if scope != nil {
		scope.CloseConsumerV1()
	}
	publicationErr := fieldsErr
	if input != nil {
		publicationErr = errors.Join(publicationErr, input.closeV1())
	}
	if publication != nil {
		publicationErr = errors.Join(publicationErr, publication.closeV1())
	}
	var err error
	if reader == nil {
		err = ErrSigningAdmissionUnavailableV1
	} else {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = reader.CloseV1(cleanup)
		cancel()
	}
	l.mu.Lock()
	l.cleanupRunning = false
	l.mu.Unlock()
	return errors.Join(err, publicationErr)
}
func (l *signerReadLeaseV1) borrowOriginalV1(e *Engine, rc *RecipientContext, mode pdfadmission.SignerReadModeV1) (*RecipientContext, *pdfadmission.ApplicationSignerScopeV1, func(), error) {
	if l == nil {
		return nil, nil, nil, ErrSigningAdmissionUnavailableV1
	}
	l.mu.Lock()
	if l.closed || l.issuer != e || l.mode != mode || l.original == nil || l.scope == nil || !reflect.DeepEqual(l.original.Document, rc.Document) || !reflect.DeepEqual(l.original.Recipient, rc.Recipient) || !reflect.DeepEqual(l.original.ControllerOrg, rc.ControllerOrg) || !reflect.DeepEqual(l.original.LawfulBasisConfirmation, rc.LawfulBasisConfirmation) {
		l.mu.Unlock()
		return nil, nil, nil, ErrMagicLinkExpired
	}
	original, scope := l.original, l.scope
	l.borrowers++
	l.mu.Unlock()
	var once sync.Once
	return original, scope, func() {
		once.Do(func() {
			l.mu.Lock()
			l.borrowers--
			finish := l.closed && l.borrowers == 0
			l.mu.Unlock()
			if finish {
				_ = l.closeV1()
			}
		})
	}, nil
}

// ValidateReadMaterializationV1 uses the charged actual current projection and
// the SAME pure checks as full Current. It performs no unadmitted history read.
func (rc *RecipientContext) ValidateReadMaterializationV1() error {
	if rc == nil || rc.Document == nil || rc.readLease == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	l := rc.readLease
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrSigningAdmissionUnavailableV1
	}
	if len(rc.Document.HtmlSourceJson) == 0 {
		return htmlsource.Validate(rc.Document, false)
	}
	return htmlmaterialization.ValidateCurrentReadProjectionV1(rc.Document, l.current)
}

// RecheckRecipientReadV1 retains actual new parent/recipient/controller/cache
// locks through the original source/notice callback, read commit and final
// original deadlines. It reuses the captured opaque scope, never a new token
// identity/expiry or an independently constructed process runtime.
func (e *Engine) RecheckRecipientReadV1(ctx context.Context, rc *RecipientContext, check func(*RecipientContext) error) (retErr error) {
	if rc == nil || rc.readLease == nil || e == nil || ctx == nil || check == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	original, scope, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return err
	}
	defer finishOriginal()
	if err := ValidateRecipientReadCredential(original, original, time.Now()); err != nil {
		return err
	}
	owned, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// This fresh reader validates current access and source only. The original
	// lease retains its actual signing/mutation source for its own consumers.
	reader, err := e.WorkRuntime.SessionsV1().NewSignerReaderV1(owned, scope, pdfadmission.SignerReadActiveRecheckV1)
	if reader != nil {
		defer func() {
			reader.CloseConsumerV1()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			_ = reader.CloseV1(cleanup)
			stop()
		}()
	}
	phase := pdfadmission.SignerReadDiagnosticOpenV1
	defer func() {
		if errors.Is(retErr, ErrSigningAdmissionUnavailableV1) && reader != nil {
			reader.LogRefusalV1(owned, rc.readLease.diagnosticRoute, pdfadmission.SignerReadDiagnosticRecheckV1, phase)
		} else if errors.Is(retErr, ErrSigningAdmissionUnavailableV1) && reader == nil {
			scope.LogReaderConstructionRefusalV1(owned, rc.readLease.diagnosticRoute, pdfadmission.SignerReadDiagnosticRecheckV1, retErr)
		}
	}()
	if err != nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	phase = pdfadmission.SignerReadDiagnosticModelsV1
	var fresh *RecipientContext
	err = reader.WithModelsV1(owned, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
		return signerReadPreflightV1(pdfadmission.SignerReadActiveV1, time.Now(), a)
	}, func(actual context.Context, models *pdfadmission.ApplicationSignerReadModelsV1) error {
		// A fresh read-only issuer borrows only the clock. It owns no process mutex,
		// journal, runtime, transaction or mutation capability.
		lookup := &Engine{Now: e.Now}
		var err error
		fresh, err = lookup.lookupByTokenQueriesV1(actual, original.Recipient.MagicTokenHash, signerReadQueriesV1{models: models})
		if err != nil {
			return signerReadErrorV1(err)
		}
		if err := ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
			return err
		}
		if len(fresh.Document.HtmlSourceJson) > 0 {
			if err := htmlmaterialization.ValidateCurrentReadProjectionV1(fresh.Document, models.Current); err != nil {
				return err
			}
		} else if err := htmlsource.Validate(fresh.Document, false); err != nil {
			return err
		}
		if err := check(fresh); err != nil {
			return err
		}
		return ValidateRecipientReadCredential(original, fresh, time.Now())
	})
	if err != nil {
		return signerReadErrorV1(err)
	}
	phase = pdfadmission.SignerReadDiagnosticCommitV1
	if err := reader.CommitReadV1(owned); err != nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if err := ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
		return err
	}
	phase = pdfadmission.SignerReadDiagnosticCloseSQLV1
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = reader.CloseSQLV1(cleanup)
	stop()
	if err != nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if err := ValidateRecipientReadCredential(original, fresh, time.Now()); err != nil {
		return err
	}
	return owned.Err()
}
func (e *Engine) recheckCompletedOwnedV1(ctx context.Context, hash []byte, rc *RecipientContext, certificate bool) error {
	observe := checkCompletedArtifactObservation
	if certificate {
		observe = checkCompletedAuditCertificateObservationV1
	}
	return e.recheckCompletedObservationOwnedV1(ctx, hash, rc, observe)
}
func (e *Engine) recheckCompletedObservationOwnedV1(ctx context.Context, hash []byte, rc *RecipientContext, observe func(*RecipientContext, *RecipientContext, time.Time) error) error {
	if e == nil || ctx == nil || rc == nil || rc.readLease == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrCompletedArtifactUnavailable
	}
	if len(hash) != sha256.Size {
		return ErrCompletedArtifactUnavailable
	}
	var presentedHash [sha256.Size]byte
	copy(presentedHash[:], hash)
	original, scope, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadCompletedV1)
	if err != nil {
		return err
	}
	defer finishOriginal()
	if !bytes.Equal(presentedHash[:], original.Recipient.MagicTokenHash) || checkCompletedArtifactAccess(original.Recipient, original.Document, e.now()) != nil {
		return ErrCompletedArtifactUnavailable
	}
	owned, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	reader, err := e.WorkRuntime.SessionsV1().NewSignerReaderV1(owned, scope, pdfadmission.SignerReadCompletedV1)
	if reader != nil {
		defer func() {
			reader.CloseConsumerV1()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			_ = reader.CloseV1(cleanup)
			stop()
		}()
	}
	if err != nil {
		return err
	}
	var fresh *RecipientContext
	err = reader.WithModelsV1(owned, func(a pdfadmission.ApplicationSignerReadAccessV1) error {
		return signerReadPreflightV1(pdfadmission.SignerReadCompletedV1, e.now(), a)
	}, func(actual context.Context, models *pdfadmission.ApplicationSignerReadModelsV1) error {
		lookup := &Engine{Now: e.Now}
		var err error
		fresh, err = lookup.lookupCompletedArtifactQueriesV1(actual, presentedHash[:], signerReadQueriesV1{models: models})
		if err != nil {
			return signerReadErrorV1(err)
		}
		return observe(original, fresh, e.now())
	})
	if err != nil {
		return signerReadErrorV1(err)
	}
	if err := reader.CommitReadV1(owned); err != nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if err := observe(original, fresh, e.now()); err != nil {
		return err
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	err = reader.CloseSQLV1(cleanup)
	stop()
	if err != nil {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	if err := owned.Err(); err != nil {
		return err
	}
	return observe(original, fresh, e.now())
}
