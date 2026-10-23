// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
)

var ErrSignerReadV1 = errors.New("pdfadmission: owned signer read unavailable")
var ErrSignerReadCredentialV1 = errors.New("pdfadmission: signer read credential changed")
var ErrSignerReadLawfulBasisV1 = errors.New("pdfadmission: signer read lawful basis unavailable")

// Actual fixed scalar header values only. This is neither a partial legal
// model nor authority to return any body; the complete policy still runs.
type ApplicationSignerReadAccessV1 struct {
	DocumentExpiresAt, RecipientExpiresAt                 pgtype.Timestamptz
	ActiveCeremony, CompletedCeremony, CompletedRecipient bool
}
type SignerReadModeV1 string

const (
	SignerReadActiveV1    SignerReadModeV1 = "active-context-v1"
	SignerReadCompletedV1 SignerReadModeV1 = "completed-artifact-v1"
	// Full active policy projections for a fresh read recheck. This purpose
	// owns no signing-source snapshot or mutation-request authority.
	SignerReadActiveRecheckV1 SignerReadModeV1 = "active-recheck-v1"
	// A response lookup retains the same complete active policy models, but
	// does not prepare the separate source copy used only by mutation inputs.
	SignerReadActiveResponseV1 SignerReadModeV1 = "active-response-v1"
)

type ApplicationSignerReadModelsV1 struct {
	Document                *generated.Document
	Recipient               *generated.GetRecipientByTokenHashRow
	ControllerOrg           *generated.Org
	LawfulBasisConfirmation *generated.DocumentLawfulBasisConfirmation
	Current                 *htmlmaterialization.CurrentReadProjectionV1
	AmendmentContext        *amendments.SignerContextV1
	Presign                 *presignexecute.RetainedAssetsV1
}
type ApplicationSignerReaderV1 struct {
	// Only the actual constructor installs this immutable identity. Value
	// copies cannot close the original mutable session/result consumers.
	self                                     *ApplicationSignerReaderV1
	diagnostic                               applicationSignerReadDiagnosticV1
	diagnosticBorrowers                      int
	mu                                       sync.Mutex
	factory                                  *ApplicationSessionFactoryV1
	session                                  *ApplicationSessionV1
	admission                                *ApplicationAdmissionV1
	scope                                    applicationSignerScopeSnapshotV1
	finishScope                              func()
	mode                                     SignerReadModeV1
	consumers                                []func()
	models                                   *ApplicationSignerReadModelsV1
	blockSigningSnapshot                     *applicationBlockSigningReadSnapshotV1
	blockSigningBorrowers                    int
	packageMemberBorrowers                   int
	presignBorrowers                         int
	creating, read, consumerClosed, released bool
}

func (f *ApplicationSessionFactoryV1) NewSignerReaderV1(ctx context.Context, scope *ApplicationSignerScopeV1, mode SignerReadModeV1) (*ApplicationSignerReaderV1, error) {
	if err := signerReaderInputRefusalV1(ctx, mode); err != nil {
		return nil, err
	}
	if f == nil || f.state == nil {
		return nil, ErrApplicationSessionV1
	}
	p := f.state
	p.mu.Lock()
	var rejection error
	switch {
	case p.closing:
		rejection = &signerReaderConstructorRefusalsV1[7]
	case p.signerReaders == nil:
		rejection = &signerReaderConstructorRefusalsV1[8]
	case len(p.signerReaders) >= applicationSessionMaxWorkV1:
		rejection = &signerReaderConstructorRefusalsV1[9]
	}
	if rejection != nil {
		p.mu.Unlock()
		return nil, rejection
	}
	// The original cap gates actual scope borrowing and allocation together.
	// A rejected concurrent constructor cannot allocate an unpriced frame.
	snapshot, finish, err := scope.borrowV1(f)
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	r := &ApplicationSignerReaderV1{factory: f, scope: snapshot, finishScope: finish, mode: mode, creating: true}
	r.self = r
	p.signerReaders[r] = struct{}{}
	p.mu.Unlock()
	h, err := f.openV1(ctx, snapshot.org, snapshot.document, r)
	r.mu.Lock()
	r.session = h
	r.mu.Unlock()
	if err == nil {
		var a *ApplicationAdmissionV1
		a, err = h.NewAdmissionV1(ctx)
		r.mu.Lock()
		r.admission = a
		r.mu.Unlock()
	}
	r.mu.Lock()
	r.creating = false
	if err != nil {
		r.recordModelFailureDiagnosticV1(ctx, err)
	}
	r.mu.Unlock()
	return r, err
}
func (r *ApplicationSignerReaderV1) appendConsumerV1(close func()) {
	// Caller holds r.mu for the complete fixed read callback.
	r.consumers = append(r.consumers, close)
}

// WithModelsV1 is a fixed one-shot model read under actual retained header/body
// loans. It exposes no SQL/transaction or caller-supplied size declarations.
// The trusted callback validates original application policy before read commit.
func (r *ApplicationSignerReaderV1) WithModelsV1(ctx context.Context, preflight func(ApplicationSignerReadAccessV1) error, fn func(context.Context, *ApplicationSignerReadModelsV1) error) error {
	if r == nil || r.self != r || preflight == nil || fn == nil || !applicationContextV1(ctx) {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.creating || r.read || r.consumerClosed || r.released || r.session == nil || r.admission == nil {
		return ErrSignerReadV1
	}
	r.read = true
	r.setModelDiagnosticV1(signerReadModelTransactionV1, signerReadModelSessionErrorV1)
	var policyErr error
	err := r.session.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) (callbackErr error) {
		defer func() {
			if callbackErr != nil {
				r.recordModelFailureDiagnosticV1(owned, callbackErr)
			}
		}()
		r.setModelDiagnosticV1(signerReadModelHeaderAdmissionV1, signerReadModelAdmissionErrorV1)
		headerClose, err := r.session.acquireSignerReadModelsV1(owned, "locked-signer-read-header", 0, 0, r)
		if err != nil {
			return err
		}
		// The scalar header rows are used only inside this callback. Full
		// returned models and immutable signing-source copies own separate loans.
		// Ending consumption here never credits capacity before SQL retirement.
		defer headerClose()
		q := generated.New(db)
		s := r.scope
		r.setModelDiagnosticV1(signerReadModelDocumentHeaderV1, signerReadModelQueryErrorV1)
		dh, err := q.GetSignerDocumentReadHeaderV1(owned, generated.GetSignerDocumentReadHeaderV1Params{DocumentID: s.document, OrgID: s.org})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSignerReadCredentialV1
			}
			return err
		}
		if dh == nil || dh.ID != s.document || dh.OrgID != s.org || dh.ServerVersionNum <= 0 || !dh.UpdatedAt.Valid {
			r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
			return ErrSignerReadV1
		}
		r.setModelDiagnosticV1(signerReadModelRecipientHeaderV1, signerReadModelQueryErrorV1)
		rh, err := q.GetSignerRecipientReadHeaderV1(owned, generated.GetSignerRecipientReadHeaderV1Params{RecipientID: s.recipient, DocumentID: s.document, OrgID: s.org, TokenHash: s.hash[:]})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSignerReadCredentialV1
			}
			return err
		}
		if rh == nil || rh.RecipientID != s.recipient || rh.DocumentID != s.document || rh.OrgID != s.org || !bytes.Equal(rh.MagicTokenHash, s.hash[:]) {
			r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
			return ErrSignerReadV1
		}
		r.setModelDiagnosticV1(signerReadModelPreflightV1, signerReadModelPreflightErrorV1)
		policyErr = preflight(ApplicationSignerReadAccessV1{DocumentExpiresAt: dh.ExpiresAt, RecipientExpiresAt: rh.MagicTokenExpiresAt, ActiveCeremony: dh.IsActiveCeremony, CompletedCeremony: dh.IsCompletedCeremony, CompletedRecipient: rh.IsCompletedRecipient})
		if policyErr != nil {
			return policyErr
		}
		r.setModelDiagnosticV1(signerReadModelMeasurementsV1, signerReadModelMeasurementErrorV1)
		if dh.PolicyMeasurementServerVersionNum != dh.ServerVersionNum || dh.ResponseMeasurementServerVersionNum != dh.ServerVersionNum || dh.ReportMeasurementServerVersionNum != dh.ServerVersionNum {
			return ErrSignerReadV1
		}
		r.setModelDiagnosticV1(signerReadModelTotalsV1, signerReadModelArithmeticErrorV1)
		wire, err := htmlAuthoringSumV1(dh.HtmlOriginWireBytes, dh.HtmlCurrentWireBytes, dh.VariablesWireBytes, dh.BlocksWireBytes, dh.MetadataWireBytes, dh.ReportWireBytes)
		if err != nil {
			return ErrSignerReadV1
		}
		raw, err := htmlAuthoringSumV1(dh.RawTextBytes, rh.RawTextBytes)
		if err != nil {
			return ErrSignerReadV1
		}
		var ch *generated.GetSignerControllerReadHeaderV1Row
		var mh *generated.GetSignerCurrentMaterializationHeaderV1Row
		if r.mode == SignerReadActiveV1 || r.mode == SignerReadActiveRecheckV1 || r.mode == SignerReadActiveResponseV1 {
			r.setModelDiagnosticV1(signerReadModelControllerHeaderV1, signerReadModelQueryErrorV1)
			ch, err = q.GetSignerControllerReadHeaderV1(owned, generated.GetSignerControllerReadHeaderV1Params{DocumentID: s.document, OrgID: s.org})
			if err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrSignerReadLawfulBasisV1
				}
				return err
			}
			if ch == nil || ch.DocumentID != s.document || ch.OrgID != s.org {
				r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
				return ErrSignerReadV1
			}
			r.diagnostic.modelOutcome = signerReadModelArithmeticErrorV1
			controllerRaw, sumErr := htmlAuthoringSumV1(ch.ConfirmationRawTextBytes, ch.OrgRawTextBytes)
			if sumErr != nil {
				return ErrSignerReadV1
			}
			if controllerRaw != ch.RawTextBytes {
				r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
				return ErrSignerReadV1
			}
			r.diagnostic.modelOutcome = signerReadModelArithmeticErrorV1
			raw, err = htmlAuthoringSumV1(raw, controllerRaw)
			if err != nil {
				return ErrSignerReadV1
			}
			if dh.HtmlCurrentWireBytes > 0 {
				r.setModelDiagnosticV1(signerReadModelMaterializationHeaderV1, signerReadModelQueryErrorV1)
				mh, err = q.GetSignerCurrentMaterializationHeaderV1(owned, generated.GetSignerCurrentMaterializationHeaderV1Params{DocumentID: s.document, OrgID: s.org})
				if err != nil {
					return err
				}
				if mh == nil || mh.DocumentID != s.document || mh.OrgID != s.org || mh.MaterializationID == [16]byte{} || mh.SourceWireBytes != dh.HtmlCurrentWireBytes || mh.MeasurementServerVersionNum != dh.ServerVersionNum || mh.ServerVersionNum != dh.ServerVersionNum || (mh.ReportWireUpperBound != 0 && mh.ReportWireUpperBound != 65536) {
					r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
					return ErrSignerReadV1
				}
				r.diagnostic.modelOutcome = signerReadModelArithmeticErrorV1
				raw, err = htmlAuthoringSumV1(raw, mh.RawTextBytes)
				if err != nil {
					return ErrSignerReadV1
				}
				wire, err = htmlAuthoringSumV1(wire, mh.SourceWireBytes, mh.ReportWireUpperBound)
				if err != nil {
					return ErrSignerReadV1
				}
			}
		}
		// The immutable optional relation is measured under the SAME native
		// scalar header loan, then funded by this retained body loan before
		// its name/digest projection is allocated or returned.
		ah, err := r.signerAmendmentHeaderV1(owned, db)
		if err != nil {
			return err
		}
		if ah != nil {
			raw, err = htmlAuthoringSumV1(raw, ah.raw)
			if err != nil {
				return ErrSignerReadV1
			}
			wire, err = htmlAuthoringSumV1(wire, ah.wire)
			if err != nil {
				return ErrSignerReadV1
			}
		}
		r.setModelDiagnosticV1(signerReadModelBodyAdmissionV1, signerReadModelAdmissionErrorV1)
		bodyClose, err := r.session.acquireSignerReadModelsV1(owned, "locked-signer-read-body", raw, wire, r)
		if err != nil {
			return err
		}
		r.appendConsumerV1(bodyClose)
		r.setModelDiagnosticV1(signerReadModelDocumentBodyV1, signerReadModelQueryErrorV1)
		doc, err := q.ReadSignerDocumentV1(owned, generated.ReadSignerDocumentV1Params{DocumentID: s.document, OrgID: s.org, ExpectedUpdatedAt: dh.UpdatedAt, ExpectedHtmlOriginWireBytes: dh.HtmlOriginWireBytes, ExpectedHtmlCurrentWireBytes: dh.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: dh.VariablesWireBytes, ExpectedBlocksWireBytes: dh.BlocksWireBytes, ExpectedMetadataWireBytes: dh.MetadataWireBytes, ExpectedReportWireBytes: dh.ReportWireBytes})
		if err != nil {
			return err
		}
		if doc == nil || doc.ID != s.document || doc.OrgID != s.org || doc.UpdatedAt != dh.UpdatedAt || signerDocumentRawBytesV1(doc) != dh.RawTextBytes || int64(len(doc.HtmlSourceJson)) != dh.HtmlOriginWireBytes || int64(len(doc.HtmlCurrentSourceJson)) != dh.HtmlCurrentWireBytes || int64(len(doc.VariablesJson)) != dh.VariablesWireBytes || int64(len(doc.BlocksJson)) != dh.BlocksWireBytes || int64(len(doc.Metadata)) != dh.MetadataWireBytes || int64(len(doc.MetadataRedactionReport)) != dh.ReportWireBytes {
			r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
			return ErrSignerReadV1
		}
		r.setModelDiagnosticV1(signerReadModelRecipientBodyV1, signerReadModelQueryErrorV1)
		rec, err := q.ReadSignerRecipientV1(owned, generated.ReadSignerRecipientV1Params{RecipientID: s.recipient, DocumentID: s.document, OrgID: s.org, TokenHash: s.hash[:], ExpectedRawTextBytes: rh.RawTextBytes})
		if err != nil {
			return err
		}
		if rec == nil || rec.ID != s.recipient || rec.DocumentID != s.document || rec.DocOrgID != s.org || !bytes.Equal(rec.MagicTokenHash, s.hash[:]) {
			r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
			return ErrSignerReadV1
		}
		recipient := generated.GetRecipientByTokenHashRow(*rec)
		if signerRecipientRawBytesV1(&recipient) != rh.RawTextBytes {
			r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
			return ErrSignerReadV1
		}
		models := &ApplicationSignerReadModelsV1{Document: doc, Recipient: &recipient}
		models.AmendmentContext, err = r.signerAmendmentBodyV1(owned, db, ah, doc)
		if err != nil {
			return err
		}
		if ch != nil {
			r.setModelDiagnosticV1(signerReadModelControllerBodyV1, signerReadModelQueryErrorV1)
			confirmation, err := q.ReadSignerLawfulBasisConfirmationV1(owned, generated.ReadSignerLawfulBasisConfirmationV1Params{DocumentID: s.document, OrgID: s.org, ExpectedRawTextBytes: ch.ConfirmationRawTextBytes})
			if err != nil {
				return err
			}
			org, err := q.ReadSignerControllerV1(owned, generated.ReadSignerControllerV1Params{OrgID: s.org, ExpectedRawTextBytes: ch.OrgRawTextBytes})
			if err != nil {
				return err
			}
			if confirmation == nil || org == nil || confirmation.DocumentID != s.document || confirmation.OrgID != s.org || org.ID != s.org || signerConfirmationRawBytesV1(confirmation) != ch.ConfirmationRawTextBytes || signerOrgRawBytesV1(org) != ch.OrgRawTextBytes {
				r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
				return ErrSignerReadV1
			}
			models.LawfulBasisConfirmation = confirmation
			models.ControllerOrg = org
		}
		if mh != nil {
			r.setModelDiagnosticV1(signerReadModelMaterializationBodyV1, signerReadModelQueryErrorV1)
			m, err := q.ReadSignerCurrentMaterializationV1(owned, generated.ReadSignerCurrentMaterializationV1Params{DocumentID: s.document, OrgID: s.org, ExpectedMaterializationID: mh.MaterializationID, ExpectedSourceWireBytes: mh.SourceWireBytes, ExpectedRawTextBytes: mh.RawTextBytes, ExpectedReportWireUpperBound: mh.ReportWireUpperBound})
			if err != nil {
				return err
			}
			if m == nil || m.ID != mh.MaterializationID || m.DocumentID != s.document || m.OrgID != s.org || int64(len(m.SourceJson)) != mh.SourceWireBytes || int64(len(m.MetadataRedactionReport)) > mh.ReportWireUpperBound || signerMaterializationRawBytesV1(m) != mh.RawTextBytes {
				r.diagnostic.modelOutcome = signerReadModelConsistencyErrorV1
				return ErrSignerReadV1
			}
			models.Current = &htmlmaterialization.CurrentReadProjectionV1{ID: m.ID, DocumentID: m.DocumentID, OrgID: m.OrgID, Sequence: m.Sequence, PageCount: m.PageCount, PdfKey: m.PdfKey, PdfVersionID: m.PdfVersionID, PdfSha256: m.PdfSha256, SourceCommitment: m.SourceCommitment, OriginCommitment: m.OriginCommitment, SourceJson: m.SourceJson, MetadataRedactionReport: m.MetadataRedactionReport}
		}
		models.Presign, err = r.readPresignAssetsV1(owned, db)
		if err != nil {
			return err
		}
		r.setModelDiagnosticV1(signerReadModelBlockSourceV1, signerReadModelBlockSourceErrorV1)
		if err = r.captureBlockSigningSourceV1(owned, models); err != nil {
			return err
		}
		r.models = models
		r.setModelDiagnosticV1(signerReadModelResponsePolicyV1, signerReadModelPolicyErrorV1)
		policyErr = fn(owned, models)
		if policyErr == nil {
			r.setModelDiagnosticV1(signerReadModelTransactionV1, signerReadModelSessionErrorV1)
		}
		return policyErr
	})
	if err != nil && r.diagnostic.errorClass == 0 {
		// The callback did not fail; sample the original caller context here.
		r.recordModelFailureDiagnosticV1(ctx, err)
	}
	if policyErr != nil {
		return policyErr
	}
	if errors.Is(err, ErrSignerReadCredentialV1) || errors.Is(err, ErrSignerReadLawfulBasisV1) {
		return err
	}
	if err != nil {
		return errors.Join(ErrSignerReadV1, err)
	}
	r.setModelDiagnosticV1(0, 0)
	return err
}
func (r *ApplicationSignerReaderV1) CommitReadV1(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	valid := !r.creating && r.read && !r.consumerClosed && !r.released && r.models != nil
	h := r.session
	r.mu.Unlock()
	if !valid || h == nil {
		return ErrSignerReadV1
	}
	return h.CommitV1(ctx)
}
func (r *ApplicationSignerReaderV1) CloseSQLV1(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	h := r.session
	a := r.admission
	creating := r.creating
	r.mu.Unlock()
	if creating {
		return ErrSignerReadV1
	}
	if h != nil {
		if err := h.CloseV1(ctx); err != nil {
			return err
		}
		if !h.RetiredV1() {
			return ErrApplicationSessionUnknownV1
		}
	}
	if a != nil {
		// Reconcile only this original admission after its actual client/backend
		// fence retired. Finished header staging can end; live body/snapshot
		// consumers remain charged and usable through their final response use.
		if _, err := a.ReconcileCleanupV1(ctx); err != nil {
			return err
		}
	}
	return nil
}
func (r *ApplicationSignerReaderV1) CloseConsumerV1() {
	if r == nil || r.self != r {
		return
	}
	r.mu.Lock()
	r.consumerClosed = true
	consumers := r.retireBlockSigningReadConsumersV1()
	r.mu.Unlock()
	for _, close := range consumers {
		close()
	}
}
func (r *ApplicationSignerReaderV1) CloseV1(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if r.self != r {
		return ErrSignerReadV1
	}
	r.CloseConsumerV1()
	if err := r.CloseSQLV1(ctx); err != nil {
		return err
	}
	return r.reconcileV1(ctx)
}
func (r *ApplicationSignerReaderV1) reconcileV1(ctx context.Context) error {
	if r == nil || r.self != r || r.factory == nil || r.factory.state == nil {
		return ErrSignerReadV1
	}
	if !applicationContextV1(ctx) {
		return ErrSignerReadV1
	}
	r.mu.Lock()
	if r.released {
		r.mu.Unlock()
		return nil
	}
	if r.creating || !r.consumerClosed {
		r.mu.Unlock()
		return nil
	}
	if r.blockSigningBorrowers != 0 || r.packageMemberBorrowers != 0 || r.presignBorrowers != 0 || r.diagnosticBorrowers != 0 {
		r.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	h, a := r.session, r.admission
	r.mu.Unlock()
	if h != nil && !h.RetiredV1() {
		return ErrApplicationSessionUnknownV1
	}
	if a != nil {
		if err := a.CloseV1(ctx); err != nil {
			return err
		}
		// Retire this exact closed admission registration as part of its own
		// reader join. A later unrelated operation must not be required to
		// reconcile this finished reader. Reuse the same remaining cleanup
		// context and original physical fence; a stale registry identity or
		// any remaining consumer can never be converted into retirement.
		p := r.factory.state
		p.mu.Lock()
		registration := p.htmlAdmissions[a]
		p.mu.Unlock()
		pending, err := r.factory.reconcileHTMLAdmissionRegistrationV1(ctx, a, registration)
		if err != nil {
			return err
		}
		if pending != 0 {
			return ErrApplicationSessionUnknownV1
		}
	}
	r.mu.Lock()
	if r.released {
		r.mu.Unlock()
		return nil
	}
	r.released = true
	r.diagnostic = applicationSignerReadDiagnosticV1{}
	finish := r.finishScope
	r.finishScope = nil
	p := r.factory.state
	r.scope = applicationSignerScopeSnapshotV1{}
	r.mu.Unlock()
	if finish != nil {
		finish()
	}
	p.mu.Lock()
	delete(p.signerReaders, r)
	p.mu.Unlock()
	return nil
}
func (f *ApplicationSessionFactoryV1) reconcileSignerReadersV1(ctx context.Context) error {
	p := f.state
	p.mu.Lock()
	list := make([]*ApplicationSignerReaderV1, 0, len(p.signerReaders))
	for reader := range p.signerReaders {
		list = append(list, reader)
	}
	p.mu.Unlock()
	var out error
	for _, r := range list {
		out = errors.Join(out, r.reconcileV1(ctx))
	}
	return out
}
func signerTextBytesV1(t pgtype.Text) int64 {
	if !t.Valid {
		return 0
	}
	return int64(len(t.String))
}
func signerDocumentRawBytesV1(d *generated.Document) int64 {
	total := int64(0)
	for _, s := range []string{d.Name, d.Status, d.RoutingMode, d.SourceKind, d.RoutingTier, d.BilingualTargetLang, d.LawfulBasis, d.DefaultLocale, d.Article13NoticeSchema, d.ParticipantReportSchema, d.SigningAdmissionPolicy} {
		total += int64(len(s))
	}
	for _, s := range []pgtype.Text{d.RenderedPdfKey, d.PdfStorageKey, d.FinalPdfKey, d.AuditCertKey, d.AuditPayloadKey, d.AuditSignatureKey, d.PdfStorageVersionID, d.RenderedPdfVersionID, d.FinalPdfVersionID, d.AuditCertVersionID, d.AuditPayloadVersionID, d.AuditSignatureVersionID, d.HtmlEffectiveSourceCommitment, d.FitsIndexStorageKey, d.FitsIndexVersionID} {
		total += signerTextBytesV1(s)
	}
	for _, b := range [][]byte{d.RenderedPdfSha, d.PdfSha256, d.FinalPdfSha, d.AuditPayloadSha256, d.AuditSignatureSha256, d.AuditCertSha256, d.HtmlReviewedPdfSha256, d.FitsIndexSha256} {
		total += int64(len(b))
	}
	return total
}
func signerRecipientRawBytesV1(r *generated.GetRecipientByTokenHashRow) int64 {
	return int64(len(r.Role)+len(r.Email)+len(r.Name)+len(r.Status)+len(r.Locale)+len(r.MagicTokenHash)+len(r.DocStatus)) + signerTextBytesV1(r.DeclinedReason)
}
func signerConfirmationRawBytesV1(c *generated.DocumentLawfulBasisConfirmation) int64 {
	return int64(len(c.LawfulBasis) + len(c.Via) + len(c.ControllerName) + len(c.ControllerContact))
}
func signerOrgRawBytesV1(o *generated.Org) int64 {
	return int64(len(o.Name) + len(o.Plan) + len(o.ChangeApprovalMode))
}
func signerMaterializationRawBytesV1(m *generated.ReadSignerCurrentMaterializationV1Row) int64 {
	return int64(len(m.PdfKey) + len(m.PdfVersionID) + len(m.PdfSha256) + len(m.SourceCommitment) + len(m.OriginCommitment))
}
