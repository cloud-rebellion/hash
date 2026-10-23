// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// presentedCredentialV1 is private request provenance, not a new credential or
// a signing permission. Only the real token lookup mints it after its policy
// checks. It owns scalar snapshots and its own digest array; exported database
// rows cannot extend, rotate or rewrite that original admission afterwards.
// It has no public serialization and is never logged, returned by ID lookup or
// used as an operation ID. Only the admitted private durable-request codec may
// encode its explicit origin fields for an immutable owned sidecar.
type presentedCredentialV1 struct {
	issuer                                                 *Engine
	tokenHash                                              [sha256.Size]byte
	orgID, documentID, recipientID                         uuid.UUID
	recipientExpiry, documentExpiry                        pgtype.Timestamptz
	sentAt, noticeEpoch                                    pgtype.Timestamptz
	noticeSchema                                           string
	noticeCommitted                                        bool
	documentName, lawfulBasis                              string
	role, recipientStatus                                  string
	documentStatus, signingPolicy, sourceKind, routingTier string
	requiresSignature, isEnvelope                          bool
	parentEnvelopeID                                       pgtype.UUID
	documentDeletedAt                                      pgtype.Timestamptz
	confirmationBy                                         pgtype.UUID
	confirmationVia                                        string
	controllerName, controllerContact, confirmationBasis   string
	confirmationAt                                         pgtype.Timestamptz
	controllerOrgName                                      string
}

func presentedStampEqualV1(a, b pgtype.Timestamptz) bool {
	return a.Valid == b.Valid && a.InfinityModifier == b.InfinityModifier && (!a.Valid || a.Time.Equal(b.Time))
}

// This constructor is called only by Engine.LookupByToken after the real query,
// expiry, active-ceremony, lawful-basis and controller checks have succeeded.
// Historical read-only lookups may retain a missing notice epoch; the strict
// fitted intent boundary separately requires finite committed notice authority.
func (e *Engine) capturePresentedCredentialV1(tokenHash []byte, rc *RecipientContext) (*presentedCredentialV1, error) {
	if e == nil || rc == nil || rc.Recipient == nil || rc.Document == nil || rc.ControllerOrg == nil || rc.LawfulBasisConfirmation == nil {
		return nil, ErrMagicLinkExpired
	}
	rec, doc, org, confirmation := rc.Recipient, rc.Document, rc.ControllerOrg, rc.LawfulBasisConfirmation
	if len(tokenHash) != sha256.Size || len(rec.MagicTokenHash) != sha256.Size || subtle.ConstantTimeCompare(tokenHash, rec.MagicTokenHash) != 1 ||
		rec.ID == uuid.Nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || rec.DocumentID != doc.ID || rec.DocOrgID != doc.OrgID ||
		org.ID != doc.OrgID || confirmation.DocumentID != doc.ID || confirmation.OrgID != doc.OrgID || !confirmation.ConfirmedAt.Valid ||
		!supportedSignerLawfulBasis(confirmation.LawfulBasis) || strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(doc.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" || strings.TrimSpace(org.Name) == "" {
		return nil, ErrMagicLinkExpired
	}
	if err := checkMagicLinkExpiry(rec, doc, e.now()); err != nil {
		return nil, err
	}
	if err := checkActiveCeremonyAccess(doc); err != nil {
		return nil, err
	}
	p := &presentedCredentialV1{
		issuer: e, orgID: doc.OrgID, documentID: doc.ID, recipientID: rec.ID,
		recipientExpiry: rec.MagicTokenExpiresAt, documentExpiry: doc.ExpiresAt,
		sentAt: doc.SentAt, noticeEpoch: doc.Article13NoticeEpochAt, noticeSchema: strings.Clone(doc.Article13NoticeSchema),
		noticeCommitted: doc.Article13NoticeEpochV61Committed, documentName: strings.Clone(doc.Name), lawfulBasis: strings.Clone(doc.LawfulBasis),
		role: strings.Clone(rec.Role), recipientStatus: strings.Clone(rec.Status),
		documentStatus: strings.Clone(doc.Status), signingPolicy: strings.Clone(doc.SigningAdmissionPolicy), sourceKind: strings.Clone(doc.SourceKind), routingTier: strings.Clone(doc.RoutingTier),
		requiresSignature: doc.RequiresSignature, isEnvelope: doc.IsEnvelope, parentEnvelopeID: doc.ParentEnvelopeID, documentDeletedAt: doc.DeletedAt,
		confirmationBy: confirmation.ConfirmedBy, confirmationVia: strings.Clone(confirmation.Via),
		controllerName: strings.Clone(confirmation.ControllerName), controllerContact: strings.Clone(confirmation.ControllerContact),
		confirmationBasis: strings.Clone(confirmation.LawfulBasis), confirmationAt: confirmation.ConfirmedAt, controllerOrgName: strings.Clone(org.Name),
	}
	copy(p.tokenHash[:], tokenHash)
	return p, nil
}

func (p *presentedCredentialV1) matchesContextV1(rc *RecipientContext) bool {
	if p == nil || p.issuer == nil || rc == nil || rc.Recipient == nil || rc.Document == nil || rc.ControllerOrg == nil || rc.LawfulBasisConfirmation == nil {
		return false
	}
	rec, doc, org, confirmation := rc.Recipient, rc.Document, rc.ControllerOrg, rc.LawfulBasisConfirmation
	return rec.ID == p.recipientID && rec.DocumentID == p.documentID && rec.DocOrgID == p.orgID && doc.ID == p.documentID && doc.OrgID == p.orgID &&
		len(rec.MagicTokenHash) == sha256.Size && subtle.ConstantTimeCompare(p.tokenHash[:], rec.MagicTokenHash) == 1 &&
		presentedStampEqualV1(rec.MagicTokenExpiresAt, p.recipientExpiry) && presentedStampEqualV1(doc.ExpiresAt, p.documentExpiry) &&
		presentedStampEqualV1(doc.SentAt, p.sentAt) && presentedStampEqualV1(doc.Article13NoticeEpochAt, p.noticeEpoch) &&
		doc.Article13NoticeSchema == p.noticeSchema && doc.Article13NoticeEpochV61Committed == p.noticeCommitted && doc.Name == p.documentName && doc.LawfulBasis == p.lawfulBasis && rec.Role == p.role && rec.Status == p.recipientStatus &&
		doc.Status == p.documentStatus && doc.SigningAdmissionPolicy == p.signingPolicy && doc.SourceKind == p.sourceKind && doc.RoutingTier == p.routingTier &&
		doc.RequiresSignature == p.requiresSignature && doc.IsEnvelope == p.isEnvelope && doc.ParentEnvelopeID == p.parentEnvelopeID && presentedStampEqualV1(doc.DeletedAt, p.documentDeletedAt) &&
		org.ID == p.orgID && org.Name == p.controllerOrgName && confirmation.DocumentID == p.documentID && confirmation.OrgID == p.orgID &&
		confirmation.ControllerName == p.controllerName && confirmation.ControllerContact == p.controllerContact && confirmation.LawfulBasis == p.confirmationBasis && presentedStampEqualV1(confirmation.ConfirmedAt, p.confirmationAt) && confirmation.ConfirmedBy == p.confirmationBy && confirmation.Via == p.confirmationVia
}

// This only binds the original routing scope. Complete current source/field/
// party, lawful-basis, credential and SQL admission checks remain mandatory.
func (p *presentedCredentialV1) fittedDocumentMatchesV1(doc *generated.Document) bool {
	return p != nil && doc != nil && doc.ID == p.documentID && doc.OrgID == p.orgID &&
		p.signingPolicy == "pdf-static-v1" && doc.SigningAdmissionPolicy == p.signingPolicy && doc.SourceKind == p.sourceKind && doc.SourceKind == "pdf" &&
		doc.RoutingTier == p.routingTier && doc.RequiresSignature == p.requiresSignature && doc.RequiresSignature && !doc.IsEnvelope && !doc.ParentEnvelopeID.Valid && !doc.DeletedAt.Valid
}

func (p *presentedCredentialV1) originalLiveV1(now time.Time) error {
	if p == nil {
		return ErrMagicLinkExpired
	}
	return checkMagicLinkExpiry(&generated.GetRecipientByTokenHashRow{MagicTokenExpiresAt: p.recipientExpiry}, &generated.Document{ExpiresAt: p.documentExpiry}, now)
}

// Fitted requests use an exclusive expiry boundary. The historical/QES lookup
// and public locked validator keep their existing timestamp contract; neither
// is sufficient by itself for fitted admission at the exact expiry instant.
func checkFittedMagicLinkExpiryV1(recipientExpiry, documentExpiry pgtype.Timestamptz, now time.Time) error {
	if !finiteFittedTimeV1(recipientExpiry) || (documentExpiry.Valid && !finiteFittedTimeV1(documentExpiry)) {
		return ErrSigningAdmissionUnavailableV1
	}
	if !now.Before(recipientExpiry.Time) || (documentExpiry.Valid && !now.Before(documentExpiry.Time)) {
		return ErrMagicLinkExpired
	}
	return nil
}

func (p *presentedCredentialV1) originalFittedLiveV1(now time.Time) error {
	if p == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	return checkFittedMagicLinkExpiryV1(p.recipientExpiry, p.documentExpiry, now)
}

// Validate immutable original and freshly locked deadlines with one clock value
// before the existing token/role/notice identity checks. Call this private seam
// again after SQL waits and immediately before a fitted commit.
func validateFittedLockedRecipientCredentialV1(rc *RecipientContext, rec *generated.Recipient, doc *generated.Document, now time.Time) error {
	if rc == nil || rc.presentedCredential == nil || rec == nil || doc == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if err := rc.presentedCredential.originalFittedLiveV1(now); err != nil {
		return err
	}
	if err := checkFittedMagicLinkExpiryV1(rec.MagicTokenExpiresAt, doc.ExpiresAt, now); err != nil {
		return err
	}
	return ValidateLockedRecipientCredential(rc, rec, doc, now)
}

// A receipt augments the existing locked check whenever one was issued. Missing
// receipts retain the historical/QES contract; fitted policy never admits one.
func (p *presentedCredentialV1) validateLockedV1(rc *RecipientContext, rec *generated.Recipient, doc *generated.Document, now time.Time) error {
	return p.validateLockedPinsV1(rc, rec, htmlCeremonyDocumentPinsForV1(doc), now)
}

// fittedSigningIntentV1 is a private immutable intent bound to one engine's
// presented request. It is consumed by the actual fitted policy/insert seams,
// never an exported factory, readiness flag, durable operation key or permission
// to dispatch. Evidence is value-only: its strings and nested Copy have no mutable
// slice/map/pointer storage. Future operation ownership remains separate.
type fittedSigningIntentV1 struct {
	credential      *presentedCredentialV1
	typedName, font string
	notice          article13.Evidence
}

func (e *Engine) validateFittedRequestV1(ctx context.Context, rc *RecipientContext, in SignInput) (*presentedCredentialV1, error) {
	if rc != nil && rc.delegated != nil {
		return nil, ErrDelegatedFittedUnsupportedV1
	}
	if ctx == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if ctx.Err() != nil {
		return nil, fittedRequestCancellationV1(ctx)
	}
	if e == nil || rc == nil || rc.presentedCredential == nil || rc.presentedCredential.issuer != e || !rc.presentedCredential.matchesContextV1(rc) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	p, doc := rc.presentedCredential, rc.Document
	if !finiteFittedTimeV1(p.recipientExpiry) || (p.documentExpiry.Valid && !finiteFittedTimeV1(p.documentExpiry)) || !finiteFittedTimeV1(p.confirmationAt) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err := p.originalFittedLiveV1(e.now()); err != nil {
		return nil, err
	}
	if doc.SigningAdmissionPolicy != "pdf-static-v1" || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || doc.DeletedAt.Valid ||
		(doc.Status != "sent" && doc.Status != "in_progress") || !p.noticeCommitted || !finiteFittedTimeV1(p.sentAt) || !finiteFittedTimeV1(p.noticeEpoch) || !p.sentAt.Time.Equal(p.noticeEpoch.Time) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if !recipients.CanRespond(p.role) || (p.recipientStatus != "pending" && p.recipientStatus != "sent" && p.recipientStatus != "viewed") {
		return nil, ErrRecipientNotEligibleForResponse
	}
	if err := requireSESTypedSignature(doc); err != nil {
		return nil, err
	}
	if !render.IsValidFont(in.Font) || render.ValidateSignatureName(in.TypedName) != nil {
		return nil, ErrSignaturePreparationChanged
	}
	if err := validateNoticeEvidence(rc, in.Notice); err != nil {
		return nil, err
	}
	legalBasis, err := article13.LegalBasisDisclosureV1(p.lawfulBasis)
	if err != nil {
		return nil, ErrInvalidNoticeEvidence
	}
	snapshot := in.Notice.Snapshot
	if snapshot.Controller != strings.TrimSpace(p.controllerName) || snapshot.ControllerContact != strings.TrimSpace(p.controllerContact) ||
		snapshot.PurposeSummary != article13.PurposeSummaryV1(p.documentName) || snapshot.LegalBasisDisclosure != legalBasis ||
		snapshot.Copy != article13.RenderedCopyV1(p.documentName) {
		return nil, ErrInvalidNoticeEvidence
	}
	if ctx.Err() != nil {
		return nil, fittedRequestCancellationV1(ctx)
	}
	return p, nil
}

func (e *Engine) issueFittedSigningIntentV1(ctx context.Context, rc *RecipientContext, in SignInput) (*fittedSigningIntentV1, error) {
	p, err := e.validateFittedRequestV1(ctx, rc, in)
	if err != nil {
		return nil, err
	}
	return &fittedSigningIntentV1{credential: p, typedName: strings.Clone(in.TypedName), font: strings.Clone(in.Font), notice: in.Notice}, nil
}

func (i *fittedSigningIntentV1) inputV1(in SignInput) SignInput {
	in.TypedName, in.Font, in.Notice = i.typedName, i.font, i.notice
	return in
}

type fittedRequestContextErrorV1 struct{ causes []error }

func (e fittedRequestContextErrorV1) Error() string   { return ErrSigningAdmissionUnavailableV1.Error() }
func (e fittedRequestContextErrorV1) Unwrap() []error { return append([]error(nil), e.causes...) }
func fittedRequestCancellationV1(ctx context.Context, phases ...error) error {
	causes := []error{ErrSigningAdmissionUnavailableV1}
	for _, phase := range phases {
		if phase != nil {
			causes = append(causes, phase)
		}
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			causes = append(causes, err)
		}
		if cause := context.Cause(ctx); cause != nil {
			causes = append(causes, cause)
		}
	}
	return fittedRequestContextErrorV1{causes: causes}
}
