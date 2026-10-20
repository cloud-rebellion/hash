// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/fitselect"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// captureFittedAuthorityV1 converts an application-owned ALL-target snapshot
// into the frozen renderer authority. Database percentages stay exact decimals;
// they must never be passed as renderer fractions. Geometry must come from
// inspection of the exact retained source, including pages without fields.
func captureFittedAuthorityV1(doc *generated.Document, recipientID uuid.UUID, fields []*generated.DocumentField, in SignInput, span []byte, geometry sanitize.PDFManualGeometry) (*manualfit.AuthorityV1, error) {
	if doc == nil || !doc.Article13NoticeEpochAt.Valid || !doc.SentAt.Valid ||
		!doc.Article13NoticeEpochAt.Time.Equal(doc.SentAt.Time) || !doc.Article13NoticeEpochV61Committed ||
		!doc.PdfStorageVersionID.Valid || !doc.EvidenceVersionPinsRequired || doc.ParentEnvelopeID.Valid ||
		geometry.SourceBytes < 1 || geometry.SourceBytes > sanitize.MaxPDFBytes {
		return nil, ErrSignaturePreparationChanged
	}
	targets, err := captureManualSignatureTargets(doc, recipientID, fields)
	if err != nil {
		return nil, ErrSignaturePreparationChanged
	}
	if err := manualfit.ValidateArchivedSpanV1(span, in.TypedName, in.Font); err != nil {
		return nil, ErrSignaturePreparationChanged
	}
	digest := sha256.Sum256(span)
	source := manualfit.SourceTupleV1{Key: targets.sourceKey.String, VersionID: targets.sourceVersion.String,
		SHA256: hex.EncodeToString(targets.sourceSHA[:]), Bytes: geometry.SourceBytes}
	input := manualfit.AuthorityInputV1{OrgID: doc.OrgID, DocumentID: doc.ID, RecipientID: recipientID,
		CeremonyEpoch: doc.Article13NoticeEpochAt.Time.UTC(), Source: source, TypedName: in.TypedName,
		Font: in.Font, SpanSHA256: hex.EncodeToString(digest[:])}
	for _, target := range targets.fields {
		input.ExpectedTargetIDs = append(input.ExpectedTargetIDs, target.id)
		input.Targets = append(input.Targets, manualfit.TargetV1{ID: target.id, OrgID: doc.OrgID, DocumentID: doc.ID,
			RecipientID: recipientID, Page: int(target.page), Required: target.required,
			X: target.x, Y: target.y, W: target.w, H: target.h})
	}
	authority, err := manualfit.BuildAuthorityV1(input, geometry)
	if err != nil {
		return nil, ErrSignaturePreparationChanged
	}
	return authority, nil
}

// insertFittedSignatureTxV1 is deliberately a transaction-only seam. It does
// not COMMIT, set recipient/document status, publish an audit event, or enable
// fitted Sign. The caller must commit the signature/companion/status/audit as
// one unit and recheck the original credential immediately before that commit.
// No storage write is performed here: selection has retained exact versions.
func (e *Engine) insertFittedSignatureTxV1(ctx context.Context, tx pgx.Tx, rc *RecipientContext, in SignInput, selected *fitselect.SelectedV1, admit fitselect.AdmissionFuncV1) (*generated.Signature, error) {
	if e == nil || ctx == nil || tx == nil || rc == nil || rc.Document == nil || rc.Recipient == nil || selected == nil || selected.Retained() == nil || admit == nil {
		return nil, fitselect.ErrInvalidV1
	}
	intent, err := e.issueFittedSigningIntentV1(ctx, rc, in)
	if err != nil {
		return nil, err
	}
	in = intent.inputV1(in)
	manifest := selected.Retained().Manifest()
	if manifest == nil {
		return nil, fitselect.ErrInvalidV1
	}
	authority := manifest.Authority().Input()
	binding := selected.Binding()
	if binding.OrgID != rc.Document.OrgID || binding.DocumentID != rc.Document.ID || binding.RecipientID != rc.Recipient.ID ||
		authority.TypedName != in.TypedName || authority.Font != in.Font {
		return nil, ErrSignaturePreparationChanged
	}
	// The application callback is always wrapped by the original request's
	// credential/notice checks. A caller cannot replace those checks with its
	// budget callback or use a lease owner as a recipient credential.
	guarded := func(call context.Context, state fitselect.LockedStateV1) (fitselect.AdmissionV1, error) {
		if err := e.validateFittedSigningPolicyV1(call, rc, in, state); err != nil {
			return fitselect.AdmissionV1{}, err
		}
		return admit(call, state)
	}
	field, err := fitselect.FinalAdmissionV1(ctx, tx, selected, guarded)
	if err != nil {
		return nil, err
	}
	span := manifest.Span()
	spanDigest, err := hex.DecodeString(span.SHA256)
	if err != nil || len(spanDigest) != sha256.Size {
		return nil, ErrSignaturePreparationChanged
	}
	var ip *netip.Addr
	if in.IP != "" {
		if parsed, err := netip.ParseAddr(in.IP); err == nil {
			ip = &parsed
		}
	}
	q := generated.New(tx)
	signature, err := q.InsertFittedManualSignatureV1(ctx, generated.InsertFittedManualSignatureV1Params{
		DocumentID: binding.DocumentID, RecipientID: binding.RecipientID, FieldID: field.ID,
		Font: authority.Font, TypedName: authority.TypedName, ImageStorageKey: span.Key, ImageSha256: spanDigest,
		ImageVersionID: pgtype.Text{String: span.VersionID, Valid: true}, SignerIp: ip, SignerUa: textOrNull(in.UserAgent),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAlreadySigned
	}
	if err != nil {
		return nil, fmt.Errorf("insert fitted signature: %w", err)
	}
	if _, err := q.CreateSignatureFitCompanion(ctx, generated.CreateSignatureFitCompanionParams{
		SignatureID: signature.ID, OrgID: binding.OrgID, DocumentID: binding.DocumentID,
		RecipientID: binding.RecipientID, FieldID: field.ID, SelectionID: selected.ID(), SpanSha256: spanDigest,
	}); err != nil {
		return nil, fmt.Errorf("insert fitted signature companion: %w", err)
	}
	return signature, nil
}

// This same application policy must wrap both pre-sign selection/retention
// and final transaction admission. It never treats a manifest, lease or budget
// proof as permission. All reads use the actual document/recipient transaction.
func (e *Engine) validateFittedSigningPolicyV1(ctx context.Context, rc *RecipientContext, in SignInput, state fitselect.LockedStateV1) error {
	return e.validateFittedSigningPolicyQueriesV1(ctx, rc, in, state.Document, state.Recipient, state.Queries)
}

// Both existing query callers and the owned application journal execute this
// SAME credential, notice, controller, SES, HTML master, intended-party,
// signing-page, role and required-field policy. Scoped projections are data
// access only; the actual owned session and resource loan remain mandatory.
func (e *Engine) validateFittedSigningPolicyQueriesV1(ctx context.Context, rc *RecipientContext, in SignInput, doc *generated.Document, recipient *generated.Recipient, q fittedPolicyQueriesV1) (retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			retErr = fittedRequestCancellationV1(ctx, retErr)
		}
	}()
	intent, err := e.issueFittedSigningIntentV1(ctx, rc, in)
	if err != nil {
		return err
	}
	in = intent.inputV1(in)
	if e == nil || signerRoleQueriesNilV1(q) || doc == nil || recipient == nil {
		return fitselect.ErrAdmissionV1
	}
	if !intent.credential.fittedDocumentMatchesV1(doc) {
		return ErrSigningAdmissionUnavailableV1
	}
	// Original finite deadlines cap this request; uncertain current authority
	// still refuses. This stricter rule belongs only to the fitted policy.
	if !finiteFittedTimeV1(recipient.MagicTokenExpiresAt) || (doc.ExpiresAt.Valid && !finiteFittedTimeV1(doc.ExpiresAt)) {
		return ErrSigningAdmissionUnavailableV1
	}
	if err := ValidateLockedNoticeEvidence(rc, doc, in.Notice); err != nil {
		return err
	}
	if err := validateFittedLockedRecipientCredentialV1(rc, recipient, doc, e.now()); err != nil {
		return err
	}
	if err := requireSESTypedSignature(doc); err != nil {
		return err
	}
	if !doc.RequiresSignature || (doc.Status != "sent" && doc.Status != "in_progress") || !recipients.CanRespond(recipient.Role) {
		return ErrDocumentNotSignable
	}
	if recipient.Status == "signed" {
		return ErrAlreadySigned
	}
	if recipient.Status != "pending" && recipient.Status != "sent" && recipient.Status != "viewed" {
		return ErrRecipientNotEligibleForResponse
	}
	confirmation, err := q.GetDocumentLawfulBasisConfirmation(ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil || confirmation == nil || !finiteFittedTimeV1(confirmation.ConfirmedAt) ||
		confirmation.DocumentID != doc.ID || confirmation.OrgID != doc.OrgID ||
		!supportedSignerLawfulBasis(confirmation.LawfulBasis) || strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(doc.LawfulBasis) ||
		strings.TrimSpace(confirmation.ControllerName) != in.Notice.Snapshot.Controller || strings.TrimSpace(confirmation.ControllerContact) != in.Notice.Snapshot.ControllerContact {
		return ErrSignerLawfulBasisUnavailable
	}
	org, err := q.GetOrg(ctx, doc.OrgID)
	if err != nil || org == nil || org.ID != doc.OrgID || strings.TrimSpace(org.Name) == "" {
		return ErrSignerControllerUnavailable
	}
	roles, err := e.signerRolesForDocumentTx(ctx, q, doc)
	if err != nil {
		return err
	}
	if _, required := signerRoleSet(roles)[recipient.Role]; !required {
		return ErrRecipientNotEligibleForResponse
	}
	unfilled, err := q.CountUnfilledRequiredForRecipient(ctx, generated.CountUnfilledRequiredForRecipientParams{
		DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
	})
	if err != nil {
		return err
	}
	if unfilled != 0 {
		return fitselect.ErrAdmissionV1
	}
	// Controller/role/required-field SQL waits may outlive the original receipt.
	// The actual transaction retains the recipient lock; recheck both deadlines.
	return validateFittedLockedRecipientCredentialV1(rc, recipient, doc, e.now())
}
