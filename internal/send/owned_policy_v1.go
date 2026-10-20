// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The view below is for existing audit payload/deadline construction only.
// Actual persistence and policy read private same-operation resolver state.
func ownedSendBindingPreparationV1(doc *generated.Document, v pdfadmission.HTMLSendResolutionSnapshotV1) *sendBindingPreparation {
	if doc == nil {
		return nil
	}
	p := &sendBindingPreparation{definitions: map[uuid.UUID][]*generated.DocumentVariableBinding{doc.ID: v.Definitions}, crmReports: map[uuid.UUID]preparedCRMReports{doc.ID: {orgID: doc.OrgID, report: v.CRMReports}}}
	for _, o := range v.Observations {
		p.observations = append(p.observations, preparedBindingObservation{resolved: o.Resolved, failed: o.Failed})
	}
	return p
}
func validateOwnedSendRecipientsV1(source *pdfadmission.ApplicationHTMLSendSourceV1, doc *generated.Document, envelopeRoles []string, recs []*generated.Recipient) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	// For reviewed HTML contracts the approved party declaration, rather than
	// the remaining editable recipient rows, owns the required signing set.
	// This check precedes the acknowledgement branch as well.
	if source == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := source.ValidatePartiesV1(doc, recs); err != nil {
		return err
	}
	for _, rec := range recs {
		if rec == nil {
			return fmt.Errorf("%w: missing recipient row", ErrInvalidRecipient)
		}
		if err := recipients.ValidatePersisted(recipients.Values{
			Email: rec.Email, Name: rec.Name, Role: rec.Role,
			OrderIndex: rec.OrderIndex, Locale: rec.Locale,
		}); err != nil {
			return fmt.Errorf("%w: recipient %s: %v", ErrInvalidRecipient, rec.ID, err)
		}
		if rec.Role == "cc" || rec.Role == "viewer" {
			return fmt.Errorf("%w: recipient %s uses role %s", ErrUnsupportedRecipientRole, rec.ID, rec.Role)
		}
	}
	var requiredRoles []string
	if doc.IsEnvelope {
		requiredRoles = envelopeRoles
	} else if doc.SourceKind == "blocks" {
		var err error
		requiredRoles, err = requiredOwnedBlockRolesV1(source)
		if err != nil {
			return err
		}
	} else if doc.RequiresSignature {
		// Preflight checks recipient uniqueness; the locked PDF-field check
		// below independently requires a visible signature for every party.
		for _, rec := range recs {
			if recipientEligibleForSend(rec) {
				requiredRoles = append(requiredRoles, rec.Role)
			}
		}
	}

	if !doc.RequiresSignature {
		eligible := 0
		for _, rec := range recs {
			if recipientEligibleForSend(rec) {
				eligible++
			}
		}
		if eligible == 0 {
			return ErrNoRecipients
		}
		return nil
	}
	if len(requiredRoles) == 0 {
		return ErrNoSignatureFields
	}
	eligible := 0
	for _, rec := range recs {
		if recipientEligibleForSend(rec) && rec.Role != "cc" {
			eligible++
		}
	}
	if eligible == 0 {
		return ErrNoSigners
	}
	return validateRequiredRoles(requiredRoles, recs)
}

// ValidateAutomationBlockRequest runs the stable block/variable/recipient
// send checks before an automation endpoint persists its draft. Provider,
// storage, billing, and row-lock checks still run in Send; this preflight keeps
// malformed templates and role mappings from leaving permanent orphan drafts.

func validateOwnedPDFSignatureFieldsV1(source *pdfadmission.ApplicationHTMLSendSourceV1, doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, pageCount int) error {
	if doc == nil {
		return ErrDocumentNotFound
	}
	if doc.SourceKind != "pdf" || !doc.RequiresSignature {
		return nil
	}

	if pageCount < 1 {
		return fmt.Errorf("%w: source page count is unavailable", ErrInvalidPDFSignatureField)
	}
	for _, rec := range recs {
		if rec == nil || !recipientEligibleForSend(rec) {
			return fmt.Errorf("%w: PDF party is not eligible for send", ErrInvalidPDFSignatureField)
		}
	}
	if source == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := source.ValidatePDFRoleFieldsV1(doc, recs, fields, pageCount); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPDFSignatureField, err)
	}
	return nil
}

// verifyPreparedEnvelopeChildren catches membership or content changes that
// raced preflight/freeze before any recipient token is rotated. Both slices
// are position-ordered by ListEnvelopeChildren.

func authorizeOwnedLifecycleActorV1(ctx context.Context, phase *ownedSendPhaseV1, tx pgx.Tx, actor *Actor) (*generated.User, error) {
	if actor == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err := requireActorAuthorization(*actor); err != nil {
		return nil, err
	}
	if phase == nil || phase.work == nil {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	user, err := phase.work.ReadActorV1(ctx, *actor.UserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, fmt.Errorf("load lifecycle authorization: %w", err)
	}
	if user.Role != string(auth.RoleOwner) && user.Role != string(auth.RoleSender) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	actor.Email = user.Email
	if err := reauthorizeLifecycleActor(ctx, tx, *actor, user); err != nil {
		return nil, err
	}
	return user, nil
}
