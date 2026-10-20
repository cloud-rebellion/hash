// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5"
)

// Every public model is backed by the actual operation's independently retained
// private body/source owners. The original and actually pinned tuple are
// distinct; no caller version/timestamp normalization creates source authority.
type ownedSealedSendSnapshotV1 struct {
	*sealedSendSnapshot
	operation        *ownedSendOperationV1
	work             *pdfadmission.ApplicationHTMLSendWorkV1
	source           *pdfadmission.ApplicationHTMLSendSourceV1
	evidence         *pdfadmission.ApplicationHTMLSendEvidenceV1
	members          []*ownedSendFamilyMemberV1
	alreadyCompleted *SendResult
}

func validateOwnedResolvedSealedSnapshotV1(source *pdfadmission.ApplicationHTMLSendSourceV1, doc *generated.Document) error {
	if source == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := validateOwnedResolvedBlockVariablesV1(source); err != nil {
		return fmt.Errorf("resume send sealing: validate frozen variables: %w", err)
	}
	if !source.MatchesDocumentV1(doc) || doc == nil || (doc.SourceKind != "pdf" && doc.SourceKind != "blocks") {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	// Original validateResolvedBlockVariables returns after reviewed validation
	// for PDF. No repeat generic source parser/Compile occurs outside its owner.
	return nil
}
func (e *Engine) loadOwnedSealedSendSnapshotV1(ctx context.Context, o *ownedSendOperationV1) (snapshot *ownedSealedSendSnapshotV1, failure error) {
	if !o.valid(ctx) {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	snapshot = &ownedSealedSendSnapshotV1{sealedSendSnapshot: &sealedSendSnapshot{}, operation: o}
	failure = o.phaseV1(pdfadmission.HTMLSendSnapshotV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if err != nil {
			return fmt.Errorf("resume send sealing: load document: %w", err)
		}
		if state.BoundedStatus != "sealing" {
			return fmt.Errorf("resume send sealing: document status is %s, want sealing", state.BoundedStatus)
		}
		if state.ParentEnvelopeID.Valid {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		models, err := p.work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		doc := models.Document
		if err = requireLifecycleRoot(doc); err != nil {
			return err
		}
		if err = validateAcknowledgementSend(doc); err != nil {
			return err
		}
		if err = requireSupportedSignatureTier(eidas.Tier(doc.RoutingTier), eidas.TierSES); err != nil {
			return err
		}
		confirmation, err := p.work.ReadConfirmationV1(call)
		if err != nil {
			return fmt.Errorf("resume send sealing: load lawful-basis confirmation: %w", err)
		}
		if err = requireConfirmedLawfulBasis(doc, confirmation); err != nil {
			return fmt.Errorf("resume send sealing: %w", err)
		}
		if err = requireValidSignerDisclosure(doc, confirmation); err != nil {
			return fmt.Errorf("resume send sealing: %w", err)
		}
		source, err := p.work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = source.ValidateReviewedV1(); err != nil {
			return fmt.Errorf("resume send sealing: HTML source: %w", err)
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return fmt.Errorf("resume send sealing: HTML source: %w", err)
		}
		if err = p.work.ValidateSigningPageStateV1(call); err != nil {
			return err
		}
		// This is exactly the original pin point, after disclosure and all reviewed
		// signing-page decisions and before any retention-start marker/provider write.
		client, ok := e.Storage.(*storage.Client)
		if !ok || client == nil {
			return errors.New("resume send sealing: evidence version resolver unavailable")
		}
		evidence, err := p.work.NewEvidenceV1(call, source, client)
		if err != nil {
			return err
		}
		snapshot.doc = doc
		snapshot.work = p.work
		snapshot.source = source
		snapshot.evidence = evidence
		return nil
	})
	if failure != nil {
		return nil, failure
	}
	originalSnapshotWork := snapshot.work
	if failure = snapshot.evidence.PreparePinsV1(); failure != nil {
		return nil, failure
	}
	failure = o.phaseV1(pdfadmission.HTMLSendPinV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if err != nil {
			return err
		}
		if state.BoundedStatus != "sealing" {
			if out, ok := completedOwnedSendStatusV1(state); ok {
				snapshot.alreadyCompleted = &out
				return nil
			}
			return fmt.Errorf("resume send sealing: document status is %s, want sealing", state.BoundedStatus)
		}
		_, err = p.work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		doc, err := p.work.PinEvidenceVersionsV1(call, snapshot.evidence)
		if err != nil {
			return fmt.Errorf("resume send sealing: persist evidence VersionIds: %w", err)
		}
		source, err := p.work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = source.ValidateReviewedV1(); err != nil {
			return fmt.Errorf("resume send sealing: HTML source: %w", err)
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return fmt.Errorf("resume send sealing: HTML source: %w", err)
		}
		if err = snapshot.evidence.BindPinnedV1(source); err != nil {
			return err
		}
		if doc.IsEnvelope {
			if e.Envelopes == nil || e.Envelopes.Q == nil {
				return errors.New("resume send envelope: child store unavailable")
			}
			client, ok := e.Storage.(*storage.Client)
			if !ok || client == nil {
				return errors.New("resume send sealing: evidence version resolver unavailable")
			}
			snapshot.members, err = pinOwnedEnvelopeMembersV1(call, p.work, client)
			if err != nil {
				return err
			}
			snapshot.children = ownedEnvelopeDocumentsV1(snapshot.members)
			snapshot.envelopeRoles, err = validateOwnedEnvelopeMembersV1(call, doc.ID, snapshot.members, "sealing", true)
			if err != nil {
				return err
			}
		}
		if err = validateOwnedResolvedSealedSnapshotV1(source, doc); err != nil {
			return err
		}
		if err = validateOwnedResolvedFamilySnapshotV1(snapshot.members); err != nil {
			return err
		}
		recipients, err := p.work.ReadRecipientsV1(call)
		if err != nil {
			return fmt.Errorf("resume send sealing: list recipients: %w", err)
		}
		if err = validateOwnedSendRecipientsV1(source, doc, snapshot.envelopeRoles, recipients); err != nil {
			return err
		}
		if doc.IsEnvelope && e.EIDAS != nil {
			if _, err = guardOwnedEnvelopeEIDASV1(doc, source, snapshot.members); err != nil {
				return err
			}
		}
		snapshot.doc = doc
		snapshot.work = p.work
		snapshot.source = source
		snapshot.recipients = recipients
		return nil
	})
	if failure != nil {
		return nil, failure
	}
	if snapshot.alreadyCompleted != nil {
		return snapshot, nil
	}
	pinnedSnapshotWork := snapshot.work
	if e.EIDAS != nil && !snapshot.doc.IsEnvelope {
		decision, err := snapshot.source.EvaluateEIDASV1()
		if err != nil {
			if errors.Is(err, pdfadmission.ErrHTMLSendEIDASInputV1) {
				return nil, fmt.Errorf("resume send sealing: build eIDAS input: %w", err)
			}
			return nil, err
		}
		if err = enforceEIDASSendDecision(eidas.Tier(snapshot.doc.RoutingTier), decision); err != nil {
			return nil, err
		}
	}
	snapshot.pageCount, failure = snapshot.evidence.InspectPDFV1()
	if errors.Is(failure, pdfadmission.ErrHTMLSendPDFMissingV1) {
		return nil, ErrAcknowledgementNeedsPDF
	}
	if failure != nil {
		return nil, failure
	}
	for _, member := range snapshot.members {
		if _, failure = member.evidence.InspectPDFV1(); failure != nil {
			return nil, failure
		}
	}
	// The original field query occurs only AFTER the actual PDF inspection.
	// A new real phase reacquires the immutable source and its scoped collections;
	// evidence transfers only after exact private tuple comparison under BOTH
	// source owners. No empty lazy model silently stands in for a DB collection.
	failure = o.phaseV1(pdfadmission.HTMLSendSnapshotFieldsV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		state, err := p.work.StateV1(call)
		if err != nil {
			return err
		}
		if state.BoundedStatus != "sealing" {
			if out, ok := completedOwnedSendStatusV1(state); ok {
				snapshot.alreadyCompleted = &out
				return nil
			}
			return fmt.Errorf("resume send sealing: document status is %s, want sealing", state.BoundedStatus)
		}
		if state.ParentEnvelopeID.Valid {
			return pdfadmission.ErrHTMLSendWorkV1
		}
		models, err := p.work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		doc := models.Document
		source, err := p.work.NewSourceV1(call)
		if err != nil {
			return err
		}
		if err = validateOwnedResolvedSealedSnapshotV1(source, doc); err != nil {
			return err
		}
		if err = source.ValidateCurrentV1(); err != nil {
			return fmt.Errorf("resume send sealing: HTML source: %w", err)
		}
		var nextMembers []*ownedSendFamilyMemberV1
		var nextRoles []string
		if doc.IsEnvelope {
			nextMembers, _, err = bindOwnedEnvelopeFieldsV1(call, p.work, snapshot.members)
			if err != nil {
				return err
			}
			nextRoles, err = validateOwnedEnvelopeMembersV1(call, doc.ID, nextMembers, "sealing", true)
			if err != nil {
				return err
			}
		}
		recipients, err := p.work.ReadRecipientsV1(call)
		if err != nil {
			return fmt.Errorf("resume send sealing: list recipients: %w", err)
		}
		if err = validateOwnedSendRecipientsV1(source, doc, nextRoles, recipients); err != nil {
			return err
		}
		var fields []*generated.DocumentField
		if doc.SourceKind == "pdf" {
			fields, err = p.work.ReadFieldsV1(call)
			if err != nil {
				return fmt.Errorf("resume send PDF: list fields: %w", err)
			}
		}
		if err = snapshot.evidence.BindFieldsV1(source); err != nil {
			return err
		}
		if doc.SourceKind == "pdf" {
			if doc.RequiresSignature {
				err = validateOwnedPDFSignatureFieldsV1(source, doc, recipients, fields, snapshot.pageCount)
			} else {
				err = validateAcknowledgementFields(fields)
			}
			if err != nil {
				return err
			}
		}
		for _, member := range nextMembers {
			if err = member.evidence.BindFieldsV1(member.source); err != nil {
				return err
			}
		}
		snapshot.members = nextMembers
		snapshot.children = ownedEnvelopeDocumentsV1(nextMembers)
		snapshot.envelopeRoles = nextRoles

		snapshot.doc = doc
		snapshot.work = p.work
		snapshot.source = source
		snapshot.recipients = recipients
		snapshot.fields = fields
		return nil
	})
	if failure != nil {
		return nil, failure
	}
	if snapshot.alreadyCompleted == nil {
		if failure = o.retireSupersededSnapshotStagesV1(snapshot.work, originalSnapshotWork, pinnedSnapshotWork); failure != nil {
			return nil, failure
		}
	}
	return snapshot, nil
}
func (s *ownedSealedSendSnapshotV1) retainReadyV1(ctx context.Context, o *ownedSendOperationV1, retainUntil time.Time) error {
	if s == nil || s.operation != o || !o.valid(ctx) || s.sealedSendSnapshot == nil || s.doc == nil || s.source == nil || s.evidence == nil || s.alreadyCompleted != nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := validateAcknowledgementSend(s.doc); err != nil {
		return err
	}
	if s.doc.RequiresSignature {
		if err := validateOwnedPDFSignatureFieldsV1(s.source, s.doc, s.recipients, s.fields, s.pageCount); err != nil {
			return err
		}
	} else if err := validateAcknowledgementFields(s.fields); err != nil {
		return err
	}
	// This repeats the original reviewed source decision using exactly the
	// successful immutable pinned validation, before any retention provider call.
	if err := s.source.ValidateReviewedV1(); err != nil {
		return fmt.Errorf("retain send evidence: HTML source: %w", err)
	}
	if !s.source.MatchesDocumentV1(s.doc) {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	for _, member := range s.members {
		if err := member.source.ValidateReviewedV1(); err != nil {
			return err
		}
	}
	if err := s.evidence.RetainReadyV1(retainUntil); err != nil {
		return err
	}
	for _, member := range s.members {
		if err := member.evidence.RetainReadyV1(retainUntil); err != nil {
			return err
		}
	}
	return nil
}
