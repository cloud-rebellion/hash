// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/hex"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Called only by the same genuine HTML author recheck, after the exact original
// API source seal. Earlier callbacks see no M79 row and emit no link/event.
// All native parent/body/final-source reads and fixed bounds are reused intact.
func (s *Server) sealPreSignAPISupersessionV1(ctx context.Context, tx pgx.Tx, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1, a auth.PreSignAPIAdmissionV1, c pdfadmission.PreSignAPISourceCommandV1, template presign.TemplatePin, p pdfadmission.PreSignSupersessionParentV1) (audit.PendingEvent, bool, error) {
	if s == nil || s.Audit == nil || tx == nil || reader == nil || p.ValidateV1() != nil || template.ID != p.Template.ID {
		return audit.PendingEvent{}, false, presignregistry.ErrInvalid
	}
	facts, ready, err := reader.ReadPreSignSupersessionBirthV1(ctx, a.UserID(), c.RequestID, c.InputSHA256, p, template.ID)
	if err != nil || !ready {
		return audit.PendingEvent{}, false, preSignAPISourceFailureV1("callback_parent_birth_read", err)
	}
	actor := a.UserID()
	event, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: a.OrgID(), ActorUserID: &actor, DocumentID: &facts.DocumentID, Kind: "presign.execution.superseded", Payload: map[string]any{
		"prior_execution_id": facts.PriorExecutionID, "prior_execution_sha256": facts.PriorExecutionSHA256, "prior_document_id": facts.PriorDocumentID,
		"document_id": facts.DocumentID, "request_id": facts.RequestID, "source_commitment": facts.SourceCommitment,
	}})
	if err != nil {
		return audit.PendingEvent{}, false, preSignAPISourceFailureV1("callback_supersession_audit", err)
	}
	if err = reader.SealPreSignSupersessionBirthV1(ctx, a.UserID(), c.RequestID, event.ID, c.InputSHA256, p, template.ID); err != nil {
		return audit.PendingEvent{}, false, preSignAPISourceFailureV1("callback_supersession_seal", err)
	}
	return event, true, nil
}

// This compares actual retained original API-source and native linked results;
// it cannot create authority or turn an absent link into an accepted receipt.
func preSignAPISupersessionResultV1(in preSignAPISourceInputV1, digest string, source pdfadmission.PreSignAPISourceViewV1, linked pdfadmission.PreSignSupersessionViewV1) error {
	if in.Prior == nil {
		return nil
	}
	if in.Prior.ValidateV1() != nil || source.SchemaVersion != 1 || source.State != "committed" || source.RequestID != in.RequestID || source.InputSHA256 != digest || source.Source == nil ||
		linked.SchemaVersion != 1 || linked.State != "committed" || linked.RequestID != in.RequestID || linked.PriorExecutionID != in.Prior.ExecutionID || linked.PriorDocumentID != in.Prior.DocumentID ||
		linked.DocumentID != source.Source.DocumentID || linked.DocumentID == in.Prior.DocumentID || linked.DocumentID == uuid.Nil || linked.SourceCommitment != source.Source.SourceCommitment || linked.SourceCommitment == in.Prior.SourceCommitment {
		return presignregistry.ErrConflict
	}
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != digest {
		return presignregistry.ErrConflict
	}
	raw, err = hex.DecodeString(linked.SourceCommitment)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != linked.SourceCommitment {
		return presignregistry.ErrConflict
	}
	return nil
}
func (s *Server) checkPreSignAPISupersessionResultV1(ctx context.Context, a auth.PreSignAPIAdmissionV1, in preSignAPISourceInputV1, digest string, source pdfadmission.PreSignAPISourceViewV1) error {
	if in.Prior == nil {
		return nil
	}
	linked, err := s.readPreSignSupersessionV1(ctx, preSignSourceActorV1(a), in.RequestID, digest)
	if err != nil {
		return preSignAPISourceFailureV1("post_linked_read", err)
	}
	return preSignAPISupersessionResultV1(in, digest, source, linked)
}
