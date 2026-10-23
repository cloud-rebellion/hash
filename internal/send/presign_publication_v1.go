// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func preSignCommittedReadV1(ctx context.Context, p *ownedSendPhaseV1) (outModels *pdfadmission.HTMLSendModelsV1, outRetained presignexecute.RetainedAssetsV1, failure error) {
	stage := "publication_read_state"
	defer func() { failure = preSignFailureV1(stage, failure) }()
	var empty presignexecute.RetainedAssetsV1
	if _, err := p.work.StateV1(ctx); err != nil {
		return nil, empty, err
	}
	stage = "publication_read_models"
	models, err := p.work.ReadModelsV1(ctx)
	if err != nil {
		return nil, empty, err
	}
	stage = "publication_read_recipients"
	if _, err = p.work.ReadRecipientsV1(ctx); err != nil {
		return nil, empty, err
	}
	stage = "publication_read_fields"
	if _, err = p.work.ReadFieldsV1(ctx); err != nil {
		return nil, empty, err
	}
	stage = "publication_read_intent"
	if _, err = p.work.ReadIntentV1(ctx); err != nil {
		return nil, empty, err
	}
	stage = "publication_read_evidence"
	if err = p.work.AcquirePresignEvidenceV1(ctx); err != nil {
		return nil, empty, err
	}
	stage = "publication_read_retained"
	retained, err := p.work.ReadRetainedPreSignV1(ctx)
	return models, retained, err
}

// ResumePreSignV1 is the fixed committed-execution worker entry. It never
// admits a grant or creates an execution. Publication can only consume the
// original durable M82/M116/epoch tuple; malformed explicit evidence refuses.
func (s *PreSignServiceV1) ResumePreSignV1(ctx context.Context, org, document uuid.UUID) error {
	if !s.runtimeV1() {
		return presignregistry.ErrUnavailable
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, org, document)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1()
	return s.resumeOwnedV1(o, "worker")
}
func (s *PreSignServiceV1) resumeOwnedV1(o *ownedSendOperationV1, via string) (failure error) {
	stage := "publication_resume_scope"
	defer func() { failure = preSignFailureV1(stage, failure) }()
	if via != "rest" && via != "automation" && via != "worker" {
		return presignexecute.ErrInvalid
	}
	var retained presignexecute.RetainedAssetsV1
	stage = "publication_recovery_open"
	err := o.phaseV1(pdfadmission.HTMLPreSignRecoveryV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		_, r, err := preSignCommittedReadV1(c, p)
		retained = r
		if err == nil {
			stage = "publication_recovery_commit"
		}
		return err
	})
	if err != nil {
		return err
	}
	if retained.Publication().State != "retaining" {
		return nil
	}
	if retained.Publication().RetentionCompletedAt.IsZero() {
		var owner *pdfadmission.ApplicationPreSignRetentionV1
		stage = "publication_retention_start_open"
		err = o.phaseV1(pdfadmission.HTMLPreSignRetentionV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
			if _, _, err := preSignCommittedReadV1(c, p); err != nil {
				return err
			}
			var err error
			stage = "publication_retention_start"
			owner, err = p.work.StartPreSignRetentionV1(c, s.Storage)
			if err == nil {
				stage = "publication_retention_start_commit"
			}
			return err
		})
		if err != nil {
			return err
		}
		defer owner.CloseConsumerV1()
		stage = "publication_retention_io"
		if err = owner.RetainV1(); err != nil {
			return err
		}
		stage = "publication_retention_complete_open"
		err = o.phaseV1(pdfadmission.HTMLPreSignRetentionV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
			if _, _, err := preSignCommittedReadV1(c, p); err != nil {
				return err
			}
			stage = "publication_retention_complete"
			if err := owner.CompleteV1(c, p.work); err != nil {
				return err
			}
			stage = "publication_retention_complete_commit"
			return nil
		})
		if err != nil {
			return err
		}
	}
	stage = "publication_open"
	return o.phaseV1(pdfadmission.HTMLPreSignPublicationV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		models, r, err := preSignCommittedReadV1(c, p)
		if err != nil {
			return err
		}
		if r.Publication().State != "retaining" {
			return nil
		}
		stage = "publication_native"
		result, err := p.work.PublishPreSignCustomerV1(c, s.Send.PublicURL, s.Send.OrgName)
		if err != nil {
			return err
		}
		stage = "publication_sent_document"
		sent, err := p.work.PreSignSentDocumentV1(c)
		if err != nil {
			return err
		}
		x := r.Execution().Snapshot()
		user, doc, customer := x.Executor.UserID, x.Document.ID, x.Document.Parties[0].ID
		a := Actor{OrgID: x.OrgID, UserID: &user, Via: via, Tool: "presign.publish.v1", LawfulBasis: "contract"}
		recipientCount := 1
		if result.Expired {
			recipientCount = 0
		}
		stage = "publication_sent_entry"
		sentEntry, err := s.Send.documentSentAuditEntry(a, sent, map[string]any{"recipient_count": recipientCount, "evidence_retained": true, "lawful_basis": "contract", "lawful_basis_confirmed": true, "retain_until": result.RetainUntil.UTC().Format(time.RFC3339Nano), "expired_before_invite": result.Expired})
		if err != nil {
			return err
		}
		stage = "publication_sent_audit"
		if err = p.appendAuditEntriesV1(c, []audit.Entry{sentEntry}); err != nil {
			return err
		}
		if result.Expired {
			expired := s.Send.auditEntry(a, &doc, nil, audit.KindDocumentExpired, map[string]any{"before_invite": true, "irreversible_sealing_recovery": true})
			stage = "publication_expired_audit"
			if err = p.appendAuditEntriesV1(c, []audit.Entry{expired}); err != nil {
				return err
			}
			stage = "publication_mark"
			if err := p.work.MarkPreSignPublicationV1(c, uuid.Nil); err != nil {
				return err
			}
			stage = "publication_commit"
			return nil
		}
		invited := s.Send.auditEntry(a, &doc, &customer, audit.KindRecipientInvited, map[string]any{"email": x.Document.Parties[0].Email, "role": "customer"})
		stage = "publication_invited_audit"
		if err = p.appendAuditEntriesV1(c, []audit.Entry{invited}); err != nil {
			return err
		}
		payload := map[string]any{"execution_id": result.ExecutionID, "execution_sha256": result.ExecutionSHA256, "visible_pdf_sha256": result.VisiblePDFSHA256, "assets_sha256": result.AssetsSHA256, "customer_recipient_id": result.CustomerRecipientID, "retain_until": result.RetainUntil.UTC().Format(time.RFC3339Nano)}
		stage = "publication_published_audit"
		pending, owner, err := ownedaudit.LogV1(s.Send.Audit, c, p.session, pdfadmission.HTMLAuditPreSignPublishedV1, audit.Entry{OrgID: x.OrgID, DocumentID: &doc, RecipientID: &customer, ActorUserID: &user, Kind: "presign.execution.published", Payload: payload})
		if err != nil {
			return err
		}
		p.pending = append(p.pending, ownedSendPendingAuditV1{event: pending, owner: owner})
		stage = "publication_model_identity"
		if models.Document.ID != doc {
			return presignexecute.ErrIntegrity
		}
		stage = "publication_mark"
		if err := p.work.MarkPreSignPublicationV1(c, pending.ID); err != nil {
			return err
		}
		stage = "publication_commit"
		return nil
	})
}
