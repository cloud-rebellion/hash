// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PreSignServiceV1 connects only the approved schema3, standalone, parallel
// two-party ceremony. It uses the SAME native Send runtime and actual concrete
// renderer/storage constructors. No partial feature switch is enabled here.
type PreSignServiceV1 struct {
	Send     *Engine
	Registry *presignregistry.Engine
	Storage  *storage.Client
	PDF      *render.Gotenberg
	Receipts *auth.SignedCookie
}

const preSignReceiptPurposeV1 = "hash.presign.execution.confirm.v1"

type preSignReceiptV1 struct {
	Version          int       `json:"version"`
	IntentSHA256     string    `json:"intent_sha256"`
	CredentialSHA256 string    `json:"credential_sha256"`
	ExpiresAt        time.Time `json:"expires_at"`
}
type preSignReadV1 struct {
	authority  presignregistry.ExecutionAuthorityV1
	models     *pdfadmission.HTMLSendModelsV1
	source     *pdfadmission.ApplicationHTMLSendSourceV1
	resolution *pdfadmission.ApplicationHTMLSendResolutionV1
}

func (s *PreSignServiceV1) runtimeV1() bool {
	return s != nil && s.Send != nil && s.Storage != nil && s.PDF != nil
}
func (s *PreSignServiceV1) validV1() bool {
	return s.runtimeV1() && s.Registry != nil && s.Receipts != nil
}
func preSignIntentActorV1(a presignregistry.ExecutionActorV1, in presignexecute.IntentV1) error {
	if _, _, err := presignexecute.CanonicalIntentV1(in); err != nil {
		return err
	}
	if in.ExpectedOrgID != a.OrgID() || in.ExpectedUserID != a.UserID() {
		return auth.ErrMutationPermissionRevoked
	}
	return nil
}

// Locks retain the existing org/user/grant/document order. Resolver/provider
// work runs only after this short read transaction has retired.
func (s *PreSignServiceV1) readV1(ctx context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx, a presignregistry.ExecutionActorV1, in presignexecute.IntentV1, requestLock bool) (*preSignReadV1, error) {
	if _, err := q.GetOrgForOwnerMutation(ctx, a.OrgID()); err != nil {
		return nil, err
	}
	if requestLock {
		if err := q.LockPresignExecutionRequest(ctx, generated.LockPresignExecutionRequestParams{OrgID: a.OrgID(), ExecutorKind: a.Identity().Kind, ExecutorUserID: a.UserID(), ExecutorCredentialID: a.Identity().CredentialID, RequestID: in.RequestID}); err != nil {
			return nil, err
		}
	}
	u, err := p.work.ReadActorV1(ctx, a.UserID())
	if err != nil {
		return nil, err
	}
	if err = a.AuthorizeV1(ctx, tx, u); err != nil {
		return nil, err
	}
	if err = p.work.AcquirePresignAuthorityV1(ctx, in.Policy.ID, in.Policy.Revision, in.Grant.ID, in.Grant.Revision); err != nil {
		return nil, err
	}
	authority, err := presignregistry.LockExecutionAuthorityV1(ctx, tx, a, in.Policy, in.Grant)
	if err != nil {
		return nil, err
	}
	state, err := p.work.StateV1(ctx)
	if err != nil {
		return nil, err
	}
	if state.BoundedStatus != "draft" {
		return nil, presignexecute.ErrConflict
	}
	if err = ValidateExpiryForSend(state.ExpiresAt, authority.ObservedAt()); err != nil {
		return nil, err
	}
	models, err := p.work.ReadModelsV1(ctx)
	if err != nil {
		return nil, err
	}
	if _, err = p.work.ReadRecipientsV1(ctx); err != nil {
		return nil, err
	}
	if _, err = p.work.ReadFieldsV1(ctx); err != nil {
		return nil, err
	}
	if err = p.work.CheckPreSignStandaloneV1(ctx); err != nil {
		return nil, err
	}
	sourcePin, err := presignexecute.EligibleSourceFromModelsV1(models.Document, models.Recipients, models.Fields)
	if err != nil || !presignexecute.MatchesIntentSourceV1(in, models.Document, sourcePin) {
		return nil, presignexecute.ErrConflict
	}
	source, err := p.work.NewSourceV1(ctx)
	if err != nil {
		return nil, err
	}
	if err = source.ValidatePreSignSourceV1(authority); err != nil {
		return nil, err
	}
	if err = source.ValidateCurrentV1(); err != nil {
		return nil, err
	}
	return &preSignReadV1{authority: authority, models: models, source: source}, nil
}

func (s *PreSignServiceV1) EligibilityV1(ctx context.Context, a presignregistry.ExecutionActorV1, document uuid.UUID) (presignexecute.EligibilityV1, error) {
	out := presignexecute.EligibilityV1{SchemaVersion: 1, OrgID: a.OrgID(), UserID: a.UserID(), DocumentID: document}
	if !s.validV1() || document == uuid.Nil {
		return out, presignregistry.ErrUnavailable
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, a.OrgID(), document)
	if err != nil {
		return out, err
	}
	defer o.closeConsumerV1()
	err = o.phaseV1(pdfadmission.HTMLPreSignReadV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := q.GetOrgForOwnerMutation(call, a.OrgID()); err != nil {
			return err
		}
		u, err := p.work.ReadActorV1(call, a.UserID())
		if err != nil {
			return err
		}
		if err = a.AuthorizeV1(call, tx, u); err != nil {
			return err
		}
		if _, err = p.work.StateV1(call); err != nil {
			return err
		}
		m, err := p.work.ReadModelsV1(call)
		if err != nil {
			return err
		}
		if _, err = p.work.ReadRecipientsV1(call); err != nil {
			return err
		}
		if _, err = p.work.ReadFieldsV1(call); err != nil {
			return err
		}
		if err = p.work.CheckPreSignStandaloneV1(call); err != nil {
			if errors.Is(err, pdfadmission.ErrPackageSendSelectionRequiredV1) {
				return a.AuthorizeV1(call, tx, u)
			}
			return err
		}
		pin, e := presignexecute.EligibleSourceFromModelsV1(m.Document, m.Recipients, m.Fields)
		if e == nil {
			out.Eligible = true
			out.Source = pin
		}
		return a.AuthorizeV1(call, tx, u)
	})
	return out, err
}

func (s *PreSignServiceV1) PreviewV1(ctx context.Context, a presignregistry.ExecutionActorV1, in presignexecute.IntentV1) (presignexecute.PreviewV1, error) {
	var out presignexecute.PreviewV1
	if !s.validV1() {
		return out, presignregistry.ErrUnavailable
	}
	if err := preSignIntentActorV1(a, in); err != nil {
		return out, err
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, a.OrgID(), in.DocumentID)
	if err != nil {
		return out, err
	}
	defer o.closeConsumerV1()
	err = o.phaseV1(pdfadmission.HTMLPreSignReadV1, func(call context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		read, err := s.readV1(call, p, q, tx, a, in, false)
		if err != nil {
			return err
		}
		_, digest, err := presignexecute.CanonicalIntentV1(in)
		if err != nil {
			return err
		}
		expires := read.authority.ObservedAt().Add(45 * time.Second)
		if o.deadline.Before(expires) {
			expires = o.deadline
		}
		if read.authority.Grant().Snapshot().ExpiresAt.Before(expires) {
			expires = read.authority.Grant().Snapshot().ExpiresAt
		}
		// Floor only after selecting the original bounds; canonical precision must never extend admission.
		expires = expires.UTC().Truncate(time.Microsecond)
		if !time.Now().Before(expires) {
			return presignexecute.ErrConflict
		}
		raw, err := json.Marshal(preSignReceiptV1{Version: 1, IntentSHA256: digest, CredentialSHA256: a.CredentialCommitment(), ExpiresAt: expires})
		if err != nil {
			return err
		}
		token, err := s.Receipts.MintPurpose(preSignReceiptPurposeV1, raw, time.Until(expires))
		if err != nil {
			return err
		}
		grant := read.authority.Grant().Snapshot()
		customer := read.models.Recipients[0]
		for _, r := range read.models.Recipients {
			if r.Role == "customer" {
				customer = r
			}
		}
		out = presignexecute.PreviewV1{SchemaVersion: 1, OrgID: a.OrgID(), UserID: a.UserID(), Intent: in, Receipt: token, ExpiresAt: expires, ProviderName: grant.Grantor.Name, ProviderEmail: grant.Grantor.Email, CustomerName: customer.Name, CustomerEmail: customer.Email, Disclosure: presignregistry.Disclosure().Text, RemainingUses: grant.MaxUses - read.authority.ConsumedUses()}
		return nil
	})
	return out, err
}

func (s *PreSignServiceV1) verifyReceiptV1(a presignregistry.ExecutionActorV1, in presignexecute.IntentV1, token string) (time.Time, error) {
	raw, err := s.Receipts.VerifyPurpose(preSignReceiptPurposeV1, token)
	if err != nil || len(raw) > 4096 {
		return time.Time{}, presignexecute.ErrConflict
	}
	var receipt preSignReceiptV1
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil {
		return time.Time{}, presignexecute.ErrConflict
	}
	canonical, _ := json.Marshal(receipt)
	_, hash, err := presignexecute.CanonicalIntentV1(in)
	if err != nil || !bytes.Equal(raw, canonical) || receipt.Version != 1 || receipt.IntentSHA256 != hash || receipt.CredentialSHA256 != a.CredentialCommitment() || !time.Now().Before(receipt.ExpiresAt) {
		return time.Time{}, presignexecute.ErrConflict
	}
	return receipt.ExpiresAt, nil
}

func (s *PreSignServiceV1) ConfirmV1(ctx context.Context, a presignregistry.ExecutionActorV1, input presignexecute.ConfirmV1) (result presignexecute.ViewV1, failure error) {
	stage := "confirm"
	defer func() { failure = preSignFailureV1(stage, failure) }()
	var empty presignexecute.ViewV1
	if !s.validV1() {
		return empty, presignregistry.ErrUnavailable
	}
	if !input.Confirmed {
		return empty, presignexecute.ErrInvalid
	}
	in := input.Intent
	if err := preSignIntentActorV1(a, in); err != nil {
		return empty, err
	}
	via := "rest"
	if a.Identity().Kind == presign.ExecutorAPIKey {
		via = "automation"
	} else if a.Identity().Kind != presign.ExecutorMember {
		return empty, presignexecute.ErrInvalid
	}
	// Resolve the original durable outcome before admitting another producer.
	stage = "original_recovery"
	if prior, err := s.recoverV1(ctx, a, in.RequestID, &in); err == nil {
		return prior, nil
	} else if !errors.Is(err, presignregistry.ErrNotFound) {
		return empty, err
	}
	stage = "confirm_receipt"
	expires, err := s.verifyReceiptV1(a, in, input.Receipt)
	if err != nil {
		return empty, err
	}
	if deadline, ok := ctx.Deadline(); !ok || deadline.Before(expires) {
		if !ok {
			return empty, presignexecute.ErrInvalid
		}
		expires = deadline
	}
	// A narrower original caller deadline can also contain nanoseconds; floor without revival or extension.
	expires = expires.UTC().Truncate(time.Microsecond)
	if !time.Now().Before(expires) {
		return empty, presignexecute.ErrConflict
	}
	call, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	o, err := s.Send.newOwnedSendOperationV1(call, a.OrgID(), in.DocumentID)
	if err != nil {
		return empty, err
	}
	defer o.closeConsumerV1()
	var initial *preSignReadV1
	stage = "preparation_read"
	err = o.phaseV1(pdfadmission.HTMLPreSignPreparationV1, func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		var err error
		initial, err = s.readV1(c, p, q, tx, a, in, false)
		if err != nil {
			return err
		}
		if s.Send.Resolver != nil {
			initial.resolution, err = p.work.NewResolverV1(c, initial.source, s.Send.Resolver)
		}
		return err
	})
	if err != nil {
		return s.preSignConcurrentOutcomeV1(ctx, o, a, in, err)
	}
	stage = "freeze_data"
	var reports []resolver.ResolveReport
	if initial.resolution != nil {
		if err = initial.resolution.FreezeV1(); err != nil {
			return empty, err
		}
		v, e := initial.resolution.SnapshotV1()
		if e != nil {
			return empty, e
		}
		reports = v.CRMReports
	}
	var admission presignregistry.DataAdmission
	preparation := uuid.New()
	key := presignexecute.RequestKey{OrgID: a.OrgID(), Executor: a.Identity(), RequestID: in.RequestID}
	var artifacts *pdfadmission.ApplicationPreSignArtifactsV1
	stage = "reserve_preparation"
	err = o.phaseV1(pdfadmission.HTMLPreSignPreparationV1, func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		fresh, err := s.readV1(c, p, q, tx, a, in, true)
		if err != nil {
			return err
		}
		if err = p.work.CheckPreSignSourceDataV1(c, fresh.source, fresh.authority, initial.resolution); err != nil {
			return err
		}
		checked, err := presignregistry.EvaluateExecutionData(fresh.authority.Definition(), fresh.authority.Grant().Snapshot().Grantor, fresh.models.Document, reports, fresh.authority.ObservedAt())
		if err != nil {
			return err
		}
		admission = checked
		if err = presignexecute.ReservePreparationV1(c, tx, key, in, a.CredentialCommitment(), preparation, expires); err != nil {
			return err
		}
		artifacts, err = p.work.NewPreSignArtifactsV1(c, fresh.source, s.Storage, s.PDF, fresh.authority, checked, preparation)
		return err
	})
	if err != nil {
		return s.preSignConcurrentOutcomeV1(ctx, o, a, in, err)
	}
	defer artifacts.CloseConsumerV1()
	stage = "prepare_artifacts"
	if err = artifacts.PrepareV1(); err != nil {
		return empty, err
	}
	objects, err := artifacts.ReservationsV1()
	if err != nil {
		return empty, err
	}
	var reservationPhase *ownedSendPhaseV1
	stage = "reserve_objects"
	err = o.phaseV1(pdfadmission.HTMLPreSignReservationV1, func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		if _, err := s.readV1(c, p, q, tx, a, in, true); err != nil {
			return err
		}
		if err := presignexecute.ReserveObjectsV1(c, tx, key, preparation, objects); err != nil {
			return err
		}
		if err := artifacts.VerifyReservationsV1(c, p.work); err != nil {
			return err
		}
		reservationPhase = p
		return nil
	})
	if err != nil {
		return empty, err
	}
	// Only reservation metadata is used after this successful phase. Its exact
	// work consumer ends here; original physical retirement still gates credit.
	// The artifact/source and initial resolver consumers retain their own lives.
	if reservationPhase == nil || reservationPhase.work == nil || reservationPhase.admission == nil {
		return empty, pdfadmission.ErrHTMLSendWorkV1
	}
	reservationPhase.work.CloseConsumerV1()
	if pending, e := reservationPhase.admission.ReconcileCleanupV1(call); e != nil || pending != 0 {
		return empty, errors.Join(pdfadmission.ErrApplicationSessionUnknownV1, e)
	}
	_ = o.factory.ReconcileCleanupV1(call)
	stage = "upload_artifacts"
	if err = artifacts.UploadV1(); err != nil {
		return empty, err
	}
	stored, err := artifacts.StoredAssetsV1()
	if err != nil {
		return empty, err
	}
	prepared, err := artifacts.PreparedDocumentV1()
	if err != nil {
		return empty, err
	}
	err = o.phaseV1(pdfadmission.HTMLPreSignCommitV1, func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		stage = "commit_read"
		fresh, err := s.readV1(c, p, q, tx, a, in, true)
		if err != nil {
			return err
		}
		stage = "commit_source"
		if err = p.work.CheckPreSignSourceDataV1(c, fresh.source, fresh.authority, initial.resolution); err != nil {
			return err
		}
		if initial.resolution != nil {
			if err = p.work.VerifyAndPersistResolutionV1(c, initial.resolution); err != nil {
				return err
			}
		}
		stage = "commit_data"
		checked, err := presignregistry.EvaluateExecutionData(fresh.authority.Definition(), fresh.authority.Grant().Snapshot().Grantor, fresh.models.Document, reports, fresh.authority.ObservedAt())
		if err != nil || checked.Commitment() != admission.Commitment() {
			return presignexecute.ErrConflict
		}
		stage = "commit_document"
		document, err := presignexecute.DocumentSnapshotFromModelsV1(fresh.models.Document, fresh.models.Recipients, fresh.models.Fields, checked, prepared.BasePDF.Artifact.Bytes)
		if err != nil || document != prepared {
			return presignexecute.ErrConflict
		}
		stage = "commit_quota"
		if s.Send.Billing != nil {
			if err = p.work.EnforceQuotaV1(c, s.Send.Billing); err != nil {
				return err
			}
		}
		stage = "confirm_lawful_basis"
		if _, err = p.work.ConfirmLawfulBasisV1(c, in.LawfulBasis, via); err != nil {
			return err
		}
		stage = "create_intent"
		if err = p.work.CreateIntentV1(c, pdfadmission.HTMLSendIntentActorV1{Via: via, Tool: "presign.execute.v1"}); err != nil {
			return err
		}
		stage = "read_intent"
		intent, err := p.work.ReadIntentV1(c)
		if err != nil {
			return err
		}
		var executed time.Time
		if err = tx.QueryRow(c, `SELECT clock_timestamp()`).Scan(&executed); err != nil {
			return err
		}
		stage = "new_execution"
		execution, assets, err := artifacts.NewExecutionV1(document, intent.Article13NoticeEpochAt.Time, executed, fresh.authority.ConsumedUses()+1)
		if err != nil {
			return err
		}
		stage = "fresh_execution"
		if err = preSignFreshV1(a, fresh.authority, execution, document, expires, executed); err != nil {
			return err
		}
		stage = "new_command"
		command, err := presignexecute.NewCommand(presignexecute.CommandSnapshot{SchemaVersion: 1, OrgID: a.OrgID(), Executor: a.Identity(), RequestID: in.RequestID, DocumentID: in.DocumentID, Document: document, Policy: in.Policy, Grant: in.Grant, SourceCommitment: in.SourceCommitment, AdmissionSHA256: checked.Commitment(), OriginalCredentialSHA256: a.CredentialCommitment()})
		if err != nil {
			return err
		}
		stage = "audit_payload"
		payload, err := presignexecute.AuditPayload(execution, command)
		if err != nil {
			return err
		}
		docID, userID, providerID := in.DocumentID, a.UserID(), execution.Snapshot().Signature.RecipientID
		stage = "commit_audit"
		pending, owner, err := ownedaudit.LogV1(s.Send.Audit, c, p.session, pdfadmission.HTMLAuditPreSignCommittedV1, audit.Entry{OrgID: a.OrgID(), DocumentID: &docID, RecipientID: &providerID, ActorUserID: &userID, Kind: presignexecute.AuditKindCommitted, Payload: payload})
		if err != nil {
			return err
		}
		p.pending = append(p.pending, ownedSendPendingAuditV1{event: pending, owner: owner})
		stage = "new_record"
		record, err := presignexecute.NewRecord(fresh.authority.Policy(), fresh.authority.Grant(), execution, command, checked, pending.ID)
		if err != nil {
			return err
		}
		stage = "resolve_objects"
		if err = presignexecute.ResolvePreparationObjectsV1(c, tx, key, preparation, stored); err != nil {
			return err
		}
		stage = "append_record"
		if err = presignexecute.AppendPreparedRecordV1(c, tx, preparation, record, assets); err != nil {
			return err
		}
		stage = "pin_base"
		if err = p.work.PinPreSignBaseV1(c); err != nil {
			return err
		}
		// Original locks remain live; native credential and natural deadlines are
		// repeated after all canonical/audit/row work and immediately before COMMIT.
		stage = "commit_actor"
		u, err := q.GetUserForShare(c, generated.GetUserForShareParams{ID: a.UserID(), OrgID: a.OrgID()})
		if err != nil {
			return err
		}
		if err = a.AuthorizeV1(c, tx, u); err != nil {
			return err
		}
		var now time.Time
		if err = tx.QueryRow(c, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			return err
		}
		stage = "commit_deadline"
		if !now.Before(expires) || !now.Before(fresh.authority.Grant().Snapshot().ExpiresAt) || (!checked.Snapshot().ValidUntil.IsZero() && !now.Before(checked.Snapshot().ValidUntil)) {
			return presignexecute.ErrConflict
		}
		stage = "commit_transaction"
		return nil
	})
	if err != nil {
		return empty, err
	}
	// The atomic legal execution is already durable. Publication failures never
	// re-admit a grant, rewrite the execution or create a replacement request.
	stage = "publication"
	// The full successful commit phase has joined SQL/audit publication and
	// closed its SQL stage. Durable recovery replaces every producer view.
	initial = nil
	reports = nil
	admission = presignregistry.DataAdmission{}
	objects = [8]storage.PresignTransientReservationV1{}
	stored = [8]presignexecute.AssetV1{}
	prepared = presign.DocumentSnapshot{}
	reservationPhase = nil
	artifacts.CloseConsumerV1()
	artifacts = nil
	if err = o.retireInitialStagesV1(); err != nil {
		return empty, err
	}
	if err = s.resumeOwnedV1(o, via); err != nil {
		return empty, err
	}
	stage = "result_recovery"
	return s.RecoverV1(ctx, a, in.RequestID)
}

// Admission may race the original producer's committed reservation or final
// execution. Retire this nonproducer before opening recovery. Only the exact
// original POST may adopt a committed result; mutation remains a conflict and
// an identical surviving preparation remains unavailable, never restarted.
func (s *PreSignServiceV1) preSignConcurrentOutcomeV1(ctx context.Context, o *ownedSendOperationV1, a presignregistry.ExecutionActorV1, in presignexecute.IntentV1, cause error) (presignexecute.ViewV1, error) {
	var empty presignexecute.ViewV1
	if !errors.Is(cause, presignexecute.ErrPreparationPendingV1) && !errors.Is(cause, presignexecute.ErrConflict) {
		return empty, cause
	}
	o.closeConsumerV1()
	prior, err := s.recoverV1(ctx, a, in.RequestID, &in)
	if err == nil {
		return prior, nil
	}
	if !errors.Is(err, presignregistry.ErrNotFound) {
		return empty, err
	}
	return empty, cause
}

func preSignFreshV1(a presignregistry.ExecutionActorV1, authority presignregistry.ExecutionAuthorityV1, e presign.Execution, document presign.DocumentSnapshot, expires, now time.Time) error {
	p, x := authority.Policy().Snapshot(), e.Snapshot()
	return presign.AuthorizeFreshExecution(authority.Policy(), authority.Grant(), e, presign.FreshObservation{OrgID: a.OrgID(), ObservedAt: authority.ObservedAt(), OriginalActor: a.Identity(), CurrentActor: a.Identity(), OriginalCredentialBindingSHA256: a.CredentialCommitment(), CurrentCredentialBindingSHA256: a.CredentialCommitment(), OriginalAdmissionExpiresAt: expires, CurrentAdmissionExpiresAt: expires, CredentialActive: true, OperationAuthorized: true, Actor: authority.Actor(), Grantor: authority.Grantor(), Policy: presign.PolicyObservation{Reference: authority.Policy().Reference(), ApprovedBy: p.ApprovedBy, ApprovedAt: p.ApprovedAt, Active: true}, Grant: presign.GrantObservation{Reference: authority.Grant().Reference(), ConsumedUses: authority.ConsumedUses()}, Template: presign.TemplateObservation{Pin: p.Template, Active: true, Approved: true}, Workflow: presign.WorkflowObservation{Pin: p.Workflow, ServerOwned: true, Active: true, Approved: true}, Document: presign.DocumentObservation{Snapshot: document, Status: "draft", NoCapturedEvidence: true, CommercialReviewSatisfied: true, InputRulesSatisfied: true, DataRulesSatisfied: true, RecipientRulesSatisfied: true}, Artifacts: presign.ArtifactObservation{Signature: x.Signature, VisiblePDF: x.VisiblePDF, VisibleStampProofSHA256: x.VisibleStampProofSHA256, Verified: true}, CeremonyEpoch: x.CeremonyEpoch}, now)
}

func (s *PreSignServiceV1) RecoverV1(ctx context.Context, a presignregistry.ExecutionActorV1, request uuid.UUID) (presignexecute.ViewV1, error) {
	return s.recoverV1(ctx, a, request, nil)
}
func (s *PreSignServiceV1) recoverV1(ctx context.Context, a presignregistry.ExecutionActorV1, request uuid.UUID, expected *presignexecute.IntentV1) (presignexecute.ViewV1, error) {
	out := presignexecute.ViewV1{SchemaVersion: 1, OrgID: a.OrgID(), UserID: a.UserID(), RequestID: request}
	if !s.validV1() || request == uuid.Nil {
		return out, presignregistry.ErrUnavailable
	}
	locator, err := s.Registry.LocateExecutionRequestV1(ctx, a, request)
	if err != nil {
		return out, err
	}
	out.State = locator.State
	if locator.State == "closed" {
		return out, nil
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, a.OrgID(), locator.DocumentID)
	if err != nil {
		return out, err
	}
	defer o.closeConsumerV1()
	err = o.phaseV1(pdfadmission.HTMLPreSignRecoveryV1, func(c context.Context, p *ownedSendPhaseV1, q *generated.Queries, tx pgx.Tx) error {
		u, err := p.work.ReadActorV1(c, a.UserID())
		if err != nil {
			return err
		}
		if err = a.AuthorizeRecoveryV1(c, tx, u); err != nil {
			return err
		}
		if _, err = p.work.StateV1(c); err != nil {
			return err
		}
		models, err := p.work.ReadModelsV1(c)
		if err != nil {
			return err
		}
		if err = p.work.AcquirePresignEvidenceV1(c); err != nil {
			return err
		}
		r, err := p.work.ReadRetainedPreSignV1(c)
		if err != nil {
			return err
		}
		x, command, pub := r.Execution().Snapshot(), r.Command(), r.Publication()
		if x.ID != locator.ExecutionID || command.RequestKey().RequestID != request || x.Executor != a.Identity() || command.Snapshot().OriginalCredentialSHA256 != a.CredentialCommitment() {
			return auth.ErrMutationPermissionRevoked
		}
		if expected != nil {
			want, _, err := presignexecute.CanonicalIntentV1(*expected)
			if err != nil {
				return err
			}
			actual, err := p.work.ReadOriginalPreSignIntentV1(c)
			if err != nil {
				return err
			}
			if !bytes.Equal(want, actual) {
				return presignexecute.ErrConflict
			}
		}
		publication := pub.State
		if publication == "retaining" {
			publication = "sealing"
		}
		if models.Document.Status == "completed" {
			publication = "completed"
		}
		out.Result = &presignexecute.CommittedViewV1{CommandSHA256: command.Commitment(), Execution: presignexecute.ExecutionReferenceV1{ID: x.ID, SHA256: r.Execution().Commitment()}, DocumentID: x.Document.ID, MaterializationID: x.Document.Materialization.ID, MaterializationRevision: x.Document.Materialization.Revision, SourceCommitment: x.Document.Materialization.SourceCommitment, VisiblePDFSHA256: x.VisiblePDF.Artifact.SHA256, PageCount: x.VisiblePDF.Pages, UseNumber: x.UseNumber, Publication: publication}
		return a.AuthorizeRecoveryV1(c, tx, u)
	})
	return out, err
}

func (s *PreSignServiceV1) CloseV1(ctx context.Context, a presignregistry.ExecutionActorV1, in presignexecute.CloseV1) (presignexecute.ViewV1, error) {
	var empty presignexecute.ViewV1
	if !s.validV1() {
		return empty, presignregistry.ErrUnavailable
	}
	if _, err := s.Registry.CloseExecutionRequestV1(ctx, a, in.RequestID, in.ExpectedOrgID, in.ExpectedUserID, in.Confirmed); err != nil {
		return empty, err
	}
	return s.RecoverV1(ctx, a, in.RequestID)
}
