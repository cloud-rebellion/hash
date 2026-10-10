// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"crypto/subtle"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// Runtime observations are separate from immutable canonical snapshots. Every
// field must be supplied by trusted admission/storage adapters under the locks
// described in the package contract. Client-supplied booleans prove nothing.
type MemberObservation struct {
	OrgID  uuid.UUID
	UserID uuid.UUID
	Name   string
	Email  string
	Role   string
	Active bool
}

type PolicyObservation struct {
	Reference  Reference
	ApprovedBy uuid.UUID
	ApprovedAt time.Time
	Active     bool
}

type GrantObservation struct {
	Reference    Reference
	Revoked      bool
	ConsumedUses int64
}

type TemplateObservation struct {
	Pin      TemplatePin
	Active   bool
	Approved bool
}

type WorkflowObservation struct {
	Pin         WorkflowPin
	ServerOwned bool
	Active      bool
	Approved    bool
}

type DocumentObservation struct {
	Snapshot                  DocumentSnapshot
	Status                    string
	Deleted                   bool
	NoCapturedEvidence        bool
	CommercialReviewSatisfied bool
	InputRulesSatisfied       bool
	DataRulesSatisfied        bool
	RecipientRulesSatisfied   bool
}

// ArtifactObservation must be derived from verified worker/renderer/storage
// results for this exact source and signature plan. This equality witness is
// not itself a parser, a visual check or an immutable storage read.
type ArtifactObservation struct {
	Signature               SignatureArtifact
	VisiblePDF              PDFPin
	VisibleStampProofSHA256 string
	Verified                bool
}

type FreshObservation struct {
	OrgID         uuid.UUID
	ObservedAt    time.Time
	OriginalActor ExecutorIdentity
	CurrentActor  ExecutorIdentity
	// Bind the originally admitted credential without including a raw token.
	// Adapters derive these opaque commitment values from their private receipt.
	OriginalCredentialBindingSHA256 string
	CurrentCredentialBindingSHA256  string
	// Each deadline is the minimum of the real credential deadline (if finite)
	// and the bounded request admission. Extensions cannot revive the original.
	OriginalAdmissionExpiresAt time.Time
	CurrentAdmissionExpiresAt  time.Time
	CredentialActive           bool
	OperationAuthorized        bool
	Actor                      MemberObservation
	Grantor                    MemberObservation
	Policy                     PolicyObservation
	Grant                      GrantObservation
	Template                   TemplateObservation
	Workflow                   WorkflowObservation
	Document                   DocumentObservation
	Artifacts                  ArtifactObservation
	CeremonyEpoch              time.Time
}

func liveMember(member MemberObservation, orgID, userID uuid.UUID) bool {
	return member.Active && member.OrgID == orgID && member.UserID == userID && visible(member.Name, 800, 200) && validEmail(member.Email) && (member.Role == "owner" || member.Role == "sender")
}

// AuthorizeFreshExecution is a pure fresh-use predicate. Successful return does
// not consume a use, acquire locks, establish observation authority, persist an
// execution or authorize recovery/readback. Caller must atomically consume the
// exact next use with the execution/signature/sealing plan and recheck at commit.
func AuthorizeFreshExecution(policy Policy, grant Grant, execution Execution, observation FreshObservation, now time.Time) error {
	if err := ValidateCommittedExecution(policy, grant, execution); err != nil {
		return err
	}
	if !validTime(now) || !validTime(observation.ObservedAt) || !validTime(observation.OriginalAdmissionExpiresAt) || !validTime(observation.CurrentAdmissionExpiresAt) || !validTime(observation.CeremonyEpoch) {
		return refused("authoritative clock or admission deadlines")
	}
	normalizeTimes(reflect.ValueOf(&observation).Elem())
	now = now.Round(0).UTC()
	p, g, e := policy.snapshot, grant.snapshot, execution.snapshot
	if observation.ObservedAt.After(e.ExecutedAt) || e.ExecutedAt.After(now) || observation.ObservedAt.After(now) || now.Sub(observation.ObservedAt) > MaxObservationAge {
		return refused("observation freshness")
	}
	if !now.Before(observation.OriginalAdmissionExpiresAt) || !now.Before(observation.CurrentAdmissionExpiresAt) || !now.Before(g.ExpiresAt) || now.Before(g.NotBefore) {
		return refused("original admission or grant expired")
	}
	if observation.OrgID != p.OrgID || observation.OriginalActor != p.Executor || observation.CurrentActor != observation.OriginalActor || !observation.CredentialActive || !observation.OperationAuthorized {
		return refused("original executor authority")
	}
	if !validSHA(observation.OriginalCredentialBindingSHA256) || !validSHA(observation.CurrentCredentialBindingSHA256) || subtle.ConstantTimeCompare([]byte(observation.OriginalCredentialBindingSHA256), []byte(observation.CurrentCredentialBindingSHA256)) != 1 {
		return refused("original credential changed")
	}
	if !liveMember(observation.Actor, p.OrgID, p.Executor.UserID) || !liveMember(observation.Grantor, p.OrgID, g.Grantor.UserID) || observation.Grantor.Name != g.Grantor.Name || observation.Grantor.Email != g.Grantor.Email {
		return refused("live named sender or executor membership")
	}
	if !observation.Policy.Active || observation.Policy.Reference != policy.Reference() || observation.Policy.ApprovedBy != p.ApprovedBy || observation.Policy.ApprovedAt != p.ApprovedAt {
		return refused("current approved policy")
	}
	if observation.Grant.Reference != grant.Reference() || observation.Grant.Revoked || observation.Grant.ConsumedUses < 0 || observation.Grant.ConsumedUses >= g.MaxUses || e.UseNumber != observation.Grant.ConsumedUses+1 {
		return refused("current grant or remaining uses")
	}
	if !observation.Template.Active || !observation.Template.Approved || observation.Template.Pin != p.Template {
		return refused("selected template approval")
	}
	if !observation.Workflow.ServerOwned || !observation.Workflow.Active || !observation.Workflow.Approved || observation.Workflow.Pin != p.Workflow {
		return refused("server-owned workflow approval")
	}
	if err := validateDocument(observation.Document.Snapshot); err != nil {
		return refused("current document eligibility")
	}
	if observation.Document.Status != "draft" || observation.Document.Deleted || !observation.Document.NoCapturedEvidence || !observation.Document.CommercialReviewSatisfied || !observation.Document.InputRulesSatisfied || !observation.Document.DataRulesSatisfied || !observation.Document.RecipientRulesSatisfied || observation.Document.Snapshot != e.Document || observation.CeremonyEpoch != e.CeremonyEpoch {
		return refused("exact reviewed document and ceremony")
	}
	if !observation.Artifacts.Verified || observation.Artifacts.Signature != e.Signature || observation.Artifacts.VisiblePDF != e.VisiblePDF || observation.Artifacts.VisibleStampProofSHA256 != e.VisibleStampProofSHA256 {
		return refused("exact prepared signature and visible artifact")
	}
	return nil
}
