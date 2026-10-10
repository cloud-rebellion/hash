// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

const (
	DefinitionVersion        = 1
	MaxDefinitionBytes       = 256 * 1024
	MaxResults               = 100
	PreviewTTL               = 5 * time.Minute
	MutationTimeout          = 10 * time.Second
	KindReviewedDocument     = "reviewed_document_send_v1"
	KindApprovedData         = "approved_data_send_v1"
	ModeReviewedValue        = "reviewed_value"
	ModeDefault              = "approved_default"
	ModeLiteral              = "literal"
	ModeAbsent               = "absent"
	ModeGrantor              = "grantor_field"
	ModeCRM                  = "crm_scalar"
	OperationApproveWorkflow = "workflow.approve"
	OperationRetireWorkflow  = "workflow.retire"
	OperationArchiveWorkflow = "workflow.archive"
	OperationCreateGrant     = "grant.create"
	OperationReviseGrant     = "grant.revise"
	OperationSelfRevoke      = "grant.self_revoke"
	OperationOwnerRevoke     = "grant.owner_revoke"
	OperationCloseRequest    = "request.close"
)

var (
	ErrInvalid     = errors.New("invalid pre-sign authority input")
	ErrConflict    = errors.New("pre-sign authority changed or request already resolved")
	ErrNotFound    = errors.New("pre-sign authority not found")
	ErrUnavailable = errors.New("pre-sign authority dependency unavailable")
	ErrAudit       = errors.New("pre-sign authority audit failed")
)

type ValueRule struct {
	Variable     string  `json:"variable"`
	Mode         string  `json:"mode"`
	Literal      *string `json:"literal,omitempty"`
	GrantorField string  `json:"grantor_field,omitempty"`
	SourceKind   string  `json:"source_kind,omitempty"`
	SourcePath   string  `json:"source_path,omitempty"`
}

type SectionRule struct {
	Section string  `json:"section"`
	Mode    string  `json:"mode"`
	Literal *string `json:"literal,omitempty"`
}

type CRMScope struct {
	ConnectionID uuid.UUID    `json:"connection_id"`
	Generation   int64        `json:"generation,string"`
	Origin       string       `json:"origin"`
	TeamID       string       `json:"team_id"`
	UserID       string       `json:"user_id"`
	Selection    string       `json:"selection"` // fixed_record_set or execution_record_set
	Records      []RecordRule `json:"records"`
}

type RecordRule struct {
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"` // fixed only; execution inputs are checked later
}

type InputRules struct {
	Version             int  `json:"version"`
	SourceSchemaVersion int  `json:"source_schema_version"`
	Standalone          bool `json:"standalone"`
	SignatureFieldsOnly bool `json:"signature_fields_only"`
	AuthorMustBeGrantor bool `json:"author_must_be_grantor"`
}

type DataRules struct {
	Version  int           `json:"version"`
	Values   []ValueRule   `json:"values"`
	Sections []SectionRule `json:"sections"`
	CRM      *CRMScope     `json:"crm,omitempty"`
}

type RecipientRules struct {
	Version                int    `json:"version"`
	Provider               string `json:"provider"` // named_grantor_exact
	Customer               string `json:"customer"` // printed_profile_exact
	Mode                   string `json:"mode"`     // parallel
	ProviderCompanyName    string `json:"provider_company_name"`
	ProviderCompanyID      string `json:"provider_company_id"`
	ProviderAuthorityBasis string `json:"provider_authority_basis"`
}

type WorkflowDefinition struct {
	Version                 int                      `json:"version"`
	ID                      uuid.UUID                `json:"id"`
	PolicyID                uuid.UUID                `json:"policy_id"`
	OrgID                   uuid.UUID                `json:"org_id"`
	Revision                int64                    `json:"revision"`
	Name                    string                   `json:"name"`
	Kind                    string                   `json:"kind"`
	Template                presign.TemplatePin      `json:"template"`
	Executor                presign.ExecutorIdentity `json:"executor"`
	Operation               string                   `json:"operation"`
	InputRules              InputRules               `json:"input_rules"`
	DataRules               DataRules                `json:"data_rules"`
	RecipientRules          RecipientRules           `json:"recipient_rules"`
	MaxGrantDurationSeconds int64                    `json:"max_grant_duration_seconds"`
	MaxUses                 int64                    `json:"max_uses"`
}

type WorkflowIntent struct {
	RequestID        uuid.UUID          `json:"request_id"`
	ExpectedOrgID    uuid.UUID          `json:"expected_org_id"`
	ExpectedUserID   uuid.UUID          `json:"expected_user_id"`
	ExpectedRevision int64              `json:"expected_revision"`
	Definition       WorkflowDefinition `json:"definition"`
}

type ConfirmWorkflowInput struct {
	Intent    WorkflowIntent `json:"intent"`
	Receipt   string         `json:"receipt"`
	Confirmed bool           `json:"confirmed"`
}

type WorkflowPreview struct {
	OrgID            uuid.UUID             `json:"org_id"`
	UserID           uuid.UUID             `json:"user_id"`
	Intent           WorkflowIntent        `json:"intent"`
	DefinitionSHA256 string                `json:"definition_sha256"`
	Rules            presign.RulesSnapshot `json:"rules"`
	Receipt          string                `json:"receipt"`
	ExpiresAt        time.Time             `json:"expires_at"`
}

type GrantIntent struct {
	RequestID        uuid.UUID         `json:"request_id"`
	ExpectedOrgID    uuid.UUID         `json:"expected_org_id"`
	ExpectedUserID   uuid.UUID         `json:"expected_user_id"`
	GrantID          uuid.UUID         `json:"grant_id"`
	ExpectedRevision int64             `json:"expected_revision"`
	Policy           presign.Reference `json:"policy"`
	CompanyName      string            `json:"company_name"`
	CompanyID        string            `json:"company_id"`
	AuthorityBasis   string            `json:"authority_basis"`
	Font             string            `json:"font"`
	NotBefore        time.Time         `json:"not_before"` // zero means actual confirmation time
	ExpiresAt        time.Time         `json:"expires_at"` // absolute; never extended on retry
	MaxUses          int64             `json:"max_uses"`
}

type ConfirmGrantInput struct {
	Intent    GrantIntent `json:"intent"`
	Receipt   string      `json:"receipt"`
	Confirmed bool        `json:"confirmed"`
}

type GrantPreview struct {
	OrgID      uuid.UUID                   `json:"org_id"`
	UserID     uuid.UUID                   `json:"user_id"`
	Intent     GrantIntent                 `json:"intent"`
	Grantor    presign.NamedRepresentative `json:"grantor"`
	Signature  presign.SignatureStyle      `json:"signature"`
	Disclosure presign.CopyPin             `json:"disclosure"`
	Receipt    string                      `json:"receipt"`
	ExpiresAt  time.Time                   `json:"expires_at"`
}

type ResourceMutationInput struct {
	RequestID      uuid.UUID         `json:"request_id"`
	ExpectedOrgID  uuid.UUID         `json:"expected_org_id"`
	ExpectedUserID uuid.UUID         `json:"expected_user_id"`
	Reference      presign.Reference `json:"reference"`
	Confirmed      bool              `json:"confirmed"`
}

type CloseRequestInput struct {
	RequestID      uuid.UUID `json:"request_id"`
	ExpectedOrgID  uuid.UUID `json:"expected_org_id"`
	ExpectedUserID uuid.UUID `json:"expected_user_id"`
	Confirmed      bool      `json:"confirmed"`
}

type Outcome struct {
	OrgID         uuid.UUID         `json:"org_id"`
	UserID        uuid.UUID         `json:"user_id"`
	RequestID     uuid.UUID         `json:"request_id"`
	State         string            `json:"state"`
	Operation     string            `json:"operation"`
	CommandSHA256 string            `json:"command_sha256,omitempty"`
	ResourceKind  string            `json:"resource_kind,omitempty"`
	Reference     presign.Reference `json:"reference"`
	OccurredAt    time.Time         `json:"occurred_at"`
}

type WorkflowView struct {
	OrgID            uuid.UUID              `json:"org_id"`
	UserID           uuid.UUID              `json:"user_id"`
	Definition       WorkflowDefinition     `json:"definition"`
	DefinitionSHA256 string                 `json:"definition_sha256"`
	Policy           presign.PolicySnapshot `json:"policy"`
	PolicyReference  presign.Reference      `json:"policy_reference"`
	CurrentRevision  int64                  `json:"current_revision"`
	Archived         bool                   `json:"archived"`
	Retired          bool                   `json:"retired"`
}

type GrantView struct {
	OrgID              uuid.UUID             `json:"org_id"`
	UserID             uuid.UUID             `json:"user_id"`
	Grant              presign.GrantSnapshot `json:"grant"`
	Reference          presign.Reference     `json:"reference"`
	CurrentRevision    int64                 `json:"current_revision"`
	Revoked            bool                  `json:"revoked"`
	RevocationReason   string                `json:"revocation_reason,omitempty"`
	Expired            bool                  `json:"expired"`
	ConsumedUses       int64                 `json:"consumed_uses"`
	ExecutionAvailable bool                  `json:"execution_available"`
}
