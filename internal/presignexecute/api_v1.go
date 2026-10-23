// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"time"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
)

// EligibilityV1 is an authenticated read projection, never a dispatch receipt.
// Unsupported documents omit Source. The preview and confirming transaction
// independently re-read the exact source and original actor before any effect.
type EligibilityV1 struct {
	SchemaVersion int               `json:"schema_version"`
	OrgID         uuid.UUID         `json:"org_id"`
	UserID        uuid.UUID         `json:"user_id"`
	DocumentID    uuid.UUID         `json:"document_id"`
	Eligible      bool              `json:"eligible"`
	Source        *EligibleSourceV1 `json:"source,omitempty"`
}

type EligibleSourceV1 struct {
	DocumentUpdatedAt       time.Time `json:"document_updated_at"`
	MaterializationID       uuid.UUID `json:"materialization_id"`
	MaterializationRevision int64     `json:"materialization_revision"`
	SourceCommitment        string    `json:"source_commitment"`
}

// IntentV1 selects immutable source and authority. None of these client values
// establishes authority; the engine derives and compares the actual rows.
type IntentV1 struct {
	RequestID               uuid.UUID         `json:"request_id"`
	ExpectedOrgID           uuid.UUID         `json:"expected_org_id"`
	ExpectedUserID          uuid.UUID         `json:"expected_user_id"`
	DocumentID              uuid.UUID         `json:"document_id"`
	DocumentUpdatedAt       time.Time         `json:"document_updated_at"`
	MaterializationID       uuid.UUID         `json:"materialization_id"`
	MaterializationRevision int64             `json:"materialization_revision"`
	SourceCommitment        string            `json:"source_commitment"`
	Policy                  presign.Reference `json:"policy"`
	Grant                   presign.Reference `json:"grant"`
	LawfulBasis             string            `json:"lawful_basis"`
}

type ConfirmV1 struct {
	Intent    IntentV1 `json:"intent"`
	Receipt   string   `json:"receipt"`
	Confirmed bool     `json:"confirmed"`
}

// PreviewV1 is original-session-bound review, never an execution or a grant use.
// It contains no source text, credential, object key or provider VersionId.
type PreviewV1 struct {
	SchemaVersion int       `json:"schema_version"`
	OrgID         uuid.UUID `json:"org_id"`
	UserID        uuid.UUID `json:"user_id"`
	Intent        IntentV1  `json:"intent"`
	Receipt       string    `json:"receipt"`
	ExpiresAt     time.Time `json:"expires_at"`
	ProviderName  string    `json:"provider_name"`
	ProviderEmail string    `json:"provider_email"`
	CustomerName  string    `json:"customer_name"`
	CustomerEmail string    `json:"customer_email"`
	Disclosure    string    `json:"disclosure"`
	RemainingUses int64     `json:"remaining_uses"`
}

type ExecutionReferenceV1 struct {
	ID     uuid.UUID `json:"id"`
	SHA256 string    `json:"sha256"`
}

// ViewV1 reports the durable original request. The closed projection omits the
// committed-only fields. A missing request is unconfirmed, never a closed one.
type ViewV1 struct {
	SchemaVersion int              `json:"schema_version"`
	OrgID         uuid.UUID        `json:"org_id"`
	UserID        uuid.UUID        `json:"user_id"`
	RequestID     uuid.UUID        `json:"request_id"`
	State         string           `json:"state"`
	Result        *CommittedViewV1 `json:"result,omitempty"`
}

type CommittedViewV1 struct {
	CommandSHA256           string               `json:"command_sha256"`
	Execution               ExecutionReferenceV1 `json:"execution"`
	DocumentID              uuid.UUID            `json:"document_id"`
	MaterializationID       uuid.UUID            `json:"materialization_id"`
	MaterializationRevision int64                `json:"materialization_revision"`
	SourceCommitment        string               `json:"source_commitment"`
	VisiblePDFSHA256        string               `json:"visible_pdf_sha256"`
	PageCount               int                  `json:"page_count"`
	UseNumber               int64                `json:"use_number"`
	Publication             string               `json:"publication"`
}

type CloseV1 struct {
	RequestID      uuid.UUID `json:"request_id"`
	ExpectedOrgID  uuid.UUID `json:"expected_org_id"`
	ExpectedUserID uuid.UUID `json:"expected_user_id"`
	Confirmed      bool      `json:"confirmed"`
}
