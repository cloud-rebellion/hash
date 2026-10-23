// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package amendments describes later changes without rewriting completed evidence.
package amendments

import (
	"github.com/google/uuid"
	"time"
)

const SchemaV1 = "hash-later-amendments-v1"

type ModeV1 string

const (
	SignatureV1       ModeV1 = "signature"
	AcknowledgementV1 ModeV1 = "acknowledgement"
	AgreedNoticeV1    ModeV1 = "agreed_notice"
)

// A legacy clause is an attributed owner's review, never signatory consent or
// a legal determination. Frozen policy IDs are resolved from native records;
// their text, allowed modes and conditions cannot be supplied by a client.
type BasisV1 struct {
	Kind               string     `json:"kind"`
	FrozenPolicyID     *uuid.UUID `json:"frozen_policy_id,omitempty"`
	ClauseReference    string     `json:"clause_reference,omitempty"`
	ReviewedClause     string     `json:"reviewed_clause,omitempty"`
	AllowedModes       []ModeV1   `json:"allowed_modes,omitempty"`
	AllowedChannels    []string   `json:"allowed_channels,omitempty"`
	EffectiveCondition string     `json:"effective_condition,omitempty"`
}

type CreateV1 struct {
	RequestID                 uuid.UUID  `json:"request_id"`
	ExpectedHeadID            *uuid.UUID `json:"expected_head_id"`
	ExpectedHeadRevision      string     `json:"expected_head_revision"`
	AmendmentDocumentID       uuid.UUID  `json:"amendment_document_id"`
	ExpectedDocumentUpdatedAt time.Time  `json:"expected_document_updated_at"`
	Mode                      ModeV1     `json:"mode"`
	Basis                     BasisV1    `json:"basis"`
	// Explicit confirmation that the independently rendered draft identifies the
	// original agreement, proposed file set and selected process. This is the
	// owner's attributed review; the server never calls it a signer's acceptance.
	CoverReviewed bool `json:"cover_reviewed"`
}

type OriginalV1 struct {
	DocumentID              uuid.UUID `json:"document_id"`
	Name                    string    `json:"name"`
	CompletedAt             time.Time `json:"completed_at"`
	FinalPDFSHA256          string    `json:"final_pdf_sha256"`
	ReportSHA256            string    `json:"report_sha256"`
	PackageCommitmentSHA256 string    `json:"package_commitment_sha256,omitempty"`
}

type BasisRecordV1 struct {
	BasisV1
	SHA256      string    `json:"sha256"`
	ReviewedBy  uuid.UUID `json:"reviewed_by"`
	ReviewedAt  time.Time `json:"reviewed_at"`
	Attribution string    `json:"attribution"`
}

type DeliveryV1 struct {
	AccessID        uuid.UUID  `json:"access_id"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	EmailDeliveryID uuid.UUID  `json:"email_delivery_id"`
	RecipientEmail  string     `json:"recipient_email"`
	// queued | retrying | provider_accepted | failed. Provider acceptance does
	// not prove recipient delivery, acknowledgement, signature or effectiveness.
	State              string     `json:"state"`
	Attempts           int32      `json:"attempts"`
	ProviderAcceptedAt *time.Time `json:"provider_accepted_at,omitempty"`
}

type NoticeV1 struct {
	ID                   uuid.UUID    `json:"id"`
	RequestID            uuid.UUID    `json:"request_id"`
	Subject              string       `json:"subject"`
	Text                 string       `json:"text"`
	SHA256               string       `json:"sha256"`
	FileCommitmentSHA256 string       `json:"file_commitment_sha256"`
	IssuedAt             time.Time    `json:"issued_at"`
	IssuedBy             uuid.UUID    `json:"issued_by"`
	Deliveries           []DeliveryV1 `json:"deliveries"`
	// No SMTP status is projected as a verified delivery receipt. A future
	// authenticated provider-receipt adapter may append separate observations.
	VerifiedReceipts []ReceiptV1 `json:"verified_receipts"`
}
type ReceiptV1 struct {
	ID              uuid.UUID `json:"id"`
	EmailDeliveryID uuid.UUID `json:"email_delivery_id"`
	Kind            string    `json:"kind"`
	ObservedAt      time.Time `json:"observed_at"`
}

type RecordV1 struct {
	ID                   uuid.UUID     `json:"id"`
	RequestID            uuid.UUID     `json:"request_id"`
	Revision             string        `json:"revision"`
	PredecessorID        *uuid.UUID    `json:"predecessor_id"`
	DocumentID           uuid.UUID     `json:"document_id"`
	DocumentName         string        `json:"document_name"`
	DocumentStatus       string        `json:"document_status"`
	Mode                 ModeV1        `json:"mode"`
	Basis                BasisRecordV1 `json:"basis"`
	FileCommitmentSHA256 string        `json:"file_commitment_sha256"`
	CreatedAt            time.Time     `json:"created_at"`
	CreatedBy            uuid.UUID     `json:"created_by"`
	Notice               *NoticeV1     `json:"notice,omitempty"`
}

type InventoryV1 struct {
	Schema             string    `json:"schema"`
	OriginalDocumentID uuid.UUID `json:"original_document_id"`
	// Head means latest proposed immutable relation, not legal effectiveness.
	HeadID         *uuid.UUID      `json:"head_id"`
	HeadRevision   string          `json:"head_revision"`
	Original       OriginalV1      `json:"original"`
	CanCreate      bool            `json:"can_create"`
	FrozenPolicies []BasisRecordV1 `json:"frozen_policies"`
	Amendments     []RecordV1      `json:"amendments"`
}

type OutcomeV1 struct {
	State                  string    `json:"state"` // committed | unchanged | unknown
	RequestID              uuid.UUID `json:"request_id"`
	ReconciliationRequired bool      `json:"reconciliation_required,omitempty"`
	Amendment              *RecordV1 `json:"amendment,omitempty"`
	Notice                 *NoticeV1 `json:"notice,omitempty"`
}

type IssueNoticeV1 struct {
	RequestID                 uuid.UUID `json:"request_id"`
	ExpectedHeadRevision      string    `json:"expected_head_revision"`
	ExpectedDocumentUpdatedAt time.Time `json:"expected_document_updated_at"`
	Subject                   string    `json:"subject"`
	Text                      string    `json:"text"`
	RecipientEmails           []string  `json:"recipient_emails"`
	Reviewed                  bool      `json:"reviewed"`
}

type CandidateRelationV1 struct {
	Schema             string    `json:"schema"`
	OriginalDocumentID uuid.UUID `json:"original_document_id"`
	Amendment          RecordV1  `json:"amendment"`
}

// FileSetV1 is private persisted native metadata, never a staff/public request.
// Actual notices must verify exact objects and retain them before dispatch.
type FileV1 struct {
	Position           int16     `json:"position"`
	DocumentID         uuid.UUID `json:"document_id"`
	Title              string    `json:"title"`
	Key                string    `json:"key"`
	VersionID          string    `json:"version_id"`
	SHA256             string    `json:"sha256"`
	Bytes              int64     `json:"bytes"`
	Pages              int32     `json:"pages"`
	IntakeReportSHA256 string    `json:"intake_report_sha256"`
}
type FileSetV1 struct {
	Schema                 string     `json:"schema"`
	DocumentID             uuid.UUID  `json:"document_id"`
	SourceCommitmentSHA256 string     `json:"source_commitment_sha256"`
	PackageID              *uuid.UUID `json:"package_id"`
	PackageGeneration      string     `json:"package_generation"`
	Files                  []FileV1   `json:"files"`
}

type RevokeOutcomeV1 struct {
	Schema                 string     `json:"schema"`
	State                  string     `json:"state"`
	AccessID               uuid.UUID  `json:"access_id"`
	RevokedAt              *time.Time `json:"revoked_at,omitempty"`
	ReconciliationRequired bool       `json:"reconciliation_required,omitempty"`
}
