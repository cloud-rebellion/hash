// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion           = 1
	PolicyDomain            = "hash:presign-policy:v1\x00"
	GrantDomain             = "hash:presign-grant:v1\x00"
	ExecutionDomain         = "hash:presign-execution:v1\x00"
	OperationPreSignAndSend = "pre_sign_and_send"
	InputReviewedDocument   = "reviewed_document"
	InputApprovedData       = "approved_data"
	ExecutorMember          = "member"
	ExecutorAPIKey          = "api_key"
	MaxSnapshotBytes        = 64 * 1024
	MaxRevision             = 1_000_000
	MaxRecordedUses         = 1_000_000
	MaxGrantDuration        = 366 * 24 * time.Hour
	MaxObservationAge       = 45 * time.Second
	MaxPDFBytes             = 50 * 1024 * 1024
	MaxPDFPages             = 500
	MaxSignatureBytes       = 1024 * 1024
)

// TemplatePin identifies the selected approved revision, not the latest head.
// Active historical approved revisions can satisfy the same exact pin.
type TemplatePin struct {
	ID            uuid.UUID `json:"id"`
	Version       int64     `json:"version"`
	ContentSHA256 string    `json:"content_sha256"`
	ApprovedBy    uuid.UUID `json:"approved_by"`
	ApprovedAt    time.Time `json:"approved_at"`
}

// WorkflowPin must come from a real server-owned, owner-approved registry.
// A client label, slug or API scope alone is not a workflow authorization.
type WorkflowPin struct {
	ID            uuid.UUID `json:"id"`
	Revision      int64     `json:"revision"`
	ContentSHA256 string    `json:"content_sha256"`
	ApprovedBy    uuid.UUID `json:"approved_by"`
	ApprovedAt    time.Time `json:"approved_at"`
}

// ExecutorIdentity binds a named Hash member, or an actual API credential owned
// by that member. Member execution has a zero CredentialID; its original session
// binding and deadline are checked separately by the caller and predicate.
type ExecutorIdentity struct {
	Kind         string    `json:"kind"`
	UserID       uuid.UUID `json:"user_id"`
	CredentialID uuid.UUID `json:"credential_id"`
}

// RulesSnapshot commits the reviewed input, data and recipient rules. These
// hashes require authoritative registry content and actual dispatch enforcement.
type RulesSnapshot struct {
	InputMode            string `json:"input_mode"`
	InputRulesSHA256     string `json:"input_rules_sha256"`
	DataRulesSHA256      string `json:"data_rules_sha256"`
	RecipientRulesSHA256 string `json:"recipient_rules_sha256"`
}

type PolicySnapshot struct {
	SchemaVersion           int              `json:"schema_version"`
	ID                      uuid.UUID        `json:"id"`
	OrgID                   uuid.UUID        `json:"org_id"`
	Revision                int64            `json:"revision"`
	Template                TemplatePin      `json:"template"`
	Workflow                WorkflowPin      `json:"workflow"`
	Executor                ExecutorIdentity `json:"executor"`
	Operation               string           `json:"operation"`
	Rules                   RulesSnapshot    `json:"rules"`
	MaxGrantDurationSeconds int64            `json:"max_grant_duration_seconds"`
	MaxUses                 int64            `json:"max_uses"`
	ApprovedBy              uuid.UUID        `json:"approved_by"`
	ApprovedAt              time.Time        `json:"approved_at"`
}

type Reference struct {
	ID       uuid.UUID `json:"id"`
	Revision int64     `json:"revision"`
	SHA256   string    `json:"sha256"`
}

// NamedRepresentative contains declared company/authority assertions. Only its
// UserID/name/email are matched to live Hash membership; a company assertion is
// not an external company-register or representative-authority verification.
type NamedRepresentative struct {
	UserID         uuid.UUID `json:"user_id"`
	Name           string    `json:"name"`
	Email          string    `json:"email"`
	CompanyName    string    `json:"company_name"`
	CompanyID      string    `json:"company_id"`
	AuthorityBasis string    `json:"authority_basis"`
}

type SignatureStyle struct {
	Font       string `json:"font"`
	FontSHA256 string `json:"font_sha256"`
}

type CopyPin struct {
	Version int64  `json:"version"`
	SHA256  string `json:"sha256"`
}

type GrantSnapshot struct {
	SchemaVersion int                 `json:"schema_version"`
	ID            uuid.UUID           `json:"id"`
	OrgID         uuid.UUID           `json:"org_id"`
	Revision      int64               `json:"revision"`
	Policy        Reference           `json:"policy"`
	Grantor       NamedRepresentative `json:"grantor"`
	Signature     SignatureStyle      `json:"signature"`
	Disclosure    CopyPin             `json:"disclosure"`
	GrantedAt     time.Time           `json:"granted_at"`
	NotBefore     time.Time           `json:"not_before"`
	ExpiresAt     time.Time           `json:"expires_at"`
	MaxUses       int64               `json:"max_uses"`
}

// ArtifactPin is private storage provenance, not a public response DTO. An
// immutable version is meaningful only together with its object key and digest.
type ArtifactPin struct {
	StorageKey string `json:"storage_key"`
	VersionID  string `json:"version_id"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
}

type PDFPin struct {
	Artifact ArtifactPin `json:"artifact"`
	Pages    int         `json:"pages"`
}

type MaterializationPin struct {
	ID               uuid.UUID `json:"id"`
	Revision         int64     `json:"revision"`
	SourceCommitment string    `json:"source_commitment"`
}

type PartySnapshot struct {
	ID             uuid.UUID `json:"id"`
	Slot           string    `json:"slot"`
	Role           string    `json:"role"`
	Name           string    `json:"name"`
	Email          string    `json:"email"`
	CompanyName    string    `json:"company_name"`
	CompanyID      string    `json:"company_id"`
	AuthorityBasis string    `json:"authority_basis"`
}

// FieldSnapshot uses percentage * 10000 integers, like source-schema-3 fields.
type FieldSnapshot struct {
	ID               uuid.UUID `json:"id"`
	RecipientID      uuid.UUID `json:"recipient_id"`
	Slot             string    `json:"slot"`
	Type             string    `json:"type"`
	Required         bool      `json:"required"`
	Page             int       `json:"page"`
	X                int64     `json:"x"`
	Y                int64     `json:"y"`
	W                int64     `json:"w"`
	H                int64     `json:"h"`
	SourceCommitment string    `json:"source_commitment"`
	OptionsSHA256    string    `json:"options_sha256"`
}

// DocumentSnapshot is a descriptor of the exact reviewed processing artifact.
// Callers must derive it from validated normalized source/history/rows, not from
// request fields. Fixed arrays preserve both parties and prohibit extra fields.
type DocumentSnapshot struct {
	ID                   uuid.UUID          `json:"id"`
	OrgID                uuid.UUID          `json:"org_id"`
	SenderID             uuid.UUID          `json:"sender_id"`
	ParentDocumentID     uuid.UUID          `json:"parent_document_id"`
	Kind                 string             `json:"kind"`
	SourceSchemaVersion  int                `json:"source_schema_version"`
	RequiresSignature    bool               `json:"requires_signature"`
	SigningMode          string             `json:"signing_mode"`
	Template             TemplatePin        `json:"template"`
	Materialization      MaterializationPin `json:"materialization"`
	BasePDF              PDFPin             `json:"base_pdf"`
	SigningPlanSHA256    string             `json:"signing_plan_sha256"`
	BrandingSHA256       string             `json:"branding_sha256"`
	ValuesSHA256         string             `json:"values_sha256"`
	SectionsSHA256       string             `json:"sections_sha256"`
	ReviewEvidenceSHA256 string             `json:"review_evidence_sha256"`
	DataEvidenceSHA256   string             `json:"data_evidence_sha256"`
	Parties              [2]PartySnapshot   `json:"parties"`
	Fields               [2]FieldSnapshot   `json:"fields"`
}

type SignatureArtifact struct {
	ID          uuid.UUID      `json:"id"`
	RecipientID uuid.UUID      `json:"recipient_id"`
	FieldID     uuid.UUID      `json:"field_id"`
	TypedName   string         `json:"typed_name"`
	Style       SignatureStyle `json:"style"`
	Image       ArtifactPin    `json:"image"`
}

type ExecutionSnapshot struct {
	SchemaVersion           int               `json:"schema_version"`
	ID                      uuid.UUID         `json:"id"`
	OrgID                   uuid.UUID         `json:"org_id"`
	Policy                  Reference         `json:"policy"`
	Grant                   Reference         `json:"grant"`
	Executor                ExecutorIdentity  `json:"executor"`
	Document                DocumentSnapshot  `json:"document"`
	CeremonyEpoch           time.Time         `json:"ceremony_epoch"`
	ExecutedAt              time.Time         `json:"executed_at"`
	UseNumber               int64             `json:"use_number"`
	Signature               SignatureArtifact `json:"signature"`
	VisiblePDF              PDFPin            `json:"visible_pdf"`
	VisibleStampProofSHA256 string            `json:"visible_stamp_proof_sha256"`
}

// Private snapshots and canonical bytes can only be populated by constructors.
type Policy struct {
	snapshot   PolicySnapshot
	canonical  []byte
	commitment string
}
type Grant struct {
	snapshot   GrantSnapshot
	canonical  []byte
	commitment string
}
type Execution struct {
	snapshot   ExecutionSnapshot
	canonical  []byte
	commitment string
}

func (p Policy) Snapshot() PolicySnapshot       { return p.snapshot }
func (g Grant) Snapshot() GrantSnapshot         { return g.snapshot }
func (e Execution) Snapshot() ExecutionSnapshot { return e.snapshot }
func (p Policy) Commitment() string             { return p.commitment }
func (g Grant) Commitment() string              { return g.commitment }
func (e Execution) Commitment() string          { return e.commitment }
func (p Policy) CanonicalJSON() []byte          { return append([]byte(nil), p.canonical...) }
func (g Grant) CanonicalJSON() []byte           { return append([]byte(nil), g.canonical...) }
func (e Execution) CanonicalJSON() []byte       { return append([]byte(nil), e.canonical...) }

func (p Policy) Reference() Reference {
	return Reference{ID: p.snapshot.ID, Revision: p.snapshot.Revision, SHA256: p.commitment}
}
func (g Grant) Reference() Reference {
	return Reference{ID: g.snapshot.ID, Revision: g.snapshot.Revision, SHA256: g.commitment}
}
