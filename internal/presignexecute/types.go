// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"errors"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

const (
	CommandVersion     = 1
	CommandDomain      = "hash:presign-execution-command:v1\x00"
	SignatureKind      = "delegated_grant_v1"
	AuditKindCommitted = "presign.execution.committed"
	AuditKindClosed    = "presign.execution.request.closed"
)

var (
	ErrInvalid   = errors.New("invalid delegated execution persistence evidence")
	ErrConflict  = errors.New("delegated execution changed or request already resolved")
	ErrIntegrity = errors.New("delegated execution stored evidence is inconsistent")
)

// RequestKey is an identity selector, never proof of the caller's authority.
// Member keys have a zero CredentialID; the original signed-session hash is
// retained in the command instead. API keys bind the actual credential UUID.
type RequestKey struct {
	OrgID     uuid.UUID
	Executor  presign.ExecutorIdentity
	RequestID uuid.UUID
}

type CommandSnapshot struct {
	SchemaVersion            int                      `json:"schema_version"`
	OrgID                    uuid.UUID                `json:"org_id"`
	Executor                 presign.ExecutorIdentity `json:"executor"`
	RequestID                uuid.UUID                `json:"request_id"`
	DocumentID               uuid.UUID                `json:"document_id"`
	Document                 presign.DocumentSnapshot `json:"document"`
	Policy                   presign.Reference        `json:"policy"`
	Grant                    presign.Reference        `json:"grant"`
	SourceCommitment         string                   `json:"source_commitment"`
	AdmissionSHA256          string                   `json:"admission_sha256"`
	OriginalCredentialSHA256 string                   `json:"original_credential_sha256"`
}

type Command struct {
	snapshot   CommandSnapshot
	canonical  []byte
	commitment string
}

func (c Command) Snapshot() CommandSnapshot { return c.snapshot }
func (c Command) CanonicalJSON() []byte     { return append([]byte(nil), c.canonical...) }
func (c Command) Commitment() string        { return c.commitment }
func (c Command) RequestKey() RequestKey {
	return RequestKey{OrgID: c.snapshot.OrgID, Executor: c.snapshot.Executor, RequestID: c.snapshot.RequestID}
}

// Record contains immutable typed evidence, not live authority or a SQL commit.
type Record struct {
	policy       presign.Policy
	grant        presign.Grant
	execution    presign.Execution
	command      Command
	admission    presignregistry.DataAdmission
	auditEventID uuid.UUID
}

func (r Record) Execution() presign.Execution { return r.execution }
func (r Record) Command() Command             { return r.command }
func (r Record) AuditEventID() uuid.UUID      { return r.auditEventID }

// Outcome has no raw credentials, IP/UA or claim of fresh grant permission.
// The execution and admission are private evidence with internal storage pins.
type Outcome struct {
	Key    RequestKey
	State  string
	Record *Record
}
