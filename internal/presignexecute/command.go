// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalid, reason) }
func digest(domain string, raw []byte) string {
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:])
}
func validSHA(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func validateKey(k RequestKey) error {
	if k.OrgID == uuid.Nil || k.RequestID == uuid.Nil || k.Executor.UserID == uuid.Nil ||
		(k.Executor.Kind != presign.ExecutorMember && k.Executor.Kind != presign.ExecutorAPIKey) ||
		(k.Executor.Kind == presign.ExecutorMember && k.Executor.CredentialID != uuid.Nil) ||
		(k.Executor.Kind == presign.ExecutorAPIKey && k.Executor.CredentialID == uuid.Nil) {
		return invalid("original executor request identity")
	}
	return nil
}
func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if e.Encode(v) != nil {
		return nil, invalid("canonical encoding")
	}
	raw := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	if len(raw) == 0 || len(raw) > presign.MaxSnapshotBytes {
		return nil, invalid("canonical byte bound")
	}
	return bytes.Clone(raw), nil
}

func NewCommand(s CommandSnapshot) (Command, error) {
	if err := validateKey(RequestKey{s.OrgID, s.Executor, s.RequestID}); err != nil {
		return Command{}, err
	}
	if s.SchemaVersion != CommandVersion || s.DocumentID == uuid.Nil || s.DocumentID != s.Document.ID ||
		s.OrgID != s.Document.OrgID || s.SourceCommitment != s.Document.Materialization.SourceCommitment ||
		!validSHA(s.SourceCommitment) || !validSHA(s.AdmissionSHA256) || !validSHA(s.OriginalCredentialSHA256) ||
		s.AdmissionSHA256 != s.Document.DataEvidenceSHA256 ||
		s.Policy.ID == uuid.Nil || s.Grant.ID == uuid.Nil || s.Policy.Revision < 1 || s.Policy.Revision > presign.MaxRevision ||
		s.Grant.Revision < 1 || s.Grant.Revision > presign.MaxRevision || !validSHA(s.Policy.SHA256) || !validSHA(s.Grant.SHA256) {
		return Command{}, invalid("exact command document or authority pins")
	}
	raw, err := encode(s)
	if err != nil {
		return Command{}, err
	}
	return Command{snapshot: s, canonical: raw, commitment: digest(CommandDomain, raw)}, nil
}

// DecodeCommand requires exact canonical bytes. Semantically similar reorders,
// case aliases, duplicate/null/unknown fields and noncanonical UUIDs cannot
// replace the captured command after an uncertain write.
func DecodeCommand(raw []byte) (Command, error) {
	if len(raw) == 0 || len(raw) > presign.MaxSnapshotBytes || sourcejson.Validate(raw) != nil {
		return Command{}, invalid("command JSON")
	}
	var s CommandSnapshot
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return Command{}, invalid("command shape")
	}
	c, err := NewCommand(s)
	if err != nil || !bytes.Equal(raw, c.CanonicalJSON()) {
		return Command{}, invalid("canonical command bytes")
	}
	return c, nil
}

func NewRecord(p presign.Policy, g presign.Grant, e presign.Execution, c Command, a presignregistry.DataAdmission, auditEventID uuid.UUID) (Record, error) {
	if err := presign.ValidateCommittedExecution(p, g, e); err != nil {
		return Record{}, invalid("immutable policy/grant/execution lineage")
	}
	decoded, err := DecodeCommand(c.CanonicalJSON())
	if err != nil || decoded.Commitment() != c.Commitment() || auditEventID == uuid.Nil {
		return Record{}, invalid("command or audit identity")
	}
	s, x := c.Snapshot(), e.Snapshot()
	if s.OrgID != x.OrgID || s.Executor != x.Executor || s.DocumentID != x.Document.ID || s.Document != x.Document ||
		s.Policy != e.Snapshot().Policy || s.Grant != e.Snapshot().Grant || s.AdmissionSHA256 != a.Commitment() ||
		presignregistry.ValidateDataAdmissionForExecution(a, p, g, x.Document) != nil {
		return Record{}, invalid("exact admission/command/execution binding")
	}
	return Record{policy: p, grant: g, execution: e, command: c, admission: a, auditEventID: auditEventID}, nil
}

// AuditPayload is the exact nonsecret lineage required by migration82. Caller
// appends it through the real chained Audit.LogTx on the same transaction.
func AuditPayload(e presign.Execution, c Command) (map[string]any, error) {
	x, s := e.Snapshot(), c.Snapshot()
	if _, err := DecodeCommand(c.CanonicalJSON()); err != nil || s.OrgID != x.OrgID || s.Executor != x.Executor ||
		s.Document != x.Document || s.Policy != x.Policy || s.Grant != x.Grant || !validSHA(e.Commitment()) {
		return nil, invalid("audit lineage")
	}
	return map[string]any{"execution_id": x.ID, "execution_sha256": e.Commitment(), "grant_id": x.Grant.ID,
		"grant_revision": x.Grant.Revision, "use_number": x.UseNumber, "request_id": s.RequestID, "command_sha256": c.Commitment(),
		"executor_kind": x.Executor.Kind, "executor_user_id": x.Executor.UserID, "executor_credential_id": x.Executor.CredentialID}, nil
}
