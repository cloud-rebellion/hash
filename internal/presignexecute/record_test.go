// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func pureFixture(t testing.TB) Record {
	t.Helper()
	read := func(name string) []byte {
		b, e := os.ReadFile("testdata/" + name + "-v1.json")
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	p, err := presign.DecodePolicy(read("policy"))
	if err != nil {
		t.Fatal(err)
	}
	g, err := presign.DecodeGrant(read("grant"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := presign.DecodeExecution(read("execution"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := presignregistry.DecodeDataAdmission(read("admission"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeCommand(read("command"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRecord(p, g, e, c, a, uuid.MustParse("00000000-0000-0000-0000-000000000011"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExecutionCommandIndependentCanonicalVector(t *testing.T) {
	r := pureFixture(t)
	expected, err := os.ReadFile("testdata/command-v1.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if r.command.Commitment() != strings.TrimSpace(string(expected)) {
		t.Fatal("independent command commitment differs")
	}
	for _, domain := range []string{presign.ExecutionDomain, presign.GrantDomain, presign.PolicyDomain, presignregistry.DataAdmissionDomain} {
		if digest(domain, r.command.CanonicalJSON()) == r.command.Commitment() {
			t.Fatal("purpose collision")
		}
	}
	for _, changed := range []func(*CommandSnapshot){
		func(s *CommandSnapshot) { s.RequestID = uuid.New() },
		func(s *CommandSnapshot) { s.OriginalCredentialSHA256 = strings.Repeat("a", 64) },
		func(s *CommandSnapshot) { s.Document.Materialization.ID = uuid.New() },
		func(s *CommandSnapshot) { s.Document.Fields[1].ID = uuid.New() },
	} {
		s := r.command.Snapshot()
		changed(&s)
		c, err := NewCommand(s)
		if err != nil || c.Commitment() == r.command.Commitment() {
			t.Fatal("exact command field did not bind")
		}
	}
}

func TestExecutionCommandStrictCapturedBytes(t *testing.T) {
	r := pureFixture(t)
	raw := r.command.CanonicalJSON()
	for name, value := range map[string][]byte{
		"null":                    bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":null`), 1),
		"unknown":                 bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1),
		"duplicate":               bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1),
		"case_alias":              bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"Schema_Version":1`), 1),
		"noncanonical_whitespace": append([]byte(" "), raw...),
		"trailing_object":         append(append([]byte{}, raw...), []byte("{}")...),
		"nul":                     bytes.Replace(raw, []byte(`"member"`), []byte(`"member\u0000"`), 1),
		"oversize":                bytes.Repeat([]byte("x"), presign.MaxSnapshotBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCommand(value); !errors.Is(err, ErrInvalid) {
				t.Fatal("malformed captured command accepted")
			}
		})
	}
	before := r.command.Commitment()
	mutated := r.command.CanonicalJSON()
	mutated[0] = '['
	s := r.command.Snapshot()
	s.Document.Parties[1].Name = "Other"
	if r.command.Commitment() != before || r.command.Snapshot().Document.Parties[1].Name == "Other" {
		t.Fatal("copy mutation escaped")
	}
}

func TestRecordRejectsCommandAdmissionAndExecutionDrift(t *testing.T) {
	r := pureFixture(t)
	for name, change := range map[string]func(*CommandSnapshot){
		"wrong_tenant":             func(s *CommandSnapshot) { s.OrgID = uuid.New(); s.Document.OrgID = s.OrgID },
		"other_original_executor":  func(s *CommandSnapshot) { s.Executor.UserID = uuid.New() },
		"other_policy":             func(s *CommandSnapshot) { s.Policy.ID = uuid.New() },
		"other_grant":              func(s *CommandSnapshot) { s.Grant.ID = uuid.New() },
		"replaced_materialization": func(s *CommandSnapshot) { s.Document.Materialization.ID = uuid.New() },
		"replaced_signature_field": func(s *CommandSnapshot) { s.Document.Fields[1].ID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			s := r.command.Snapshot()
			change(&s)
			c, err := NewCommand(s)
			if err == nil {
				_, err = NewRecord(r.policy, r.grant, r.execution, c, r.admission, r.auditEventID)
			}
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("drifted record accepted")
			}
		})
	}
	if _, err := NewRecord(r.policy, r.grant, r.execution, r.command, r.admission, uuid.Nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing chained audit accepted")
	}
	// Historical integrity is intentionally independent of now/expiry/revocation;
	// fresh admission remains the separate presign predicate and caller fences.
	if _, err := NewRecord(r.policy, r.grant, r.execution, r.command, r.admission, r.auditEventID); err != nil {
		t.Fatal("frozen expired descriptor could not be read")
	}
}

func TestStoredExecutionRejectsEveryDenormalizedBinding(t *testing.T) {
	r := pureFixture(t)
	x, c := r.execution.Snapshot(), r.command.Snapshot()
	row := &generated.PresignExecution{OrgID: x.OrgID, ID: x.ID, DocumentID: x.Document.ID, GrantID: x.Grant.ID, GrantRevision: x.Grant.Revision, GrantSha256: unhex(x.Grant.SHA256), PolicyID: x.Policy.ID, PolicyRevision: x.Policy.Revision, PolicySha256: unhex(x.Policy.SHA256), ExecutorKind: x.Executor.Kind, ExecutorUserID: x.Executor.UserID, ExecutorCredentialID: x.Executor.CredentialID, RequestID: c.RequestID, CommandCanonical: r.command.CanonicalJSON(), CommandSha256: unhex(r.command.Commitment()), OriginalCredentialSha256: unhex(c.OriginalCredentialSHA256), CanonicalExecution: r.execution.CanonicalJSON(), ExecutionSha256: unhex(r.execution.Commitment()), AdmissionCanonical: r.admission.CanonicalJSON(), AdmissionSha256: unhex(r.admission.Commitment()), AuditEventID: r.auditEventID, SignatureID: x.Signature.ID, ProviderRecipientID: x.Signature.RecipientID, ProviderFieldID: x.Signature.FieldID, MaterializationID: x.Document.Materialization.ID, SourceCommitment: unhex(x.Document.Materialization.SourceCommitment), CeremonyEpoch: pgtype.Timestamptz{Time: x.CeremonyEpoch, Valid: true}, ExecutedAt: pgtype.Timestamptz{Time: x.ExecutedAt, Valid: true}, UseNumber: x.UseNumber}
	if _, err := decodeStored(row, r.policy, r.grant); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*generated.PresignExecution){
		"tenant":          func(s *generated.PresignExecution) { s.OrgID = uuid.New() },
		"request":         func(s *generated.PresignExecution) { s.RequestID = uuid.New() },
		"signature":       func(s *generated.PresignExecution) { s.SignatureID = uuid.New() },
		"provider":        func(s *generated.PresignExecution) { s.ProviderRecipientID = uuid.New() },
		"field":           func(s *generated.PresignExecution) { s.ProviderFieldID = uuid.New() },
		"materialization": func(s *generated.PresignExecution) { s.MaterializationID = uuid.New() },
		"use":             func(s *generated.PresignExecution) { s.UseNumber++ },
		"credential":      func(s *generated.PresignExecution) { s.OriginalCredentialSha256 = unhex(strings.Repeat("f", 64)) },
		"canonical": func(s *generated.PresignExecution) {
			s.CanonicalExecution = append([]byte(" "), s.CanonicalExecution...)
		},
		"admission": func(s *generated.PresignExecution) { s.AdmissionSha256 = unhex(strings.Repeat("f", 64)) },
		"epoch":     func(s *generated.PresignExecution) { s.CeremonyEpoch.Time = s.CeremonyEpoch.Time.Add(1) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *row
			change(&copy)
			if _, err := decodeStored(&copy, r.policy, r.grant); !errors.Is(err, ErrIntegrity) {
				t.Fatal("stored tuple drift accepted")
			}
		})
	}
}

func TestDelegatedAuditPayloadBindsExactNonsecretLineage(t *testing.T) {
	r := pureFixture(t)
	payload, err := AuditPayload(r.execution, r.command)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(payload)
	if len(payload) != 10 || bytes.Contains(raw, []byte("storage_key")) || bytes.Contains(raw, []byte("signer_ip")) || bytes.Contains(raw, []byte("original_credential")) {
		t.Fatal("audit leaks private evidence or omits lineage")
	}
	s := r.command.Snapshot()
	s.Document.Fields[1].ID = uuid.New()
	c, _ := NewCommand(s)
	if _, err := AuditPayload(r.execution, c); !errors.Is(err, ErrInvalid) {
		t.Fatal("audit accepted another field")
	}
}
