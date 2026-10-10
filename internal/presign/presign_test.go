// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixtureID(n byte) uuid.UUID { var id uuid.UUID; id[15] = n; return id }
func fixtureSHA(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// These are synthetic pure descriptors, not authenticated members, a workflow
// registry, a renderer, actual storage versions, or committed database rows.
func fixture(t *testing.T) (Policy, Grant, Execution, FreshObservation, time.Time) {
	t.Helper()
	approved := time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC)
	policy, err := NewPolicy(PolicySnapshot{
		SchemaVersion: 1, ID: fixtureID(1), OrgID: fixtureID(2), Revision: 1,
		Template: TemplatePin{ID: fixtureID(3), Version: 7, ContentSHA256: fixtureSHA("template"), ApprovedBy: fixtureID(4), ApprovedAt: approved.Add(-time.Hour)},
		Workflow: WorkflowPin{ID: fixtureID(5), Revision: 2, ContentSHA256: fixtureSHA("workflow"), ApprovedBy: fixtureID(4), ApprovedAt: approved.Add(-30 * time.Minute)},
		Executor: ExecutorIdentity{Kind: ExecutorMember, UserID: fixtureID(6)}, Operation: OperationPreSignAndSend,
		Rules:                   RulesSnapshot{InputMode: InputReviewedDocument, InputRulesSHA256: fixtureSHA("input rules"), DataRulesSHA256: fixtureSHA("data rules"), RecipientRulesSHA256: fixtureSHA("recipient rules")},
		MaxGrantDurationSeconds: 86400, MaxUses: 2, ApprovedBy: fixtureID(4), ApprovedAt: approved,
	})
	if err != nil {
		t.Fatal(err)
	}
	granted := approved.Add(time.Minute)
	grant, err := NewGrant(GrantSnapshot{
		SchemaVersion: 1, ID: fixtureID(7), OrgID: fixtureID(2), Revision: 1, Policy: policy.Reference(),
		Grantor:   NamedRepresentative{UserID: fixtureID(6), Name: "Åsa Provider", Email: "Asa.Provider@example.test", CompanyName: "Provider AB", CompanyID: "556000-0001", AuthorityBasis: "Authorized representative"},
		Signature: SignatureStyle{Font: "Caveat", FontSHA256: fixtureSHA("font")}, Disclosure: CopyPin{Version: 1, SHA256: fixtureSHA("delegation copy")},
		GrantedAt: granted, NotBefore: granted, ExpiresAt: granted.Add(24 * time.Hour), MaxUses: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	observed := approved.Add(2 * time.Minute)
	materialization := MaterializationPin{ID: fixtureID(8), Revision: 3, SourceCommitment: fixtureSHA("source")}
	doc := DocumentSnapshot{
		ID: fixtureID(9), OrgID: fixtureID(2), SenderID: fixtureID(6), Kind: "pdf", SourceSchemaVersion: 3, RequiresSignature: true, SigningMode: "parallel",
		Template: policy.Snapshot().Template, Materialization: materialization,
		BasePDF:           PDFPin{Artifact: ArtifactPin{StorageKey: "org/document/source.pdf", VersionID: "source-v1", SHA256: fixtureSHA("base pdf"), Bytes: 1000}, Pages: 3},
		SigningPlanSHA256: fixtureSHA("plan"), BrandingSHA256: fixtureSHA("branding"), ValuesSHA256: fixtureSHA("values"), SectionsSHA256: fixtureSHA("sections"), ReviewEvidenceSHA256: fixtureSHA("review"), DataEvidenceSHA256: fixtureSHA("data proof"),
		Parties: [2]PartySnapshot{
			{ID: fixtureID(10), Slot: "customer", Role: "customer", Name: "Customer Person", Email: "customer@example.test", CompanyName: "Customer AB", CompanyID: "556000-0002", AuthorityBasis: "Authorized representative"},
			{ID: fixtureID(11), Slot: "provider", Role: "provider", Name: grant.Snapshot().Grantor.Name, Email: grant.Snapshot().Grantor.Email, CompanyName: grant.Snapshot().Grantor.CompanyName, CompanyID: grant.Snapshot().Grantor.CompanyID, AuthorityBasis: grant.Snapshot().Grantor.AuthorityBasis},
		},
		Fields: [2]FieldSnapshot{
			{ID: fixtureID(12), RecipientID: fixtureID(10), Slot: "customer", Type: "signature", Required: true, Page: 3, X: 100000, Y: 420000, W: 800000, H: 70000, SourceCommitment: materialization.SourceCommitment, OptionsSHA256: fixtureSHA("customer options")},
			{ID: fixtureID(13), RecipientID: fixtureID(11), Slot: "provider", Type: "signature", Required: true, Page: 3, X: 100000, Y: 790000, W: 800000, H: 70000, SourceCommitment: materialization.SourceCommitment, OptionsSHA256: fixtureSHA("provider options")},
		},
	}
	execution, err := NewExecution(ExecutionSnapshot{
		SchemaVersion: 1, ID: fixtureID(14), OrgID: fixtureID(2), Policy: policy.Reference(), Grant: grant.Reference(), Executor: policy.Snapshot().Executor, Document: doc,
		CeremonyEpoch: observed, ExecutedAt: observed, UseNumber: 1,
		Signature: SignatureArtifact{ID: fixtureID(15), RecipientID: fixtureID(11), FieldID: fixtureID(13), TypedName: grant.Snapshot().Grantor.Name, Style: grant.Snapshot().Signature,
			Image: ArtifactPin{StorageKey: "org/document/provider.html", VersionID: "signature-v1", SHA256: fixtureSHA("signature image"), Bytes: 300}},
		VisiblePDF:              PDFPin{Artifact: ArtifactPin{StorageKey: "org/document/provider-visible.pdf", VersionID: "visible-v1", SHA256: fixtureSHA("visible pdf"), Bytes: 1100}, Pages: 3},
		VisibleStampProofSHA256: fixtureSHA("visible stamp proof"),
	})
	if err != nil {
		t.Fatal(err)
	}
	p, g := policy.Snapshot(), grant.Snapshot()
	member := MemberObservation{OrgID: p.OrgID, UserID: g.Grantor.UserID, Name: g.Grantor.Name, Email: g.Grantor.Email, Role: "sender", Active: true}
	observation := FreshObservation{
		OrgID: p.OrgID, ObservedAt: observed, OriginalActor: p.Executor, CurrentActor: p.Executor,
		OriginalCredentialBindingSHA256: fixtureSHA("original credential receipt"), CurrentCredentialBindingSHA256: fixtureSHA("original credential receipt"),
		OriginalAdmissionExpiresAt: observed.Add(30 * time.Second), CurrentAdmissionExpiresAt: observed.Add(30 * time.Second), CredentialActive: true, OperationAuthorized: true, Actor: member, Grantor: member,
		Policy: PolicyObservation{Reference: policy.Reference(), ApprovedBy: p.ApprovedBy, ApprovedAt: p.ApprovedAt, Active: true},
		Grant:  GrantObservation{Reference: grant.Reference()}, Template: TemplateObservation{Pin: p.Template, Active: true, Approved: true},
		Workflow: WorkflowObservation{Pin: p.Workflow, ServerOwned: true, Active: true, Approved: true},
		Document: DocumentObservation{Snapshot: doc, Status: "draft", NoCapturedEvidence: true, CommercialReviewSatisfied: true, InputRulesSatisfied: true, DataRulesSatisfied: true, RecipientRulesSatisfied: true}, CeremonyEpoch: observed,
		Artifacts: ArtifactObservation{Signature: execution.Snapshot().Signature, VisiblePDF: execution.Snapshot().VisiblePDF, VisibleStampProofSHA256: execution.Snapshot().VisibleStampProofSHA256, Verified: true},
	}
	return policy, grant, execution, observation, observed.Add(time.Second)
}

func TestVersionOneIndependentCanonicalVectors(t *testing.T) {
	p, g, e, _, _ := fixture(t)
	for _, item := range []struct {
		name             string
		raw              []byte
		commitment, want string
	}{
		{"policy", p.CanonicalJSON(), p.Commitment(), "7014f6c7beeb7c2e1de19293f867b4b36d52897912c75397c0a14111f5e6490f"},
		{"grant", g.CanonicalJSON(), g.Commitment(), "2a5978641227f120e8d8b976b1fc414170df9af294fbcff44f885eddf6af2843"},
		{"execution", e.CanonicalJSON(), e.Commitment(), "4ce57707fe60b4100a2fd4af21df23b4ecbde1de69a299461958f697138bd955"},
	} {
		t.Run(item.name, func(t *testing.T) {
			// These checked-in exact bytes were independently declared and encoded
			// with Python's standard JSON/SHA-256; no Go implementation was executed
			// to produce either the expectations or their purpose-separated hashes.
			wantRaw, err := os.ReadFile("testdata/" + item.name + "-v1.json")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(item.raw, wantRaw) || item.commitment != item.want {
				t.Fatal("version-one canonical evidence changed")
			}
		})
	}
}

func TestSnapshotsRoundTripWithSeparateCommitments(t *testing.T) {
	p, g, e, _, _ := fixture(t)
	p2, err := DecodePolicy(p.CanonicalJSON())
	if err != nil {
		t.Fatal(err)
	}
	g2, err := DecodeGrant(g.CanonicalJSON())
	if err != nil {
		t.Fatal(err)
	}
	e2, err := DecodeExecution(e.CanonicalJSON())
	if err != nil {
		t.Fatal(err)
	}
	if p2.Commitment() != p.Commitment() || g2.Commitment() != g.Commitment() || e2.Commitment() != e.Commitment() {
		t.Fatal("round trip changed a commitment")
	}
	if err := ValidateCommittedExecution(p2, g2, e2); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		raw                []byte
		domain, commitment string
	}{{p.CanonicalJSON(), PolicyDomain, p.Commitment()}, {g.CanonicalJSON(), GrantDomain, g.Commitment()}, {e.CanonicalJSON(), ExecutionDomain, e.Commitment()}} {
		sum := sha256.Sum256(append([]byte(item.domain), item.raw...))
		if hex.EncodeToString(sum[:]) != item.commitment || bytes.HasSuffix(item.raw, []byte{'\n'}) {
			t.Fatal("canonical commitment or framing mismatch")
		}
		for _, other := range []string{PolicyDomain, GrantDomain, ExecutionDomain, "hash.html-source.v3\x00"} {
			if other == item.domain {
				continue
			}
			otherSum := sha256.Sum256(append([]byte(other), item.raw...))
			if hex.EncodeToString(otherSum[:]) == item.commitment {
				t.Fatal("purpose collision")
			}
		}
	}
}

func TestSnapshotsDoNotExposeMutableCanonicalState(t *testing.T) {
	p, g, e, _, _ := fixture(t)
	ps, gs, es := p.Snapshot(), g.Snapshot(), e.Snapshot()
	ps.Rules.InputRulesSHA256 = fixtureSHA("tampered rules")
	gs.Grantor.Name = "Other Name"
	es.Document.Parties[1].Name = "Other Name"
	for _, raw := range [][]byte{p.CanonicalJSON(), g.CanonicalJSON(), e.CanonicalJSON()} {
		raw[0] = '['
	}
	if p.Snapshot() == ps || g.Snapshot() == gs || e.Snapshot() == es {
		t.Fatal("snapshot accessor mutated private state")
	}
	if err := ValidateCommittedExecution(p, g, e); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 20; j++ {
				copy := e.Snapshot()
				copy.Document.Fields[1].Y = 0
				raw := e.CanonicalJSON()
				raw[0] = '['
				if e.Snapshot().Document.Fields[1].Y != 790000 {
					t.Error("concurrent copy mutated state")
				}
			}
		}()
	}
	wait.Wait()
	for _, value := range []any{p, g, e} {
		raw, err := json.Marshal(value)
		if err != nil || len(raw) < 3 || bytes.Equal(raw, []byte("{}")) {
			t.Fatal("immutable snapshot marshaling lost evidence")
		}
	}
	for _, value := range []any{Policy{}, Grant{}, Execution{}} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatal("zero snapshot silently marshaled")
		}
	}
}

func mutateJSON(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	out, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestStrictDecodeRejectsAmbiguousOrIncompleteEvidence(t *testing.T) {
	p, g, e, _, _ := fixture(t)
	for _, target := range []struct {
		name   string
		raw    []byte
		decode func([]byte) error
	}{
		{"policy", p.CanonicalJSON(), func(raw []byte) error { _, err := DecodePolicy(raw); return err }},
		{"grant", g.CanonicalJSON(), func(raw []byte) error { _, err := DecodeGrant(raw); return err }},
		{"execution", e.CanonicalJSON(), func(raw []byte) error { _, err := DecodeExecution(raw); return err }},
	} {
		t.Run(target.name, func(t *testing.T) {
			cases := map[string][]byte{
				"duplicate":             append([]byte(`{"schema_version":1,`), target.raw[1:]...),
				"escaped_duplicate":     append([]byte(`{"schema\u005fversion":1,`), target.raw[1:]...),
				"additional_case_alias": append([]byte(`{"Schema_version":1,`), target.raw[1:]...),
				"unknown":               append([]byte(`{"unused":true,`), target.raw[1:]...),
				"trailing":              append(append([]byte(nil), target.raw...), []byte(` {}`)...),
				"null_root":             []byte(`null`), "array_root": []byte(`[]`), "oversize": bytes.Repeat([]byte(" "), MaxSnapshotBytes+1),
				"invalid_utf8":       append([]byte{0xff}, target.raw...),
				"unpaired_surrogate": append([]byte(`{"unused":"\ud800",`), target.raw[1:]...),
				"missing":            mutateJSON(t, target.raw, func(v map[string]any) { delete(v, "schema_version") }),
				"null_required":      mutateJSON(t, target.raw, func(v map[string]any) { v["schema_version"] = nil }),
				"wrong_schema":       mutateJSON(t, target.raw, func(v map[string]any) { v["schema_version"] = 2 }),
				"float_version":      bytes.Replace(target.raw, []byte(`"schema_version":1`), []byte(`"schema_version":1.0`), 1),
				"string_version":     mutateJSON(t, target.raw, func(v map[string]any) { v["schema_version"] = "1" }),
				"uuid_alias":         mutateJSON(t, target.raw, func(v map[string]any) { v["id"] = "00000000000000000000000000000001" }),
			}
			for name, raw := range cases {
				t.Run(name, func(t *testing.T) {
					if err := target.decode(raw); !errors.Is(err, ErrInvalid) {
						t.Fatalf("malformed evidence accepted: %v", err)
					}
				})
			}
		})
	}
	for name, raw := range map[string][]byte{
		"null_nested":            mutateJSON(t, p.CanonicalJSON(), func(v map[string]any) { v["template"] = nil }),
		"unknown_nested":         mutateJSON(t, p.CanonicalJSON(), func(v map[string]any) { v["template"].(map[string]any)["slug"] = "trusted-by-label" }),
		"nested_alias":           mutateJSON(t, p.CanonicalJSON(), func(v map[string]any) { v["template"].(map[string]any)["Version"] = 7 }),
		"noncanonical_timestamp": mutateJSON(t, p.CanonicalJSON(), func(v map[string]any) { v["approved_at"] = "2026-10-10T10:00:00+00:00" }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePolicy(raw); !errors.Is(err, ErrInvalid) {
				t.Fatal("nested ambiguity accepted")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"null_boolean":    mutateJSON(t, e.CanonicalJSON(), func(v map[string]any) { v["document"].(map[string]any)["requires_signature"] = nil }),
		"missing_boolean": mutateJSON(t, e.CanonicalJSON(), func(v map[string]any) { delete(v["document"].(map[string]any), "requires_signature") }),
		"third_party": mutateJSON(t, e.CanonicalJSON(), func(v map[string]any) {
			d := v["document"].(map[string]any)
			a := d["parties"].([]any)
			d["parties"] = append(a, a[0])
		}),
		"missing_field": mutateJSON(t, e.CanonicalJSON(), func(v map[string]any) { d := v["document"].(map[string]any); d["fields"] = d["fields"].([]any)[:1] }),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExecution(raw); !errors.Is(err, ErrInvalid) {
				t.Fatal("partial party/field/boolean evidence accepted")
			}
		})
	}
}

func TestPolicyRequiresRealPinnedApprovalAndExecutorScope(t *testing.T) {
	p, _, _, _, _ := fixture(t)
	cases := map[string]func(*PolicySnapshot){
		"missing_workflow_id":       func(s *PolicySnapshot) { s.Workflow.ID = uuid.Nil },
		"missing_workflow_approval": func(s *PolicySnapshot) { s.Workflow.ApprovedBy = uuid.Nil },
		"unapproved_template":       func(s *PolicySnapshot) { s.Template.ApprovedAt = time.Time{} },
		"nil_executor":              func(s *PolicySnapshot) { s.Executor.UserID = uuid.Nil },
		"unknown_executor":          func(s *PolicySnapshot) { s.Executor.Kind = "workflow_slug" },
		"unbound_machine":           func(s *PolicySnapshot) { s.Executor.Kind = ExecutorAPIKey },
		"member_has_machine_id":     func(s *PolicySnapshot) { s.Executor.CredentialID = fixtureID(20) },
		"unsupported_operation":     func(s *PolicySnapshot) { s.Operation = "sign_any_contract" },
		"arbitrary_prose":           func(s *PolicySnapshot) { s.Rules.InputMode = "write_legal_text" },
		"missing_recipient_rules":   func(s *PolicySnapshot) { s.Rules.RecipientRulesSHA256 = "" },
		"uppercase_sha":             func(s *PolicySnapshot) { s.Template.ContentSHA256 = strings.ToUpper(s.Template.ContentSHA256) },
		"policy_before_review":      func(s *PolicySnapshot) { s.ApprovedAt = s.Template.ApprovedAt.Add(-time.Second) },
		"unbounded_uses":            func(s *PolicySnapshot) { s.MaxUses = MaxRecordedUses + 1 },
		"unbounded_lifetime":        func(s *PolicySnapshot) { s.MaxGrantDurationSeconds = int64(MaxGrantDuration/time.Second) + 1 },
		"sub_microsecond_time":      func(s *PolicySnapshot) { s.ApprovedAt = s.ApprovedAt.Add(time.Nanosecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := p.Snapshot()
			mutate(&s)
			if _, err := NewPolicy(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid policy accepted: %v", err)
			}
		})
	}
}

func TestGrantRequiresNamedIdentityAndFiniteAllowance(t *testing.T) {
	_, g, _, _, _ := fixture(t)
	cases := map[string]func(*GrantSnapshot){
		"missing_grantor":       func(s *GrantSnapshot) { s.Grantor.UserID = uuid.Nil },
		"display_email":         func(s *GrantSnapshot) { s.Grantor.Email = "Provider <provider@example.test>" },
		"outer_name_whitespace": func(s *GrantSnapshot) { s.Grantor.Name = " Provider" },
		"name_controls":         func(s *GrantSnapshot) { s.Grantor.Name = "Provider\nPerson" },
		"overlong_name":         func(s *GrantSnapshot) { s.Grantor.Name = strings.Repeat("a", 201) },
		"no_company_authority":  func(s *GrantSnapshot) { s.Grantor.AuthorityBasis = "" },
		"no_expiry":             func(s *GrantSnapshot) { s.ExpiresAt = time.Time{} },
		"no_valid_window":       func(s *GrantSnapshot) { s.ExpiresAt = s.NotBefore },
		"too_long":              func(s *GrantSnapshot) { s.ExpiresAt = s.GrantedAt.Add(MaxGrantDuration + time.Second) },
		"starts_before_granted": func(s *GrantSnapshot) { s.NotBefore = s.GrantedAt.Add(-time.Second) },
		"zero_uses":             func(s *GrantSnapshot) { s.MaxUses = 0 },
		"unbounded_uses":        func(s *GrantSnapshot) { s.MaxUses = MaxRecordedUses + 1 },
		"font_fallback":         func(s *GrantSnapshot) { s.Signature.Font = "system cursive" },
		"unpinned_font":         func(s *GrantSnapshot) { s.Signature.FontSHA256 = "" },
		"unrecorded_copy":       func(s *GrantSnapshot) { s.Disclosure.SHA256 = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := g.Snapshot()
			mutate(&s)
			if _, err := NewGrant(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid grant accepted: %v", err)
			}
		})
	}
}

func TestExecutionRequiresExactSourcePartiesGeometryAndArtifacts(t *testing.T) {
	_, _, e, _, _ := fixture(t)
	cases := map[string]func(*ExecutionSnapshot){
		"legacy_source":           func(s *ExecutionSnapshot) { s.Document.SourceSchemaVersion = 2 },
		"envelope":                func(s *ExecutionSnapshot) { s.Document.ParentDocumentID = fixtureID(20) },
		"acknowledgment":          func(s *ExecutionSnapshot) { s.Document.RequiresSignature = false },
		"sequential":              func(s *ExecutionSnapshot) { s.Document.SigningMode = "sequential" },
		"blocks":                  func(s *ExecutionSnapshot) { s.Document.Kind = "blocks" },
		"foreign_org":             func(s *ExecutionSnapshot) { s.Document.OrgID = fixtureID(20) },
		"missing_materialization": func(s *ExecutionSnapshot) { s.Document.Materialization.ID = uuid.Nil },
		"missing_review":          func(s *ExecutionSnapshot) { s.Document.ReviewEvidenceSHA256 = "" },
		"same_recipient":          func(s *ExecutionSnapshot) { s.Document.Parties[0].ID = s.Document.Parties[1].ID },
		"same_mailbox":            func(s *ExecutionSnapshot) { s.Document.Parties[0].Email = strings.ToLower(s.Document.Parties[1].Email) },
		"same_company_id":         func(s *ExecutionSnapshot) { s.Document.Parties[0].CompanyID = s.Document.Parties[1].CompanyID },
		"wrong_order": func(s *ExecutionSnapshot) {
			s.Document.Parties[0], s.Document.Parties[1] = s.Document.Parties[1], s.Document.Parties[0]
		},
		"unsigned_role":           func(s *ExecutionSnapshot) { s.Document.Parties[1].Role = "cc" },
		"wrong_field_owner":       func(s *ExecutionSnapshot) { s.Document.Fields[1].RecipientID = s.Document.Parties[0].ID },
		"custom_field":            func(s *ExecutionSnapshot) { s.Document.Fields[0].Type = "text" },
		"optional_signature":      func(s *ExecutionSnapshot) { s.Document.Fields[1].Required = false },
		"drifted_geometry":        func(s *ExecutionSnapshot) { s.Document.Fields[1].Y++ },
		"earlier_page":            func(s *ExecutionSnapshot) { s.Document.Fields[1].Page-- },
		"old_source_options":      func(s *ExecutionSnapshot) { s.Document.Fields[1].SourceCommitment = fixtureSHA("old source") },
		"unsigned_provider_image": func(s *ExecutionSnapshot) { s.Signature.Image.SHA256 = "" },
		"unversioned_image":       func(s *ExecutionSnapshot) { s.Signature.Image.VersionID = "null" },
		"image_too_large":         func(s *ExecutionSnapshot) { s.Signature.Image.Bytes = MaxSignatureBytes + 1 },
		"misbound_signature":      func(s *ExecutionSnapshot) { s.Signature.FieldID = s.Document.Fields[0].ID },
		"different_typed_name":    func(s *ExecutionSnapshot) { s.Signature.TypedName = "Different Provider" },
		"same_source_bytes":       func(s *ExecutionSnapshot) { s.VisiblePDF.Artifact.SHA256 = s.Document.BasePDF.Artifact.SHA256 },
		"overwritten_source_key":  func(s *ExecutionSnapshot) { s.VisiblePDF.Artifact.StorageKey = s.Document.BasePDF.Artifact.StorageKey },
		"wrong_visible_pages":     func(s *ExecutionSnapshot) { s.VisiblePDF.Pages++ },
		"pdf_too_large":           func(s *ExecutionSnapshot) { s.VisiblePDF.Artifact.Bytes = MaxPDFBytes + 1 },
		"pdf_too_many_pages":      func(s *ExecutionSnapshot) { s.Document.BasePDF.Pages = MaxPDFPages + 1 },
		"relative_key":            func(s *ExecutionSnapshot) { s.Signature.Image.StorageKey = "../signature.html" },
		"bad_version":             func(s *ExecutionSnapshot) { s.Signature.Image.VersionID = "version\nnext" },
		"execution_before_epoch":  func(s *ExecutionSnapshot) { s.ExecutedAt = s.CeremonyEpoch.Add(-time.Second) },
		"no_visible_proof":        func(s *ExecutionSnapshot) { s.VisibleStampProofSHA256 = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := e.Snapshot()
			mutate(&s)
			if _, err := NewExecution(s); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid execution accepted: %v", err)
			}
		})
	}
}
