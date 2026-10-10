// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"errors"
	"testing"
	"time"
)

func TestFreshExecutionRequiresOriginalAuthorityAndExactObservations(t *testing.T) {
	p, g, e, observation, now := fixture(t)
	if err := AuthorizeFreshExecution(p, g, e, observation, now); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*FreshObservation){
		"foreign_org":                 func(o *FreshObservation) { o.OrgID = fixtureID(20) },
		"original_actor_substitution": func(o *FreshObservation) { o.OriginalActor.UserID = fixtureID(20) },
		"renewed_actor":               func(o *FreshObservation) { o.CurrentActor.UserID = fixtureID(20) },
		"original_receipt_missing":    func(o *FreshObservation) { o.OriginalCredentialBindingSHA256 = "" },
		"credential_rotation":         func(o *FreshObservation) { o.CurrentCredentialBindingSHA256 = fixtureSHA("renewed credential") },
		"credential_revoked":          func(o *FreshObservation) { o.CredentialActive = false },
		"operation_missing":           func(o *FreshObservation) { o.OperationAuthorized = false },
		"actor_removed":               func(o *FreshObservation) { o.Actor.Active = false },
		"actor_foreign_org":           func(o *FreshObservation) { o.Actor.OrgID = fixtureID(20) },
		"actor_demoted":               func(o *FreshObservation) { o.Actor.Role = "viewer" },
		"grantor_removed":             func(o *FreshObservation) { o.Grantor.Active = false },
		"grantor_demoted":             func(o *FreshObservation) { o.Grantor.Role = "viewer" },
		"grantor_user_replaced":       func(o *FreshObservation) { o.Grantor.UserID = fixtureID(20) },
		"grantor_name_changed":        func(o *FreshObservation) { o.Grantor.Name = "Different Person" },
		"grantor_email_case_changed":  func(o *FreshObservation) { o.Grantor.Email = "asa.provider@example.test" },
		"policy_retired":              func(o *FreshObservation) { o.Policy.Active = false },
		"policy_generation_changed":   func(o *FreshObservation) { o.Policy.Reference.Revision++ },
		"policy_digest_changed":       func(o *FreshObservation) { o.Policy.Reference.SHA256 = fixtureSHA("new policy") },
		"policy_owner_changed":        func(o *FreshObservation) { o.Policy.ApprovedBy = fixtureID(20) },
		"grant_revoked":               func(o *FreshObservation) { o.Grant.Revoked = true },
		"grant_generation_changed":    func(o *FreshObservation) { o.Grant.Reference.Revision++ },
		"grant_digest_changed":        func(o *FreshObservation) { o.Grant.Reference.SHA256 = fixtureSHA("new grant") },
		"negative_used_count":         func(o *FreshObservation) { o.Grant.ConsumedUses = -1 },
		"exhausted_used_count":        func(o *FreshObservation) { o.Grant.ConsumedUses = g.Snapshot().MaxUses },
		"concurrent_use_consumed":     func(o *FreshObservation) { o.Grant.ConsumedUses = 1 },
		"template_archived":           func(o *FreshObservation) { o.Template.Active = false },
		"approval_missing":            func(o *FreshObservation) { o.Template.Approved = false },
		"selected_revision_changed":   func(o *FreshObservation) { o.Template.Pin.Version++ },
		"selected_origin_changed":     func(o *FreshObservation) { o.Template.Pin.ContentSHA256 = fixtureSHA("changed selected template") },
		"workflow_not_server_owned":   func(o *FreshObservation) { o.Workflow.ServerOwned = false },
		"workflow_retired":            func(o *FreshObservation) { o.Workflow.Active = false },
		"workflow_approval_missing":   func(o *FreshObservation) { o.Workflow.Approved = false },
		"workflow_revision_changed":   func(o *FreshObservation) { o.Workflow.Pin.Revision++ },
		"document_deleted":            func(o *FreshObservation) { o.Document.Deleted = true },
		"document_no_longer_draft":    func(o *FreshObservation) { o.Document.Status = "sealing" },
		"captured_signature":          func(o *FreshObservation) { o.Document.NoCapturedEvidence = false },
		"commercial_review_stale":     func(o *FreshObservation) { o.Document.CommercialReviewSatisfied = false },
		"new_unreviewed_prose":        func(o *FreshObservation) { o.Document.InputRulesSatisfied = false },
		"data_rule_failed":            func(o *FreshObservation) { o.Document.DataRulesSatisfied = false },
		"recipient_rule_failed":       func(o *FreshObservation) { o.Document.RecipientRulesSatisfied = false },
		"document_switched":           func(o *FreshObservation) { o.Document.Snapshot.ID = fixtureID(20) },
		"materialization_advanced":    func(o *FreshObservation) { o.Document.Snapshot.Materialization.Revision++ },
		"base_pdf_version_changed":    func(o *FreshObservation) { o.Document.Snapshot.BasePDF.Artifact.VersionID = "new-source-version" },
		"same_sha_new_source_object":  func(o *FreshObservation) { o.Document.Snapshot.BasePDF.Artifact.StorageKey = "other/source.pdf" },
		"provider_identity_drift":     func(o *FreshObservation) { o.Document.Snapshot.Parties[1].Name = "Different Provider" },
		"customer_identity_drift":     func(o *FreshObservation) { o.Document.Snapshot.Parties[0].Email = "different-customer@example.test" },
		"provider_field_replaced":     func(o *FreshObservation) { o.Document.Snapshot.Fields[1].ID = fixtureID(20) },
		"options_drift": func(o *FreshObservation) {
			o.Document.Snapshot.Fields[1].OptionsSHA256 = fixtureSHA("modified options")
		},
		"branding_drift":              func(o *FreshObservation) { o.Document.Snapshot.BrandingSHA256 = fixtureSHA("changed brand") },
		"manual_wording_drift":        func(o *FreshObservation) { o.Document.Snapshot.SectionsSHA256 = fixtureSHA("new wording") },
		"optional_presence_drift":     func(o *FreshObservation) { o.Document.Snapshot.ValuesSHA256 = fixtureSHA("different value presence") },
		"different_ceremony":          func(o *FreshObservation) { o.CeremonyEpoch = o.CeremonyEpoch.Add(time.Microsecond) },
		"unverified_artifacts":        func(o *FreshObservation) { o.Artifacts.Verified = false },
		"different_signature_version": func(o *FreshObservation) { o.Artifacts.Signature.Image.VersionID = "other-image-version" },
		"different_visible_sha":       func(o *FreshObservation) { o.Artifacts.VisiblePDF.Artifact.SHA256 = fixtureSHA("other-visible-pdf") },
		"different_visible_version":   func(o *FreshObservation) { o.Artifacts.VisiblePDF.Artifact.VersionID = "other-visible-version" },
		"different_visibility_proof":  func(o *FreshObservation) { o.Artifacts.VisibleStampProofSHA256 = fixtureSHA("other-stamp-proof") },
		"observation_from_future":     func(o *FreshObservation) { o.ObservedAt = now.Add(time.Second) },
		"stale_observation":           func(o *FreshObservation) { o.ObservedAt = now.Add(-MaxObservationAge - time.Microsecond) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := observation
			mutate(&o)
			if err := AuthorizeFreshExecution(p, g, e, o, now); !errors.Is(err, ErrRefused) {
				t.Fatalf("fresh use accepted or misclassified: %v", err)
			}
		})
	}
}

func TestOriginalDeadlinesCannotBeRevivedByExtensions(t *testing.T) {
	p, g, e, o, now := fixture(t)
	for name, mutate := range map[string]func(*FreshObservation){
		"original_expired_current_extended": func(o *FreshObservation) {
			o.OriginalAdmissionExpiresAt = now
			o.CurrentAdmissionExpiresAt = now.Add(time.Hour)
		},
		"fresh_expired_original_live": func(o *FreshObservation) {
			o.CurrentAdmissionExpiresAt = now
			o.OriginalAdmissionExpiresAt = now.Add(time.Hour)
		},
		"missing_original_deadline": func(o *FreshObservation) { o.OriginalAdmissionExpiresAt = time.Time{} },
	} {
		t.Run(name, func(t *testing.T) {
			copy := o
			mutate(&copy)
			if err := AuthorizeFreshExecution(p, g, e, copy, now); !errors.Is(err, ErrRefused) {
				t.Fatal("original/current deadline not enforced")
			}
		})
	}
	// Same credential and extended current expiry still cannot revive a request
	// whose original deadline naturally elapsed during an audit wait.
	deadline := o.OriginalAdmissionExpiresAt
	o.CurrentAdmissionExpiresAt = deadline.Add(time.Hour)
	if err := AuthorizeFreshExecution(p, g, e, o, deadline); !errors.Is(err, ErrRefused) {
		t.Fatalf("expired original admission revived: %v", err)
	}
	if err := AuthorizeFreshExecution(p, g, e, o, deadline.Add(-time.Microsecond)); err != nil {
		t.Fatalf("valid original admission refused prematurely: %v", err)
	}
}

func TestRevocationAndNaturalExpiryDoNotRewriteRecordedExecution(t *testing.T) {
	p, g, e, o, now := fixture(t)
	original := e.Commitment()
	o.Grant.Revoked = true
	if err := AuthorizeFreshExecution(p, g, e, o, now); !errors.Is(err, ErrRefused) {
		t.Fatal("revoked grant permitted another fresh use")
	}
	if err := ValidateCommittedExecution(p, g, e); err != nil {
		t.Fatalf("revocation invalidated frozen recorded descriptor: %v", err)
	}
	if e.Commitment() != original {
		t.Fatal("revocation rewrote execution")
	}
	o.Grant.Revoked = false
	deadline := g.Snapshot().ExpiresAt
	// Keep observations/admission fresh so refusal specifically depends on the
	// finite grant deadline. Recorded integrity never receives a current clock.
	s := e.Snapshot()
	s.ExecutedAt = deadline.Add(-time.Microsecond)
	s.CeremonyEpoch = s.ExecutedAt
	late, err := NewExecution(s)
	if err != nil {
		t.Fatal(err)
	}
	o.ObservedAt = s.ExecutedAt
	o.CeremonyEpoch = s.CeremonyEpoch
	o.OriginalAdmissionExpiresAt = deadline.Add(time.Minute)
	o.CurrentAdmissionExpiresAt = o.OriginalAdmissionExpiresAt
	if err := AuthorizeFreshExecution(p, g, late, o, deadline); !errors.Is(err, ErrRefused) {
		t.Fatalf("natural grant expiry ignored: %v", err)
	}
	if err := ValidateCommittedExecution(p, g, late); err != nil {
		t.Fatalf("a historically in-window descriptor lost integrity after expiry: %v", err)
	}
	o.Grant.ConsumedUses = g.Snapshot().MaxUses
	if err := AuthorizeFreshExecution(p, g, e, o, deadline); err == nil {
		t.Fatal("integrity readback admitted a new use")
	}
	if err := ValidateCommittedExecution(p, g, e); err != nil {
		t.Fatal(err)
	}
}

func TestSelectedApprovedHistoricalRevisionRemainsEligible(t *testing.T) {
	p, g, e, o, now := fixture(t)
	// Selected revision 7 remains active/approved; the package has no latest-head
	// requirement. Current HTML APIs deliberately support historical approvals.
	if p.Snapshot().Template.Version != 7 {
		t.Fatal("fixture does not exercise historical selection")
	}
	if err := AuthorizeFreshExecution(p, g, e, o, now); err != nil {
		t.Fatal(err)
	}
	o.Template.Pin.Version = 8
	if err := AuthorizeFreshExecution(p, g, e, o, now); !errors.Is(err, ErrRefused) {
		t.Fatal("selected origin silently adopted the latest revision")
	}
}

func TestMachineExecutionBindsActualCredentialAndNamedGrantor(t *testing.T) {
	p, g, e, o, now := fixture(t)
	ps := p.Snapshot()
	ps.Executor = ExecutorIdentity{Kind: ExecutorAPIKey, UserID: fixtureID(20), CredentialID: fixtureID(21)}
	ps.Rules.InputMode = InputApprovedData
	machinePolicy, err := NewPolicy(ps)
	if err != nil {
		t.Fatal(err)
	}
	gs := g.Snapshot()
	gs.Policy = machinePolicy.Reference()
	machineGrant, err := NewGrant(gs)
	if err != nil {
		t.Fatal(err)
	}
	es := e.Snapshot()
	es.Policy = machinePolicy.Reference()
	es.Grant = machineGrant.Reference()
	es.Executor = ps.Executor
	machineExecution, err := NewExecution(es)
	if err != nil {
		t.Fatal(err)
	}
	o.OriginalActor = ps.Executor
	o.CurrentActor = ps.Executor
	o.Actor.UserID = ps.Executor.UserID
	o.Actor.Name = "Automation Operator"
	o.Actor.Email = "operator@example.test"
	o.Policy.Reference = machinePolicy.Reference()
	o.Grant.Reference = machineGrant.Reference()
	if err := AuthorizeFreshExecution(machinePolicy, machineGrant, machineExecution, o, now); err != nil {
		t.Fatal(err)
	}
	o.CurrentActor.CredentialID = fixtureID(22)
	if err := AuthorizeFreshExecution(machinePolicy, machineGrant, machineExecution, o, now); !errors.Is(err, ErrRefused) {
		t.Fatal("different machine key inherited authority")
	}
	// The grantor is still the exact named provider/sender, not the API executor.
	if machineExecution.Snapshot().Document.SenderID == ps.Executor.UserID {
		t.Fatal("executor replaced named provider grantor")
	}
}

func TestRecordedUseSequenceIsNotAReusableAdmission(t *testing.T) {
	p, g, e, o, now := fixture(t)
	o.Grant.ConsumedUses = 1
	if err := AuthorizeFreshExecution(p, g, e, o, now); !errors.Is(err, ErrRefused) {
		t.Fatal("already consumed use admitted twice")
	}
	if err := ValidateCommittedExecution(p, g, e); err != nil {
		t.Fatal("committed readback should not consume another use")
	}
	s := e.Snapshot()
	s.ID = fixtureID(25)
	s.Signature.ID = fixtureID(26)
	s.UseNumber = 2
	next, err := NewExecution(s)
	if err != nil {
		t.Fatal(err)
	}
	o.Artifacts.Signature = next.Snapshot().Signature
	if err := AuthorizeFreshExecution(p, g, next, o, now); err != nil {
		t.Fatal(err)
	}
	o.Grant.ConsumedUses = 2
	if err := AuthorizeFreshExecution(p, g, next, o, now); !errors.Is(err, ErrRefused) {
		t.Fatal("last allowed use could be replayed as fresh")
	}
	if err := ValidateCommittedExecution(p, g, next); err != nil {
		t.Fatal(err)
	}
}

func TestRecordedExecutionRequiresExactGrantPolicyAndPrintedProvider(t *testing.T) {
	p, g, e, _, _ := fixture(t)
	cases := map[string]func(*ExecutionSnapshot){
		"other_policy_id":          func(s *ExecutionSnapshot) { s.Policy.ID = fixtureID(20) },
		"other_policy_revision":    func(s *ExecutionSnapshot) { s.Policy.Revision++ },
		"other_policy_commitment":  func(s *ExecutionSnapshot) { s.Policy.SHA256 = fixtureSHA("other policy") },
		"other_grant_id":           func(s *ExecutionSnapshot) { s.Grant.ID = fixtureID(20) },
		"other_grant_revision":     func(s *ExecutionSnapshot) { s.Grant.Revision++ },
		"other_grant_commitment":   func(s *ExecutionSnapshot) { s.Grant.SHA256 = fixtureSHA("other grant") },
		"other_sender":             func(s *ExecutionSnapshot) { s.Document.SenderID = fixtureID(20) },
		"other_selected_template":  func(s *ExecutionSnapshot) { s.Document.Template.Version++ },
		"other_provider_company":   func(s *ExecutionSnapshot) { s.Document.Parties[1].CompanyID = "556000-0099" },
		"other_provider_authority": func(s *ExecutionSnapshot) { s.Document.Parties[1].AuthorityBasis = "Different assertion" },
		"different_font_asset":     func(s *ExecutionSnapshot) { s.Signature.Style.FontSHA256 = fixtureSHA("other font") },
		"over_grant_uses":          func(s *ExecutionSnapshot) { s.UseNumber = g.Snapshot().MaxUses + 1 },
		"outside_grant_window":     func(s *ExecutionSnapshot) { s.ExecutedAt = g.Snapshot().ExpiresAt },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := e.Snapshot()
			mutate(&s)
			candidate, err := NewExecution(s)
			if err != nil {
				t.Fatal("fixture mutation unexpectedly violates structural validation")
			}
			if err := ValidateCommittedExecution(p, g, candidate); !errors.Is(err, ErrInvalid) {
				t.Fatalf("broken recorded lineage accepted: %v", err)
			}
		})
	}
	for _, invalid := range []struct {
		p Policy
		g Grant
		e Execution
	}{{Policy{}, g, e}, {p, Grant{}, e}, {p, g, Execution{}}} {
		if err := ValidateCommittedExecution(invalid.p, invalid.g, invalid.e); !errors.Is(err, ErrInvalid) {
			t.Fatal("zero value treated as committed evidence")
		}
	}
	gs := g.Snapshot()
	gs.MaxUses = p.Snapshot().MaxUses + 1
	wider, err := NewGrant(gs)
	if err != nil {
		t.Fatal(err)
	}
	es := e.Snapshot()
	es.Grant = wider.Reference()
	widerExecution, err := NewExecution(es)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCommittedExecution(p, wider, widerExecution); !errors.Is(err, ErrInvalid) {
		t.Fatal("grant exceeded owner-approved policy allowance")
	}
}
