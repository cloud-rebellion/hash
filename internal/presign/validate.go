// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presign

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

var (
	ErrInvalid = errors.New("invalid pre-sign descriptor")
	ErrRefused = errors.New("fresh pre-sign execution refused")
)

func invalid(path string) error   { return fmt.Errorf("%w: %s", ErrInvalid, path) }
func refused(reason string) error { return fmt.Errorf("%w: %s", ErrRefused, reason) }

func validSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validTime(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0 && t.Year() >= 2000 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0
}

func visible(value string, maxBytes, maxRunes int) bool {
	if value == "" || len(value) > maxBytes || !utf8.ValidString(value) || utf8.RuneCountInString(value) > maxRunes || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return false
		}
	}
	return true
}

func validEmail(value string) bool {
	if !visible(value, 254, 254) {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

func validRevision(value int64) bool { return value >= 1 && value <= MaxRevision }

func validateTemplate(t TemplatePin) error {
	if t.ID == uuid.Nil || !validRevision(t.Version) || !validSHA(t.ContentSHA256) || t.ApprovedBy == uuid.Nil || !validTime(t.ApprovedAt) {
		return invalid("template selected approval")
	}
	return nil
}

func validateWorkflow(w WorkflowPin) error {
	if w.ID == uuid.Nil || !validRevision(w.Revision) || !validSHA(w.ContentSHA256) || w.ApprovedBy == uuid.Nil || !validTime(w.ApprovedAt) {
		return invalid("workflow selected approval")
	}
	return nil
}

func validateExecutor(e ExecutorIdentity) error {
	if e.UserID == uuid.Nil {
		return invalid("executor member")
	}
	switch e.Kind {
	case ExecutorMember:
		if e.CredentialID != uuid.Nil {
			return invalid("member executor credential")
		}
	case ExecutorAPIKey:
		if e.CredentialID == uuid.Nil {
			return invalid("API executor credential")
		}
	default:
		return invalid("executor kind")
	}
	return nil
}

func validateReference(r Reference) error {
	if r.ID == uuid.Nil || !validRevision(r.Revision) || !validSHA(r.SHA256) {
		return invalid("snapshot reference")
	}
	return nil
}

func validatePolicy(p PolicySnapshot) error {
	if p.SchemaVersion != SchemaVersion || p.ID == uuid.Nil || p.OrgID == uuid.Nil || !validRevision(p.Revision) {
		return invalid("policy identity or schema")
	}
	if err := validateTemplate(p.Template); err != nil {
		return err
	}
	if err := validateWorkflow(p.Workflow); err != nil {
		return err
	}
	if err := validateExecutor(p.Executor); err != nil {
		return err
	}
	if p.Operation != OperationPreSignAndSend {
		return invalid("policy operation")
	}
	if (p.Rules.InputMode != InputReviewedDocument && p.Rules.InputMode != InputApprovedData) || !validSHA(p.Rules.InputRulesSHA256) || !validSHA(p.Rules.DataRulesSHA256) || !validSHA(p.Rules.RecipientRulesSHA256) {
		return invalid("policy reviewed rules")
	}
	if p.MaxGrantDurationSeconds < 1 || p.MaxGrantDurationSeconds > int64(MaxGrantDuration/time.Second) || p.MaxUses < 1 || p.MaxUses > MaxRecordedUses {
		return invalid("policy finite allowance")
	}
	if p.ApprovedBy == uuid.Nil || !validTime(p.ApprovedAt) || p.ApprovedAt.Before(p.Template.ApprovedAt) || p.ApprovedAt.Before(p.Workflow.ApprovedAt) {
		return invalid("policy approval")
	}
	return nil
}

func validateRepresentative(p NamedRepresentative) error {
	if p.UserID == uuid.Nil || !visible(p.Name, 800, 200) || !validEmail(p.Email) || !visible(p.CompanyName, 800, 200) || !visible(p.CompanyID, 400, 100) || !visible(p.AuthorityBasis, 2048, 500) {
		return invalid("named grantor identity")
	}
	return nil
}

func validateStyle(s SignatureStyle) error {
	switch s.Font {
	case "Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple":
	default:
		return invalid("signature font")
	}
	if !validSHA(s.FontSHA256) {
		return invalid("signature font asset")
	}
	return nil
}

func validateGrant(g GrantSnapshot) error {
	if g.SchemaVersion != SchemaVersion || g.ID == uuid.Nil || g.OrgID == uuid.Nil || !validRevision(g.Revision) {
		return invalid("grant identity or schema")
	}
	if err := validateReference(g.Policy); err != nil {
		return err
	}
	if err := validateRepresentative(g.Grantor); err != nil {
		return err
	}
	if err := validateStyle(g.Signature); err != nil {
		return err
	}
	if !validRevision(g.Disclosure.Version) || !validSHA(g.Disclosure.SHA256) {
		return invalid("grant disclosure")
	}
	if !validTime(g.GrantedAt) || !validTime(g.NotBefore) || !validTime(g.ExpiresAt) || g.NotBefore.Before(g.GrantedAt) || !g.ExpiresAt.After(g.NotBefore) || g.ExpiresAt.Sub(g.GrantedAt) > MaxGrantDuration {
		return invalid("grant finite validity")
	}
	if g.MaxUses < 1 || g.MaxUses > MaxRecordedUses {
		return invalid("grant finite uses")
	}
	return nil
}

func validateArtifact(a ArtifactPin, maxBytes int64) error {
	if !validSHA(a.SHA256) || a.Bytes < 1 || a.Bytes > maxBytes || len(a.StorageKey) == 0 || len(a.StorageKey) > 1024 || len(a.VersionID) == 0 || len(a.VersionID) > 1024 || a.VersionID == "null" {
		return invalid("artifact exact version or bounds")
	}
	for _, r := range a.VersionID {
		if r < 33 || r > 126 {
			return invalid("artifact version syntax")
		}
	}
	if strings.HasPrefix(a.StorageKey, "/") || strings.HasSuffix(a.StorageKey, "/") {
		return invalid("artifact key syntax")
	}
	for _, part := range strings.Split(a.StorageKey, "/") {
		if part == "" || part == "." || part == ".." {
			return invalid("artifact key syntax")
		}
		for _, r := range part {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.') {
				return invalid("artifact key syntax")
			}
		}
	}
	return nil
}

func validatePDF(p PDFPin) error {
	if err := validateArtifact(p.Artifact, MaxPDFBytes); err != nil {
		return err
	}
	if p.Pages < 2 || p.Pages > MaxPDFPages {
		return invalid("source3 PDF page bounds")
	}
	return nil
}

func validateParty(p PartySnapshot, slot string) error {
	if p.ID == uuid.Nil || p.Slot != slot || p.Role != slot || !visible(p.Name, 800, 200) || !validEmail(p.Email) || !visible(p.CompanyName, 800, 200) || !visible(p.CompanyID, 400, 100) || !visible(p.AuthorityBasis, 2048, 500) {
		return invalid("printed " + slot + " identity")
	}
	return nil
}

func validateDocument(d DocumentSnapshot) error {
	if d.ID == uuid.Nil || d.OrgID == uuid.Nil || d.SenderID == uuid.Nil || d.ParentDocumentID != uuid.Nil || d.Kind != "pdf" || d.SourceSchemaVersion != 3 || !d.RequiresSignature || d.SigningMode != "parallel" {
		return invalid("source3 standalone signing eligibility")
	}
	if err := validateTemplate(d.Template); err != nil {
		return err
	}
	if d.Materialization.ID == uuid.Nil || !validRevision(d.Materialization.Revision) || !validSHA(d.Materialization.SourceCommitment) {
		return invalid("document materialization")
	}
	if err := validatePDF(d.BasePDF); err != nil {
		return err
	}
	for _, digest := range []string{d.SigningPlanSHA256, d.BrandingSHA256, d.ValuesSHA256, d.SectionsSHA256, d.ReviewEvidenceSHA256, d.DataEvidenceSHA256} {
		if !validSHA(digest) {
			return invalid("document content or review commitment")
		}
	}
	for i, slot := range [2]string{"customer", "provider"} {
		if err := validateParty(d.Parties[i], slot); err != nil {
			return err
		}
		f := d.Fields[i]
		y := int64(420000)
		if slot == "provider" {
			y = 790000
		}
		if f.ID == uuid.Nil || f.RecipientID != d.Parties[i].ID || f.Slot != slot || f.Type != "signature" || !f.Required || f.Page != d.BasePDF.Pages || f.X != 100000 || f.Y != y || f.W != 800000 || f.H != 70000 || f.SourceCommitment != d.Materialization.SourceCommitment || !validSHA(f.OptionsSHA256) {
			return invalid("protected " + slot + " signature field")
		}
	}
	if d.Parties[0].ID == d.Parties[1].ID || d.Fields[0].ID == d.Fields[1].ID || strings.EqualFold(d.Parties[0].Email, d.Parties[1].Email) || strings.EqualFold(d.Parties[0].CompanyID, d.Parties[1].CompanyID) {
		return invalid("distinct signing parties and fields")
	}
	return nil
}

func validateExecution(e ExecutionSnapshot) error {
	if e.SchemaVersion != SchemaVersion || e.ID == uuid.Nil || e.OrgID == uuid.Nil {
		return invalid("execution identity or schema")
	}
	if err := validateReference(e.Policy); err != nil {
		return err
	}
	if err := validateReference(e.Grant); err != nil {
		return err
	}
	if err := validateExecutor(e.Executor); err != nil {
		return err
	}
	if err := validateDocument(e.Document); err != nil {
		return err
	}
	if e.Document.OrgID != e.OrgID || !validTime(e.CeremonyEpoch) || !validTime(e.ExecutedAt) || e.ExecutedAt.Before(e.CeremonyEpoch) || e.UseNumber < 1 || e.UseNumber > MaxRecordedUses {
		return invalid("execution ceremony or use")
	}
	s := e.Signature
	if s.ID == uuid.Nil || s.ID == e.ID || s.RecipientID != e.Document.Parties[1].ID || s.FieldID != e.Document.Fields[1].ID || s.TypedName != e.Document.Parties[1].Name {
		return invalid("provider signature ownership or identity")
	}
	if err := validateStyle(s.Style); err != nil {
		return err
	}
	if err := validateArtifact(s.Image, MaxSignatureBytes); err != nil {
		return err
	}
	if err := validatePDF(e.VisiblePDF); err != nil {
		return err
	}
	if e.VisiblePDF.Pages != e.Document.BasePDF.Pages || e.VisiblePDF.Artifact.SHA256 == e.Document.BasePDF.Artifact.SHA256 || e.VisiblePDF.Artifact.StorageKey == e.Document.BasePDF.Artifact.StorageKey || !validSHA(e.VisibleStampProofSHA256) {
		return invalid("separate visible provider artifact")
	}
	return nil
}

// ValidateCommittedExecution checks frozen descriptor integrity without current
// authority observations. It is not proof of commit, authorization for readback,
// permission to publish, or a fresh-use predicate.
func ValidateCommittedExecution(policy Policy, grant Grant, execution Execution) error {
	if !validSHA(policy.commitment) || !validSHA(grant.commitment) || !validSHA(execution.commitment) {
		return invalid("uninitialized immutable snapshot")
	}
	p, g, e := policy.snapshot, grant.snapshot, execution.snapshot
	if err := validatePolicy(p); err != nil {
		return err
	}
	if err := validateGrant(g); err != nil {
		return err
	}
	if err := validateExecution(e); err != nil {
		return err
	}
	if p.OrgID != g.OrgID || p.OrgID != e.OrgID || g.Policy != policy.Reference() || e.Policy != policy.Reference() || e.Grant != grant.Reference() {
		return invalid("policy/grant/execution lineage")
	}
	if g.GrantedAt.Before(p.ApprovedAt) || g.ExpiresAt.Sub(g.GrantedAt) > time.Duration(p.MaxGrantDurationSeconds)*time.Second || g.MaxUses > p.MaxUses {
		return invalid("grant policy allowance")
	}
	if e.Executor != p.Executor || e.Document.Template != p.Template || e.Document.SenderID != g.Grantor.UserID || e.Signature.Style != g.Signature {
		return invalid("execution approved scope")
	}
	provider := e.Document.Parties[1]
	if provider.Name != g.Grantor.Name || provider.Email != g.Grantor.Email || provider.CompanyName != g.Grantor.CompanyName || provider.CompanyID != g.Grantor.CompanyID || provider.AuthorityBasis != g.Grantor.AuthorityBasis {
		return invalid("printed provider differs from grantor")
	}
	if e.CeremonyEpoch.Before(g.NotBefore) || e.ExecutedAt.Before(g.NotBefore) || !e.ExecutedAt.Before(g.ExpiresAt) || e.UseNumber > g.MaxUses {
		return invalid("execution recorded grant allowance")
	}
	return nil
}
