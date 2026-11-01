// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type providerPartialFixture struct {
	doc        *generated.Document
	rows       []*generated.Recipient
	fields     []*generated.DocumentField
	signatures []*generated.Signature
	evidence   ProviderPartialEvidence
}

func partialFixtureSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// This is a synthetic pure state fixture: no real PDF, committed SQL row,
// storage archive, authenticated authority, renderer or worker acceptance.
func newProviderPartialFixture(t *testing.T, mode string) *providerPartialFixture {
	t.Helper()
	input, doc, rows := testfixture.BrandedHTMLContract(t)
	doc.RoutingMode = "parallel"
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentSourceJson = bytes.Clone(doc.HtmlSourceJson)
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlReviewedMaterializationID = doc.HtmlCurrentMaterializationID
	executed := doc.HtmlReviewedAt.Time.Add(time.Minute)
	doc.Article13NoticeEpochAt = pgtype.Timestamptz{Time: executed, Valid: true}
	fields := testfixture.BrandedSignatureFields(t, doc)
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		t.Fatal("synthetic signing artifact", err)
	}
	template := presign.TemplatePin{ID: input.TemplateID, Version: int64(input.TemplateVersion), ContentSHA256: input.TemplateContentSHA256,
		ApprovedBy: input.TemplateApprovedBy, ApprovedAt: input.TemplateApprovedAt}
	approved := input.TemplateApprovedAt.Add(time.Minute)
	definition := presignregistry.WorkflowDefinition{Version: 1, ID: uuid.New(), PolicyID: uuid.New(), OrgID: doc.OrgID, Revision: 1, Name: "Synthetic reviewed provider workflow",
		Kind: presignregistry.KindReviewedDocument, Template: template, Executor: presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: doc.SenderID}, Operation: presign.OperationPreSignAndSend,
		InputRules: presignregistry.InputRules{Version: 1, SourceSchemaVersion: 3, Standalone: true, SignatureFieldsOnly: true, AuthorMustBeGrantor: true},
		DataRules:  presignregistry.DataRules{Version: 1, Values: []presignregistry.ValueRule{}, Sections: []presignregistry.SectionRule{}},
		RecipientRules: presignregistry.RecipientRules{Version: 1, Provider: "named_grantor_exact", Customer: "printed_profile_exact", Mode: "parallel",
			ProviderCompanyName: input.Values["provider_company"], ProviderCompanyID: input.Values["provider_company_id"], ProviderAuthorityBasis: input.Values["provider_authority"]},
		MaxGrantDurationSeconds: 86400, MaxUses: 2}
	if mode == presign.InputApprovedData {
		definition.Kind = presignregistry.KindApprovedData
		doc.HtmlReviewedPdfSha256 = nil
		doc.HtmlReviewedBy = pgtype.UUID{}
		doc.HtmlReviewedAt = pgtype.Timestamptz{}
		doc.HtmlReviewedMaterializationID = pgtype.UUID{}
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	providerGrantorFields := map[string]string{}
	for _, party := range master.ContractProfile.Parties {
		if party.Slot == "provider" {
			providerGrantorFields[party.RepresentativeName] = "name"
			providerGrantorFields[party.RepresentativeEmail] = "email"
			providerGrantorFields[party.CompanyName] = "company_name"
			providerGrantorFields[party.CompanyID] = "company_id"
			providerGrantorFields[party.RepresentativeAuthority] = "authority_basis"
		}
	}
	for _, value := range master.Values {
		rule := presignregistry.ValueRule{Variable: value.Name, Mode: presignregistry.ModeReviewedValue}
		if mode == presign.InputApprovedData {
			if field, provider := providerGrantorFields[value.Name]; provider {
				rule.Mode, rule.GrantorField = presignregistry.ModeGrantor, field
			} else {
				literal := input.Values[value.Name]
				rule.Mode, rule.Literal = presignregistry.ModeLiteral, &literal
			}
		}
		definition.DataRules.Values = append(definition.DataRules.Values, rule)
	}
	_, definitionSHA, rules, err := presignregistry.CanonicalDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := presign.NewPolicy(presign.PolicySnapshot{SchemaVersion: 1, ID: definition.PolicyID, OrgID: doc.OrgID, Revision: 1,
		Template: template, Workflow: presign.WorkflowPin{ID: definition.ID, Revision: 1, ContentSHA256: definitionSHA, ApprovedBy: doc.SenderID, ApprovedAt: approved},
		Executor: definition.Executor, Operation: presign.OperationPreSignAndSend, Rules: rules,
		MaxGrantDurationSeconds: 86400, MaxUses: 2, ApprovedBy: doc.SenderID, ApprovedAt: approved})
	if err != nil {
		t.Fatal(err)
	}
	var font []byte
	for _, asset := range render.FontAssets() {
		if asset.Filename == "Caveat.woff2" {
			font = bytes.Clone(asset.Bytes)
		}
	}
	if len(font) == 0 {
		t.Fatal("missing synthetic fixture font input")
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	bySlot := make(map[string]htmlsource.ContractParty, 2)
	for _, party := range parties {
		bySlot[party.Slot] = party
	}
	provider := bySlot["provider"]
	granted := approved.Add(time.Minute)
	grant, err := presign.NewGrant(presign.GrantSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: doc.OrgID, Revision: 1, Policy: policy.Reference(),
		Grantor:   presign.NamedRepresentative{UserID: doc.SenderID, Name: provider.Name, Email: provider.Email, CompanyName: provider.CompanyName, CompanyID: provider.CompanyID, AuthorityBasis: provider.Authority},
		Signature: presign.SignatureStyle{Font: "Caveat", FontSHA256: partialFixtureSHA(font)}, Disclosure: presign.CopyPin{Version: 1, SHA256: partialFixtureSHA([]byte("app-owned disclosure"))},
		GrantedAt: granted, NotBefore: granted, ExpiresAt: granted.Add(24 * time.Hour), MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := presignregistry.EvaluateExecutionData(definition, grant.Snapshot().Grantor, doc, nil, executed)
	if err != nil {
		t.Fatal("synthetic evaluated data admission", err)
	}
	// Fresh rule evaluation is admitted only for a draft. The separately
	// validated committed-partial state is constructed after that succeeds.
	doc.Status = "sent"
	admitted := admission.Snapshot()
	span, err := render.RenderSignatureSpan(provider.Name, "Caveat")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := presign.DocumentSnapshot{ID: doc.ID, OrgID: doc.OrgID, SenderID: doc.SenderID, Kind: "pdf", SourceSchemaVersion: 3, RequiresSignature: true, SigningMode: "parallel", Template: template,
		Materialization:   presign.MaterializationPin{ID: uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes), Revision: 1, SourceCommitment: commitment},
		BasePDF:           presign.PDFPin{Artifact: presign.ArtifactPin{StorageKey: doc.PdfStorageKey.String, VersionID: doc.PdfStorageVersionID.String, SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: 1000}, Pages: 2},
		SigningPlanSHA256: artifact.PlanSHA256, BrandingSHA256: partialFixtureSHA([]byte("orchestrator branding domain")), ValuesSHA256: admitted.ValuesSHA256,
		SectionsSHA256: admitted.SectionsSHA256, ReviewEvidenceSHA256: admitted.ReviewEvidenceSHA256, DataEvidenceSHA256: admission.Commitment()}
	for i, slot := range [2]string{"customer", "provider"} {
		party := bySlot[slot]
		f := fields[i]
		r := artifact.Fields[i]
		options, err := htmlsource.SigningFieldOptions(doc, slot)
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Parties[i] = presign.PartySnapshot{ID: party.RecipientID, Slot: slot, Role: slot, Name: party.Name, Email: party.Email, CompanyName: party.CompanyName, CompanyID: party.CompanyID, AuthorityBasis: party.Authority}
		snapshot.Fields[i] = presign.FieldSnapshot{ID: f.ID, RecipientID: party.RecipientID, Slot: slot, Type: "signature", Required: true, Page: 2,
			X: r.X, Y: r.Y, W: r.W, H: r.H, SourceCommitment: commitment, OptionsSHA256: partialFixtureSHA(options)}
	}
	signatureID := uuid.New()
	execution, err := presign.NewExecution(presign.ExecutionSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: doc.OrgID, Policy: policy.Reference(), Grant: grant.Reference(), Executor: policy.Snapshot().Executor,
		Document: snapshot, CeremonyEpoch: executed, ExecutedAt: executed, UseNumber: 1,
		Signature: presign.SignatureArtifact{ID: signatureID, RecipientID: provider.RecipientID, FieldID: fields[1].ID, TypedName: provider.Name, Style: grant.Snapshot().Signature,
			Image: presign.ArtifactPin{StorageKey: "synthetic/presign/span.html", VersionID: "synthetic-span-version", SHA256: partialFixtureSHA([]byte(span)), Bytes: int64(len(span))}},
		VisiblePDF:              presign.PDFPin{Artifact: presign.ArtifactPin{StorageKey: "synthetic/presign/visible.pdf", VersionID: "synthetic-visible-version", SHA256: partialFixtureSHA([]byte("synthetic derivative")), Bytes: 1100}, Pages: 2},
		VisibleStampProofSHA256: partialFixtureSHA([]byte("synthetic worker proof"))})
	if err != nil {
		t.Fatal(err)
	}
	rows[0].Status = "signed"
	rows[0].SignedAt = pgtype.Timestamptz{Time: executed, Valid: true}
	rows[0].MagicTokenHash = []byte{}
	rows[0].MagicTokenExpiresAt = pgtype.Timestamptz{Time: time.Unix(0, 0).UTC(), Valid: true}
	s := execution.Snapshot().Signature
	sum, err := hex.DecodeString(s.Image.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	f := &providerPartialFixture{doc: doc, rows: rows, fields: fields, signatures: []*generated.Signature{{ID: s.ID, DocumentID: doc.ID, RecipientID: s.RecipientID, FieldID: s.FieldID,
		Font: s.Style.Font, TypedName: s.TypedName, ImageStorageKey: s.Image.StorageKey, ImageSha256: sum, SignedAt: rows[0].SignedAt,
		ImageVersionID: pgtype.Text{String: s.Image.VersionID, Valid: true}, ImageVersionPinRequired: true, SignatureKind: "delegated_grant_v1", PresignExecutionID: pgtype.UUID{Bytes: execution.Snapshot().ID, Valid: true}}},
		evidence: ProviderPartialEvidence{Policy: policy, Grant: grant, Execution: execution, SignatureSpanRecipe: ProviderSignatureSpanRecipeV1, SignatureSpan: []byte(span), SignatureFontBytes: font, DataAdmission: admission}}
	f.syncRelation()
	return f
}

func (f *providerPartialFixture) syncRelation() {
	e := f.evidence.Execution.Snapshot()
	f.evidence.Relation = ProviderExecutionRelation{OrgID: e.OrgID, DocumentID: e.Document.ID, ExecutionID: e.ID, ExecutionSHA256: f.evidence.Execution.Commitment(), SignatureID: e.Signature.ID, CeremonyEpoch: e.CeremonyEpoch}
}

func (f *providerPartialFixture) replaceExecution(t *testing.T, change func(*presign.ExecutionSnapshot)) {
	t.Helper()
	snapshot := f.evidence.Execution.Snapshot()
	change(&snapshot)
	execution, err := presign.NewExecution(snapshot)
	if err != nil {
		t.Fatal("invalid adversarial fixture descriptor", err)
	}
	f.evidence.Execution = execution
	f.syncRelation()
}

func (f *providerPartialFixture) validate() error {
	return ValidateProviderPartialSignatureRows(f.doc, f.rows, f.fields, f.signatures, 2, f.evidence)
}

func TestProviderPartialAcceptsExactCommittedStateWithoutCompletingCustomer(t *testing.T) {
	for _, status := range []string{"pending", "sent", "viewed"} {
		t.Run(status, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.rows[1].Status = status
			before, err := json.Marshal([]any{f.doc, f.rows, f.fields, f.signatures, f.evidence.Policy, f.evidence.Grant, f.evidence.Execution, f.evidence.DataAdmission.CanonicalJSON(), f.evidence.SignatureSpan, f.evidence.SignatureFontBytes})
			if err != nil {
				t.Fatal(err)
			}
			if err := f.validate(); err != nil {
				t.Fatal(err)
			}
			after, _ := json.Marshal([]any{f.doc, f.rows, f.fields, f.signatures, f.evidence.Policy, f.evidence.Grant, f.evidence.Execution, f.evidence.DataAdmission.CanonicalJSON(), f.evidence.SignatureSpan, f.evidence.SignatureFontBytes})
			if !bytes.Equal(before, after) {
				t.Fatal("partial validation mutated recorded state")
			}
			if !errors.Is(ValidateSignatureRows(f.doc, f.rows, f.fields, f.signatures, 2), ErrInvalid) {
				t.Fatal("provider-only evidence completed the unchanged all-party validator")
			}
		})
	}
}

func TestProviderPartialApprovalModeDoesNotFabricateHumanReview(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputApprovedData)
	if err := f.validate(); err != nil {
		t.Fatal(err)
	}
	if f.doc.HtmlReviewedAt.Valid || f.doc.HtmlReviewedBy.Valid || len(f.doc.HtmlReviewedPdfSha256) != 0 || f.doc.HtmlReviewedMaterializationID.Valid {
		t.Fatal("approved-data validation fabricated review")
	}
	other := newProviderPartialFixture(t, presign.InputApprovedData)
	for _, admission := range []presignregistry.DataAdmission{{}, other.evidence.DataAdmission} {
		f.evidence.DataAdmission = admission
		if !errors.Is(f.validate(), ErrInvalid) {
			t.Fatal("missing or unrelated persisted data admission accepted")
		}
	}
	reviewed := newProviderPartialFixture(t, presign.InputReviewedDocument)
	reviewed.doc.HtmlReviewedAt = pgtype.Timestamptz{}
	if !errors.Is(reviewed.validate(), ErrInvalid) {
		t.Fatal("reviewed-document mode accepted absent human review")
	}
}

func TestProviderPartialSealingEpochPublicationStates(t *testing.T) {
	for name, epoch := range map[string]func(time.Time) pgtype.Timestamptz{
		"not yet published": func(time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{} },
		"previous ceremony": func(now time.Time) pgtype.Timestamptz {
			return pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true}
		},
		"exact already published": func(now time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: now, Valid: true} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.doc.Status = "sealing"
			f.doc.Article13NoticeEpochAt = epoch(f.evidence.Execution.Snapshot().CeremonyEpoch)
			if err := f.validate(); err != nil {
				t.Fatal("committed sealing incorrectly required epoch publication", err)
			}
			// The relation/intent epoch must remain exact even while the document
			// has no published new epoch; prior/null cannot replace that evidence.
			f.evidence.Relation.CeremonyEpoch = f.evidence.Relation.CeremonyEpoch.Add(-time.Microsecond)
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("pending publication accepted a different committed relation epoch")
			}
		})
	}
	for _, status := range []string{"sent", "in_progress", "expired"} {
		t.Run(status, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.doc.Status = status
			if err := f.validate(); err != nil {
				t.Fatal("exact published partial state rejected", err)
			}
			f.doc.Article13NoticeEpochAt = pgtype.Timestamptz{}
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("active/expired state accepted an unpublished epoch")
			}
			f.doc.Article13NoticeEpochAt = pgtype.Timestamptz{Time: f.evidence.Execution.Snapshot().CeremonyEpoch.Add(-time.Hour), Valid: true}
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("active/expired state accepted a stale published epoch")
			}
		})
	}
	for name, epoch := range map[string]func(time.Time) pgtype.Timestamptz{
		"future": func(now time.Time) pgtype.Timestamptz {
			return pgtype.Timestamptz{Time: now.Add(time.Microsecond), Valid: true}
		},
		"zero": func(time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Valid: true} },
		"infinite": func(now time.Time) pgtype.Timestamptz {
			return pgtype.Timestamptz{Time: now, InfinityModifier: pgtype.Infinity, Valid: true}
		},
	} {
		t.Run("invalid sealing "+name, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.doc.Status = "sealing"
			f.doc.Article13NoticeEpochAt = epoch(f.evidence.Execution.Snapshot().CeremonyEpoch)
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("invalid sealing epoch accepted")
			}
		})
	}
	for _, status := range []string{"draft", "", "unsupported", "changes_requested", "declined", "voided", "finalizing", "completed"} {
		t.Run("refuse "+status, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.doc.Status = status
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("inconsistent or non-partial lifecycle accepted")
			}
		})
	}
}

func TestProviderPartialCommittedArchiveIsIndependentOfCurrentBundle(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputReviewedDocument)
	// A synthetic former archive supplies its own pinned bytes; this tests the
	// integrity contract only, not WOFF parsing or historical font provenance.
	f.evidence.SignatureFontBytes = []byte("synthetic former pinned font archive")
	grantSnapshot := f.evidence.Grant.Snapshot()
	grantSnapshot.Signature.FontSHA256 = partialFixtureSHA(f.evidence.SignatureFontBytes)
	grant, err := presign.NewGrant(grantSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	f.evidence.Grant = grant
	f.replaceExecution(t, func(e *presign.ExecutionSnapshot) {
		e.Grant = grant.Reference()
		e.Signature.Style = grant.Snapshot().Signature
	})
	current, err := render.SignatureFontSHA256("Caveat")
	if err != nil || current == grantSnapshot.Signature.FontSHA256 {
		t.Fatal("test must differ from current bundle", err)
	}
	if err := f.validate(); err != nil {
		t.Fatal("committed evidence depended on current font bundle", err)
	}
	f.evidence.SignatureFontBytes[0] ^= 1
	if !errors.Is(f.validate(), ErrInvalid) {
		t.Fatal("archive byte tampering accepted")
	}
}

func TestProviderPartialApprovedDataDoesNotRelyOnIncidentalHumanReview(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputApprovedData)
	// A real existing review may be present, but this policy's admission records
	// that it did not rely on it. Do not claim the document was never reviewed.
	f.doc.HtmlReviewedBy = pgtype.UUID{Bytes: f.doc.SenderID, Valid: true}
	f.doc.HtmlReviewedAt = pgtype.Timestamptz{Time: f.evidence.Execution.Snapshot().ExecutedAt.Add(-time.Minute), Valid: true}
	f.doc.HtmlReviewedPdfSha256 = bytes.Clone(f.doc.PdfSha256)
	f.doc.HtmlReviewedMaterializationID = f.doc.HtmlCurrentMaterializationID
	if f.evidence.DataAdmission.Snapshot().ReviewKind != "none" || f.evidence.Execution.Snapshot().Document.ReviewEvidenceSHA256 != presignregistry.NoHumanReviewSHA256() {
		t.Fatal("approved-data fixture must record explicit review non-reliance")
	}
	if err := f.validate(); err != nil {
		t.Fatal("incidental review was incorrectly required or forbidden", err)
	}
}

func TestProviderPartialCanonicalOptionsAndOrderedRows(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputReviewedDocument)
	commitment := f.evidence.Execution.Snapshot().Document.Materialization.SourceCommitment
	// JSONB member ordering is not an options commitment. The canonical typed
	// projection remains unchanged while exact required options are checked.
	f.fields[0].OptionsJson = json.RawMessage(`{"source_commitment":"` + commitment + `","slot":"customer","policy":"hash-branded-signing-page-a4-v1"}`)
	f.rows[0], f.rows[1] = f.rows[1], f.rows[0]
	f.fields[0], f.fields[1] = f.fields[1], f.fields[0]
	if err := f.validate(); err != nil {
		t.Fatal("incidental database ordering changed pinned meaning", err)
	}
}

func TestProviderPartialRejectsUnboundAndForgedState(t *testing.T) {
	cases := map[string]func(*providerPartialFixture){
		"zero execution":       func(f *providerPartialFixture) { f.evidence.Execution = presign.Execution{} },
		"missing document":     func(f *providerPartialFixture) { f.doc = nil },
		"foreign document":     func(f *providerPartialFixture) { f.doc.ID = uuid.New() },
		"foreign organization": func(f *providerPartialFixture) { f.doc.OrgID = uuid.New() },
		"other author":         func(f *providerPartialFixture) { f.doc.SenderID = uuid.New() },
		"sequential":           func(f *providerPartialFixture) { f.doc.RoutingMode = "sequential" },
		"envelope":             func(f *providerPartialFixture) { f.doc.IsEnvelope = true },
		"parent envelope":      func(f *providerPartialFixture) { f.doc.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true} },
		"deleted": func(f *providerPartialFixture) {
			f.doc.DeletedAt = pgtype.Timestamptz{Time: f.evidence.Execution.Snapshot().ExecutedAt, Valid: true}
		},
		"unregistered materialization": func(f *providerPartialFixture) { f.doc.HtmlCurrentMaterializationID = pgtype.UUID{} },
		"other materialization":        func(f *providerPartialFixture) { f.doc.HtmlCurrentMaterializationID.Bytes = uuid.New() },
		"other revision":               func(f *providerPartialFixture) { f.doc.HtmlCurrentMaterializationSequence.Int32++ },
		"current source missing":       func(f *providerPartialFixture) { f.doc.HtmlCurrentSourceJson = nil },
		"current source corrupted":     func(f *providerPartialFixture) { f.doc.HtmlCurrentSourceJson[0] ^= 1 },
		"other page count":             func(f *providerPartialFixture) { f.doc.HtmlCurrentPageCount.Int32++ },
		"base storage key":             func(f *providerPartialFixture) { f.doc.PdfStorageKey.String = "other/base.pdf" },
		"base storage version":         func(f *providerPartialFixture) { f.doc.PdfStorageVersionID.String = "other-version" },
		"base digest":                  func(f *providerPartialFixture) { f.doc.PdfSha256[0] ^= 1 },
		"mutable storage":              func(f *providerPartialFixture) { f.doc.EvidenceVersionPinsRequired = false },
		"template ID":                  func(f *providerPartialFixture) { f.doc.TemplateID.Bytes = uuid.New() },
		"reviewer identity":            func(f *providerPartialFixture) { f.doc.HtmlReviewedBy.Bytes = uuid.New() },
		"review timestamp": func(f *providerPartialFixture) {
			f.doc.HtmlReviewedAt.Time = f.doc.HtmlReviewedAt.Time.Add(time.Microsecond)
		},
		"review postdates execution": func(f *providerPartialFixture) {
			f.doc.HtmlReviewedAt.Time = f.evidence.Execution.Snapshot().ExecutedAt.Add(time.Microsecond)
		},
		"ceremony epoch": func(f *providerPartialFixture) {
			f.doc.Article13NoticeEpochAt.Time = f.doc.Article13NoticeEpochAt.Time.Add(time.Microsecond)
		},
		"relation organization": func(f *providerPartialFixture) { f.evidence.Relation.OrgID = uuid.New() },
		"relation document":     func(f *providerPartialFixture) { f.evidence.Relation.DocumentID = uuid.New() },
		"relation execution":    func(f *providerPartialFixture) { f.evidence.Relation.ExecutionID = uuid.New() },
		"relation commitment": func(f *providerPartialFixture) {
			f.evidence.Relation.ExecutionSHA256 = partialFixtureSHA([]byte("other execution"))
		},
		"relation signature": func(f *providerPartialFixture) { f.evidence.Relation.SignatureID = uuid.New() },
		"relation epoch": func(f *providerPartialFixture) {
			f.evidence.Relation.CeremonyEpoch = f.evidence.Relation.CeremonyEpoch.Add(time.Microsecond)
		},
		"extra recipient": func(f *providerPartialFixture) {
			f.rows = append(f.rows, &generated.Recipient{ID: uuid.New(), DocumentID: f.doc.ID, Role: "signer"})
		},
		"missing recipient":            func(f *providerPartialFixture) { f.rows = f.rows[:1] },
		"nil recipient":                func(f *providerPartialFixture) { f.rows[0] = nil },
		"replaced provider identity":   func(f *providerPartialFixture) { f.rows[0].Name = "Other Provider" },
		"replaced provider email case": func(f *providerPartialFixture) { f.rows[0].Email = "Provider@example.test" },
		"provider status only":         func(f *providerPartialFixture) { f.rows[0].SignedAt = pgtype.Timestamptz{} },
		"provider unsigned":            func(f *providerPartialFixture) { f.rows[0].Status = "pending" },
		"provider different signing time": func(f *providerPartialFixture) {
			f.rows[0].SignedAt.Time = f.rows[0].SignedAt.Time.Add(time.Microsecond)
		},
		"provider manual token":                    func(f *providerPartialFixture) { f.rows[0].MagicTokenHash = []byte("synthetic credential digest") },
		"provider manual token deadline":           func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt = f.rows[0].SignedAt },
		"provider disabled expiry missing":         func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt = pgtype.Timestamptz{} },
		"provider disabled expiry zero":            func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt = pgtype.Timestamptz{Valid: true} },
		"provider disabled expiry infinite":        func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt.InfinityModifier = pgtype.Infinity },
		"provider disabled expiry other past":      func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt.Time = time.Unix(-1, 0).UTC() },
		"provider disabled expiry subsecond drift": func(f *providerPartialFixture) { f.rows[0].MagicTokenExpiresAt.Time = time.Unix(0, 1000).UTC() },
		"provider invitation":                      func(f *providerPartialFixture) { f.rows[0].SentAt = f.rows[0].SignedAt },
		"provider visit":                           func(f *providerPartialFixture) { f.rows[0].FirstViewedAt = f.rows[0].SignedAt },
		"customer signed status":                   func(f *providerPartialFixture) { f.rows[1].Status = "signed" },
		"customer signing timestamp":               func(f *providerPartialFixture) { f.rows[1].SignedAt = f.rows[0].SignedAt },
		"customer declined":                        func(f *providerPartialFixture) { f.rows[1].Status = "declined" },
		"extra field":                              func(f *providerPartialFixture) { f.fields = append(f.fields, f.fields[0]) },
		"missing field":                            func(f *providerPartialFixture) { f.fields = f.fields[:1] },
		"nil field":                                func(f *providerPartialFixture) { f.fields[0] = nil },
		"new field same rectangle":                 func(f *providerPartialFixture) { f.fields[1].ID = uuid.New() },
		"other field owner":                        func(f *providerPartialFixture) { f.fields[1].RecipientID = f.fields[0].RecipientID },
		"fillable field":                           func(f *providerPartialFixture) { f.fields[1].Type = "text" },
		"optional signature":                       func(f *providerPartialFixture) { f.fields[1].Required = false },
		"moved rectangle": func(f *providerPartialFixture) {
			f.fields[1].YPct = pgtype.Numeric{Int: big.NewInt(780000), Exp: -4, Valid: true}
		},
		"float rounded subprecision": func(f *providerPartialFixture) {
			f.fields[1].XPct = pgtype.Numeric{Int: new(big.Int).SetUint64(100000000000000001), Exp: -16, Valid: true}
		},
		"wrong field options":         func(f *providerPartialFixture) { f.fields[1].OptionsJson = f.fields[0].OptionsJson },
		"filled signature field":      func(f *providerPartialFixture) { f.fields[1].Value = pgtype.Text{String: f.rows[0].Name, Valid: true} },
		"completed signature field":   func(f *providerPartialFixture) { f.fields[1].CompletedAt = f.rows[0].SignedAt },
		"missing signature":           func(f *providerPartialFixture) { f.signatures = nil },
		"extra signature":             func(f *providerPartialFixture) { f.signatures = append(f.signatures, f.signatures[0]) },
		"nil signature":               func(f *providerPartialFixture) { f.signatures[0] = nil },
		"manual kind":                 func(f *providerPartialFixture) { f.signatures[0].SignatureKind = "manual" },
		"absent execution reference":  func(f *providerPartialFixture) { f.signatures[0].PresignExecutionID = pgtype.UUID{} },
		"foreign execution reference": func(f *providerPartialFixture) { f.signatures[0].PresignExecutionID.Bytes = uuid.New() },
		"signature ID":                func(f *providerPartialFixture) { f.signatures[0].ID = uuid.New() },
		"signature document":          func(f *providerPartialFixture) { f.signatures[0].DocumentID = uuid.New() },
		"signature customer":          func(f *providerPartialFixture) { f.signatures[0].RecipientID = f.rows[1].ID },
		"signature customer field":    func(f *providerPartialFixture) { f.signatures[0].FieldID = f.fields[0].ID },
		"signature typed name":        func(f *providerPartialFixture) { f.signatures[0].TypedName = "Other Provider" },
		"signature font":              func(f *providerPartialFixture) { f.signatures[0].Font = "Great Vibes" },
		"signature time": func(f *providerPartialFixture) {
			f.signatures[0].SignedAt.Time = f.signatures[0].SignedAt.Time.Add(time.Microsecond)
		},
		"signature infinite time": func(f *providerPartialFixture) { f.signatures[0].SignedAt.InfinityModifier = pgtype.Infinity },
		"signature manual IP": func(f *providerPartialFixture) {
			ip := netip.MustParseAddr("192.0.2.1")
			f.signatures[0].SignerIp = &ip
		},
		"signature manual UA": func(f *providerPartialFixture) {
			f.signatures[0].SignerUa = pgtype.Text{String: "synthetic UA", Valid: true}
		},
		"signature key":            func(f *providerPartialFixture) { f.signatures[0].ImageStorageKey = "other/span.html" },
		"signature version":        func(f *providerPartialFixture) { f.signatures[0].ImageVersionID.String = "other-version" },
		"signature no version pin": func(f *providerPartialFixture) { f.signatures[0].ImageVersionPinRequired = false },
		"signature SHA":            func(f *providerPartialFixture) { f.signatures[0].ImageSha256[0] ^= 1 },
		"span missing":             func(f *providerPartialFixture) { f.evidence.SignatureSpan = nil },
		"span tampered":            func(f *providerPartialFixture) { f.evidence.SignatureSpan[0] ^= 1 },
		"span recipe unknown":      func(f *providerPartialFixture) { f.evidence.SignatureSpanRecipe = "hash-signature-span-v2" },
		"span oversized": func(f *providerPartialFixture) {
			f.evidence.SignatureSpan = bytes.Repeat([]byte("x"), presign.MaxSignatureBytes+1)
		},
		"font missing":  func(f *providerPartialFixture) { f.evidence.SignatureFontBytes = nil },
		"font tampered": func(f *providerPartialFixture) { f.evidence.SignatureFontBytes[0] ^= 1 },
		"font oversized": func(f *providerPartialFixture) {
			f.evidence.SignatureFontBytes = bytes.Repeat([]byte("x"), presign.MaxSignatureBytes+1)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			change(f)
			if err := f.validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("forged or misbound state accepted: %v", err)
			}
		})
	}
}

func TestProviderPartialRejectsInternallyValidDescriptorsThatDisagreeWithRows(t *testing.T) {
	for name, change := range map[string]func(*presign.ExecutionSnapshot){
		"field ID": func(e *presign.ExecutionSnapshot) { e.Document.Fields[0].ID = uuid.New() },
		"field options digest": func(e *presign.ExecutionSnapshot) {
			e.Document.Fields[0].OptionsSHA256 = partialFixtureSHA([]byte("other options"))
		},
		"customer company": func(e *presign.ExecutionSnapshot) { e.Document.Parties[0].CompanyName = "Other Customer AB" },
		"signing plan": func(e *presign.ExecutionSnapshot) {
			e.Document.SigningPlanSHA256 = partialFixtureSHA([]byte("other plan"))
		},
		"source commitment": func(e *presign.ExecutionSnapshot) {
			e.Document.Materialization.SourceCommitment = partialFixtureSHA([]byte("other source"))
			e.Document.Fields[0].SourceCommitment = e.Document.Materialization.SourceCommitment
			e.Document.Fields[1].SourceCommitment = e.Document.Materialization.SourceCommitment
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newProviderPartialFixture(t, presign.InputReviewedDocument)
			f.replaceExecution(t, change)
			if err := presign.ValidateCommittedExecution(f.evidence.Policy, f.evidence.Grant, f.evidence.Execution); err != nil {
				t.Fatal("test must retain valid immutable descriptor integrity", err)
			}
			if !errors.Is(f.validate(), ErrInvalid) {
				t.Fatal("valid-shaped descriptor replaced exact stored rows")
			}
		})
	}
}

func TestProviderPartialRejectsSelfConsistentArbitrarySignatureHTML(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputReviewedDocument)
	f.evidence.SignatureSpan = []byte(`<span class="hash-signature" data-font="Caveat"><img src="https://invalid.test/tracker"></span>`)
	f.replaceExecution(t, func(e *presign.ExecutionSnapshot) {
		e.Signature.Image.SHA256 = partialFixtureSHA(f.evidence.SignatureSpan)
		e.Signature.Image.Bytes = int64(len(f.evidence.SignatureSpan))
	})
	sum := sha256.Sum256(f.evidence.SignatureSpan)
	f.signatures[0].ImageSha256 = sum[:]
	if !errors.Is(f.validate(), ErrInvalid) {
		t.Fatal("matching SHA alone admitted arbitrary signature markup")
	}
}

func TestProviderPartialRejectsLegacySourceAndLeavesFinalValidationStrict(t *testing.T) {
	f := newProviderPartialFixture(t, presign.InputReviewedDocument)
	_, legacy, rows := testfixture.HTMLContract(t)
	fields := testfixture.ContractSignatureFields(legacy, rows)
	if !errors.Is(ValidateProviderPartialSignatureRows(legacy, rows, fields, nil, 1, f.evidence), ErrInvalid) {
		t.Fatal("partial mode admitted generic/manual source")
	}
	// Completing the customer changes the supported state to all-party final;
	// it must not remain acceptable as a provider-only partial state.
	f.rows[1].Status = "signed"
	f.rows[1].SignedAt = f.rows[0].SignedAt
	f.signatures = append(f.signatures, &generated.Signature{ID: uuid.New(), DocumentID: f.doc.ID, RecipientID: f.rows[1].ID, FieldID: f.fields[0].ID})
	if err := ValidateSignatureRows(f.doc, f.rows, f.fields, f.signatures, 2); err != nil {
		t.Fatal("existing all-party row validator behavior changed", err)
	}
	if !errors.Is(f.validate(), ErrInvalid) {
		t.Fatal("all-party final state mislabeled provider partial")
	}
}
