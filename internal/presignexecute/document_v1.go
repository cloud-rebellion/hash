// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"encoding/hex"
	"encoding/json"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
)

// EligibleSourceFromModelsV1 validates only the explicitly supported source
// class. It is not a grant permission or execution. The caller supplies its
// actual owned current models after original credential and source admission.
func EligibleSourceFromModelsV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField) (*EligibleSourceV1, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.Status != "draft" || doc.DeletedAt.Valid || doc.ParentEnvelopeID.Valid ||
		doc.IsEnvelope || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.RoutingMode != "parallel" || doc.SigningAdmissionPolicy != "historical" || !doc.UpdatedAt.Valid ||
		!doc.HtmlCurrentMaterializationID.Valid || !doc.HtmlCurrentMaterializationSequence.Valid || doc.HtmlCurrentMaterializationSequence.Int32 < 1 ||
		!doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || len(doc.PdfSha256) != 32 || doc.RenderedPdfKey.Valid || doc.RenderedPdfVersionID.Valid || len(doc.RenderedPdfSha) != 0 || len(rows) != 2 || len(fields) != 2 {
		return nil, ErrInvalid
	}
	if htmlsource.Validate(doc, false) != nil || htmlsource.ValidateContractParties(doc, rows) != nil {
		return nil, ErrInvalid
	}
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil || artifact.Composition.FinalPages < 1 || artifact.Composition.FinalPages > presign.MaxPDFPages ||
		htmlsource.ValidateSigningFields(doc, fields, artifact.Composition.FinalPages) != nil {
		return nil, ErrInvalid
	}
	for _, r := range rows {
		if r == nil || r.Status != "pending" || r.SentAt.Valid || r.FirstViewedAt.Valid || r.SignedAt.Valid {
			return nil, ErrInvalid
		}
	}
	for _, f := range fields {
		if f == nil || f.Value.Valid || f.CompletedAt.Valid {
			return nil, ErrInvalid
		}
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil || !validSHA(commitment) {
		return nil, ErrInvalid
	}
	return &EligibleSourceV1{DocumentUpdatedAt: doc.UpdatedAt.Time.UTC(), MaterializationID: uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes),
		MaterializationRevision: int64(doc.HtmlCurrentMaterializationSequence.Int32), SourceCommitment: commitment}, nil
}

// DocumentSnapshotFromModelsV1 binds actual source, printed parties, protected
// fields and evaluated data. baseBytes is taken only from a verified exact
// source-version read by the owned preparation adapter; it is not a wire field.
func DocumentSnapshotFromModelsV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, admission presignregistry.DataAdmission, baseBytes int64) (presign.DocumentSnapshot, error) {
	var out presign.DocumentSnapshot
	source, err := EligibleSourceFromModelsV1(doc, rows, fields)
	if err != nil || baseBytes < 1 || baseBytes > presign.MaxPDFBytes || presignregistry.ValidateDataAdmissionDocument(admission, doc) != nil {
		return out, ErrInvalid
	}
	in, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		return out, ErrInvalid
	}
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil {
		return out, ErrInvalid
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil || len(parties) != 2 {
		return out, ErrInvalid
	}
	brand, err := json.Marshal(policy.Branding)
	if err != nil {
		return out, ErrInvalid
	}
	a := admission.Snapshot()
	out = presign.DocumentSnapshot{ID: doc.ID, OrgID: doc.OrgID, SenderID: doc.SenderID, Kind: "pdf", SourceSchemaVersion: 3, RequiresSignature: true, SigningMode: "parallel",
		Template:          presign.TemplatePin{ID: in.TemplateID, Version: int64(in.TemplateVersion), ContentSHA256: in.TemplateContentSHA256, ApprovedBy: in.TemplateApprovedBy, ApprovedAt: in.TemplateApprovedAt},
		Materialization:   presign.MaterializationPin{ID: source.MaterializationID, Revision: source.MaterializationRevision, SourceCommitment: source.SourceCommitment},
		BasePDF:           presign.PDFPin{Artifact: presign.ArtifactPin{StorageKey: doc.PdfStorageKey.String, VersionID: doc.PdfStorageVersionID.String, SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: baseBytes}, Pages: artifact.Composition.FinalPages},
		SigningPlanSHA256: artifact.PlanSHA256, BrandingSHA256: digest("hash:presign-signing-branding:v1\x00", brand), ValuesSHA256: a.ValuesSHA256, SectionsSHA256: a.SectionsSHA256,
		ReviewEvidenceSHA256: a.ReviewEvidenceSHA256, DataEvidenceSHA256: admission.Commitment()}
	for i, slot := range []string{"customer", "provider"} {
		// EligibleSourceFromModelsV1 already validated the actual stored options
		// semantically. M82 commits their existing typed canonical encoding,
		// never PostgreSQL's reordered/spaced JSONB output.
		options, err := htmlsource.SigningFieldOptions(doc, slot)
		if err != nil {
			return presign.DocumentSnapshot{}, ErrInvalid
		}
		for _, p := range parties {
			if p.Slot == slot {
				out.Parties[i] = presign.PartySnapshot{ID: p.RecipientID, Slot: slot, Role: p.Role, Name: p.Name, Email: p.Email, CompanyName: p.CompanyName, CompanyID: p.CompanyID, AuthorityBasis: p.Authority}
			}
		}
		for _, f := range fields {
			if f.RecipientID.Valid && uuid.UUID(f.RecipientID.Bytes) == out.Parties[i].ID {
				r := artifact.Fields[i]
				if r.Slot != slot {
					return presign.DocumentSnapshot{}, ErrInvalid
				}
				out.Fields[i] = presign.FieldSnapshot{ID: f.ID, RecipientID: out.Parties[i].ID, Slot: slot, Type: f.Type, Required: f.Required, Page: int(f.Page), X: r.X, Y: r.Y, W: r.W, H: r.H, SourceCommitment: source.SourceCommitment, OptionsSHA256: assetSHA256V1(options)}
			}
		}
	}
	return out, nil
}

func MatchesIntentSourceV1(in IntentV1, doc *generated.Document, s *EligibleSourceV1) bool {
	return doc != nil && s != nil && in.ExpectedOrgID == doc.OrgID && in.DocumentID == doc.ID &&
		in.DocumentUpdatedAt.Equal(s.DocumentUpdatedAt) && in.MaterializationID == s.MaterializationID &&
		in.MaterializationRevision == s.MaterializationRevision && in.SourceCommitment == s.SourceCommitment
}
