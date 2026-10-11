// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const ProviderSignatureSpanRecipeV1 = "hash-signature-span-v1"

// ProviderExecutionRelation is read from the committed companion row, under
// the caller's document/evidence locks. A signature status or a supplied UUID
// alone is never a substitute for this exact relation.
type ProviderExecutionRelation struct {
	OrgID           uuid.UUID
	DocumentID      uuid.UUID
	ExecutionID     uuid.UUID
	ExecutionSHA256 string
	SignatureID     uuid.UUID
	CeremonyEpoch   time.Time
}

// ProviderPartialEvidence contains authoritative stored descriptors and bytes
// read from their exact immutable storage/archive versions, never public JSON
// assertions. Font bytes are checked against the recorded style, not today's
// bundle, so a later bundle update cannot invalidate committed evidence.
//
// DataAdmission is the separately paired persisted admission record. Its
// canonical mode, data, review and lineage bindings are checked here. This
// validator does not reevaluate workflow rules, prove a storage read, or define
// new digest domains. Locked source/admission derivation, branding, archived
// recipe/disclosure provenance, visible-PDF proof, authentication and fresh
// authorization remain the caller's duties.
type ProviderPartialEvidence struct {
	Policy              presign.Policy
	Grant               presign.Grant
	Execution           presign.Execution
	Relation            ProviderExecutionRelation
	SignatureSpanRecipe string
	SignatureSpan       []byte
	SignatureFontBytes  []byte
	DataAdmission       presignregistry.DataAdmission
}

// ValidateProviderPartialSignatureRows validates only the committed provider
// partial state. It neither admits a new use nor authorizes publication or
// readback. Final all-party validation remains ValidateSignatureRows.
//
// doc retains the original source/base PDF: a separately witnessed provider
// derivative must not replace that source. Both fields remain unfilled and
// fixed; the provider mark exists as its separate signature/execution evidence.
// A committed sealing state can precede publication of its new notice epoch;
// the companion relation is authoritative there. Active/expired partial states
// require the exact published epoch. Expiry permits private integrity checks,
// never a signing link or permission to publish an invitation.
func ValidateProviderPartialSignatureRows(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, signatures []*generated.Signature, pageCount int, evidence ProviderPartialEvidence) error {
	if err := presign.ValidateCommittedExecution(evidence.Policy, evidence.Grant, evidence.Execution); err != nil {
		return invalid("provider execution descriptor integrity: %v", err)
	}
	e := evidence.Execution.Snapshot()
	d := e.Document
	if doc == nil || doc.ID != d.ID || doc.OrgID != d.OrgID || doc.SenderID != d.SenderID || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || doc.DeletedAt.Valid || doc.RoutingMode != "parallel" {
		return invalid("provider partial requires the exact standalone parallel document")
	}
	if pageCount != d.BasePDF.Pages || !doc.HtmlCurrentMaterializationID.Valid || uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) != d.Materialization.ID ||
		!doc.HtmlCurrentMaterializationSequence.Valid || int64(doc.HtmlCurrentMaterializationSequence.Int32) != d.Materialization.Revision ||
		!doc.HtmlCurrentPageCount.Valid || int(doc.HtmlCurrentPageCount.Int32) != pageCount {
		return invalid("provider partial materialization or page count differs")
	}
	if !doc.EvidenceVersionPinsRequired || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String != d.BasePDF.Artifact.StorageKey ||
		!doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String != d.BasePDF.Artifact.VersionID ||
		len(doc.PdfSha256) != sha256.Size || hex.EncodeToString(doc.PdfSha256) != d.BasePDF.Artifact.SHA256 {
		return invalid("provider partial base PDF version differs")
	}
	r := evidence.Relation
	switch doc.Status {
	case "sealing":
		// BeginDocumentSendSealing changes only status. Until completion the
		// document can retain a previous epoch or NULL while the new committed
		// execution/intent already has its independently allocated exact epoch.
		if doc.Article13NoticeEpochAt.Valid && (doc.Article13NoticeEpochAt.InfinityModifier != pgtype.Finite || doc.Article13NoticeEpochAt.Time.IsZero() || doc.Article13NoticeEpochAt.Time.After(e.CeremonyEpoch)) {
			return invalid("provider partial sealing has an invalid prior notice epoch")
		}
	case "sent", "in_progress", "expired":
		if !partialTimestampEquals(doc.Article13NoticeEpochAt, e.CeremonyEpoch) {
			return invalid("provider partial published notice epoch differs")
		}
	default:
		return invalid("provider partial document is not in a supported committed lifecycle state")
	}
	if r.OrgID != e.OrgID || r.DocumentID != d.ID || r.ExecutionID != e.ID ||
		r.ExecutionSHA256 != evidence.Execution.Commitment() || r.SignatureID != e.Signature.ID || !r.CeremonyEpoch.Equal(e.CeremonyEpoch) {
		return invalid("provider partial execution relation or ceremony differs")
	}
	mode := evidence.Policy.Snapshot().Rules.InputMode
	if err := htmlsource.Validate(doc, mode == presign.InputReviewedDocument); err != nil {
		return invalid("provider partial source/review: %v", err)
	}
	if mode == presign.InputReviewedDocument && doc.HtmlReviewedAt.Time.After(e.ExecutedAt) {
		return invalid("provider partial review postdates execution")
	}
	if evidence.DataAdmission.Commitment() != d.DataEvidenceSHA256 || presignregistry.ValidateDataAdmissionForExecution(evidence.DataAdmission, evidence.Policy, evidence.Grant, d) != nil ||
		presignregistry.ValidateDataAdmissionDocument(evidence.DataAdmission, doc) != nil {
		return invalid("provider partial persisted data admission differs")
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil || commitment != d.Materialization.SourceCommitment {
		return invalid("provider partial source commitment differs")
	}
	policy, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil || artifact == nil || artifact.PlanSHA256 != d.SigningPlanSHA256 {
		return invalid("provider partial requires the exact source-schema-3 signing plan")
	}
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil || !doc.TemplateID.Valid || uuid.UUID(doc.TemplateID.Bytes) != d.Template.ID || input.TemplateID != d.Template.ID || int64(input.TemplateVersion) != d.Template.Version ||
		input.TemplateContentSHA256 != d.Template.ContentSHA256 || input.TemplateApprovedBy != d.Template.ApprovedBy || !input.TemplateApprovedAt.Equal(d.Template.ApprovedAt) {
		return invalid("provider partial approved template differs")
	}
	if len(rows) != 2 || len(fields) != 2 || len(signatures) != 1 {
		return invalid("provider partial requires exactly two parties/fields and one signature")
	}
	if _, err := RequiredRoles(doc, rows, fields, pageCount); err != nil {
		return err
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil || len(parties) != 2 {
		return invalid("provider partial printed parties are absent")
	}
	bySlot := make(map[string]htmlsource.ContractParty, 2)
	for _, party := range parties {
		bySlot[party.Slot] = party
	}
	byID := make(map[uuid.UUID]*generated.Recipient, 2)
	for _, row := range rows {
		byID[row.ID] = row
	}
	for i, expected := range d.Parties {
		party := bySlot[expected.Slot]
		if party.RecipientID != expected.ID || party.Role != expected.Role || party.Name != expected.Name || party.Email != expected.Email || party.CompanyName != expected.CompanyName || party.CompanyID != expected.CompanyID || party.Authority != expected.AuthorityBasis {
			return invalid("provider partial printed party differs from execution")
		}
		fieldPin := d.Fields[i]
		var field *generated.DocumentField
		for _, candidate := range fields {
			if candidate.ID == fieldPin.ID {
				field = candidate
			}
		}
		options, err := htmlsource.SigningFieldOptions(doc, expected.Slot)
		if err != nil || partialSHA256(options) != fieldPin.OptionsSHA256 || field == nil || !field.RecipientID.Valid || uuid.UUID(field.RecipientID.Bytes) != fieldPin.RecipientID ||
			field.Type != fieldPin.Type || field.Required != fieldPin.Required || int(field.Page) != fieldPin.Page ||
			!partialNumericEquals(field.XPct, fieldPin.X) || !partialNumericEquals(field.YPct, fieldPin.Y) || !partialNumericEquals(field.WPct, fieldPin.W) || !partialNumericEquals(field.HPct, fieldPin.H) ||
			field.Value.Valid || field.Value.String != "" || field.CompletedAt.Valid {
			return invalid("provider partial protected field differs or was filled in place")
		}
		row := byID[expected.ID]
		if expected.Slot == "provider" {
			// The recipient schema requires a finite expiry. Empty hash plus the
			// Unix epoch is the explicit disabled-access marker, never evidence
			// of an invitation, portal visit or manually supplied credential.
			if row.Status != "signed" || !partialTimestampEquals(row.SignedAt, e.ExecutedAt) || len(row.MagicTokenHash) != 0 ||
				!partialTimestampEquals(row.MagicTokenExpiresAt, time.Unix(0, 0).UTC()) || row.SentAt.Valid || row.FirstViewedAt.Valid || row.DeclinedReason.Valid {
				return invalid("provider partial has missing signature status or fabricated manual journey")
			}
		} else if (row.Status != "pending" && row.Status != "sent" && row.Status != "viewed") || row.SignedAt.Valid || row.DeclinedReason.Valid {
			return invalid("provider partial customer must remain unsigned")
		}
	}
	signature := signatures[0]
	s := e.Signature
	if signature == nil || signature.ID != s.ID || signature.DocumentID != d.ID || signature.RecipientID != s.RecipientID || signature.FieldID != s.FieldID ||
		signature.SignatureKind != "delegated_grant_v1" || !signature.PresignExecutionID.Valid || uuid.UUID(signature.PresignExecutionID.Bytes) != e.ID ||
		signature.TypedName != s.TypedName || signature.Font != s.Style.Font || !partialTimestampEquals(signature.SignedAt, e.ExecutedAt) ||
		signature.SignerIp != nil || signature.SignerUa.Valid || signature.SignerUa.String != "" || !signature.ImageVersionPinRequired ||
		signature.ImageStorageKey != s.Image.StorageKey || !signature.ImageVersionID.Valid || signature.ImageVersionID.String != s.Image.VersionID ||
		len(signature.ImageSha256) != sha256.Size || hex.EncodeToString(signature.ImageSha256) != s.Image.SHA256 {
		return invalid("provider partial signature row is not exact delegated evidence")
	}
	if evidence.SignatureSpanRecipe != ProviderSignatureSpanRecipeV1 || len(evidence.SignatureSpan) < 1 || len(evidence.SignatureSpan) > presign.MaxSignatureBytes ||
		int64(len(evidence.SignatureSpan)) != s.Image.Bytes || partialSHA256(evidence.SignatureSpan) != s.Image.SHA256 ||
		len(evidence.SignatureFontBytes) < 1 || len(evidence.SignatureFontBytes) > presign.MaxSignatureBytes || partialSHA256(evidence.SignatureFontBytes) != s.Style.FontSHA256 {
		return invalid("provider partial signature span/font archive differs")
	}
	// This fixed recipe is the existing controlled v1 span, not arbitrary HTML.
	// Font validity already came from the immutable presign style validator;
	// RenderSignatureSpan therefore cannot silently choose its legacy fallback.
	span, err := render.RenderSignatureSpan(s.TypedName, s.Style.Font)
	if err != nil || !bytes.Equal(evidence.SignatureSpan, []byte(span)) {
		return invalid("provider partial signature does not match the controlled v1 recipe")
	}
	return nil
}

func partialSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func partialTimestampEquals(value pgtype.Timestamptz, expected time.Time) bool {
	return value.Valid && value.InfinityModifier == pgtype.Finite && !value.Time.IsZero() && value.Time.Equal(expected)
}

// Match database NUMERIC(7,4) geometry exactly, without float rounding or
// unbounded powers for synthetic malformed inputs. Equivalent representations
// within this bounded decimal domain are accepted.
func partialNumericEquals(value pgtype.Numeric, expected int64) bool {
	if !value.Valid || value.NaN || value.InfinityModifier != pgtype.Finite || value.Int == nil || value.Int.BitLen() > 32 || value.Exp < -4 || value.Exp > 3 {
		return false
	}
	scaled := new(big.Int).Set(value.Int)
	power := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(value.Exp)+4), nil)
	scaled.Mul(scaled, power)
	return scaled.Cmp(big.NewInt(expected)) == 0
}
