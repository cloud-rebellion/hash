// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"reflect"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Data-access interfaces preserve one existing policy for both ordinary query
// callers and the owned fitted journal. No interface grants admission or dispatch.
type signerRoleQueriesV1 interface {
	ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error)
	ListFieldsByDocument(context.Context, uuid.UUID) ([]*generated.DocumentField, error)
	GetDocumentBrandingOverride(context.Context, uuid.UUID) (*generated.DocumentBrandingOverride, error)
}
type fittedPolicyQueriesV1 interface {
	signerRoleQueriesV1
	GetDocumentLawfulBasisConfirmation(context.Context, generated.GetDocumentLawfulBasisConfirmationParams) (*generated.DocumentLawfulBasisConfirmation, error)
	GetOrg(context.Context, uuid.UUID) (*generated.Org, error)
	CountUnfilledRequiredForRecipient(context.Context, generated.CountUnfilledRequiredForRecipientParams) (int64, error)
}

func signerRoleQueriesNilV1(q signerRoleQueriesV1) bool {
	if q == nil {
		return true
	}
	v := reflect.ValueOf(q)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

// Construct only after AcquireRequestJournalV1 admitted the exact protected M91
// header on this same owned SQL session. The wrapper narrows projected data;
// neither header nor private constructor substitutes for resource authority.
type applicationFittedPolicyQueriesV1 struct {
	queries       *generated.Queries
	key           applicationRequestKeyV1
	admissionID   uuid.UUID
	header        generated.GetSignatureFitHTMLPolicySizeHeaderV1Row
	contextHeader generated.GetSignatureFitRequestScopeHeaderV1Row
}

func applicationRequestPolicyHeaderV1(h *generated.GetSignatureFitHTMLPolicySizeHeaderV1Row, key applicationRequestKeyV1, admissionID uuid.UUID) (int64, error) {
	if h == nil || h.DocumentID != key.document || h.OrgID != key.org || !h.AdmissionID.Valid || uuid.UUID(h.AdmissionID.Bytes) != admissionID || admissionID == uuid.Nil || h.PartyCount < 1 || h.PartyCount > 100 || h.FieldCount < 1 || h.FieldCount > 1000 || h.BrandingCount < 0 || h.BrandingCount > 1 {
		return 0, errApplicationBoundRequestV1
	}
	if h.HasHtmlSource != (h.HtmlOriginWireBytes > 0) || h.HasCurrentHtmlSource != (h.HtmlCurrentWireBytes > 0) {
		return 0, errApplicationBoundRequestV1
	}
	n := int64(4096) * (1 + h.PartyCount + h.FieldCount + h.BrandingCount)
	for _, v := range []int64{h.HtmlOriginWireBytes, h.HtmlCurrentWireBytes, h.VariablesWireBytes, h.ProjectedTextBytes, h.FieldOptionsWireBytes} {
		var err error
		n, err = requestPayloadAddV1(n, v)
		if err != nil {
			return 0, err
		}
	}
	if n != h.PolicyBytes {
		return 0, errApplicationBoundRequestV1
	}
	return n, nil
}
func (q *applicationFittedPolicyQueriesV1) validScopeV1(ctx context.Context, documentID uuid.UUID) error {
	if q == nil || q.queries == nil || documentID != q.key.document || q.key.org == uuid.Nil || q.admissionID == uuid.Nil {
		return errApplicationBoundRequestV1
	}
	return requestPayloadCheckContextV1(ctx)
}
func (q *applicationFittedPolicyQueriesV1) documentV1(ctx context.Context) (*generated.Document, error) {
	if q == nil {
		return nil, errApplicationBoundRequestV1
	}
	if err := q.validScopeV1(ctx, q.key.document); err != nil {
		return nil, err
	}
	row, err := q.queries.ReadSignatureFitPolicyDocumentV1(ctx, generated.ReadSignatureFitPolicyDocumentV1Params{DocumentID: q.key.document, OrgID: q.key.org, AdmissionID: pgtype.UUID{Bytes: q.admissionID, Valid: true}, ExpectedOriginWireBytes: q.header.HtmlOriginWireBytes, ExpectedCurrentWireBytes: q.header.HtmlCurrentWireBytes, ExpectedVariablesWireBytes: q.header.VariablesWireBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != q.key.document || row.OrgID != q.key.org || !row.SigningAdmissionActiveID.Valid || uuid.UUID(row.SigningAdmissionActiveID.Bytes) != q.admissionID || int64(len(row.HtmlSourceJson)) != q.header.HtmlOriginWireBytes || int64(len(row.HtmlCurrentSourceJson)) != q.header.HtmlCurrentWireBytes || int64(len(row.VariablesJson)) != q.header.VariablesWireBytes || int64(len(row.Name)) != q.contextHeader.DocumentNameBytes || int64(len(row.LawfulBasis)) != q.contextHeader.LawfulBasisBytes {
		return nil, errApplicationBoundRequestV1
	}
	// Keep every saved HTML origin/current/master/variables/review/party/signing
	// page projection required by the shared validator. Unrelated document JSON
	// and draft/final output fields are not queried or decoded.
	return &generated.Document{ID: row.ID, OrgID: row.OrgID, TemplateID: row.TemplateID, Name: row.Name, Status: row.Status, RoutingMode: row.RoutingMode, SourceKind: row.SourceKind,
		VariablesJson: row.VariablesJson, PdfStorageKey: row.PdfStorageKey, PdfSha256: row.PdfSha256, PdfStorageVersionID: row.PdfStorageVersionID,
		ExpiresAt: row.ExpiresAt, SentAt: row.SentAt, ParentEnvelopeID: row.ParentEnvelopeID, IsEnvelope: row.IsEnvelope, RoutingTier: row.RoutingTier, LawfulBasis: row.LawfulBasis, DeletedAt: row.DeletedAt, DefaultLocale: row.DefaultLocale, RequiresSignature: row.RequiresSignature,
		EvidenceVersionPinsRequired: row.EvidenceVersionPinsRequired, Article13NoticeEpochAt: row.Article13NoticeEpochAt, Article13NoticeSchema: row.Article13NoticeSchema, Article13NoticeEpochV61Committed: row.Article13NoticeEpochV61Committed,
		HtmlSourceJson: row.HtmlSourceJson, HtmlReviewedPdfSha256: row.HtmlReviewedPdfSha256, HtmlReviewedBy: row.HtmlReviewedBy, HtmlReviewedAt: row.HtmlReviewedAt,
		HtmlCurrentMaterializationID: row.HtmlCurrentMaterializationID, HtmlCurrentSourceJson: row.HtmlCurrentSourceJson, HtmlCurrentPageCount: row.HtmlCurrentPageCount, HtmlCurrentMaterializationSequence: row.HtmlCurrentMaterializationSequence,
		HtmlReviewedMaterializationID: row.HtmlReviewedMaterializationID, HtmlEffectiveSourceCommitment: row.HtmlEffectiveSourceCommitment, SigningAdmissionPolicy: row.SigningAdmissionPolicy, SigningAdmissionActiveID: row.SigningAdmissionActiveID}, nil
}
func (q *applicationFittedPolicyQueriesV1) recipientV1(ctx context.Context) (*generated.Recipient, error) {
	if q == nil {
		return nil, errApplicationBoundRequestV1
	}
	if err := q.validScopeV1(ctx, q.key.document); err != nil {
		return nil, err
	}
	row, err := q.queries.ReadSignatureFitPolicyRecipientV1(ctx, generated.ReadSignatureFitPolicyRecipientV1Params{RecipientID: q.key.recipient, DocumentID: q.key.document, OrgID: q.key.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != q.key.recipient || row.DocumentID != q.key.document {
		return nil, errApplicationBoundRequestV1
	}
	return &generated.Recipient{ID: row.ID, DocumentID: row.DocumentID, Role: row.Role, Email: row.Email, Name: row.Name, OrderIndex: row.OrderIndex, Status: row.Status, MagicTokenHash: row.MagicTokenHash, SentAt: row.SentAt, FirstViewedAt: row.FirstViewedAt, SignedAt: row.SignedAt, CreatedAt: row.CreatedAt, MagicTokenExpiresAt: row.MagicTokenExpiresAt}, nil
}
func (q *applicationFittedPolicyQueriesV1) ListRecipientsByDocument(ctx context.Context, documentID uuid.UUID) ([]*generated.Recipient, error) {
	if err := q.validScopeV1(ctx, documentID); err != nil {
		return nil, err
	}
	rows, err := q.queries.ListSignatureFitPolicyPartiesV1(ctx, generated.ListSignatureFitPolicyPartiesV1Params{DocumentID: q.key.document, OrgID: q.key.org})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != q.header.PartyCount {
		return nil, errApplicationBoundRequestV1
	}
	out := make([]*generated.Recipient, 0, len(rows))
	for _, r := range rows {
		if r == nil || r.ID == uuid.Nil || r.DocumentID != q.key.document {
			return nil, errApplicationBoundRequestV1
		}
		out = append(out, &generated.Recipient{ID: r.ID, DocumentID: r.DocumentID, Role: r.Role, Email: r.Email, Name: r.Name, OrderIndex: r.OrderIndex, Status: r.Status, CreatedAt: r.CreatedAt})
	}
	return out, requestPayloadCheckContextV1(ctx)
}
func (q *applicationFittedPolicyQueriesV1) ListFieldsByDocument(ctx context.Context, documentID uuid.UUID) ([]*generated.DocumentField, error) {
	if err := q.validScopeV1(ctx, documentID); err != nil {
		return nil, err
	}
	rows, err := q.queries.ListSignatureFitPolicyFieldsV1(ctx, generated.ListSignatureFitPolicyFieldsV1Params{DocumentID: q.key.document, OrgID: q.key.org})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != q.header.FieldCount {
		return nil, errApplicationBoundRequestV1
	}
	out := make([]*generated.DocumentField, 0, len(rows))
	var optionsBytes int64
	for _, r := range rows {
		if r == nil || r.ID == uuid.Nil || r.DocumentID != q.key.document || int64(len(r.OptionsJson)) != r.OptionsWireBytes {
			return nil, errApplicationBoundRequestV1
		}
		var err error
		optionsBytes, err = requestPayloadAddV1(optionsBytes, r.OptionsWireBytes)
		if err != nil {
			return nil, err
		}
		out = append(out, &generated.DocumentField{ID: r.ID, DocumentID: r.DocumentID, RecipientID: r.RecipientID, Type: r.Type, Page: r.Page, XPct: r.XPct, YPct: r.YPct, WPct: r.WPct, HPct: r.HPct, Required: r.Required, Label: r.Label, OptionsJson: r.OptionsJson})
	}
	if optionsBytes != q.header.FieldOptionsWireBytes {
		return nil, errApplicationBoundRequestV1
	}
	return out, requestPayloadCheckContextV1(ctx)
}
func (q *applicationFittedPolicyQueriesV1) GetDocumentBrandingOverride(ctx context.Context, documentID uuid.UUID) (*generated.DocumentBrandingOverride, error) {
	if err := q.validScopeV1(ctx, documentID); err != nil {
		return nil, err
	}
	row, err := q.queries.ReadSignatureFitPolicyBrandingV1(ctx, generated.ReadSignatureFitPolicyBrandingV1Params{DocumentID: q.key.document, OrgID: q.key.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != q.key.document || q.header.BrandingCount != 1 {
		return nil, errApplicationBoundRequestV1
	}
	return &generated.DocumentBrandingOverride{DocumentID: row.DocumentID, PrimaryHex: row.PrimaryHex, AccentHex: row.AccentHex, SurfaceHex: row.SurfaceHex, TextHex: row.TextHex, MutedHex: row.MutedHex, LogoUrl: row.LogoUrl, LogoAlt: row.LogoAlt, FontHeading: row.FontHeading, FontBody: row.FontBody, SignatureColor: row.SignatureColor}, nil
}
func (q *applicationFittedPolicyQueriesV1) GetDocumentLawfulBasisConfirmation(ctx context.Context, params generated.GetDocumentLawfulBasisConfirmationParams) (*generated.DocumentLawfulBasisConfirmation, error) {
	if err := q.validScopeV1(ctx, params.DocumentID); err != nil {
		return nil, err
	}
	if params.OrgID != q.key.org {
		return nil, errApplicationBoundRequestV1
	}
	row, err := q.queries.ReadSignatureFitPolicyControllerV1(ctx, generated.ReadSignatureFitPolicyControllerV1Params{DocumentID: q.key.document, OrgID: q.key.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.DocumentID != q.key.document || row.OrgID != q.key.org || int64(len(row.ControllerName)) != q.contextHeader.ControllerNameBytes || int64(len(row.ControllerContact)) != q.contextHeader.ControllerContactBytes || int64(len(row.LawfulBasis)) != q.contextHeader.ConfirmationBasisBytes || int64(len(row.Via)) != q.contextHeader.ConfirmationViaBytes {
		return nil, errApplicationBoundRequestV1
	}
	return &generated.DocumentLawfulBasisConfirmation{DocumentID: row.DocumentID, OrgID: row.OrgID, LawfulBasis: row.LawfulBasis, ConfirmedAt: row.ConfirmedAt, ConfirmedBy: row.ConfirmedBy, Via: row.Via, ControllerName: row.ControllerName, ControllerContact: row.ControllerContact}, nil
}
func (q *applicationFittedPolicyQueriesV1) GetOrg(ctx context.Context, orgID uuid.UUID) (*generated.Org, error) {
	if q == nil {
		return nil, errApplicationBoundRequestV1
	}
	if err := q.validScopeV1(ctx, q.key.document); err != nil {
		return nil, err
	}
	if orgID != q.key.org {
		return nil, errApplicationBoundRequestV1
	}
	row, err := q.queries.ReadSignatureFitPolicyOrgV1(ctx, q.key.org)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != q.key.org || int64(len(row.Name)) != q.contextHeader.ControllerOrgNameBytes {
		return nil, errApplicationBoundRequestV1
	}
	return &generated.Org{ID: row.ID, Name: row.Name}, nil
}
func (q *applicationFittedPolicyQueriesV1) CountUnfilledRequiredForRecipient(ctx context.Context, params generated.CountUnfilledRequiredForRecipientParams) (int64, error) {
	if err := q.validScopeV1(ctx, params.DocumentID); err != nil {
		return 0, err
	}
	if !params.RecipientID.Valid || uuid.UUID(params.RecipientID.Bytes) != q.key.recipient {
		return 0, errApplicationBoundRequestV1
	}
	return q.queries.CountUnfilledRequiredForRecipient(ctx, generated.CountUnfilledRequiredForRecipientParams{DocumentID: q.key.document, RecipientID: pgtype.UUID{Bytes: q.key.recipient, Valid: true}})
}
