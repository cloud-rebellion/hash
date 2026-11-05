// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type mcpDesignBridgeV1 struct{ server *Server }

func (s *Server) MCPDesignBridgeV1() mcp.DesignBridgeV1 { return &mcpDesignBridgeV1{server: s} }

func validMCPDesignActorV1(ctx context.Context, a mcp.DesignActorV1) error {
	key, user, org, err := auth.DesignCredentialIdentityV1(ctx)
	if err != nil || key != a.KeyID || user != a.UserID || org != a.OrgID || a.Authorize == nil {
		return auth.ErrMutationPermissionRevoked
	}
	return nil
}
func safeMCPDesignFailureV1(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{auth.ErrMutationPermissionRevoked, auth.ErrMutationCredentialExpired, context.Canceled, context.DeadlineExceeded, errHTMLTemplatePreviewReceipt, documentpurpose.ErrInvalid} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, errHTMLTemplateConflict) || errors.Is(err, errHTMLDocumentRevisionConflict) || errors.Is(err, resolver.ErrPreviewChanged) || errors.Is(err, htmlmaterialization.ErrInvalid) || errors.Is(err, htmlsource.ErrInvalid) {
		return errors.New("design or document changed; reload its exact source and PDF before continuing")
	}
	if errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrMissingValues) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
		return errors.New("HTML master, declared values or embedded assets are invalid or incomplete")
	}
	return errors.New("native design operation unavailable or refused")
}
func (b *mcpDesignBridgeV1) ReadTemplateV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignTemplateReadInputV1) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return out, err
	}
	legacy, v, close, err := b.server.readHTMLTemplateSelectionOwnedV1(ctx, a.OrgID, a.UserID, id, a.Authorize, htmlTemplateReadSelectionV1{Version: in.Version, ExpectedContentSHA256: in.ExpectedContentSHA256})
	if in.LegacyResponse {
		return mcp.DesignResultV1{Value: legacy, Release: close}, err
	}
	return mcp.DesignResultV1{Value: v, Release: close}, err
}
func (b *mcpDesignBridgeV1) WriteTemplateV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignTemplateInputV1, input *pdfadmission.ApplicationHTMLAuthoringInputV1, profileRaw json.RawMessage) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return out, err
	}
	if input == nil || strings.TrimSpace(in.Name) == "" || !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') || (id == uuid.Nil && in.ExpectedVersion != 0) || (id != uuid.Nil && in.ExpectedVersion < 1) {
		return out, htmlmaster.ErrInvalid
	}
	var err error
	var bundle *catalog.DesignBundleV1
	canonicalInput := input
	var expanded *pdfadmission.ApplicationHTMLAuthoringInputV1
	retained := false
	defer func() {
		if !retained {
			if expanded != nil {
				expanded.CloseConsumerV1()
			}
			if bundle != nil {
				bundle.Close()
			}
		}
	}()
	if len(profileRaw) > 0 {
		if b.server.BrandCatalog == nil {
			return out, catalog.ErrUnavailableV1
		}
		var ref catalog.ProfileRefV1
		if validateUniqueJSONObject(profileRaw) != nil {
			return out, catalog.ErrInputV1
		}
		d := json.NewDecoder(bytes.NewReader(profileRaw))
		d.DisallowUnknownFields()
		if err = d.Decode(&ref); err != nil || d.Decode(new(any)) != io.EOF {
			return out, catalog.ErrInputV1
		}
		bundle, err = b.server.BrandCatalog.ResolveDesignBundleV1(ctx, a.Actor, ref, func(call context.Context, m catalog.BundleMeasureV1) (func(), error) {
			return input.RetainDesignBundleV1(call, m.ProfileBytes, m.MetadataBytes, m.RawAssetBytes, m.Base64Bytes, m.AssetCount)
		})
		if err != nil {
			return out, err
		}
		if len(bundle.Assets) > 0 {
			expanded, err = input.ExpandDesignAssetsV1(ctx, bundle.Assets)
			if err != nil {
				return out, err
			}
			canonicalInput = expanded
		}
	}
	// Resolve opaque slots first, then canonicalize only the complete expanded
	// native input. Its producer grants memory before any JSON expansion.
	content, err := canonicalInput.CanonicalTemplateV1(ctx)
	if err != nil {
		return out, err
	}
	if err = scanHTMLMaster(ctx, content.MasterJSON); err != nil {
		return out, err
	}
	result, close, err := b.server.writeHTMLTemplateActorOwnedV1(ctx, a.Actor, id, htmlTemplateInput{Name: in.Name, ExpectedVersion: in.ExpectedVersion}, content, bundle)
	if err != nil {
		return out, err
	}
	retained = true
	out = mcp.DesignResultV1{Value: map[string]any{"template_id": result.ID, "version": result.Version, "content_sha256": content.SHA256, "approved": false, "visual_review": "pending", "next": "preview_design_template"}, Release: func() {
		if close != nil {
			close()
		}
		if expanded != nil {
			expanded.CloseConsumerV1()
		}
		if bundle != nil {
			bundle.Close()
		}
	}}
	return out, nil
}

const mcpDesignPreviewPurposeV1 = "hash.mcp-design-preview.v1"

func (s *Server) mintMCPDesignPreviewV1(p htmlTemplatePreviewReceipt) (string, error) {
	if s.Cookies == nil || p.CredentialID == uuid.Nil || p.validate(time.Now()) != nil {
		return "", errHTMLTemplatePreviewReceipt
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > maxHTMLPreviewReceiptJSON {
		return "", errHTMLTemplatePreviewReceipt
	}
	return s.Cookies.MintPurpose(mcpDesignPreviewPurposeV1, raw, time.Until(p.ExpiresAt))
}
func (s *Server) validateMCPDesignPreviewV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignApprovalInputV1) (htmlTemplatePreviewReceipt, error) {
	var p htmlTemplatePreviewReceipt
	if validMCPDesignActorV1(ctx, a) != nil || s.Cookies == nil || len(in.PreviewReceipt) == 0 || len(in.PreviewReceipt) > maxHTMLPreviewReceipt || !htmlPreviewSHA256(in.ExpectedContentSHA256) || !htmlPreviewSHA256(in.ExpectedPreviewPDFSHA256) {
		return p, errHTMLTemplatePreviewReceipt
	}
	raw, err := s.Cookies.VerifyPurpose(mcpDesignPreviewPurposeV1, in.PreviewReceipt)
	if err != nil || len(raw) == 0 || len(raw) > maxHTMLPreviewReceiptJSON {
		return p, errHTMLTemplatePreviewReceipt
	}
	if err = validateUniqueJSONObject(raw); err != nil {
		return p, errHTMLTemplatePreviewReceipt
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil || d.Decode(new(any)) != io.EOF || p.validate(time.Now()) != nil || p.CredentialID != a.KeyID || p.OrgID != a.OrgID || p.ReviewerID != a.UserID || p.TemplateID != id || p.Version != in.ExpectedVersion || p.TemplateContentSHA256 != in.ExpectedContentSHA256 || p.PDFSHA256 != in.ExpectedPreviewPDFSHA256 {
		return htmlTemplatePreviewReceipt{}, errHTMLTemplatePreviewReceipt
	}
	return p, nil
}
func (b *mcpDesignBridgeV1) PreviewTemplateV1(parent context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignPreviewInputV1) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	if err := validMCPDesignActorV1(parent, a); err != nil {
		return out, err
	}
	s := b.server
	if s.Sign == nil || s.Sign.PDF == nil || in.ExpectedVersion < 1 || !htmlPreviewSHA256(in.ExpectedContentSHA256) {
		return out, htmlmaster.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(parent, htmlTemplatePreviewTimeout)
	release, err := importguard.Shared.Acquire(a.OrgID)
	if err != nil {
		cancel()
		return out, err
	}
	var closeContent func()
	retained := false
	defer func() {
		if !retained {
			if closeContent != nil {
				closeContent()
			}
			release()
			cancel()
		}
	}()
	native := htmlTemplatePreviewInput{ExpectedVersion: in.ExpectedVersion, ExpectedContentSHA256: in.ExpectedContentSHA256, Values: htmlStringMap(in.Values), Sections: htmlStringMap(in.Sections)}
	content, closeContent, err := s.loadHTMLTemplatePreview(ctx, a.Actor, id, in.ExpectedVersion, in.ExpectedContentSHA256, in.Values, in.Sections)
	if err != nil {
		return out, err
	}
	cleaned, pages, material, err := s.renderHTMLTemplatePDFV1(ctx, a.Actor, content, native)
	if err != nil {
		return out, err
	}
	digest := sha256.Sum256(cleaned.Bytes)
	now := time.Now().UTC()
	p := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: a.OrgID, ReviewerID: a.UserID, CredentialID: a.KeyID, TemplateID: id, Version: in.ExpectedVersion, TemplateContentSHA256: content.SHA256, MaterializationSHA256: material, PDFSHA256: hex.EncodeToString(digest[:]), PageCount: pages, IssuedAt: now, ExpiresAt: now.Add(htmlTemplatePreviewTTL)}
	token, err := s.mintMCPDesignPreviewV1(p)
	if err != nil {
		return out, err
	}
	_, closeRecheck, err := s.loadHTMLTemplatePreview(ctx, a.Actor, id, in.ExpectedVersion, in.ExpectedContentSHA256, nil, nil)
	if err != nil {
		return out, err
	}
	closeRecheck()
	if p.validate(time.Now()) != nil || ctx.Err() != nil {
		return out, errHTMLTemplatePreviewReceipt
	}
	retained = true
	return mcp.DesignResultV1{Value: map[string]any{"template_id": id, "version": p.Version, "content_sha256": p.TemplateContentSHA256, "materialization_sha256": material, "pdf_sha256": p.PDFSHA256, "page_count": pages, "pdf_base64": base64.StdEncoding.EncodeToString(cleaned.Bytes), "preview_receipt": token, "preview_expires_at": p.ExpiresAt, "visual_review": "pending", "review_instructions": "Render and inspect every page of these exact bytes. A hash, download, save or readback does not establish visual quality."}, Release: func() { closeContent(); release(); cancel() }}, nil
}
func (b *mcpDesignBridgeV1) ApproveTemplateV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignApprovalInputV1, pages []int) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	p, err := b.server.validateMCPDesignPreviewV1(ctx, a, id, in)
	if err != nil {
		return out, err
	}
	if err = mcp.DesignPageCoverageV1(pages, p.PageCount); err != nil {
		return out, err
	}
	a.Authorize = htmlTemplatePreviewReceiptAuthorization(a.Authorize, p)
	digest, _ := hex.DecodeString(in.ExpectedContentSHA256)
	row, close, err := b.server.approveHTMLTemplateOwnedV1(ctx, a.Actor, id, htmlTemplateApprovalInput{ExpectedVersion: in.ExpectedVersion, ExpectedContentSHA256: in.ExpectedContentSHA256, ExpectedPreviewPDFSHA256: in.ExpectedPreviewPDFSHA256, PreviewReceipt: in.PreviewReceipt}, digest, p)
	if err != nil {
		return out, err
	}
	return mcp.DesignResultV1{Value: map[string]any{"template_id": id, "version": row.Version, "content_sha256": in.ExpectedContentSHA256, "approved_by": a.UserID, "approved_at": row.ApprovedAt.Time, "visual_review": "caller_attested_all_pages", "contract_approval": false, "sent": false}, Release: close}, nil
}

func (b *mcpDesignBridgeV1) CreateDocumentV1(parent context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignCreationInputV1) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	if err := validMCPDesignActorV1(parent, a); err != nil {
		return out, err
	}
	if in.Purpose == "" || documentpurpose.Validate(in.Purpose) != nil || in.RequestID == uuid.Nil || strings.TrimSpace(in.Name) == "" || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') || in.ExpectedTemplateVersion < 1 || !htmlPreviewSHA256(in.ExpectedTemplateContentSHA256) {
		return out, htmlmaster.ErrInvalid
	}
	s := b.server
	if s.Sign == nil || s.Sign.PDF == nil || s.Storage == nil || s.Audit == nil || s.Billing == nil || s.Versions == nil {
		return out, pdfadmission.ErrHTMLCreationWriterV1
	}
	ctx, cancel := context.WithTimeout(parent, 75*time.Second)
	release, err := importguard.Shared.Acquire(a.OrgID)
	if err != nil {
		cancel()
		return out, err
	}
	retained := false
	defer func() {
		if !retained {
			release()
			cancel()
		}
	}()
	finish := func(close func()) func() {
		return func() {
			if close != nil {
				close()
			}
			release()
			cancel()
		}
	}
	native := htmlDocumentInput{Purpose: in.Purpose, Name: in.Name, ExpectedTemplateVersion: in.ExpectedTemplateVersion, ExpectedTemplateContentSHA256: in.ExpectedTemplateContentSHA256, Values: htmlStringMap(in.Values), Sections: htmlStringMap(in.Sections), RequestID: in.RequestID, ExpectedOrgID: a.OrgID, ExpectedUserID: a.UserID}
	inputDigest, err := crmTemplateCreateInputDigest(a.Actor, id, native)
	if err != nil {
		return out, err
	}
	prior, err := s.findHTMLCreationRequest(ctx, a.Actor, id, in.RequestID, inputDigest)
	if err != nil {
		return out, err
	}
	if prior != nil {
		retained = true
		return mcp.DesignResultV1{Value: prior.response(), Release: finish(prior.closeOwnedWriterV1)}, nil
	}
	digest, _ := hex.DecodeString(in.ExpectedTemplateContentSHA256)
	created, err := s.instantiateHTMLDocument(ctx, a.Actor, id, native, digest, pgtype.Timestamptz{}, nil, inputDigest)
	if err != nil {
		return out, err
	}
	retained = true
	return mcp.DesignResultV1{Value: created.response(), Release: finish(created.closeOwnedWriterV1)}, nil
}

func (b *mcpDesignBridgeV1) scopeV1(parent context.Context, a mcp.DesignActorV1, id uuid.UUID) (*htmlDocumentReadScope, error) {
	if err := validMCPDesignActorV1(parent, a); err != nil {
		return nil, err
	}
	u, ok := auth.FromContext(parent)
	if !ok || b.server.Pool == nil || b.server.Queries == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(parent, resolver.PreviewTimeout)
	return &htmlDocumentReadScope{ctx: ctx, cancel: cancel, id: id, user: u, authorize: a.Authorize}, nil
}
func (b *mcpDesignBridgeV1) sourceV1(scope *htmlDocumentReadScope) (htmlDocumentSourceResponse, *generated.Document, *generated.HtmlDocumentMaterialization, error) {
	doc, current, err := b.server.loadHTMLDocumentRead(scope)
	if err != nil {
		return htmlDocumentSourceResponse{}, nil, nil, err
	}
	var pages int32
	if current != nil {
		pages = current.PageCount
	} else {
		_, pages, err = b.server.readHTMLDocumentPages(scope.ctx, doc)
		if err != nil {
			return htmlDocumentSourceResponse{}, nil, nil, err
		}
	}
	response, err := htmlDocumentSourceDescriptor(doc, pages)
	if err != nil {
		return response, nil, nil, err
	}
	response.CanEdit, err = b.server.checkHTMLDocumentRead(scope, doc, current)
	return response, doc, current, err
}
func (b *mcpDesignBridgeV1) DocumentSourceV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	scope, err := b.scopeV1(ctx, a, id)
	if err != nil {
		return out, err
	}
	defer scope.cancel()
	source, doc, current, err := b.sourceV1(scope)
	if err != nil {
		return out, err
	}
	var provenance any
	if b.server.BrandCatalog != nil {
		provenance, err = b.server.BrandCatalog.TemplateProvenanceV1(scope.ctx, a.Actor, source.TemplateID, source.TemplateVersion)
		if errors.Is(err, catalog.ErrNotFoundV1) {
			provenance = nil
			err = nil
		}
		if err != nil {
			return out, err
		}
	}
	if _, err = b.server.checkHTMLDocumentRead(scope, doc, current); err != nil {
		return out, err
	}
	return mcp.DesignResultV1{Value: map[string]any{"declared_source": source, "editable_template": map[string]any{"template_id": source.TemplateID, "frozen_version": source.TemplateVersion, "frozen_content_sha256": source.TemplateContentSHA256, "read_tool": "get_design_template", "read_arguments": map[string]any{"template_id": source.TemplateID, "version": source.TemplateVersion, "expected_content_sha256": source.TemplateContentSHA256}, "layout_edit": "update_design_template creates a new template version; preview and explicitly approve it, then create a new document from that version. This document retains its frozen layout."}, "brand_provenance": provenance, "visual_review": "not_proven_by_source_readback"}}, nil
}
func (b *mcpDesignBridgeV1) DocumentHistoryV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	scope, err := b.scopeV1(ctx, a, id)
	if err != nil {
		return out, err
	}
	defer scope.cancel()
	doc, current, err := b.server.loadHTMLDocumentRead(scope)
	if err != nil {
		return out, err
	}
	rows, err := b.server.Queries.ListHTMLDocumentMaterializations(scope.ctx, generated.ListHTMLDocumentMaterializationsParams{DocumentID: doc.ID, OrgID: doc.OrgID, RowLimit: 200})
	if err != nil {
		return out, err
	}
	result := make([]htmlDocumentHistoryResponse, 0, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || row.OrgID != doc.OrgID || row.Sequence < 1 || len(row.SourceCommitment) != sha256.Size || len(row.PdfSha256) != sha256.Size || row.PageCount < 1 || row.PageCount > 500 || row.CreatedBy == uuid.Nil || !row.CreatedAt.Valid || row.CreatedAt.InfinityModifier != pgtype.Finite || !utf8.ValidString(row.Summary) || utf8.RuneCountInString(row.Summary) > 500 || (row.IsCurrent && (current == nil || row.ID != current.ID)) {
			return out, htmlmaterialization.ErrInvalid
		}
		result = append(result, htmlDocumentHistoryResponse{Sequence: row.Sequence, ID: row.ID, SourceCommitment: hex.EncodeToString(row.SourceCommitment), PDFSHA256: hex.EncodeToString(row.PdfSha256), PageCount: row.PageCount, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano), Summary: row.Summary, Current: row.IsCurrent})
	}
	if _, err = b.server.checkHTMLDocumentRead(scope, doc, current); err != nil {
		return out, err
	}
	return mcp.DesignResultV1{Value: map[string]any{"revisions": result}}, nil
}
func (b *mcpDesignBridgeV1) DocumentPDFV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignPDFInputV1) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	scope, err := b.scopeV1(ctx, a, id)
	if err != nil {
		return out, err
	}
	defer scope.cancel()
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || !htmlPreviewSHA256(in.ExpectedPDFSHA256) || in.Revision < 0 {
		return out, htmlsource.ErrInvalid
	}
	doc, err := b.server.Queries.GetDocument(scope.ctx, generated.GetDocumentParams{ID: id, OrgID: a.OrgID})
	if err != nil {
		return out, err
	}
	if !doc.UpdatedAt.Time.Equal(expected) {
		return out, resolver.ErrPreviewChanged
	}
	delegated, err := b.server.Queries.HasPresignExecutionForDocumentV1(scope.ctx, generated.HasPresignExecutionForDocumentV1Params{OrgID: a.OrgID, DocumentID: id})
	if err != nil || delegated {
		return out, auth.ErrMutationPermissionRevoked
	}
	var body []byte
	var pages int32
	var source string
	revision := int32(0)
	if len(doc.HtmlSourceJson) > 0 {
		var observed, historical *generated.Document
		var row *generated.HtmlDocumentMaterialization
		if in.Revision > 0 {
			observed, historical, row, err = b.server.loadHTMLHistoricalDocumentRevision(scope, in.Revision)
		} else {
			observed, row, err = b.server.loadHTMLDocumentRead(scope)
			historical = observed
		}
		if err != nil {
			return out, err
		}
		if !observed.UpdatedAt.Time.Equal(expected) {
			return out, resolver.ErrPreviewChanged
		}
		source, err = htmlsource.Commitment(historical)
		if err != nil {
			return out, err
		}
		if in.ExpectedHTMLSourceCommitment != source || in.ExpectedPDFSHA256 != hex.EncodeToString(historical.PdfSha256) {
			return out, resolver.ErrPreviewChanged
		}
		body, pages, err = b.server.readHTMLDocumentPages(scope.ctx, historical)
		if err != nil {
			return out, err
		}
		if _, err = b.server.checkHTMLDocumentRead(scope, observed, row); err != nil {
			return out, err
		}
		if row != nil {
			revision = row.Sequence
		} else {
			revision = 1
		}
	} else {
		if in.Revision != 0 || in.ExpectedHTMLSourceCommitment != "" || in.ExpectedPDFSHA256 != hex.EncodeToString(doc.PdfSha256) || !doc.PdfStorageKey.Valid {
			return out, resolver.ErrPreviewChanged
		}
		body, err = readDocumentArtifact(scope.ctx, b.server.Storage, doc, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID)
		if err != nil {
			return out, err
		}
		count, err := sanitize.PageCountWithContext(scope.ctx, body)
		if err != nil || count < 1 || count > sanitize.MaxPDFPages {
			return out, htmlsource.ErrInvalid
		}
		pages = int32(count)
		if err = resolver.CheckPreview(scope.ctx, b.server.Pool, doc, nil, a.UserID, a.Authorize); err != nil {
			return out, err
		}
	}
	return mcp.DesignResultV1{Value: map[string]any{"document_id": id, "updated_at": in.ExpectedUpdatedAt, "materialization_revision": revision, "html_source_commitment": source, "pdf_sha256": in.ExpectedPDFSHA256, "page_count": pages, "pdf_base64": base64.StdEncoding.EncodeToString(body), "visual_review": "pending"}}, nil
}
func (b *mcpDesignBridgeV1) ReviseDocumentV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignRevisionInputV1, input *pdfadmission.ApplicationHTMLAuthoringInputV1) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	if err := validMCPDesignActorV1(ctx, a); err != nil {
		return out, err
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || !htmlPreviewSHA256(in.ExpectedHTMLSourceCommitment) || !utf8.ValidString(in.Summary) || utf8.RuneCountInString(in.Summary) > 500 || strings.ContainsRune(in.Summary, '\x00') {
		return out, htmlsource.ErrInvalid
	}
	if b.server.Storage == nil || b.server.Sign == nil || b.server.Sign.PDF == nil || b.server.Versions == nil || b.server.Audit == nil {
		return out, pdfadmission.ErrHTMLRevisionOperationV1
	}
	release, err := importguard.Shared.Acquire(a.OrgID)
	if err != nil {
		return out, err
	}
	defer release()
	result, close, err := b.server.reviseHTMLDocumentOwnedV1(ctx, a.Actor, id, htmlDocumentRevisionInput{ExpectedUpdatedAt: in.ExpectedUpdatedAt, ExpectedHTMLSourceCommitment: in.ExpectedHTMLSourceCommitment, Values: htmlStringMap(in.Values), Sections: htmlStringMap(in.Sections), Summary: in.Summary}, expected, input)
	if err != nil {
		return out, err
	}
	return mcp.DesignResultV1{Value: map[string]any{"document": toDocumentResponse(result.Document), "materialization_revision": result.MaterializationRevision, "page_count": result.PageCount, "review_required": true, "placement_reset": true}, Release: close}, nil
}
func (b *mcpDesignBridgeV1) ReviewDocumentV1(ctx context.Context, a mcp.DesignActorV1, id uuid.UUID, in mcp.DesignReviewInputV1, pages []int) (out mcp.DesignResultV1, failure error) {
	defer func() { failure = safeMCPDesignFailureV1(failure) }()
	scope, err := b.scopeV1(ctx, a, id)
	if err != nil {
		return out, err
	}
	defer scope.cancel()
	source, _, _, err := b.sourceV1(scope)
	if err != nil {
		return out, err
	}
	if source.UpdatedAt != in.ExpectedUpdatedAt || source.PDFSHA256 != in.ExpectedPDFSHA256 || source.HTMLSourceCommitment != in.ExpectedHTMLSourceCommitment {
		return out, resolver.ErrPreviewChanged
	}
	if err = mcp.DesignPageCoverageV1(pages, int(source.PageCount)); err != nil {
		return out, err
	}
	expected, _ := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	pdf, _ := hex.DecodeString(in.ExpectedPDFSHA256)
	doc, close, err := b.server.reviewHTMLDocumentOwnedV1(ctx, a.Actor, id, htmlDocumentReviewInput{ExpectedUpdatedAt: in.ExpectedUpdatedAt, ExpectedPDFSHA256: in.ExpectedPDFSHA256, ExpectedHTMLSourceCommitment: in.ExpectedHTMLSourceCommitment}, expected, pdf)
	if err != nil {
		return out, err
	}
	return mcp.DesignResultV1{Value: map[string]any{"document": toDocumentResponse(doc), "visual_review": "caller_attested_all_pages", "contract_approval": false, "sent": false}, Release: close}, nil
}

var _ mcp.DesignBridgeV1 = (*mcpDesignBridgeV1)(nil)
