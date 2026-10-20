// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// Fixed revision htmlsource grammar. These private nodes are selected only by
// the genuine native revision owner after its actual scoped model/header checks.
// This allocation-free shape filter is not validity, approval or work authority.
const (
	htmlRevisionSourceNodeV1 htmlInputNodeV1 = 128 + iota
	htmlRevisionPartyBindingNodeV1
	htmlRevisionSigningArtifactNodeV1
	htmlRevisionCompositionNodeV1
	htmlRevisionPageGeometryNodeV1
	htmlRevisionRectangleNodeV1
	htmlRevisionPartyBindingsNodeV1
	htmlRevisionRectanglesNodeV1
	htmlRevisionBoxesNodeV1
	htmlRevisionBoxNodeV1
)

var htmlRevisionSourceFieldsV1 = [...]htmlInputFieldV1{
	{"schema_version", htmlInputScalarV1}, {"document_id", htmlInputScalarV1}, {"org_id", htmlInputScalarV1}, {"template_id", htmlInputScalarV1}, {"template_version", htmlInputScalarV1}, {"template_content_sha256", htmlInputScalarV1}, {"template_approved_by", htmlInputScalarV1}, {"template_approved_at", htmlInputScalarV1},
	{"master", htmlInputMasterV1}, {"default_values", htmlInputStringMapV1}, {"values", htmlInputStringMapV1}, {"sections", htmlInputStringMapV1}, {"master_digest", htmlInputScalarV1}, {"content_digest", htmlInputScalarV1}, {"pdf_key", htmlInputScalarV1}, {"pdf_sha256", htmlInputScalarV1}, {"pdf_version_id", htmlInputScalarV1}, {"commitment", htmlInputScalarV1},
	{"party_bindings", htmlRevisionPartyBindingsNodeV1}, {"signing_artifact", htmlRevisionSigningArtifactNodeV1},
}
var htmlRevisionPartyBindingFieldsV1 = [...]htmlInputFieldV1{{"slot", htmlInputScalarV1}, {"recipient_id", htmlInputScalarV1}}
var htmlRevisionSigningArtifactFieldsV1 = [...]htmlInputFieldV1{{"version", htmlInputScalarV1}, {"policy", htmlInputScalarV1}, {"plan_sha256", htmlInputScalarV1}, {"composition", htmlRevisionCompositionNodeV1}, {"fields", htmlRevisionRectanglesNodeV1}}
var htmlRevisionCompositionFieldsV1 = [...]htmlInputFieldV1{{"schema_version", htmlInputScalarV1}, {"policy", htmlInputScalarV1}, {"body_sha256", htmlInputScalarV1}, {"signing_page_sha256", htmlInputScalarV1}, {"merged_sha256", htmlInputScalarV1}, {"merged_bytes", htmlInputScalarV1}, {"output_sha256", htmlInputScalarV1}, {"body_pages", htmlInputScalarV1}, {"final_pages", htmlInputScalarV1}, {"body_geometry_sha256", htmlInputScalarV1}, {"geometry_sha256", htmlInputScalarV1}, {"signing_page", htmlRevisionPageGeometryNodeV1}}
var htmlRevisionPageGeometryFieldsV1 = [...]htmlInputFieldV1{{"boxes_milli_points", htmlRevisionBoxesNodeV1}, {"rotation", htmlInputScalarV1}, {"user_unit_milli", htmlInputScalarV1}}
var htmlRevisionRectangleFieldsV1 = [...]htmlInputFieldV1{{"slot", htmlInputScalarV1}, {"page", htmlInputScalarV1}, {"x", htmlInputScalarV1}, {"y", htmlInputScalarV1}, {"w", htmlInputScalarV1}, {"h", htmlInputScalarV1}}

func htmlRevisionCanonicalFieldsV1(n htmlInputNodeV1) []htmlInputFieldV1 {
	switch n {
	case htmlRevisionSourceNodeV1:
		return htmlRevisionSourceFieldsV1[:]
	case htmlRevisionPartyBindingNodeV1:
		return htmlRevisionPartyBindingFieldsV1[:]
	case htmlRevisionSigningArtifactNodeV1:
		return htmlRevisionSigningArtifactFieldsV1[:]
	case htmlRevisionCompositionNodeV1:
		return htmlRevisionCompositionFieldsV1[:]
	case htmlRevisionPageGeometryNodeV1:
		return htmlRevisionPageGeometryFieldsV1[:]
	case htmlRevisionRectangleNodeV1:
		return htmlRevisionRectangleFieldsV1[:]
	}
	return nil
}
func htmlRevisionCanonicalArrayV1(n htmlInputNodeV1) (htmlInputNodeV1, int) {
	switch n {
	case htmlRevisionPartyBindingsNodeV1:
		return htmlRevisionPartyBindingNodeV1, 2
	case htmlRevisionRectanglesNodeV1:
		return htmlRevisionRectangleNodeV1, 2
	case htmlRevisionBoxesNodeV1:
		return htmlRevisionBoxNodeV1, 5
	case htmlRevisionBoxNodeV1:
		return htmlInputScalarV1, 4
	}
	return htmlInputScalarV1, 0
}

// Same existing htmlsource decode ceiling; this filter counts actual immutable
// bytes before typed source/master decoders. It never supplies source validity.
func htmlRevisionSourceShapeV1(ctx context.Context, raw []byte) (htmlAuthoringInputShapeV1, error) {
	var empty htmlAuthoringInputShapeV1
	if !applicationContextV1(ctx) {
		return empty, ErrHTMLAuthoringReadV1
	}
	if len(raw) == 0 || len(raw) > 24<<20 {
		return empty, htmlsource.ErrInvalid
	}
	shape, err := htmlAuthoringInputRootShapeV1(ctx, htmlRevisionSourceNodeV1, raw)
	if err != nil {
		return empty, errors.Join(htmlsource.ErrInvalid, err)
	}
	if shape.masterEnd <= shape.masterStart || shape.defaultsEnd <= shape.defaultsStart {
		return empty, htmlsource.ErrInvalid
	}
	return shape, nil
}
