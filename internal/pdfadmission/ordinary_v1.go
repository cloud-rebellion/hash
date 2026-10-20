// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"sort"
	"strconv"

	"github.com/bright-interaction/hash/internal/ordinarypage"
)

// OrdinaryPlansV1 admits every ordinary field against the owned producer
// policy without normalization, then returns exactly the pages that paint ink.
// False/empty values on a painted page are retained in that page's complete
// field set. Non-painted pages remain committed by FieldsJSON in the static
// basis. This mapping neither proves source inspection nor seals the basis.
func OrdinaryPlansV1(b *BasisV1) ([]ordinarypage.PlanV1, error) {
	if b == nil || !bytes.Equal(b.OrdinaryRecipeJSON(), ordinarypage.RecipeJSONV1()) || b.OrdinaryRecipeSHA256() != ordinarypage.RecipeSHA256V1() {
		return nil, ErrBasisV1
	}
	input := b.Input()
	byPage := make(map[int][]ordinarypage.FieldV1)
	for _, f := range input.Fields {
		if f.Type == "signature" {
			continue
		}
		byPage[int(f.Page)] = append(byPage[int(f.Page)], ordinarypage.FieldV1{
			ID: f.ID.String(), RecipientID: f.RecipientID.String(), Type: f.Type,
			Required: f.Required, XPct: f.X, YPct: f.Y, WPct: f.W, HPct: f.H,
			ValueValid: f.ValueValid, Value: f.Value,
		})
	}
	pages := make([]int, 0, len(byPage))
	for page := range byPage {
		pages = append(pages, page)
	}
	sort.Ints(pages)
	painted := make(map[int]bool)
	for _, page := range b.OrdinaryPages() {
		painted[page] = true
	}
	out := make([]ordinarypage.PlanV1, 0, len(painted))
	for _, page := range pages {
		g := input.Geometry.Pages[page-1]
		width, height, err := g.ViewportPoints()
		if err != nil {
			return nil, ErrBasisV1
		}
		p := ordinarypage.PlanV1{
			Schema: 1, OrgID: input.OrgID.String(), DocumentID: input.DocumentID.String(),
			CeremonyEpoch: input.CeremonyEpoch.Format("2006-01-02T15:04:05.999999999Z07:00"),
			SourceKey:     input.Source.Key, SourceVersionID: input.Source.VersionID, SourceSHA256: input.Source.SHA256,
			SourceBytes: input.Source.Bytes, SourcePages: len(input.Geometry.Pages), GeometrySHA256: input.Geometry.GeometrySHA256,
			Page: page, Geometry: ordinarypage.PageGeometryV1{Boxes: g.Boxes, Rotation: g.Rotation, UserUnit: g.UserUnit},
			WidthPoints: strconv.FormatFloat(width, 'f', -1, 64), HeightPoints: strconv.FormatFloat(height, 'f', -1, 64),
			StaticBasisSHA256: b.SHA256(), FieldsSHA256: b.FieldsSHA256(), BrandingContextSHA256: b.BrandingCSSSHA256(),
			RenderRecipeSHA256: b.OrdinaryRecipeSHA256(), Fields: byPage[page],
		}
		// This also rejects oversized/control-character values on a page that
		// paints no ink. Nothing unsupported can silently vanish at selection.
		if ordinarypage.ValidatePlanV1(p) != nil {
			return nil, ErrBasisV1
		}
		if painted[page] {
			out = append(out, p)
		}
	}
	return out, nil
}
