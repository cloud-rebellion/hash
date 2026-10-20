// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/google/uuid"
)

func ownOrdinaryRecipeV1(in *InputV1) {
	r := ordinarypage.KnownRecipeV1()
	in.RenderRecipe.Schema = r.Schema
	in.RenderRecipe.RecipeID = r.RecipeID
	in.RenderRecipe.HTMLTemplateSHA256 = r.HTMLTemplateSHA256
	in.RenderRecipe.CoreCSSSHA256 = r.CoreCSSSHA256
	in.RenderRecipe.MeasurementSHA256 = r.MeasurementSHA256
	in.RenderRecipe.SnapshotSHA256 = r.SnapshotSHA256
	in.RenderRecipe.PrintRecipeSHA256 = r.PrintRecipeSHA256
}

func TestOrdinaryPlansV1FrozenBindingAndCompleteValues(t *testing.T) {
	in := basisInputV1(t, true)
	ownOrdinaryRecipeV1(&in)
	in.Fields[1].Value = "  Åsa Á & Co\r\n<approved text>  "
	f := in.Fields[1]
	f.ID = uuid.MustParse("40000000-0000-0000-0000-000000000003")
	f.Type = "checkbox"
	f.Value = "false"
	f.Required = true
	in.Fields = append(in.Fields, f)
	b, err := BuildV1(in)
	if err != nil {
		t.Fatal(err)
	}
	original := b.CanonicalJSON()
	plans, err := OrdinaryPlansV1(b)
	if err != nil || len(plans) != 1 {
		t.Fatal("owned frozen ordinary plan refused", err)
	}
	p := plans[0]
	if p.Page != 2 || len(p.Fields) != 2 || p.Fields[0].Value != in.Fields[1].Value || p.Fields[0].XPct != "5.0000" || p.Fields[1].Value != "false" || !p.Fields[1].Required || !p.Fields[1].ValueValid {
		t.Fatal("ordinary raw values, exact decimals or false checkbox were dropped")
	}
	if p.StaticBasisSHA256 != b.SHA256() || p.FieldsSHA256 != b.FieldsSHA256() || p.RenderRecipeSHA256 != ordinarypage.RecipeSHA256V1() || p.BrandingContextSHA256 != b.BrandingCSSSHA256() ||
		p.RenderRecipeSHA256 == b.RenderRecipeSHA256() || p.SourceVersionID != in.Source.VersionID || p.Geometry != (ordinarypage.PageGeometryV1{Boxes: in.Geometry.Pages[1].Boxes, Rotation: in.Geometry.Pages[1].Rotation, UserUnit: in.Geometry.Pages[1].UserUnit}) {
		t.Fatal("producer received wrong source, full geometry or component commitment")
	}
	p.Fields[0].Value = "changed"
	if !bytes.Equal(original, b.CanonicalJSON()) {
		t.Fatal("mapper lent immutable basis fields")
	}
}

func TestOrdinaryPlansV1KnownRecipeAndUnsupportedValues(t *testing.T) {
	for _, mode := range []string{"unowned-recipe", "tab", "oversized-painted", "oversized-no-ink"} {
		t.Run(mode, func(t *testing.T) {
			in := basisInputV1(t, true)
			ownOrdinaryRecipeV1(&in)
			in.Fields[1].Value = "Original"
			switch mode {
			case "unowned-recipe":
				in.RenderRecipe.MeasurementSHA256 = strings.Repeat("1", 64)
			case "tab":
				in.Fields[1].Value = "Original\tunchanged"
			case "oversized-painted":
				in.Fields[1].Value = strings.Repeat("x", ordinarypage.MaxValueBytesV1+1)
			case "oversized-no-ink":
				in.Fields[1].Type = "checkbox"
				in.Fields[1].Value = strings.Repeat(" ", ordinarypage.MaxValueBytesV1+1)
			}
			b, err := BuildV1(in)
			if err != nil {
				t.Fatal("model binding should preserve provisional unsupported input", err)
			}
			raw := b.CanonicalJSON()
			if _, err := OrdinaryPlansV1(b); !errors.Is(err, ErrBasisV1) {
				t.Fatal("unsupported producer input was silently altered/admitted")
			}
			if !bytes.Equal(raw, b.CanonicalJSON()) {
				t.Fatal("refusal altered original static snapshot")
			}
		})
	}
}

func TestOrdinaryPlansV1NoInkAndSignatureOnly(t *testing.T) {
	for _, mode := range []string{"blank", "false", "signature-only"} {
		t.Run(mode, func(t *testing.T) {
			in := basisInputV1(t, mode != "signature-only")
			ownOrdinaryRecipeV1(&in)
			if mode != "signature-only" {
				in.Fields[1].Value = ""
				if mode == "false" {
					in.Fields[1].Type = "checkbox"
					in.Fields[1].Value = "false"
				}
			}
			b, err := BuildV1(in)
			if err != nil {
				t.Fatal(err)
			}
			plans, err := OrdinaryPlansV1(b)
			if err != nil || len(plans) != 0 || plans == nil {
				t.Fatal("invented ordinary paint or required-checkbox authority", err)
			}
		})
	}
}
