// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (v *RevisionValidationV1) ContractProfileV1() (*htmlmaster.ContractProfile, error) {
	if !v.validV1() {
		return nil, invalid("revision validation scope")
	}
	s := v.effective
	if s.SchemaVersion != ContractSchemaVersion && s.SchemaVersion != SigningPageSchemaVersion {
		return nil, nil
	}
	return v.design.rawCompiled.ContractProfile(), nil
}
func (v *RevisionValidationV1) ContractPartiesV1() ([]ContractParty, error) {
	if !v.validV1() {
		return nil, invalid("revision validation scope")
	}
	s := v.effective
	if s.SchemaVersion != ContractSchemaVersion && s.SchemaVersion != SigningPageSchemaVersion {
		return nil, nil
	}
	readiness, err := v.design.rawCompiled.ContractReadiness(htmlmaster.Input{Values: s.Values, Sections: s.Sections})
	if err != nil || !readiness.Complete || len(readiness.Parties) != 2 {
		return nil, invalid("reviewed contract essentials are incomplete")
	}
	bySlot := make(map[string]uuid.UUID, 2)
	for _, binding := range s.PartyBindings {
		bySlot[binding.Slot] = binding.RecipientID
	}
	parties := make([]ContractParty, 0, 2)
	for _, party := range readiness.Parties {
		id := bySlot[party.Slot]
		if id == uuid.Nil {
			return nil, invalid("reviewed contract party binding is absent")
		}
		parties = append(parties, ContractParty{Slot: party.Slot, Role: party.Slot, RecipientID: id, Name: party.RepresentativeName, Email: party.RepresentativeEmail, CompanyName: party.CompanyName, CompanyID: party.CompanyID, Authority: party.RepresentativeAuthority})
	}
	return parties, nil
}
func (v *RevisionValidationV1) ValidateContractPartiesV1(rows []*generated.Recipient) error {
	parties, err := v.ContractPartiesV1()
	if err != nil || len(parties) == 0 {
		return err
	}
	if len(rows) != len(parties) {
		return invalid("reviewed contract requires exactly its two intended recipients")
	}
	byID := make(map[uuid.UUID]*generated.Recipient, len(rows))
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != v.document.ID || byID[row.ID] != nil {
			return invalid("invalid reviewed contract recipient")
		}
		byID[row.ID] = row
	}
	for _, party := range parties {
		row := byID[party.RecipientID]
		if row == nil || row.Role != party.Role || row.Name != party.Name || row.Email != party.Email {
			return invalid("intended party differs from the current printed contract; revise and review its PDF")
		}
	}
	return nil
}
func (v *RevisionValidationV1) SigningPageV1() (*htmlmaster.SigningPagePolicy, *SigningArtifact, error) {
	if !v.validV1() {
		return nil, nil, invalid("revision validation scope")
	}
	if v.effective.SchemaVersion != SigningPageSchemaVersion {
		return nil, nil, nil
	}
	return v.design.rawCompiled.SigningPagePolicy(), cloneSigningArtifact(v.effective.SigningArtifact), nil
}
func (v *RevisionValidationV1) SigningFieldOptionsV1(slot string) (json.RawMessage, error) {
	_, artifact, err := v.SigningPageV1()
	if err != nil || artifact == nil {
		return nil, invalid("automatic signature field source")
	}
	if slot != "customer" && slot != "provider" {
		return nil, invalid("automatic signature field slot")
	}
	commitment, err := v.CommitmentV1()
	if err != nil {
		return nil, err
	}
	return json.Marshal(signingFieldOptions{Policy: artifact.Policy, Slot: slot, SourceCommitment: commitment})
}

func (v *RevisionValidationV1) ValidateSigningFieldsV1(rows []*generated.DocumentField, pages int) error {
	if !v.validV1() {
		return invalid("revision validation scope")
	}
	s := v.effective
	doc := v.document
	if s.SchemaVersion != SigningPageSchemaVersion {
		return nil
	}
	if len(rows) != 2 || (pages > 0 && pages != s.SigningArtifact.Composition.FinalPages) ||
		(doc.HtmlCurrentPageCount.Valid && int(doc.HtmlCurrentPageCount.Int32) != s.SigningArtifact.Composition.FinalPages) {
		return invalid("automatic signature field count or page")
	}
	seen := map[uuid.UUID]bool{}
	for i, rectangle := range s.SigningArtifact.Fields {
		var matched *generated.DocumentField
		for _, row := range rows {
			if row != nil && row.RecipientID.Valid && uuid.UUID(row.RecipientID.Bytes) == s.PartyBindings[i].RecipientID {
				if matched != nil {
					return invalid("duplicate automatic signature field")
				}
				matched = row
			}
		}
		if matched == nil || matched.ID == uuid.Nil || seen[matched.ID] || matched.DocumentID != doc.ID || matched.Type != "signature" || !matched.Required || matched.Page != rectangle.Page ||
			!matched.Label.Valid || matched.Label.String != strings.ToUpper(rectangle.Slot[:1])+rectangle.Slot[1:]+" signature" ||
			!numericEqual(matched.XPct, rectangle.X) || !numericEqual(matched.YPct, rectangle.Y) || !numericEqual(matched.WPct, rectangle.W) || !numericEqual(matched.HPct, rectangle.H) {
			return invalid("automatic signature field placement or ownership")
		}
		seen[matched.ID] = true
		var options signingFieldOptions
		if err := strictDecode(matched.OptionsJson, &options, 2048); err != nil {
			return invalid("automatic signature field binding")
		}
		canonical, _ := json.Marshal(options)
		var original, typed any
		if json.Unmarshal(matched.OptionsJson, &original) != nil || json.Unmarshal(canonical, &typed) != nil || !reflect.DeepEqual(original, typed) ||
			options.Policy != s.SigningArtifact.Policy || options.Slot != rectangle.Slot || options.SourceCommitment != s.Commitment {
			return invalid("automatic signature field source binding")
		}
	}
	return nil
}

func (v *RevisionValidationV1) ValidateSigningBrandingV1(row *generated.DocumentBrandingOverride) error {
	policy, artifact, err := v.SigningPageV1()
	if err != nil || artifact == nil {
		return err
	}
	if row == nil || row.DocumentID != v.document.ID {
		return invalid("reviewed signing page branding missing")
	}
	b := policy.Branding
	for _, field := range []struct {
		actual   pgtype.Text
		expected string
	}{
		{row.PrimaryHex, b.PrimaryHex}, {row.AccentHex, b.AccentHex}, {row.SurfaceHex, b.SurfaceHex}, {row.TextHex, b.TextHex}, {row.MutedHex, b.MutedHex},
		{row.LogoUrl, b.LogoURL}, {row.LogoAlt, b.LogoAlt}, {row.FontHeading, b.FontHeading}, {row.FontBody, b.FontBody}, {row.SignatureColor, b.SignatureColor},
	} {
		if !field.actual.Valid || field.actual.String != field.expected {
			return invalid("reviewed signing page branding drifted")
		}
	}
	return nil
}

// Fresh q-backed models and page count are checked on EACH invocation. This
// operation caches no recipient, field, branding, policy decision or SQL proof.
// Native ownership/scoped collection admission remains a separate fixed gate.
func (v *RevisionValidationV1) ValidateSigningPageStateV1(ctx context.Context, q signingStateQueries, pages int) error {
	_, artifact, err := v.SigningPageV1()
	if err != nil || artifact == nil {
		return err
	}
	if q == nil {
		return invalid("signing page state store unavailable")
	}
	parties, err := q.ListRecipientsByDocument(ctx, v.document.ID)
	if err != nil {
		return err
	}
	if err = v.ValidateContractPartiesV1(parties); err != nil {
		return err
	}
	fields, err := q.ListFieldsByDocument(ctx, v.document.ID)
	if err != nil {
		return err
	}
	if err = v.ValidateSigningFieldsV1(fields, pages); err != nil {
		return err
	}
	brand, err := q.GetDocumentBrandingOverride(ctx, v.document.ID)
	if err != nil {
		return invalid("signing page branding unavailable")
	}
	return v.ValidateSigningBrandingV1(brand)
}
