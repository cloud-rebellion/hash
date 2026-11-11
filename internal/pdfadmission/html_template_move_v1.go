// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// Typed refusals for moving a draft HTML document to another approved version
// of its own template. Callers map Stale, NotForward and Superseded to 409 and
// Schema and Undeclared to 422; none of them carries document text.
var (
	ErrHTMLTemplateMoveStaleV1      = errors.New("template move pins are stale or the target version is not an approved revision of this document's template")
	ErrHTMLTemplateMoveNotForwardV1 = errors.New("a draft can only move to a newer template version")
	ErrHTMLTemplateMoveSchemaV1     = errors.New("the target version changes the schema version or contract party slots; create a new document instead")
	ErrHTMLTemplateMoveSupersededV1 = errors.New("the target is not the template's current version; a newer approved version exists")
	ErrHTMLTemplateMoveUndeclaredV1 = errors.New("values or sections are not declared by the target template version")
)

// HTMLTemplateMoveTargetV1 is an approved, content-verified template revision.
type HTMLTemplateMoveTargetV1 struct {
	TemplateID uuid.UUID
	Version    int32
	Content    htmlmaster.TemplateCommitment
	ApprovedBy uuid.UUID
	ApprovedAt time.Time
}

// LoadHTMLTemplateMoveTargetV1 reads one retained revision of the document's
// own template and proves it is approved and matches both pins. The canonical
// content hash is recomputed here from the stored master and defaults; the
// stored content_sha256 column is only compared with it, never trusted.
func LoadHTMLTemplateMoveTargetV1(ctx context.Context, q *generated.Queries, org, templateID uuid.UUID, version int32, expectedSHA256 string) (*HTMLTemplateMoveTargetV1, error) {
	template, err := q.GetHTMLTemplate(ctx, generated.GetHTMLTemplateParams{ID: templateID, OrgID: org})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrHTMLTemplateMoveStaleV1
	}
	if err != nil {
		return nil, err
	}
	row, err := q.GetHTMLTemplateRevision(ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: templateID, OrgID: org, Version: version})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrHTMLTemplateMoveStaleV1
	}
	if err != nil {
		return nil, err
	}
	if !row.ApprovedBy.Valid || !row.ApprovedAt.Valid || row.TemplateID != templateID || row.OrgID != org || row.Version != version {
		return nil, ErrHTMLTemplateMoveStaleV1
	}
	content, err := htmlmaster.CanonicalTemplate(row.HtmlMasterJson, row.VariablesJson)
	if err != nil {
		return nil, fmt.Errorf("%w: retained revision is not canonical", ErrHTMLTemplateMoveStaleV1)
	}
	if content.SHA256 != expectedSHA256 || hex.EncodeToString(row.ContentSha256) != content.SHA256 {
		return nil, ErrHTMLTemplateMoveStaleV1
	}
	if template.Version != version {
		return nil, ErrHTMLTemplateMoveSupersededV1
	}
	return &HTMLTemplateMoveTargetV1{TemplateID: templateID, Version: version, Content: content,
		ApprovedBy: uuid.UUID(row.ApprovedBy.Bytes), ApprovedAt: row.ApprovedAt.Time}, nil
}

// HTMLTemplateMoveDiffV1 reports what the planner decided beyond carrying the
// current inputs over: names newly declared by the target that took its
// default, and names the target no longer declares that were dropped because
// the document only held the old default or an empty text. All sorted.
type HTMLTemplateMoveDiffV1 struct {
	AdoptedDefaultValues []string
	DroppedValues        []string
	DroppedSections      []string
}

// PlanHTMLTemplateMoveV1 builds the next source input from the document's
// current one. A value the user typed is never replaced: current values and
// sections are carried over exactly, even when they equal the old default.
// Only names the target newly declares take the target's defaults (never for
// contract party fields). A removed name is dropped only when its current
// value equals the old default or is empty; otherwise the move is refused.
func PlanHTMLTemplateMoveV1(current htmlsource.Input, target *HTMLTemplateMoveTargetV1, values, sections map[string]string) (htmlsource.Input, HTMLTemplateMoveDiffV1, error) {
	var diff HTMLTemplateMoveDiffV1
	fail := func(err error) (htmlsource.Input, HTMLTemplateMoveDiffV1, error) {
		return htmlsource.Input{}, HTMLTemplateMoveDiffV1{}, err
	}
	if target == nil || current.TemplateID != target.TemplateID {
		return fail(ErrHTMLTemplateMoveStaleV1)
	}
	if target.Version <= current.TemplateVersion {
		return fail(ErrHTMLTemplateMoveNotForwardV1)
	}
	oldMaster, err := htmlmaster.Decode(current.MasterJSON)
	if err != nil {
		return fail(err)
	}
	oldCompiled, err := htmlmaster.Compile(oldMaster)
	if err != nil {
		return fail(err)
	}
	newMaster, err := htmlmaster.Decode(target.Content.MasterJSON)
	if err != nil {
		return fail(err)
	}
	newCompiled, err := htmlmaster.Compile(newMaster)
	if err != nil {
		return fail(err)
	}
	if oldMaster.SchemaVersion != newMaster.SchemaVersion || contractKindV1(oldCompiled) != contractKindV1(newCompiled) ||
		!slices.Equal(partySlotsV1(oldCompiled), partySlotsV1(newCompiled)) ||
		!slices.Equal(partySlotsV1(newCompiled), bindingSlotsV1(current.PartyBindings)) {
		return fail(ErrHTMLTemplateMoveSchemaV1)
	}
	declaredValues, declaredSections := map[string]bool{}, map[string]bool{}
	for _, v := range newMaster.Values {
		declaredValues[v.Name] = true
	}
	for _, s := range newMaster.Sections {
		declaredSections[s.Name] = true
	}
	var oldDefaults, newDefaults map[string]string
	if json.Unmarshal(current.DefaultVarsJSON, &oldDefaults) != nil || json.Unmarshal(target.Content.DefaultsJSON, &newDefaults) != nil {
		return fail(ErrHTMLTemplateMoveStaleV1)
	}
	oldSectionDefaults := map[string]string{}
	for _, s := range oldMaster.Sections {
		oldSectionDefaults[s.Name] = s.DefaultText
	}
	undeclared := []string{}
	for _, name := range sortedKeysV1(values) {
		if !declaredValues[name] {
			undeclared = append(undeclared, "value "+name)
		}
	}
	for _, name := range sortedKeysV1(sections) {
		if !declaredSections[name] {
			undeclared = append(undeclared, "section "+name)
		}
	}
	for _, name := range sortedKeysV1(current.Values) {
		if declaredValues[name] {
			continue
		}
		if v := current.Values[name]; v == "" || v == oldDefaults[name] {
			diff.DroppedValues = append(diff.DroppedValues, name)
		} else {
			undeclared = append(undeclared, "value "+name)
		}
	}
	for _, name := range sortedKeysV1(current.Sections) {
		if declaredSections[name] {
			continue
		}
		if v := current.Sections[name]; v == "" || v == oldSectionDefaults[name] {
			diff.DroppedSections = append(diff.DroppedSections, name)
		} else {
			undeclared = append(undeclared, "section "+name)
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return fail(fmt.Errorf("%w: %s", ErrHTMLTemplateMoveUndeclaredV1, strings.Join(slices.Compact(undeclared), ", ")))
	}
	next := current
	next.TemplateVersion, next.TemplateContentSHA256 = target.Version, target.Content.SHA256
	next.MasterJSON, next.DefaultVarsJSON = bytes.Clone(target.Content.MasterJSON), bytes.Clone(target.Content.DefaultsJSON)
	next.TemplateApprovedBy, next.TemplateApprovedAt = target.ApprovedBy, target.ApprovedAt
	next.SigningArtifact = nil
	next.Values, next.Sections = map[string]string{}, map[string]string{}
	party := partyValueNamesV1(newCompiled)
	for _, name := range sortedKeysV1(declaredValues) {
		if old, had := current.Values[name]; had {
			next.Values[name] = old
		} else if def, ok := newDefaults[name]; ok && !party[name] {
			if _, requested := values[name]; !requested {
				diff.AdoptedDefaultValues = append(diff.AdoptedDefaultValues, name)
			}
			next.Values[name] = def
		}
	}
	for name, text := range current.Sections {
		if declaredSections[name] {
			next.Sections[name] = text
		}
	}
	maps.Copy(next.Values, values)
	maps.Copy(next.Sections, sections)
	return next, diff, nil
}

func sortedKeysV1[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func contractKindV1(c *htmlmaster.Compiled) string {
	if p := c.ContractProfile(); p != nil {
		return "profile:" + p.Kind
	}
	return ""
}

// Value names that carry a contract party's identity. Defaults never fill them.
func partyValueNamesV1(c *htmlmaster.Compiled) map[string]bool {
	out := map[string]bool{}
	if p := c.ContractProfile(); p != nil {
		for _, q := range p.Parties {
			for _, n := range []string{q.CompanyName, q.CompanyID, q.RepresentativeName, q.RepresentativeEmail, q.RepresentativeAuthority} {
				out[n] = true
			}
		}
	}
	return out
}

func partySlotsV1(c *htmlmaster.Compiled) []string {
	profile := c.ContractProfile()
	if profile == nil {
		return nil
	}
	slots := make([]string, 0, len(profile.Parties))
	for _, p := range profile.Parties {
		slots = append(slots, p.Slot)
	}
	sort.Strings(slots)
	return slots
}

func bindingSlotsV1(bindings []htmlsource.PartyBinding) []string {
	var slots []string
	for _, b := range bindings {
		slots = append(slots, b.Slot)
	}
	sort.Strings(slots)
	return slots
}
