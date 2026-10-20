// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// UpdatePartiesAndFieldsV1 preserves the original post-capture identity update,
// token invalidation, full current-party check, automatic field construction,
// full field validation and exact approved branding projection. The immutable
// old and new pure operations avoid recompiling the same source for each check.
func (w *ApplicationHTMLRevisionWriterV1) UpdatePartiesAndFieldsV1(call context.Context) (bool, error) {
	done, err := w.beginV1(call)
	if err != nil {
		return false, err
	}
	defer done()
	w.mu.Lock()
	if !w.appended || w.fieldsAttempted || w.fieldsWritten || w.validation == nil {
		w.mu.Unlock()
		return false, ErrHTMLRevisionWriterV1
	}
	w.fieldsAttempted = true
	w.mu.Unlock()
	s := w.source
	s.mu.Lock()
	if s.processing {
		s.mu.Unlock()
		return false, ErrHTMLRevisionWriterV1
	}
	s.processing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	// Two old-party readiness checks, three new-party checks, and the same two
	// Normalize mail parses. The last is bounded by one new readiness mail pair.
	oldCost, err := htmlRevisionContractReadinessComponentsForV1(s.effectiveRawMaster, htmlmaster.Input{Values: s.effectiveInput.Values, Sections: s.effectiveInput.Sections})
	if err != nil {
		return false, err
	}
	nextInput := w.candidate.input
	nextCost, err := htmlRevisionContractReadinessComponentsForV1(s.effectiveRawMaster, htmlmaster.Input{Values: nextInput.Values, Sections: nextInput.Sections})
	if err != nil {
		return false, err
	}
	scratch := int64(0)
	if !htmlInputAddV1(&scratch, oldCost.parentBytes, 2) || !htmlInputAddV1(&scratch, nextCost.parentBytes, 4) ||
		!htmlInputAddV1(&scratch, int64(unsafe.Sizeof(htmlsource.ContractParty{})), 10) {
		return false, ErrHTMLRevisionWriterV1
	}
	if err = s.holdV1(htmlRevisionSourceCandidateV1, scratch, 0); err != nil {
		return false, err
	}
	before, err := s.validation.ContractPartiesV1()
	if err != nil {
		return false, err
	}
	changed := false
	if len(before) != 0 {
		rows, err := w.collections.ListRecipientsByDocument(call, w.original.ID)
		if err != nil {
			return false, err
		}
		if err = s.validation.ValidateContractPartiesV1(rows); err != nil {
			return false, err
		}
		next, err := w.validation.ContractPartiesV1()
		if err != nil || len(next) != 2 {
			return false, htmlmaster.ErrContractIncomplete
		}
		for _, party := range next {
			for _, old := range before {
				if party.Slot != old.Slot {
					continue
				}
				for _, row := range rows {
					if row.ID != old.RecipientID {
						continue
					}
					values, err := recipients.Normalize(recipients.Values{Role: party.Slot, Name: party.Name, Email: party.Email, OrderIndex: row.OrderIndex, Locale: row.Locale})
					if err != nil {
						return false, err
					}
					if row.Name == values.Name && row.Email == values.Email && row.Role == values.Role {
						continue
					}
					if _, err = w.queries.UpdateRecipient(call, generated.UpdateRecipientParams{ID: row.ID, DocumentID: w.original.ID, Name: values.Name, Email: values.Email, Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale}); err != nil {
						return false, err
					}
					changed = true
				}
			}
		}
		if changed {
			if err = w.queries.InvalidateRecipientTokens(call, w.original.ID); err != nil {
				return false, err
			}
		}
	}
	// Parent UPDATE and the original complete-set locks remain held. These are
	// the SAME actual recipients after this writer's own bounded identity writes.
	current, err := w.queries.ListRecipientsByDocument(call, w.original.ID)
	if err != nil {
		return false, err
	}
	if int64(len(current)) != w.collections.header.RecipientCount {
		return false, ErrHTMLRevisionWriterV1
	}
	if err = w.validation.ValidateContractPartiesV1(current); err != nil {
		return false, err
	}
	policy, artifact, err := w.validation.SigningPageV1()
	if err != nil {
		return false, err
	}
	if artifact == nil {
		w.mu.Lock()
		w.fieldsWritten = true
		w.mu.Unlock()
		return changed, nil
	}
	parties, err := w.validation.ContractPartiesV1()
	if err != nil {
		return false, err
	}
	bySlot := map[string]htmlsource.ContractParty{}
	for _, party := range parties {
		bySlot[party.Slot] = party
	}
	fresh := make([]*generated.DocumentField, 0, 2)
	ids := make([]uuid.UUID, 0, 2)
	for _, rectangle := range artifact.Fields {
		party, ok := bySlot[rectangle.Slot]
		if !ok {
			return false, htmlsource.ErrInvalid
		}
		options, err := w.validation.SigningFieldOptionsV1(rectangle.Slot)
		if err != nil {
			return false, err
		}
		if len(options) > 2048 {
			return false, ErrHTMLRevisionWriterV1
		}
		// Identical original fixed percentage precision, label, UUID ownership,
		// required status and options source commitment. No field is copied from
		// old geometry or accepted through a caller-generated ID list.
		percent := func(v int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(v), Exp: -4, Valid: true} }
		row, err := w.queries.CreateDraftField(call, generated.CreateDraftFieldParams{DocumentID: w.updated.ID, OrgID: w.updated.OrgID,
			RecipientID: pgtype.UUID{Bytes: party.RecipientID, Valid: true}, Type: "signature", Page: rectangle.Page,
			XPct: percent(rectangle.X), YPct: percent(rectangle.Y), WPct: percent(rectangle.W), HPct: percent(rectangle.H), Required: true,
			Label: pgtype.Text{String: strings.ToUpper(rectangle.Slot[:1]) + rectangle.Slot[1:] + " signature", Valid: true}, OptionsJson: options})
		if err != nil {
			return false, err
		}
		if row == nil || row.ID == uuid.Nil || row.DocumentID != w.updated.ID {
			return false, ErrHTMLRevisionWriterV1
		}
		fresh = append(fresh, row)
		ids = append(ids, row.ID)
	}
	fields, err := w.queries.ListFieldsByDocument(call, w.updated.ID)
	if err != nil {
		return false, err
	}
	if len(fields) != len(fresh) {
		return false, ErrHTMLRevisionWriterV1
	}
	if err = w.validation.ValidateSigningFieldsV1(fields, artifact.Composition.FinalPages); err != nil {
		return false, err
	}
	if policy == nil {
		return false, htmlsource.ErrInvalid
	}
	b := policy.Branding
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	if _, err = w.queries.UpsertDocumentBrandingOverride(call, generated.UpsertDocumentBrandingOverrideParams{DocumentID: w.updated.ID,
		PrimaryHex: text(b.PrimaryHex), AccentHex: text(b.AccentHex), SurfaceHex: text(b.SurfaceHex), TextHex: text(b.TextHex), MutedHex: text(b.MutedHex),
		LogoUrl: text(b.LogoURL), LogoAlt: text(b.LogoAlt), FontHeading: text(b.FontHeading), FontBody: text(b.FontBody), SignatureColor: text(b.SignatureColor)}); err != nil {
		return false, errors.Join(errors.New("persist reviewed signing-page branding"), err)
	}
	if !applicationContextV1(s.binding.ctx) {
		return false, ErrHTMLRevisionWriterV1
	}
	w.mu.Lock()
	w.freshFields = fresh
	w.freshFieldIDs = ids
	w.fieldsWritten = true
	w.mu.Unlock()
	return changed, nil
}

func (w *ApplicationHTMLRevisionWriterV1) SnapshotVersionV1(call context.Context) error {
	done, err := w.beginV1(call)
	if err != nil {
		return err
	}
	defer done()
	w.mu.Lock()
	ready := w.appended && w.fieldsWritten && !w.versionAttempted
	doc := w.updated
	if ready {
		w.versionAttempted = true
	}
	w.mu.Unlock()
	if !ready || doc == nil {
		return ErrHTMLRevisionWriterV1
	}
	if doc.Name == "" {
		return errors.New("snapshot: name required")
	}
	if doc.SourceKind != "blocks" && doc.SourceKind != "pdf" {
		return fmt.Errorf("snapshot: invalid source_kind %q", doc.SourceKind)
	}
	maxNo, err := w.queries.GetLatestDocumentVersionNo(call, doc.ID)
	if err != nil {
		return fmt.Errorf("snapshot: latest version_no: %w", err)
	}
	if maxNo < 0 || maxNo == int32(^uint32(0)>>1) {
		return ErrHTMLRevisionWriterV1
	}
	var parent pgtype.UUID
	if maxNo > 0 {
		latest, err := w.queries.GetHTMLRevisionLatestVersionIdentityV1(call, doc.ID)
		if err != nil {
			return fmt.Errorf("snapshot: get latest: %w", err)
		}
		if latest == nil || latest.ID == uuid.Nil || latest.DocumentID != doc.ID || latest.OrgID != doc.OrgID || latest.VersionNo != maxNo {
			return ErrHTMLRevisionWriterV1
		}
		parent = pgtype.UUID{Bytes: latest.ID, Valid: true}
	}
	// This is the original handler's exact SnapshotInput: blocks omitted, actual
	// projected Variables, full new authoring source, same materialization, human
	// actor, fixed summary and schema1. No old full-version body is read.
	version, err := w.queries.InsertDocumentVersion(call, generated.InsertDocumentVersionParams{DocumentID: doc.ID, OrgID: doc.OrgID, VersionNo: maxNo + 1,
		VariablesJson: doc.VariablesJson, Name: doc.Name, SourceKind: doc.SourceKind, Summary: "HTML contract text revised", CreatedBy: pgtype.UUID{Bytes: w.stage.operation.actor, Valid: true},
		CreatedVia: "human", ParentID: parent, SchemaVersion: 1, HtmlSourceJson: w.candidate.sourceJSON, HtmlMaterializationID: doc.HtmlCurrentMaterializationID})
	if err != nil {
		return fmt.Errorf("snapshot: insert: %w", err)
	}
	if version == nil || version.ID == uuid.Nil || version.DocumentID != doc.ID || version.OrgID != doc.OrgID || version.VersionNo != maxNo+1 {
		return ErrHTMLRevisionWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validV1(call) {
		return ErrHTMLRevisionWriterV1
	}
	w.versionWritten = true
	return nil
}
