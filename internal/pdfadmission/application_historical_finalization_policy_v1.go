// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/google/uuid"
	"sort"
	"unsafe"
)

var ErrHistoricalFinalizationNotReadyV1 = errors.New("pdfadmission: document still has required recipients awaiting completion")

func (w *ApplicationHTMLSendWorkV1) historicalFinalizationSourceV1(call context.Context) (*ApplicationHTMLSendSourceV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	source := state.source
	w.mu.Unlock()
	if source != nil {
		return source, nil
	}
	source, err = w.NewSourceV1(call)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return nil, ErrHTMLSendWorkV1
	}
	state.source = source
	return source, nil
}

// Native source validation preserves the original ContractParties decision
// without decoding/recompiling a caller/public document outside source credit.
func (w *ApplicationHTMLSendWorkV1) HistoricalFinalizationPartiesV1(call context.Context) ([]htmlsource.ContractParty, error) {
	source, err := w.historicalFinalizationSourceV1(call)
	if err != nil {
		return nil, err
	}
	state := source.state
	if !state.lockV1() {
		return nil, ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.owner == nil {
		return nil, ErrHTMLSendWorkV1
	}
	owner := state.owner
	if err = owner.beginV1(); err != nil {
		return nil, err
	}
	defer owner.finishV1()
	validation, err := state.prepareValidationV1()
	if err != nil {
		return nil, err
	}
	if err = state.holdPolicyV1(); err != nil {
		return nil, err
	}
	return validation.ContractPartiesV1()
}
func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalFinalizationSigningPageV1(call context.Context) error {
	source, err := w.historicalFinalizationSourceV1(call)
	if err != nil {
		return err
	}
	state := source.state
	if !state.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.owner == nil {
		return ErrHTMLSendWorkV1
	}
	owner := state.owner
	if err = owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	validation, err := state.prepareValidationV1()
	if err != nil {
		return err
	}
	scratch, err := owner.stateComponentsV1()
	if err != nil {
		return err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, scratch, 0); err != nil {
		return err
	}
	owner.stateScratchBase = scratch
	return validation.ValidateSigningPageStateV1(call, &applicationHTMLSendSigningStateV1{work: w, source: owner}, 0)
}
func (w *ApplicationHTMLSendWorkV1) historicalFinalizationPDFRolesV1(call context.Context) ([]string, error) {
	source, err := w.historicalFinalizationSourceV1(call)
	if err != nil {
		return nil, err
	}
	state := source.state
	if !state.lockV1() {
		return nil, ErrHTMLSendWorkV1
	}
	defer state.unlockV1()
	if state.closeRequested.Load() || state.owner == nil {
		return nil, ErrHTMLSendWorkV1
	}
	owner := state.owner
	if err = owner.beginV1(); err != nil {
		return nil, err
	}
	defer owner.finishV1()
	validation, err := state.prepareValidationV1()
	if err != nil {
		return nil, err
	}
	scratch, err := owner.stateComponentsV1()
	if err != nil {
		return nil, err
	}
	if err = owner.holdV1(htmlRevisionSourceStateV1, scratch, 0); err != nil {
		return nil, err
	}
	owner.stateScratchBase = scratch
	if err = validation.ValidateSigningPageStateV1(call, &applicationHTMLSendSigningStateV1{work: w, source: owner}, 0); err != nil {
		return nil, err
	}
	if _, err = w.ReadRecipientsV1(call); err != nil {
		return nil, err
	}
	if _, err = w.ReadFieldsV1(call); err != nil {
		return nil, err
	}
	if err = state.holdPolicyV1(); err != nil {
		return nil, err
	}
	if err = owner.fieldOptionsComponentsV1(w.sourceFields); err != nil {
		return nil, err
	}
	return pdflayout.RequiredRolesPreparedHTMLV1(owner.snapshot.document, w.sourceRecipients, w.sourceFields, 0, validation)
}
func (w *ApplicationHTMLSendWorkV1) HistoricalFinalizationRolesV1(call context.Context) ([]string, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	if state.rolesRead {
		roles := state.roleViews
		w.mu.Unlock()
		return roles, nil
	}
	if state.rolesAttempted {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	state.rolesAttempted = true
	doc := w.sourceDocument
	w.mu.Unlock()
	var roles []string
	if !doc.IsEnvelope {
		if doc.SourceKind == "pdf" {
			roles, err = w.historicalFinalizationPDFRolesV1(call)
		} else {
			var source *ApplicationHTMLSendSourceV1
			source, err = w.historicalFinalizationSourceV1(call)
			if err == nil {
				roles, err = source.BlockRolesForSigningV1()
			}
		}
	} else {
		members, e := w.ReadEnvelopeMembersV1(call)
		if e != nil {
			return nil, fmt.Errorf("resolve signer roles: list envelope children: %w", e)
		}
		if len(members) == 0 {
			return nil, errors.New("resolve signer roles: envelope has no children")
		}
		raw := int64(0)
		for _, member := range members {
			if member == nil {
				return nil, ErrHTMLSendWorkV1
			}
			if _, e = member.ReadModelsV1(call); e != nil {
				return nil, e
			}
			member.mu.Lock()
			d := member.sourceDocument
			n := int64(len(d.BlocksJson)) + int64(len(d.VariablesJson))
			member.mu.Unlock()
			if !htmlInputAddV1(&raw, n, 64) {
				return nil, ErrHTMLSendWorkV1
			}
		}
		w.mu.Lock()
		closeUnion, e := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
		if e == nil {
			w.closes = append(w.closes, closeUnion)
		}
		w.mu.Unlock()
		if e != nil {
			return nil, e
		}
		union := make(map[string]struct{})
		for i, member := range members {
			member.mu.Lock()
			d := member.sourceDocument
			member.mu.Unlock()
			if d == nil {
				return nil, fmt.Errorf("resolve signer roles: child %d is nil", i+1)
			}
			if !d.ParentEnvelopeID.Valid || uuid.UUID(d.ParentEnvelopeID.Bytes) != doc.ID {
				return nil, fmt.Errorf("resolve signer roles: child %s is not attached", d.ID)
			}
			if d.IsEnvelope {
				return nil, fmt.Errorf("resolve signer roles: child %s is itself an envelope", d.ID)
			}
			if e := historicalFinalizingRoleCommitmentV1(doc, d); e != nil {
				return nil, fmt.Errorf("resolve signer roles: child %s: %w", d.ID, e)
			}
			if d.SourceKind != "blocks" {
				return nil, fmt.Errorf("resolve signer roles: child %s is not a blocks document", d.ID)
			}
			source, e := member.historicalFinalizationSourceV1(call)
			if e != nil {
				return nil, e
			}
			memberRoles, e := source.BlockRolesForSigningV1()
			if e != nil {
				return nil, fmt.Errorf("resolve signer roles: child %s: %w", d.ID, e)
			}
			for _, role := range memberRoles {
				union[role] = struct{}{}
			}
		}
		if len(union) == 0 {
			return nil, errors.New("resolve signer roles: envelope children contain no signature fields")
		}
		roles = make([]string, 0, len(union))
		for role := range union {
			roles = append(roles, role)
		}
		sort.Strings(roles)
	}
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return nil, ErrHTMLSendWorkV1
	}
	state.roles = append([]string(nil), roles...)
	state.roleViews = roles
	state.rolesRead = true
	return roles, nil
}

// The source/rows have already passed their original fixed policy points. This
// method consumes only privately retained actual rows, never caller role lists.
func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalFinalizationReadinessV1(call context.Context, mode string) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	if !w.recipientsRead {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	doc := w.sourceDocument
	rows := w.sourceRecipients
	if mode != "signature" && mode != "acknowledgement" || (mode == "signature") != doc.RequiresSignature {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	if mode == "acknowledgement" {
		found := false
		for _, row := range rows {
			if row == nil || row.Role == "cc" {
				continue
			}
			found = true
			if row.Status != "accepted" {
				w.mu.Unlock()
				return ErrHistoricalFinalizationNotReadyV1
			}
		}
		if !found {
			w.mu.Unlock()
			return ErrHistoricalFinalizationNotReadyV1
		}
		state.ready = true
		state.mode = mode
		w.mu.Unlock()
		return nil
	}
	if !state.rolesRead || len(state.roles) == 0 {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	// Price actual role maps before construction; all role strings remain owned
	// by this original native source/recipient graph through its real last use.
	raw := int64(0)
	if !htmlInputAddV1(&raw, int64(len(state.roles)), 8*int64(unsafe.Sizeof(""))+8*int64(unsafe.Sizeof(uintptr(0)))+64) {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	closeMaps, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.closes = append(w.closes, closeMaps)
	required := make(map[string]bool, len(state.roles))
	for _, role := range state.roles {
		required[role] = false
	}
	for _, row := range rows {
		if row == nil {
			continue
		}
		if _, needed := required[row.Role]; needed {
			if row.Status != "signed" {
				w.mu.Unlock()
				return ErrHistoricalFinalizationNotReadyV1
			}
			required[row.Role] = true
		}
	}
	for _, seen := range required {
		if !seen {
			w.mu.Unlock()
			return ErrHistoricalFinalizationNotReadyV1
		}
	}
	isPDF := doc.SourceKind == "pdf"
	w.mu.Unlock()
	if isPDF {
		if _, err = w.ReadFieldsV1(call); err != nil {
			return err
		}
		if _, err = w.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
			return err
		}
		source, err := w.historicalFinalizationSourceV1(call)
		if err != nil {
			return err
		}
		ss := source.state
		if !ss.lockV1() {
			return ErrHTMLSendWorkV1
		}
		defer ss.unlockV1()
		if ss.closeRequested.Load() || ss.owner == nil {
			return ErrHTMLSendWorkV1
		}
		owner := ss.owner
		if err = owner.beginV1(); err != nil {
			return err
		}
		defer owner.finishV1()
		validation, err := ss.prepareValidationV1()
		if err != nil {
			return err
		}
		if err = ss.holdPolicyV1(); err != nil {
			return err
		}
		if err = owner.fieldOptionsComponentsV1(w.sourceFields); err != nil {
			return err
		}
		if err = pdflayout.ValidateSignatureRowsPreparedHTMLV1(owner.snapshot.document, w.sourceRecipients, w.sourceFields, state.signatures, 0, validation); err != nil {
			return fmt.Errorf("%w: %v", ErrHistoricalFinalizationNotReadyV1, err)
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return ErrHTMLSendWorkV1
	}
	state.ready = true
	state.mode = mode
	return nil
}
