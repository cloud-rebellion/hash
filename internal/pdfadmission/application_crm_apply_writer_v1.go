// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
)

// Reuse the original native block source/return/measurement owner. The sole
// extra source kind is an HTML mapping-only touch; that method cannot change
// HTML values/source or measure/repair existing rows. Ordinary constructors
// retain their original no-HTML guard.
type ApplicationCRMApplyWriterV1 struct {
	state *applicationBlocksMutationStateV1
}

func (h *ApplicationSessionV1) NewCRMApplyWriterV1(ctx context.Context, reader *ApplicationHTMLRevisionReaderV1) (*ApplicationCRMApplyWriterV1, error) {
	w, err := h.newBlocksMutationWriterWithCRMV1(ctx, reader, false, true)
	if err != nil {
		return nil, err
	}
	return &ApplicationCRMApplyWriterV1{state: w.state}, nil
}

func (o *applicationHTMLRevisionOperationV1) borrowCRMApplyValuesV1(ctx context.Context, s *applicationBlocksMutationStateV1) (htmlRevisionDeclarationV1, func(), error) {
	if o == nil || s == nil || s.session == nil || s.session.state == nil || !applicationContextV1(ctx) {
		return htmlRevisionDeclarationV1{}, nil, ErrBlocksWriterV1
	}
	o.mu.Lock()
	if !o.usableV1() || !o.crmApply || !o.crmValuesOnly || o.factory.state != s.session.state.factory || o.org != s.session.state.org || o.document != s.session.state.document {
		o.mu.Unlock()
		return htmlRevisionDeclarationV1{}, nil, ErrBlocksWriterV1
	}
	found := false
	for stage := range o.stages {
		stage.mu.Lock()
		same := s.reader != nil && stage.reader == s.reader && stage.session == s.session && !stage.consumerClosed
		stage.mu.Unlock()
		if same {
			found = true
			break
		}
	}
	if !found {
		o.mu.Unlock()
		return htmlRevisionDeclarationV1{}, nil, ErrBlocksWriterV1
	}
	o.sourceUses++
	declaration := o.declaration
	o.mu.Unlock()
	var once sync.Once
	return declaration, func() { once.Do(o.releaseSourceInputV1) }, nil
}

// Only a native capsule from the SAME actual CRM request/protected snapshot
// supplies values. Preserve exact existing tree bytes and every unmapped manual
// value. All parser/map/output/RETURNING work is admitted before materialization.
// Mapping-only/unlink still advances the original parent edit witness.
func (w *ApplicationCRMApplyWriterV1) ApplyV1(ctx context.Context, input *ApplicationHTMLRevisionOperationV1) (*generated.Document, bool, error) {
	if w == nil || w.state == nil || input == nil || input.state == nil {
		return nil, false, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, false, ErrBlocksWriterV1
	}
	declaration, release, err := input.state.borrowCRMApplyValuesV1(ctx, s)
	if err != nil {
		return nil, false, err
	}
	defer release()
	old := s.snapshot.document
	expected, err := time.Parse(time.RFC3339Nano, declaration.ExpectedUpdatedAt)
	if err != nil || !old.UpdatedAt.Time.Equal(expected) {
		return nil, false, ErrBlocksWriterV1
	}
	rawWork, err := plainSendBlockLexicalWorkV1(ctx, old.VariablesJson)
	if err != nil {
		return nil, false, err
	}
	if err = s.sourceWork.holdV1(ctx, rawWork, 0); err != nil {
		return nil, false, err
	}
	values, err := blocks.ParseVariableValues(old.VariablesJson)
	if err != nil {
		return nil, false, err
	}
	count := len(values)
	changed := false
	for name, value := range declaration.Values {
		current, present := values[name]
		if !present {
			count++
		}
		if !present || current != value {
			changed = true
		}
	}
	// A fixed HTML mapping touch must never become a second HTML renderer.
	if changed && (old.SourceKind != "blocks" || len(old.HtmlSourceJson) != 0) {
		return nil, false, ErrPlainDraftBlockInputV1
	}
	current := old
	s.attempted = true
	if changed {
		growth := int64(4096)
		if !htmlInputAddV1(&growth, 2*htmlInputPowerV1(max(8, (int64(count)*8+6)/7)), 2*80) {
			return nil, false, ErrBlocksWriterV1
		}
		upper := int64(2)
		for name, value := range values {
			if replacement, ok := declaration.Values[name]; ok {
				value = replacement
			}
			if !htmlInputAddV1(&upper, int64(len(name)+len(value)), 6) || !htmlInputAddV1(&upper, 1, 8) {
				return nil, false, ErrBlocksWriterV1
			}
		}
		for name, value := range declaration.Values {
			if _, present := values[name]; !present {
				if !htmlInputAddV1(&upper, int64(len(name)+len(value)), 6) || !htmlInputAddV1(&upper, 1, 8) {
					return nil, false, ErrBlocksWriterV1
				}
			}
		}
		parent, err := htmlAuthoringSumV1(growth, upper)
		if err != nil {
			return nil, false, err
		}
		if err = s.sourceWork.holdV1(ctx, parent, upper); err != nil {
			return nil, false, err
		}
		for name, value := range declaration.Values {
			values[name] = value
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return nil, false, err
		}
		wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, encoded)
		if err != nil {
			return nil, false, err
		}
		current, err = s.writePlainSourceV1(ctx, old, old.BlocksJson, encoded, int64(len(old.BlocksJson)), wire)
		if err != nil {
			return nil, false, err
		}
	}
	current, err = s.patchPlainDetailsV1(ctx, PlainDraftPatchV1{}, current)
	return current, changed, err
}

func (w *ApplicationCRMApplyWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil || w.state == nil {
		return ErrBlocksWriterV1
	}
	return (&ApplicationPlainDraftMutationWriterV1{state: w.state}).MeasureFreshPolicyV1(ctx)
}
func (w *ApplicationCRMApplyWriterV1) CloseConsumerV1() {
	if w != nil {
		(&ApplicationBlocksMutationWriterV1{state: w.state}).CloseConsumerV1()
	}
}
