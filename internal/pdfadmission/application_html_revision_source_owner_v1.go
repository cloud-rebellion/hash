// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

var ErrHTMLRevisionSourceV1 = errors.New("pdfadmission: owned HTML revision source unavailable")

// These fixed private purposes are selected only by their actual native constructors.
// Shared immutable source validation grants no revision/Send mutation authority.
type htmlOwnedSourcePurposeV1 uint8

const (
	htmlRevisionSourcePurposeV1 htmlOwnedSourcePurposeV1 = iota + 1
	htmlSendSourcePurposeV1
	htmlCeremonySourcePurposeV1
	htmlPackageSelectionSourcePurposeV1
)

type htmlRevisionSourceStageV1 uint8

const (
	htmlRevisionSourceInitialV1 htmlRevisionSourceStageV1 = iota + 1
	htmlRevisionSourceRawV1
	htmlRevisionSourceCanonicalV1
	htmlRevisionSourceRecordV1
	htmlRevisionSourcePrepareV1
	htmlRevisionSourceStateV1
	htmlRevisionSourceCandidateV1
)

// Only this private actual native binding can create a fixed source grant.
// Its identity/scope/fence/deadline fields never change after publication.
type applicationHTMLRevisionSourceBindingV1 struct {
	factory       *applicationSessionFactoryStateV1
	session       *ApplicationSessionV1
	admission     *ApplicationAdmissionV1
	registration  *applicationHTMLAdmissionRegistrationV1
	org, document uuid.UUID
	ctx           context.Context
	deadline      time.Time
}
type applicationHTMLRevisionSourceGrantV1 struct {
	self        *applicationHTMLRevisionSourceGrantV1
	owner       *applicationHTMLRevisionSourceOwnerV1
	binding     *applicationHTMLRevisionSourceBindingV1
	stage       htmlRevisionSourceStageV1
	parentBytes int64
}

func (g *applicationHTMLRevisionSourceGrantV1) validV1(ctx context.Context, org, document uuid.UUID) bool {
	return g != nil && g.self == g && g.owner != nil && g.owner.self == g.owner && (g.owner.purpose == htmlRevisionSourcePurposeV1 || g.owner.purpose == htmlSendSourcePurposeV1 || g.owner.purpose == htmlCeremonySourcePurposeV1 || g.owner.purpose == htmlPackageSelectionSourcePurposeV1) && g.binding != nil && g.owner.binding == g.binding &&
		g.binding.org == org && g.binding.document == document && g.binding.ctx == ctx && applicationContextV1(ctx) &&
		g.binding.factory != nil && g.binding.factory.work != nil && g.binding.admission != nil && g.binding.registration != nil &&
		g.stage >= htmlRevisionSourceInitialV1 && g.stage <= htmlRevisionSourceCandidateV1 && g.parentBytes > 0
}

// One original route stage owns one immutable source operation. This shell can
// be copied without copying locks, models or release authority. No caller can
// install a Document, Compiled, source digest, work cost or resource callback.
type ApplicationHTMLRevisionSourceV1 struct {
	state *applicationHTMLRevisionSourceOwnerV1
}
type applicationHTMLRevisionSourceOwnerV1 struct {
	mu                                     sync.Mutex
	self                                   *applicationHTMLRevisionSourceOwnerV1
	purpose                                htmlOwnedSourcePurposeV1
	binding                                *applicationHTMLRevisionSourceBindingV1
	operation                              *applicationHTMLRevisionOperationV1
	snapshot                               *applicationHTMLRevisionSourceSnapshotV1
	releaseBorrower                        func()
	cancel                                 context.CancelFunc
	closes                                 []func()
	active                                 int
	closed, retired, attempted, processing bool
	failure                                error
	validation                             *htmlsource.RevisionValidationV1
	currentValidation                      *htmlsource.RevisionValidationV1
	currentAttempted                       bool
	currentValidated                       bool
	stateAttempted                         bool
	stateValidated                         bool
	stateScratchBase                       int64
	prepareAttempted                       bool
	prepared                               *applicationHTMLRevisionPreparedV1
	candidateAttempted                     bool
	candidate                              *applicationHTMLRevisionCandidateV1
	effectiveCanonical                     htmlmaster.TemplateCommitment
	effectiveCanonicalScratch              int64
	effectiveInput                         htmlsource.Input
	effectiveRawMaster                     htmlmaster.Master
	effectiveOutput                        htmlRevisionCanonicalOutputComponentsV1
	effectiveRawScratch                    int64
	maxScratch                             int64
	parentLoan                             *applicationHTMLRevisionSourceLoanV1
	designs                                []htmlRevisionPreparedDesignV1
}
type htmlRevisionPreparedDesignV1 struct {
	master, defaults []byte
	canonical        htmlRevisionCanonicalOutputComponentsV1
	canonicalScratch int64
	rawScratch       int64
	rawMaster        htmlmaster.Master
}

// The fixed route invokes this INSIDE the actual registered SQL stage after
// ReadDocumentWithActorV1. Source CPU later uses the ORIGINAL operation context,
// never the automatically cancelled SQL callback or a fresh cleanup context.
func (h *ApplicationHTMLRevisionSQLV1) NewSourceV1(call context.Context) (*ApplicationHTMLRevisionSourceV1, error) {
	if h == nil || h.state == nil || !applicationContextV1(call) {
		return nil, ErrHTMLRevisionSourceV1
	}
	stage := h.state
	stage.mu.Lock()
	op, reader, session, closed := stage.operation, stage.reader, stage.session, stage.consumerClosed
	stage.mu.Unlock()
	if closed || op == nil || reader == nil || session == nil || session.state == nil {
		return nil, ErrHTMLRevisionSourceV1
	}
	snapshot, release, err := op.borrowSourceV1(reader)
	if err != nil {
		return nil, errors.Join(ErrHTMLRevisionSourceV1, err)
	}
	physical := session.state
	p := physical.factory
	p.mu.Lock()
	physical.mu.Lock()
	a := physical.admission
	registration := p.htmlAdmissions[a]
	if p.closing || physical.observer || physical.closed || physical.retired || physical.unknown || physical.ended ||
		!physical.callbackActive || physical.sqlActive || call.Value(applicationSessionCallbackKeyV1{}) != physical ||
		a == nil || !a.valid() || a.fence != physical.fence || a.cleanupDone != physical.fence.clientDone || registration == nil {
		physical.mu.Unlock()
		p.mu.Unlock()
		release()
		return nil, ErrHTMLRevisionSourceV1
	}
	original, cancel := context.WithCancel(op.ctx)
	deadline, _ := original.Deadline()
	binding := &applicationHTMLRevisionSourceBindingV1{factory: p, session: session, admission: a, registration: registration, org: physical.org, document: physical.document, ctx: original, deadline: deadline}
	physical.mu.Unlock()
	p.mu.Unlock()
	purpose := htmlRevisionSourcePurposeV1
	if op.workflow != 0 {
		purpose = htmlCeremonySourcePurposeV1
	}
	state := &applicationHTMLRevisionSourceOwnerV1{purpose: purpose, binding: binding, operation: op, snapshot: snapshot, releaseBorrower: release, cancel: cancel}
	state.self = state
	handle := &ApplicationHTMLRevisionSourceV1{state: state}
	op.mu.Lock()
	if !op.usableV1() {
		op.mu.Unlock()
		handle.CloseConsumerV1()
		return nil, ErrHTMLRevisionSourceV1
	}
	if op.sources == nil {
		op.sources = make(map[*applicationHTMLRevisionSourceOwnerV1]struct{})
	}
	op.sources[state] = struct{}{}
	op.sourceUses++
	state.releaseBorrower = func() { release(); op.releaseSourceInputV1() }
	op.mu.Unlock()
	// Birth's active pin joins Close/cancellation through all parser pricing.
	if err = state.beginV1(); err != nil {
		handle.CloseConsumerV1()
		return nil, err
	}
	initial, err := state.initialComponentsV1()
	if err == nil {
		err = state.holdV1(htmlRevisionSourceInitialV1, 0, initial)
	}
	state.finishV1()
	if err != nil {
		handle.CloseConsumerV1()
		return nil, errors.Join(ErrHTMLRevisionSourceV1, err)
	}
	return handle, nil
}
func (s *applicationHTMLRevisionSourceOwnerV1) beginV1() error {
	if s == nil || s.self != s {
		return ErrHTMLRevisionSourceV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired || (s.purpose != htmlRevisionSourcePurposeV1 && s.purpose != htmlSendSourcePurposeV1 && s.purpose != htmlCeremonySourcePurposeV1 && s.purpose != htmlPackageSelectionSourcePurposeV1) || s.binding == nil || !applicationContextV1(s.binding.ctx) || s.snapshot == nil {
		return ErrHTMLRevisionSourceV1
	}
	s.active++
	return nil
}
func (s *applicationHTMLRevisionSourceOwnerV1) finishV1() {
	s.mu.Lock()
	s.active--
	closes, release := s.retireLockedV1()
	s.mu.Unlock()
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
}
func (s *applicationHTMLRevisionSourceOwnerV1) retireLockedV1() ([]func(), func()) {
	if !s.closed || s.retired || s.active != 0 {
		return nil, nil
	}
	s.retired = true
	// Clear all private data/Compiled/source references BEFORE signalling any
	// model/CPU consumer closure. Physical SQL retirement remains independent.
	s.snapshot = nil
	s.validation = nil
	s.failure = nil
	s.currentValidation = nil
	s.designs = nil
	s.parentLoan = nil
	s.prepared = nil
	s.candidate = nil
	s.effectiveCanonical = htmlmaster.TemplateCommitment{}
	s.effectiveInput = htmlsource.Input{}
	s.effectiveRawMaster = htmlmaster.Master{}
	s.effectiveOutput = htmlRevisionCanonicalOutputComponentsV1{}
	closes, release := s.closes, s.releaseBorrower
	s.closes = nil
	s.releaseBorrower = nil
	return closes, release
}
func (h *ApplicationHTMLRevisionSourceV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.closed = true
	s.cancel()
	candidate := s.candidate
	closes, release := s.retireLockedV1()
	s.mu.Unlock()
	if candidate != nil {
		(&ApplicationHTMLRevisionCandidateV1{state: candidate}).CloseConsumerV1()
	}
	for _, close := range closes {
		close()
	}
	if release != nil {
		release()
	}
}

// hold admits a positive delta of the greatest serialized scratch stage, PLUS
// separately retained actual outputs. Previous grants are never refunded here;
// this is logical staging, not an assertion that Go GC/pools/RSS retired.
// All deltas grow ONE private source-owner grant; expression count does not
// create independent outstanding grant objects or release any earlier bytes.
// Existing same-admission registration must still be present. A retired SQL
// session creates no new SQL authority: these are Parent-only CPU/result loans.
func (s *applicationHTMLRevisionSourceOwnerV1) holdV1(stage htmlRevisionSourceStageV1, scratch, retained int64) error {
	if scratch < 0 || retained < 0 {
		return ErrHTMLRevisionSourceV1
	}
	s.mu.Lock()
	if s.closed || s.retired || s.active == 0 || !applicationContextV1(s.binding.ctx) {
		s.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	if s.parentLoan == nil {
		s.parentLoan = &applicationHTMLRevisionSourceLoanV1{owner: s, binding: s.binding}
		s.parentLoan.self = s.parentLoan
	}
	parentLoan := s.parentLoan
	old := s.maxScratch
	next := max(old, scratch)
	amount, err := htmlAuthoringSumV1(next-old, retained)
	s.mu.Unlock()
	if err != nil {
		return ErrHTMLRevisionSourceV1
	}
	if amount == 0 {
		return nil
	}
	b := s.binding
	p := b.factory
	physical := b.session.state
	p.mu.Lock()
	physical.mu.Lock()
	currentRegistration := p.htmlAdmissions[b.admission]
	if p.closing || currentRegistration == nil || currentRegistration.admission != b.admission || physical.factory != p ||
		physical.admission != b.admission || physical.fence == nil || b.admission.fence != physical.fence ||
		b.admission.cleanupDone != physical.fence.clientDone || physical.unknown || physical.commitUnknown {
		physical.mu.Unlock()
		p.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	// Refresh the same actual-admission registration before granting. Other
	// legitimate header/event producers also refresh it; captured registration
	// pointer equality is not a lifetime authority and must not reject them.
	p.htmlAdmissions[b.admission] = &applicationHTMLAdmissionRegistrationV1{admission: b.admission}
	grant := &applicationHTMLRevisionSourceGrantV1{owner: s, binding: b, stage: stage, parentBytes: amount}
	grant.self = grant
	close, err := b.admission.admitHTMLRevisionSourceParentV1(b.ctx, ApplicationBudgetV1{Phase: "owned-html-revision-source", OrgID: b.org, DocumentID: b.document,
		WorkingBytes: amount, htmlRevisionSourceGrant: grant}, parentLoan)
	physical.mu.Unlock()
	p.mu.Unlock()
	// The one original consumer closure is retained even if cancellation became
	// visible immediately after successful native acquisition. Later positive
	// growth changes only that SAME loan, never its physical/consumer fence.
	if close != nil {
		s.mu.Lock()
		s.closes = append(s.closes, close)
		s.mu.Unlock()
	}
	if err != nil {
		return errors.Join(ErrHTMLRevisionSourceV1, err)
	}
	s.mu.Lock()
	s.maxScratch = next
	s.mu.Unlock()
	return nil
}
func (s *applicationHTMLRevisionSourceOwnerV1) initialComponentsV1() (int64, error) {
	return s.initialDocumentComponentsV1(s.snapshot.document)
}
func (s *applicationHTMLRevisionSourceOwnerV1) initialDocumentComponentsV1(doc *generated.Document) (int64, error) {
	initial, err := htmlRevisionPreparedDocumentCloneV1(doc)
	if err != nil {
		return 0, err
	}
	ceiling, err := htmlRevisionPreparedMasterProjectionCeilingV1()
	if err != nil {
		return 0, err
	}
	for _, raw := range [][]byte{doc.HtmlSourceJson, doc.HtmlCurrentSourceJson} {
		if len(raw) == 0 {
			continue
		}
		parts, err := htmlRevisionSourceDecodeComponentsForV1(s.binding.ctx, raw)
		if err != nil {
			return 0, htmlRevisionStoredShapeErrorV1(s.binding.ctx, err)
		}
		getter, err := htmlRevisionPreparedInputProjectionFromSourceV1(raw, parts)
		if err != nil {
			return 0, err
		}
		master, err := htmlAuthoringInputRootShapeV1(s.binding.ctx, htmlInputMasterV1, raw[parts.masterStart:parts.masterEnd])
		if err != nil {
			return 0, htmlRevisionStoredShapeErrorV1(s.binding.ctx, err)
		}
		masterParser, err := htmlAuthoringInputParserArenaV1(master, 5)
		if err != nil {
			return 0, err
		}
		defaults, err := htmlAuthoringInputRootShapeV1(s.binding.ctx, htmlInputStringMapV1, raw[parts.defaultsStart:parts.defaultsEnd])
		if err != nil {
			return 0, htmlRevisionStoredShapeErrorV1(s.binding.ctx, err)
		}
		defaultsParser, err := htmlAuthoringInputParserArenaV1(defaults, 2)
		if err != nil {
			return 0, err
		}
		for _, n := range []int64{parts.sourceParserBytes, parts.retainedTypedSourceBytes, parts.artifactOriginalParserBytes,
			parts.artifactCanonicalParserBytes, parts.artifactEncodeBytes, masterParser, defaultsParser} {
			if !htmlInputAddV1(&initial, n, 1) {
				return 0, ErrHTMLRevisionSourceV1
			}
		}
		// At most Raw/Canonical/Record actual getters per source record. These
		// copies are priced BEFORE a getter can allocate, without a pricing Compile.
		if !htmlInputAddV1(&initial, getter, 3) || !htmlInputAddV1(&initial, ceiling, 3) {
			return 0, ErrHTMLRevisionSourceV1
		}
		pins, err := htmlRevisionPreparedRecordPinsProjectionV1(htmlsource.RevisionValidationRecordPinsV1{
			PDFSHA256: doc.PdfSha256, VariablesJSON: doc.VariablesJson})
		if err != nil || !htmlInputAddV1(&initial, pins, 1) || !htmlInputAddV1(&initial, 32, 2) {
			return 0, ErrHTMLRevisionSourceV1
		}
	}
	return initial, nil
}

// ValidateV1 drives only the three concrete staged producers. It cannot execute
// a caller callback, SQL statement, new design or arbitrary Compile count.
func (h *ApplicationHTMLRevisionSourceV1) ValidateV1() (failure error) {
	if h == nil || h.state == nil {
		return ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.attempted {
		s.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	s.attempted = true
	s.processing = true
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.failure = failure; s.mu.Unlock() }()
	validated, err := s.validateDocumentV1(s.snapshot.document)
	if err != nil {
		return err
	}
	if !applicationContextV1(s.binding.ctx) {
		return ErrHTMLRevisionSourceV1
	}
	s.mu.Lock()
	s.validation = validated
	s.mu.Unlock()
	return nil
}
func (s *applicationHTMLRevisionSourceOwnerV1) validateDocumentV1(document *generated.Document) (*htmlsource.RevisionValidationV1, error) {
	builder, err := htmlsource.NewRevisionValidationBuilderV1(document)
	if err != nil {
		return nil, err
	}
	for {
		if !applicationContextV1(s.binding.ctx) {
			return nil, ErrHTMLRevisionSourceV1
		}
		stage, err := builder.StageV1()
		if err != nil {
			return nil, err
		}
		if stage == htmlsource.RevisionValidationDoneV1 {
			return builder.FinishV1()
		}
		master, err := builder.MasterV1()
		if err != nil {
			return nil, err
		}
		input, err := builder.InputV1()
		if err != nil {
			return nil, err
		}
		switch stage {
		case htmlsource.RevisionValidationRawCompileV1, htmlsource.RevisionValidationCanonicalCompileV1:
			inspection, err := htmlInputCanonicalInspectionResourcesV1(master)
			if err != nil {
				return nil, err
			}
			if err = s.holdV1(htmlRevisionSourceRawV1, inspection, 0); err != nil {
				return nil, err
			}
			stats, err := htmlInputCanonicalInspectV1(s.binding.ctx, master)
			if err != nil {
				return nil, err
			}
			defaultsShape, err := htmlAuthoringInputRootShapeV1(s.binding.ctx, htmlInputStringMapV1, input.DefaultVarsJSON)
			if err != nil {
				return nil, err
			}
			out, err := htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaultsShape)
			if err != nil {
				return nil, err
			}
			raw, defaults := input.MasterJSON, input.DefaultVarsJSON
			if stage == htmlsource.RevisionValidationCanonicalCompileV1 {
				actual, err := builder.CanonicalV1()
				if err != nil {
					return nil, err
				}
				raw, defaults = actual.MasterJSON, actual.DefaultsJSON
			}
			scratch, err := htmlInputCanonicalResourcesV1(raw, defaults, master, stats)
			if err != nil {
				return nil, err
			}
			retained, err := htmlRevisionPreparedCompiledRetentionV1(master, stats, out)
			if err != nil {
				return nil, err
			}
			typed, err := htmlRevisionPreparedMasterRetentionV1(master)
			if err != nil || !htmlInputAddV1(&retained, typed, 1) {
				return nil, ErrHTMLRevisionSourceV1
			}
			phase := htmlRevisionSourceCanonicalV1
			if stage == htmlsource.RevisionValidationRawCompileV1 {
				phase = htmlRevisionSourceRawV1
				template, err := htmlRevisionPreparedTemplateRetentionV1(out)
				// Canonical result plus at most three actual canonical getters (next
				// canonical stage and two records sharing this one exact design).
				if err != nil || !htmlInputAddV1(&retained, template, 4) || !htmlInputAddV1(&retained, out.masterParserBytes, 1) || !htmlInputAddV1(&retained, out.defaultsParserBytes, 1) {
					return nil, ErrHTMLRevisionSourceV1
				}
			}
			if err = s.holdV1(phase, scratch, retained); err != nil {
				return nil, err
			}
			if stage == htmlsource.RevisionValidationRawCompileV1 {
				if err = builder.PrepareRawV1(); err != nil {
					return nil, err
				}
				s.designs = append(s.designs, htmlRevisionPreparedDesignV1{master: input.MasterJSON, defaults: input.DefaultVarsJSON, rawMaster: master, rawScratch: scratch})
			} else {
				if err = builder.PrepareCanonicalV1(); err != nil {
					return nil, err
				}
				i := len(s.designs) - 1
				if i < 0 || !bytes.Equal(s.designs[i].master, input.MasterJSON) || !bytes.Equal(s.designs[i].defaults, input.DefaultVarsJSON) {
					return nil, ErrHTMLRevisionSourceV1
				}
				s.designs[i].canonical = out
				s.designs[i].canonicalScratch = scratch
			}
		case htmlsource.RevisionValidationRecordV1:
			canonical, err := builder.CanonicalV1()
			if err != nil {
				return nil, err
			}
			pins, err := builder.RecordPinsV1()
			if err != nil {
				return nil, err
			}
			record, err := htmlRevisionRecordComponentsForV1(s.binding.ctx, input, canonical, pins)
			if err != nil {
				return nil, err
			}
			var design *htmlRevisionPreparedDesignV1
			for i := range s.designs {
				if bytes.Equal(s.designs[i].master, input.MasterJSON) && bytes.Equal(s.designs[i].defaults, input.DefaultVarsJSON) {
					design = &s.designs[i]
					break
				}
			}
			if design == nil {
				return nil, ErrHTMLRevisionSourceV1
			}
			scratch, retained, err := htmlRevisionRecordStageComponentsV1(master, input, record, design.canonical, design.canonicalScratch)
			if err != nil {
				return nil, err
			}
			if err = s.holdV1(htmlRevisionSourceRecordV1, scratch, retained); err != nil {
				return nil, err
			}
			if err = builder.ValidateRecordV1(); err != nil {
				return nil, err
			}
			s.effectiveInput = input
			s.effectiveRawMaster = design.rawMaster
			s.effectiveOutput = design.canonical
			s.effectiveRawScratch = design.rawScratch
			s.effectiveCanonical = canonical
			s.effectiveCanonicalScratch = design.canonicalScratch
		default:
			return nil, ErrHTMLRevisionSourceV1
		}
	}
}

func (h *ApplicationHTMLRevisionSourceV1) CommitmentV1() (string, error) {
	if h == nil || h.state == nil {
		return "", ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return "", err
	}
	defer s.finishV1()
	s.mu.Lock()
	v := s.validation
	failure := s.failure
	s.mu.Unlock()
	if v == nil || failure != nil {
		return "", ErrHTMLRevisionSourceV1
	}
	return v.CommitmentV1()
}

// This fixed validation call retains source, collection rows and all nested
// callback outputs until the actual original helper and every query have joined.
func (h *ApplicationHTMLRevisionSourceV1) ValidateSigningPageStateV1(call context.Context, collections *ApplicationHTMLRevisionCollectionsV1, pages int) error {
	if h == nil || h.state == nil || h.state.purpose != htmlRevisionSourcePurposeV1 || collections == nil {
		return ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.processing || s.stateAttempted || !s.currentValidated || s.validation == nil {
		s.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	s.stateAttempted = true
	s.processing = true
	v := s.validation
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	if collections.reader != s.snapshot.owner || call.Value(applicationSessionCallbackKeyV1{}) != s.binding.session.state {
		return ErrHTMLRevisionSourceV1
	}
	cost, err := s.stateComponentsV1()
	if err != nil {
		return err
	}
	s.stateScratchBase = cost
	if err = s.holdV1(htmlRevisionSourceStateV1, cost, 0); err != nil {
		return err
	}
	if err := collections.validateSigningPageStateWithSourceV1(call, v, pages, s); err != nil {
		return err
	}
	s.mu.Lock()
	s.stateValidated = true
	s.mu.Unlock()
	return nil
}

// Current12's original metadata/report checks precede any separately needed
// row-source validation. Exact transport reuse is local to this actual owned
// snapshot; legal different transport takes a distinct full builder operation.
func (h *ApplicationHTMLRevisionSourceV1) ValidateCurrentV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.processing || s.currentAttempted || s.validation == nil {
		s.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	s.currentAttempted = true
	s.processing = true
	v := s.validation
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	doc, row := s.snapshot.document, s.snapshot.current
	required, err := htmlmaterialization.ValidateCurrentReadProjectionMetadataPreparedV1(doc, row, v)
	if err != nil {
		return err
	}
	if !required {
		s.mu.Lock()
		s.currentValidated = true
		s.mu.Unlock()
		return nil
	}
	rowValidation := v
	if !bytes.Equal(doc.HtmlCurrentSourceJson, row.SourceJson) {
		actual := *doc
		actual.HtmlCurrentSourceJson = row.SourceJson
		initial, err := s.initialDocumentComponentsV1(&actual)
		if err != nil {
			return htmlRevisionCurrentValidationErrorV1(err)
		}
		if err = s.holdV1(htmlRevisionSourceInitialV1, 0, initial); err != nil {
			return err
		}
		oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch := s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch
		rowValidation, err = s.validateDocumentV1(&actual)
		s.effectiveInput, s.effectiveRawMaster, s.effectiveOutput, s.effectiveRawScratch, s.effectiveCanonical, s.effectiveCanonicalScratch = oldInput, oldMaster, oldOutput, oldScratch, oldCanonical, oldCanonicalScratch
		if err != nil {
			return htmlRevisionCurrentValidationErrorV1(err)
		}
		s.mu.Lock()
		s.currentValidation = rowValidation
		s.mu.Unlock()
	}
	if err := htmlmaterialization.ValidateCurrentReadProjectionPreparedV1(doc, row, v, rowValidation); err != nil {
		return err
	}
	if !applicationContextV1(s.binding.ctx) {
		return ErrHTMLRevisionSourceV1
	}
	s.mu.Lock()
	s.currentValidated = true
	s.mu.Unlock()
	return nil
}

// Current historically masks a malformed row source as materialization invalid.
// Capacity/native/context errors retain their actual unavailable/cancel cause.
func htmlRevisionCurrentValidationErrorV1(err error) error {
	if errors.Is(err, htmlsource.ErrInvalid) || errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrMissingValues) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
		return errors.Join(htmlmaterialization.ErrInvalid, err)
	}
	return err
}

// Allocation-free stored-input shape refusal is a source business error, not
// capacity denial. Actual admission/runtime/cancellation errors stay separate.
func htmlRevisionStoredShapeErrorV1(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx.Err() != nil || !htmlAuthoringInputRuntimeOKV1 {
		return err
	}
	return errors.Join(htmlsource.ErrInvalid, err)
}
