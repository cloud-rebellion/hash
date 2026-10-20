// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"log/slog"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
)

// Diagnostic enums carry no credential, source, SQL or retry authority.
type SignerReadDiagnosticRouteV1 uint8

const (
	SignerReadDiagnosticOtherV1 SignerReadDiagnosticRouteV1 = iota
	SignerReadDiagnosticFieldsV1
	SignerReadDiagnosticPDFV1
	SignerReadDiagnosticCommentsV1
	SignerReadDiagnosticViewV1
	SignerReadDiagnosticPackageV1
)

type SignerReadDiagnosticOperationV1 uint8

const (
	SignerReadDiagnosticLookupV1 SignerReadDiagnosticOperationV1 = iota + 1
	SignerReadDiagnosticRecheckV1
	SignerReadDiagnosticViewMutationV1
)

type SignerReadDiagnosticPhaseV1 uint8

const (
	SignerReadDiagnosticOpenV1 SignerReadDiagnosticPhaseV1 = iota + 1
	SignerReadDiagnosticModelsV1
	SignerReadDiagnosticCommitV1
	SignerReadDiagnosticCloseSQLV1
	SignerReadDiagnosticViewMutationPhaseV1
)

type applicationSignerReadDiagnosticV1 struct {
	denial                                         workguard.AdmissionDenialV1
	captured, logged                               bool
	modelStep                                      applicationSignerReadModelStepV1
	modelOutcome                                   applicationSignerReadModelOutcomeV1
	errorClass, contextState                       uint8
	startPhase, startErrorClass, startContextState uint8
}

// These fixed labels describe the actual last model-read branch. They confer
// no retry, policy, SQL or admission authority and retain no private error.
type applicationSignerReadModelStepV1 uint8

const (
	signerReadModelTransactionV1 applicationSignerReadModelStepV1 = iota + 1
	signerReadModelHeaderAdmissionV1
	signerReadModelDocumentHeaderV1
	signerReadModelRecipientHeaderV1
	signerReadModelPreflightV1
	signerReadModelMeasurementsV1
	signerReadModelTotalsV1
	signerReadModelControllerHeaderV1
	signerReadModelMaterializationHeaderV1
	signerReadModelBodyAdmissionV1
	signerReadModelDocumentBodyV1
	signerReadModelRecipientBodyV1
	signerReadModelControllerBodyV1
	signerReadModelMaterializationBodyV1
	signerReadModelBlockSourceV1
	signerReadModelResponsePolicyV1
)

type applicationSignerReadModelOutcomeV1 uint8

const (
	signerReadModelSessionErrorV1 applicationSignerReadModelOutcomeV1 = iota + 1
	signerReadModelAdmissionErrorV1
	signerReadModelQueryErrorV1
	signerReadModelConsistencyErrorV1
	signerReadModelMeasurementErrorV1
	signerReadModelArithmeticErrorV1
	signerReadModelPreflightErrorV1
	signerReadModelPolicyErrorV1
	signerReadModelBlockSourceErrorV1
)

// Caller is the actual WithModelsV1 owner and already holds r.mu. Never call
// a locking recorder or the logger inside that callback.
func (r *ApplicationSignerReaderV1) setModelDiagnosticV1(step applicationSignerReadModelStepV1, outcome applicationSignerReadModelOutcomeV1) {
	r.diagnostic.modelStep, r.diagnostic.modelOutcome = step, outcome
}

// The existing process scope owns its fixed 8MiB control class before reader
// construction. Reserve bounded reader/session controls, the embedded decision,
// two synchronous copies, three admission companion copies and twenty-seven fixed log attributes for EVERY possible
// registered reader in that same class. Legal models/bodies have separate loans.
// No constructor allocates a reader until the existing registry cap is held.
const applicationSignerReadDiagnosticControlBytesV1 = int64(unsafe.Sizeof(applicationSignerScopeStateV1{})) +
	2*int64(unsafe.Sizeof(applicationSignerScopeDiagnosticV1{})) +
	2*int64(unsafe.Sizeof(workguard.AdmissionDenialSnapshotV1{})) +
	3*int64(unsafe.Sizeof(workguard.AdmissionDenialV1{})) +
	16*int64(unsafe.Sizeof(slog.Attr{})) + 256 +
	applicationSessionMaxWorkV1*(int64(unsafe.Sizeof(ApplicationSignerReaderV1{}))+
		int64(unsafe.Sizeof(applicationOwnedSessionV1{}))+
		2*int64(unsafe.Sizeof(applicationSignerReadDiagnosticV1{}))+
		2*int64(unsafe.Sizeof(workguard.AdmissionDenialSnapshotV1{}))+
		3*int64(unsafe.Sizeof(workguard.AdmissionDenialV1{}))+
		27*int64(unsafe.Sizeof(slog.Attr{}))+4*int64(unsafe.Sizeof(sync.Once{}))+256)

// Only the actual registered constructor reader may bind this session before
// its first SQL acquisition. The original Open checks still control dispatch.
func (r *ApplicationSignerReaderV1) bindDiagnosticSessionV1(f *ApplicationSessionFactoryV1, h *ApplicationSessionV1) bool {
	if r == nil || r.self != r || f == nil || f.state == nil || h == nil || h.state == nil {
		return false
	}
	f.state.mu.Lock()
	_, registered := f.state.signerReaders[r]
	f.state.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !registered || r.factory != f || !r.creating || r.consumerClosed || r.released || r.finishScope == nil || r.session != nil ||
		h.state.factory != f.state || h.state.org != r.scope.org || h.state.document != r.scope.document || h.state.observer {
		return false
	}
	r.session = h
	return true
}
func (r *ApplicationSignerReaderV1) recordSQLDenialV1(s *applicationOwnedSessionV1, denial workguard.AdmissionDenialV1) {
	if r == nil || r.self != r || s == nil || r.factory == nil || r.factory.state == nil {
		return
	}
	p := r.factory.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	p.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !registered || !r.creating || r.consumerClosed || r.released || r.finishScope == nil || r.session == nil || r.session.state != s ||
		s.factory != p || s.org != r.scope.org || s.document != r.scope.document || s.observer || r.diagnostic.captured {
		return
	}
	r.diagnostic.denial = denial
	r.diagnostic.captured = true
}

// The view mutation label describes only the actual handler branch. It does
// not make an earlier successful reader's zero facts a mutation admission proof.
func validSignerReadDiagnosticLabelsV1(route SignerReadDiagnosticRouteV1, operation SignerReadDiagnosticOperationV1, phase SignerReadDiagnosticPhaseV1) bool {
	if route != SignerReadDiagnosticFieldsV1 && route != SignerReadDiagnosticPDFV1 && route != SignerReadDiagnosticCommentsV1 && route != SignerReadDiagnosticViewV1 && route != SignerReadDiagnosticPackageV1 {
		return false
	}
	if operation == SignerReadDiagnosticViewMutationV1 || phase == SignerReadDiagnosticViewMutationPhaseV1 {
		return route == SignerReadDiagnosticViewV1 && operation == SignerReadDiagnosticViewMutationV1 && phase == SignerReadDiagnosticViewMutationPhaseV1
	}
	return (operation == SignerReadDiagnosticLookupV1 || operation == SignerReadDiagnosticRecheckV1) && phase >= SignerReadDiagnosticOpenV1 && phase <= SignerReadDiagnosticCloseSQLV1
}

// LogRefusalV1 consumes only fixed numeric observation while THIS genuine
// reader and its original scope borrower still own the control frame. Call
// synchronously before failure cleanup; no diagnostic error/body escapes.
// Only an actual SQL or native model admission decision claims atomic facts.
// Probe, observer, validation and quarantine failures keep that flag false.
func (r *ApplicationSignerReaderV1) LogRefusalV1(ctx context.Context, route SignerReadDiagnosticRouteV1, operation SignerReadDiagnosticOperationV1, phase SignerReadDiagnosticPhaseV1) {
	if r == nil || r.self != r || ctx == nil || !validSignerReadDiagnosticLabelsV1(route, operation, phase) {
		return
	}
	if r.factory == nil || r.factory.state == nil {
		return
	}
	p := r.factory.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	p.mu.Unlock()
	r.mu.Lock()
	if !registered || r.finishScope == nil || r.released || r.consumerClosed || r.diagnostic.logged {
		r.mu.Unlock()
		return
	}
	frame := r.diagnostic
	r.diagnostic.logged = true
	r.diagnosticBorrowers++
	r.mu.Unlock()
	// Concurrent Close may end SQL/models, but this real control consumer keeps
	// the original scope frame charged until the synchronous handler returns.
	defer func() { r.mu.Lock(); r.diagnosticBorrowers--; r.mu.Unlock() }()
	d := frame.denial.SnapshotV1()
	dimensionValue := func(v workguard.VectorV1) int64 {
		switch d.Dimension {
		case workguard.AdmissionSQLSessionsV1:
			return v.SQLSessions
		case workguard.AdmissionParentBytesV1:
			return v.ParentBytes
		case workguard.AdmissionDBStagingBytesV1:
			return v.DBStagingBytes
		default:
			return 0
		}
	}
	slog.LogAttrs(ctx, slog.LevelWarn, "owned signer read refused",
		slog.Int("route", int(route)), slog.Int("operation", int(operation)), slog.Int("phase", int(phase)),
		slog.Bool("atomic_decision", frame.captured), slog.Int("reason", int(d.Reason)), slog.Int("dimension", int(d.Dimension)),
		slog.Int64("requested_sql", d.Requested.SQLSessions), slog.Int64("global_sql_before", d.Before.Global.SQLSessions),
		slog.Int64("org_sql_before", d.Before.Organisation.SQLSessions), slog.Int64("global_sql_limit", d.GlobalLimit.SQLSessions),
		slog.Int64("org_sql_limit", d.OrganisationLimit.SQLSessions), slog.Int64("global_grants_before", d.Before.GlobalGrants),
		slog.Int64("org_grants_before", d.Before.OrganisationGrants), slog.Int64("global_grant_limit", d.GlobalGrantLimit),
		slog.Int64("org_grant_limit", d.OrganisationGrantLimit),
		slog.Int("model_step", int(frame.modelStep)), slog.Int("model_outcome", int(frame.modelOutcome)),
		slog.Int64("requested_resource", dimensionValue(d.Requested)),
		slog.Int64("global_resource_before", dimensionValue(d.Before.Global)),
		slog.Int64("org_resource_before", dimensionValue(d.Before.Organisation)),
		slog.Int64("global_resource_limit", dimensionValue(d.GlobalLimit)),
		slog.Int64("org_resource_limit", dimensionValue(d.OrganisationLimit)),
		slog.Int("model_error_class", int(frame.errorClass)), slog.Int("model_context_state", int(frame.contextState)),
		slog.Int("session_start_phase", int(frame.startPhase)),
		slog.Int("session_start_error_class", int(frame.startErrorClass)),
		slog.Int("session_start_context_state", int(frame.startContextState)))
}
