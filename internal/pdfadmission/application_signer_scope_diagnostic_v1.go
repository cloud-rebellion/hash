// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"log/slog"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
)

// Fixed observations of actual branches; none selects work or conveys authority.
type applicationSignerScopePhaseV1 uint8

const (
	signerScopeControlV1 applicationSignerScopePhaseV1 = iota + 1
	signerScopeObserverV1
	signerScopeOwnerV1
	signerScopeStartV1
	signerScopeBeginV1
	signerScopeQueryV1
	signerScopeCloseV1
	signerScopeRetirementV1
	signerScopeReaderConstructorV1
	signerScopeQuarantineV1
	signerScopeJoinV1
	signerScopeRegistryV1
)

type applicationSignerScopeDiagnosticV1 struct {
	denial           workguard.AdmissionDenialV1
	phase            applicationSignerScopePhaseV1
	cleanupClass     uint8
	captured, logged bool
}

// Do not retain or log private error strings, SQL, identities or credentials.
func signerScopeErrorClassV1(err error) uint8 {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.DeadlineExceeded):
		return 1
	case errors.Is(err, context.Canceled):
		return 2
	case errors.Is(err, workguard.ErrUnavailableV1):
		return 5
	case errors.Is(err, ErrApplicationSessionUnknownV1):
		return 3
	case errors.Is(err, ErrApplicationSessionV1):
		return 4
	case errors.Is(err, pgx.ErrNoRows):
		return 6
	default:
		return 7
	}
}

func (s *applicationSignerScopeStateV1) setProbePhaseV1(phase applicationSignerScopePhaseV1) {
	if s != nil {
		s.mu.Lock()
		s.diagnostic.phase = phase
		s.mu.Unlock()
	}
}

func (s *applicationSignerScopeStateV1) recordProcessSQLDenialV1(owner *applicationOwnedSessionV1, denial workguard.AdmissionDenialV1) {
	if s == nil || owner == nil || s.factory == nil {
		return
	}
	p := s.factory
	p.mu.Lock()
	_, registered := p.signerScopes[s]
	_, owned := p.sessions[owner]
	p.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !registered || !owned || s.release == nil || s.consumerClosed || s.released || s.diagnostic.captured ||
		s.session == nil || s.session.state != owner || owner.factory != p || owner.observer ||
		owner.organisation == nil || !owner.organisation.processControl {
		return
	}
	s.diagnostic.denial, s.diagnostic.captured = denial, true
}

func (s *ApplicationSignerScopeV1) LogReaderConstructionRefusalV1(ctx context.Context, route SignerReadDiagnosticRouteV1, operation SignerReadDiagnosticOperationV1, err error) {
	if s == nil || s.state == nil {
		return
	}
	s.state.setProbePhaseV1(signerScopeReaderConstructorV1)
	s.logProbeRefusalV1(ctx, route, operation, err)
}

// Log before failure cleanup. The original registered scope keeps its existing
// control loan through the synchronous log call, including concurrent Close.
// Observer failures have no captured process decision and never claim one.
func (s *ApplicationSignerScopeV1) logProbeRefusalV1(ctx context.Context, route SignerReadDiagnosticRouteV1, operation SignerReadDiagnosticOperationV1, err error) {
	if s == nil || s.state == nil || ctx == nil || err == nil ||
		!validSignerReadDiagnosticLabelsV1(route, operation, SignerReadDiagnosticOpenV1) {
		return
	}
	p := s.state
	if p.factory == nil {
		return
	}
	p.factory.mu.Lock()
	_, registered := p.factory.signerScopes[p]
	p.factory.mu.Unlock()
	p.mu.Lock()
	if !registered || p.release == nil || p.released || p.consumerClosed || p.diagnostic.logged ||
		(errors.Is(err, pgx.ErrNoRows) && p.diagnostic.cleanupClass == 0) {
		p.mu.Unlock()
		return
	}
	frame := p.diagnostic
	p.diagnostic.logged = true
	p.borrowers++
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.borrowers--; p.mu.Unlock(); p.reconcileV1() }()
	d := frame.denial.SnapshotV1()
	slog.LogAttrs(ctx, slog.LevelWarn, "owned signer scope refused",
		slog.Int("route", int(route)), slog.Int("operation", int(operation)), slog.Int("probe_phase", int(frame.phase)),
		slog.Int("error_class", int(signerScopeErrorClassV1(err))), slog.Int("cleanup_class", int(frame.cleanupClass)),
		slog.Int("constructor_cause", int(signerReaderConstructorCauseV1(err))),
		slog.Bool("atomic_decision", frame.captured), slog.Int("reason", int(d.Reason)), slog.Int("dimension", int(d.Dimension)),
		slog.Int64("requested_sql", d.Requested.SQLSessions), slog.Int64("global_sql_before", d.Before.Global.SQLSessions),
		slog.Int64("global_sql_limit", d.GlobalLimit.SQLSessions), slog.Int64("global_grants_before", d.Before.GlobalGrants),
		slog.Int64("global_grant_limit", d.GlobalGrantLimit))
}
