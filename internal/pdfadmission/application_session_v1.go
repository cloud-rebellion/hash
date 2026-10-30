// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	ErrApplicationSessionV1              = errors.New("pdfadmission: owned SQL session unavailable")
	ErrApplicationSessionUnknownV1       = errors.New("pdfadmission: owned SQL session or observer retirement unresolved")
	ErrApplicationSessionCommitUnknownV1 = errors.New("pdfadmission: SQL commit acknowledgement unresolved")
)

type ApplicationSessionProfileV1 string

const ApplicationSessionDirectProfileV1 ApplicationSessionProfileV1 = "direct-single-attempt-v1"
const applicationSessionMaxOrganisationsV1 = 32
const applicationSessionMaxWorkV1 = 128

// A dispatched control observation owns its bounded lifetime. A caller's
// cancellation cannot tear down the shared observer used by other work owners.
// The synchronous borrower joins before returning; caller cancellation still
// prevents its observation from granting retirement credit.
const applicationObserverProbeBudgetV1 = time.Second

func applicationObserverProbeContextV1(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if !applicationContextV1(ctx) {
		return nil, nil, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
	}
	probe, cancel := context.WithTimeout(context.WithoutCancel(ctx), applicationObserverProbeBudgetV1)
	return probe, cancel, nil
}

type ApplicationSessionFactoryV1 struct {
	state *applicationSessionFactoryStateV1
}
type applicationSessionFactoryStateV1 struct {
	mu                        sync.Mutex
	config                    *pgx.ConnConfig
	work                      *WorkAdmissionV1
	organisations             map[uuid.UUID]*applicationSessionOrganisationV1
	signerControl             *applicationSessionOrganisationV1
	signerScopes              map[*applicationSignerScopeStateV1]struct{}
	sendRecoveryScans         map[*applicationHTMLSendRecoveryScanStateV1]struct{}
	htmlCatalogMaintenance    map[*applicationCatalogMaintenanceStateV1]struct{}
	signerReaders             map[*ApplicationSignerReaderV1]struct{}
	sessions                  map[*applicationOwnedSessionV1]struct{}
	htmlAdmissions            map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1
	htmlInputProducers        map[*applicationHTMLAuthoringInputStateV1]struct{}
	htmlCanonicalConsumers    map[*applicationHTMLCanonicalModelConsumerV1]struct{}
	documentPackageOperations [applicationSessionMaxWorkV1]*applicationDocumentPackageOperationStateV1
	packageRecoveryBatches    [applicationSessionMaxWorkV1]*applicationPackageSendRecoveryBatchStateV1
	documentAIAccountings     [applicationSessionMaxWorkV1]*applicationDocumentAIAccountingStateV1
	signerPackageMemberReads  [applicationSessionMaxWorkV1]*applicationSignerPackageMemberReadStateV1
	closing                   bool
}

// Nonzero private identity prevents an old empty cleanup observation from
// removing a newer actual registry installation. It confers no work authority.
type applicationHTMLAdmissionRegistrationV1 struct{ admission *ApplicationAdmissionV1 }
type applicationSessionOrganisationV1 struct {
	factory        *applicationSessionFactoryStateV1
	org            uuid.UUID
	processControl bool
	mu             sync.Mutex
	initializing   bool
	observer       *applicationOwnedSessionV1
	guard          chan struct{}
}
type applicationSessionCallbackKeyV1 struct{}
type ApplicationSessionV1 struct{ state *applicationOwnedSessionV1 }
type applicationOwnedSessionV1 struct {
	mu                                                         sync.Mutex
	changed                                                    chan struct{}
	factory                                                    *applicationSessionFactoryStateV1
	organisation                                               *applicationSessionOrganisationV1
	org, document                                              uuid.UUID
	observer                                                   bool
	grant                                                      func()
	conn                                                       *pgx.Conn
	socket                                                     net.Conn
	tx                                                         pgx.Tx
	fence                                                      *applicationSessionFenceV1
	admission                                                  *ApplicationAdmissionV1
	active                                                     int
	retiring                                                   int
	cancel                                                     context.CancelFunc
	cancelSQL                                                  context.CancelFunc
	callbackActive, sqlActive                                  bool
	creating, closed, ended, retired, releasing, closingClient bool
	dialed, unknown, commitAttempted, commitUnknown            bool
	htmlWriterStarted                                          bool
}
type ApplicationSessionPendingV1 struct {
	WorkSessions, ObserverSessions, UnknownStarts int
	HTMLAdmissions                                int
	HTMLInputProducers                            int
	HTMLCanonicalConsumers                        int
	SignerScopes                                  int
	HTMLSendRecoveryScans                         int
	CatalogMaintenance                            int
	DocumentAIAccountings                         int
	SignerReaders                                 int
	DocumentPackageOperations                     int
	PackageSendRecoveryBatches                    int
	SignerPackageMemberReads                      int
	Closing                                       bool
}

type applicationSessionFailureV1 struct {
	causes []error
	start  ApplicationSessionStartObservationV1
}

func (*applicationSessionFailureV1) Error() string     { return ErrApplicationSessionV1.Error() }
func (e *applicationSessionFailureV1) Unwrap() []error { return append([]error(nil), e.causes...) }
func applicationSessionErrorV1(ctx context.Context, phase error, cause error) error {
	causes := []error{ErrApplicationSessionV1}
	if phase != nil {
		causes = append(causes, phase)
	}
	if cause != nil {
		causes = append(causes, cause)
	}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
	}
	return &applicationSessionFailureV1{causes: causes}
}
func applicationSessionFunctionSameV1(a, b any) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if !va.IsValid() || !vb.IsValid() {
		return !va.IsValid() && !vb.IsValid()
	}
	if va.Kind() != reflect.Func || vb.Kind() != reflect.Func {
		return false
	}
	if va.IsNil() || vb.IsNil() {
		return va.IsNil() && vb.IsNil()
	}
	return va.Pointer() == vb.Pointer()
}

// The explicit new profile preserves effective credential/TLS/runtime/timeout/
// tracing configuration, while fixing the actual transport to one direct numeric
// endpoint. Unsupported auth/protocol/net hooks and host/TLS fallbacks refuse
// before dispatch. No caller connection, dial result or retired bool is trusted.
// Secrets/configuration remain in memory and are never included in error text.
// This component preserves, but does not yet validate, server timeout settings.
// Activation requires bounded nonzero statement_timeout, lock_timeout and
// idle_in_transaction_session_timeout for the approved deployment profile.
// Cancellation cannot open an extra unadmitted CancelRequest socket; interrupted
// server work remains charged until the fixed observer proves actual retirement.
// A timeout or logical commit never supplies retirement/durable-disposition proof.
func NewApplicationSessionFactoryV1(config *pgx.ConnConfig, work *WorkAdmissionV1, profile ApplicationSessionProfileV1) (*ApplicationSessionFactoryV1, error) {
	if config == nil || work == nil || profile != ApplicationSessionDirectProfileV1 || config.ConnString() == "" || config.Host == "" || config.Database == "" || config.User == "" || config.Port == 0 || len(config.Fallbacks) != 0 {
		return nil, ErrApplicationSessionV1
	}
	canonical, err := pgx.ParseConfig(config.ConnString())
	if err != nil {
		return nil, ErrApplicationSessionV1
	}
	if config.AfterNetConnect != nil || config.AfterConnect != nil || config.ValidateConnect != nil || config.OAuthTokenProvider != nil || config.OnNotice != nil || config.OnNotification != nil ||
		!applicationSessionFunctionSameV1(config.OnPgError, canonical.OnPgError) ||
		!applicationSessionFunctionSameV1(config.DialFunc, canonical.DialFunc) || !applicationSessionFunctionSameV1(config.LookupFunc, canonical.LookupFunc) ||
		!applicationSessionFunctionSameV1(config.BuildFrontend, canonical.BuildFrontend) || !applicationSessionFunctionSameV1(config.BuildContextWatcherHandler, canonical.BuildContextWatcherHandler) {
		return nil, ErrApplicationSessionV1
	}
	if config.TLSConfig != nil && (config.TLSConfig.Time != nil || config.TLSConfig.Rand != nil || config.TLSConfig.VerifyConnection != nil || config.TLSConfig.VerifyPeerCertificate != nil || config.TLSConfig.GetCertificate != nil || config.TLSConfig.GetClientCertificate != nil || config.TLSConfig.GetConfigForClient != nil || config.TLSConfig.KeyLogWriter != nil || config.TLSConfig.ClientSessionCache != nil || config.TLSConfig.EncryptedClientHelloRejectionVerify != nil || config.TLSConfig.GetEncryptedClientHelloKeys != nil || config.TLSConfig.UnwrapSession != nil || config.TLSConfig.WrapSession != nil) {
		return nil, ErrApplicationSessionV1
	}
	state := &applicationSessionFactoryStateV1{config: config.Copy(), work: work, organisations: make(map[uuid.UUID]*applicationSessionOrganisationV1), sessions: make(map[*applicationOwnedSessionV1]struct{}), signerScopes: make(map[*applicationSignerScopeStateV1]struct{}), sendRecoveryScans: make(map[*applicationHTMLSendRecoveryScanStateV1]struct{}), htmlCatalogMaintenance: make(map[*applicationCatalogMaintenanceStateV1]struct{}), signerReaders: make(map[*ApplicationSignerReaderV1]struct{}), htmlAdmissions: make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1), htmlInputProducers: make(map[*applicationHTMLAuthoringInputStateV1]struct{}), htmlCanonicalConsumers: make(map[*applicationHTMLCanonicalModelConsumerV1]struct{})}
	// Execute fresh private canonical protocol functions, not a caller closure
	// whose code pointer alone cannot prove its captured state.
	state.config.OnPgError = canonical.OnPgError
	state.config.BuildFrontend = canonical.BuildFrontend
	state.config.BuildContextWatcherHandler = canonical.BuildContextWatcherHandler
	return &ApplicationSessionFactoryV1{state: state}, nil
}
func (f *ApplicationSessionFactoryV1) PendingV1() ApplicationSessionPendingV1 {
	if f == nil || f.state == nil {
		return ApplicationSessionPendingV1{}
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	out := ApplicationSessionPendingV1{Closing: p.closing, HTMLAdmissions: len(p.htmlAdmissions), HTMLInputProducers: len(p.htmlInputProducers), HTMLCanonicalConsumers: len(p.htmlCanonicalConsumers), SignerScopes: len(p.signerScopes), HTMLSendRecoveryScans: len(p.sendRecoveryScans), CatalogMaintenance: len(p.htmlCatalogMaintenance), SignerReaders: len(p.signerReaders)}
	for _, operation := range p.documentPackageOperations {
		if operation != nil {
			out.DocumentPackageOperations++
		}
	}
	for _, batch := range p.packageRecoveryBatches {
		if batch != nil {
			out.PackageSendRecoveryBatches++
		}
	}
	for _, accounting := range p.documentAIAccountings {
		if accounting != nil {
			out.DocumentAIAccountings++
		}
	}
	for _, member := range p.signerPackageMemberReads {
		if member != nil {
			out.SignerPackageMemberReads++
		}
	}
	for s := range p.sessions {
		s.mu.Lock()
		if s.grant != nil {
			out.WorkSessions++
		}
		if s.unknown && s.dialed && s.fence == nil {
			out.UnknownStarts++
		}
		s.mu.Unlock()
	}
	for _, org := range p.controlsV1Locked() {
		org.mu.Lock()
		s := org.observer
		org.mu.Unlock()
		if s != nil {
			s.mu.Lock()
			if s.grant != nil {
				out.ObserverSessions++
			}
			if s.unknown && s.dialed && s.fence == nil {
				out.UnknownStarts++
			}
			s.mu.Unlock()
		}
	}
	return out
}
func applicationSessionSignalV1(s *applicationOwnedSessionV1) {
	close(s.changed)
	s.changed = make(chan struct{})
}
func (f *ApplicationSessionFactoryV1) organisationV1(ctx context.Context, org uuid.UUID) (*applicationSessionOrganisationV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) {
		return nil, applicationSessionErrorV1(ctx, nil, nil)
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing {
		return nil, ErrApplicationSessionV1
	}
	o := p.organisations[org]
	if o == nil {
		if len(p.organisations) >= applicationSessionMaxOrganisationsV1 {
			return nil, ErrApplicationSessionV1
		}
		o = &applicationSessionOrganisationV1{factory: p, org: org, guard: make(chan struct{}, 1)}
		p.organisations[org] = o
	}
	return o, nil
}
func applicationSessionNewOwnerV1(o *applicationSessionOrganisationV1, doc uuid.UUID, observer bool) *applicationOwnedSessionV1 {
	return &applicationOwnedSessionV1{factory: o.factory, organisation: o, org: o.org, document: doc, observer: observer, changed: make(chan struct{})}
}

// Resolve the declared route under the actual caller deadline. The actual dial
// receives one numeric address, never a hostname that can hide Happy Eyeballs.
// Ambiguous DNS and unsupported multi-host/TLS profiles fail closed.
func applicationSessionEndpointV1(ctx context.Context, c *pgx.ConnConfig) (string, string, error) {
	if strings.HasPrefix(c.Host, "/") {
		return "unix", strings.TrimRight(c.Host, "/") + "/.s.PGSQL." + strconv.Itoa(int(c.Port)), nil
	}
	ip := net.ParseIP(c.Host)
	if ip == nil {
		values, err := (&net.Resolver{PreferGo: true}).LookupIPAddr(ctx, c.Host)
		if err != nil || ctx.Err() != nil || len(values) != 1 || values[0].Zone != "" {
			return "", "", applicationSessionStartErrorV1(ctx, nil, err, 1)
		}
		ip = values[0].IP
	}
	if ip == nil {
		return "", "", ErrApplicationSessionV1
	}
	return "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(c.Port))), nil
}
func applicationSessionConnectV1(ctx context.Context, s *applicationOwnedSessionV1) error {
	cfg := s.factory.config.Copy()
	network, address, err := applicationSessionEndpointV1(ctx, cfg)
	if err != nil {
		return err
	}
	if network == "tcp" {
		host, _, _ := net.SplitHostPort(address)
		cfg.LookupFunc = func(context.Context, string) ([]string, error) { return []string{host}, nil }
	}
	cfg.DialFunc = func(dialCtx context.Context, n, a string) (net.Conn, error) {
		s.mu.Lock()
		if s.dialed || s.closed || n != network || a != address {
			s.mu.Unlock()
			return nil, ErrApplicationSessionV1
		}
		s.dialed = true
		applicationSessionSignalV1(s)
		s.mu.Unlock()
		conn, err := (&net.Dialer{Timeout: cfg.ConnectTimeout, FallbackDelay: -1}).DialContext(dialCtx, network, address)
		s.mu.Lock()
		if conn != nil {
			s.socket = conn
		}
		closed := s.closed
		s.mu.Unlock()
		if closed && conn != nil {
			_ = conn.Close()
		}
		return conn, err
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()
	if err != nil {
		return applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, err, 2)
	}
	var identity applicationBackendIdentityV1
	rows, err := conn.Query(ctx, applicationBackendIdentitySQLV1)
	if err != nil {
		return applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, err, 3)
	}
	defer rows.Close()
	if !rows.Next() {
		err := rows.Err()
		if err == nil {
			err = pgx.ErrNoRows
		}
		return applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, err, 4)
	}
	err = rows.Scan(&identity.pid, &identity.backendStart, &identity.databaseOID, &identity.userOID, &identity.address, &identity.port, &identity.postmasterStart)
	if err != nil || !applicationIdentityValidV1(identity) || uint32(identity.pid) != conn.PgConn().PID() {
		observed := ApplicationSessionStartObservationV1{Phase: 5, ErrorClass: signerReadFailureClassV1(err), ContextState: signerReadFailureContextV1(ctx)}
		rows.Close()
		failure := applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, errors.Join(err, rows.Err())).(*applicationSessionFailureV1)
		failure.start = observed
		return failure
	}
	// The real backend has supplied its complete validated identity. Preserve
	// that physical cleanup evidence BEFORE trailing protocol drain or caller
	// cancellation can fail. This never permits further startup on an error,
	// and the grant still requires actual client and observer retirement proof.
	fence := &applicationSessionFenceV1{clientDone: conn.PgConn().CleanupDone(), identity: identity}
	if !s.observer {
		fence.observe = s.organisation.observeV1
	}
	s.mu.Lock()
	s.fence = fence
	s.mu.Unlock()
	rows.Close()
	if err := rows.Err(); err != nil || ctx.Err() != nil {
		return applicationSessionStartErrorV1(ctx, ErrApplicationSessionUnknownV1, err, 6)
	}
	return nil
}
func applicationSessionStartV1(ctx context.Context, s *applicationOwnedSessionV1) error {
	return applicationSessionStartForSignerV1(ctx, s, nil)
}
func applicationSessionStartForSignerV1(ctx context.Context, s *applicationOwnedSessionV1, reader *ApplicationSignerReaderV1) error {
	return applicationSessionStartForSignerScopeV1(ctx, s, reader, nil)
}
func applicationSessionStartForSignerScopeV1(ctx context.Context, s *applicationOwnedSessionV1, reader *ApplicationSignerReaderV1, scope *applicationSignerScopeStateV1) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrApplicationSessionV1
	}
	var release func()
	var err error
	if s.organisation != nil && s.organisation.processControl {
		if scope != nil {
			var denial workguard.AdmissionDenialV1
			release, denial, err = s.factory.work.signerProcessSQLWithDenialV1(ctx)
			if err != nil {
				scope.recordProcessSQLDenialV1(s, denial)
			}
		} else {
			release, err = s.factory.work.signerProcessSQLV1(ctx)
		}
	} else if reader != nil {
		// The frame is already owned by the real reader's process scope.
		grant, denial, acquireErr := s.factory.work.coordinator.TryAcquireWithDenialV1(ctx, s.org, workguard.VectorV1{SQLSessions: 1})
		err = acquireErr
		if err != nil {
			reader.recordSQLDenialV1(s, denial)
		} else {
			release = grant.Close
		}
	} else {
		release, err = s.factory.work.SQLSessionV1(ctx, s.org)
	}
	if err != nil || release == nil {
		s.mu.Lock()
		s.closed = true
		s.retired = true
		applicationSessionSignalV1(s)
		s.mu.Unlock()
		return applicationSessionErrorV1(ctx, nil, err)
	}
	ownCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		release()
		return ErrApplicationSessionV1
	}
	s.grant = release
	s.creating = true
	s.active = 1
	s.cancel = cancel
	s.mu.Unlock()
	err = applicationSessionConnectV1(ownCtx, s)
	cancel()
	s.mu.Lock()
	s.active = 0
	s.creating = false
	s.cancel = nil
	if err != nil {
		s.unknown = true
	}
	zeroDispatch := !s.dialed
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	if err != nil && zeroDispatch {
		s.mu.Lock()
		s.grant = nil
		s.retired = true
		s.closed = true
		s.mu.Unlock()
		release()
	}
	return err
}
func (o *applicationSessionOrganisationV1) ensureObserverV1(ctx context.Context) error {
	// Join only the actual fixed observer activity before inspecting its idle
	// connection. A concurrent retirement probe is normal work, not a broken
	// observer, and no second probe/observer is created by this wait.
	if !applicationContextV1(ctx) || o == nil || o.guard == nil {
		return ErrApplicationSessionV1
	}
	select {
	case o.guard <- struct{}{}:
	case <-ctx.Done():
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	defer func() { <-o.guard }()
	// Register the control owner under the same factory gate that closes dispatch.
	// Factory.Close must see every attempt before it can observe no pending owner.
	p := o.factory
	p.mu.Lock()
	if p.closing {
		p.mu.Unlock()
		return ErrApplicationSessionV1
	}
	o.mu.Lock()
	if o.initializing {
		o.mu.Unlock()
		p.mu.Unlock()
		return ErrApplicationSessionV1
	}
	if o.observer != nil {
		s := o.observer
		o.mu.Unlock()
		p.mu.Unlock()
		s.mu.Lock()
		if s.active != 0 || s.creating {
			s.mu.Unlock()
			return ErrApplicationSessionV1
		}
		ready := !s.closed && !s.unknown && s.conn != nil && !s.conn.IsClosed() && s.conn.PgConn().TxStatus() == 'I' && s.fence != nil
		if !ready {
			s.unknown = true
		}
		s.mu.Unlock()
		if ready {
			return nil
		}
		return ErrApplicationSessionUnknownV1
	}
	o.initializing = true
	s := applicationSessionNewOwnerV1(o, uuid.Nil, true)
	o.observer = s
	o.mu.Unlock()
	p.mu.Unlock()
	err := applicationSessionStartV1(ctx, s)
	s.mu.Lock()
	zero := s.retired && !s.dialed && s.grant == nil
	s.mu.Unlock()
	o.mu.Lock()
	o.initializing = false
	if err != nil && zero && o.observer == s {
		o.observer = nil
	}
	o.mu.Unlock()
	return err
}
func (o *applicationSessionOrganisationV1) observeV1(ctx context.Context, old applicationBackendIdentityV1) (bool, error) {
	if !applicationContextV1(ctx) {
		return false, applicationSessionErrorV1(ctx, nil, nil)
	}
	select {
	case o.guard <- struct{}{}:
	case <-ctx.Done():
		return false, applicationSessionErrorV1(ctx, nil, nil)
	}
	defer func() { <-o.guard }()
	probeCtx, cancel, err := applicationObserverProbeContextV1(ctx)
	if err != nil {
		return false, err
	}
	defer cancel()
	o.mu.Lock()
	s := o.observer
	o.mu.Unlock()
	if s == nil {
		return false, ErrApplicationSessionUnknownV1
	}
	s.mu.Lock()
	if s.conn == nil || s.fence == nil || s.closed || s.unknown || s.active != 0 {
		s.mu.Unlock()
		return false, ErrApplicationSessionUnknownV1
	}
	conn := s.conn
	s.active++
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.active--
		s.cancel = nil
		applicationSessionSignalV1(s)
		s.mu.Unlock()
	}()
	if conn.PgConn().TxStatus() != 'I' || !applicationObserverConfigSameV1(conn.Config(), s.factory.config) {
		return false, ErrApplicationSessionUnknownV1
	}
	if ctx.Err() != nil {
		return false, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
	}
	if _, err := conn.Exec(probeCtx, "SELECT pg_catalog.pg_stat_clear_snapshot()"); err != nil {
		return false, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, err)
	}
	var current applicationBackendIdentityV1
	var pid *int32
	var started *time.Time
	var database, user *int64
	err = conn.QueryRow(probeCtx, applicationBackendObservationSQLV1, old.pid).Scan(&current.pid, &current.backendStart, &current.databaseOID, &current.userOID, &current.address, &current.port, &current.postmasterStart, &pid, &started, &database, &user)
	if err != nil || probeCtx.Err() != nil || ctx.Err() != nil {
		return false, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, err)
	}
	s.mu.Lock()
	expected := s.fence.identity
	s.mu.Unlock()
	if !applicationServerSameV1(expected, current) {
		return false, ErrApplicationSessionUnknownV1
	}
	return applicationObservedRetiredV1(ctx, old, current, pid, started, database, user)
}

// OpenV1 returns the retained session on uncertain work creation errors. The
// factory also owns it until fixed reconciliation, even if the caller drops its
// handle. Unknown observer startup remains in the factory's bounded org registry.
func (f *ApplicationSessionFactoryV1) OpenV1(ctx context.Context, org, document uuid.UUID) (*ApplicationSessionV1, error) {
	return f.openV1(ctx, org, document, nil)
}
func (f *ApplicationSessionFactoryV1) openV1(ctx context.Context, org, document uuid.UUID, reader *ApplicationSignerReaderV1) (*ApplicationSessionV1, error) {
	return f.openProfileV1(ctx, org, document, reader, false)
}

// Only the fixed document-AI accounting constructor uses the private
// autocommit profile. No Conn/DBTX/caller SQL is exposed by that owner.
func (f *ApplicationSessionFactoryV1) openProfileV1(ctx context.Context, org, document uuid.UUID, reader *ApplicationSignerReaderV1, accounting bool) (*ApplicationSessionV1, error) {
	if document == uuid.Nil {
		return nil, ErrApplicationSessionV1
	}
	o, err := f.organisationV1(ctx, org)
	if err != nil {
		return nil, err
	}
	if err = o.ensureObserverV1(ctx); err != nil {
		// The factory retains the control observer and its unresolved grant.
		// A failed work constructor must never hand control cleanup authority to
		// a request owner that expects an ordinary work session.
		return nil, err
	}
	p := f.state
	var s *applicationOwnedSessionV1
	for {
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			return nil, ErrApplicationSessionV1
		}
		var joining *applicationOwnedSessionV1
		// A true unknown/unjoined quarantine still forbids replacement. Only a
		// genuine already-running CloseV1 continuation may be joined before this
		// fixed pre-dispatch admission retries the existing quarantine predicate.
		for old := range p.sessions {
			old.mu.Lock()
			blocked := old.org == org && (old.closed || old.unknown) && !old.retired
			canJoin := old.org == org && old.closed && old.retiring > 0 && (!old.unknown || old.retired)
			old.mu.Unlock()
			if blocked && !canJoin {
				p.mu.Unlock()
				return nil, ErrApplicationSessionUnknownV1
			}
			if canJoin {
				joining = old
			}
		}
		if joining != nil {
			p.mu.Unlock()
			if err = applicationSessionWaitRetiringV1(ctx, joining); err != nil {
				return nil, err
			}
			continue
		}
		if len(p.sessions) >= applicationSessionMaxWorkV1 {
			p.mu.Unlock()
			return nil, ErrApplicationSessionV1
		}
		s = applicationSessionNewOwnerV1(o, document, false)
		p.sessions[s] = struct{}{}
		p.mu.Unlock()
		break
	}
	handle := &ApplicationSessionV1{state: s}
	if reader != nil && !reader.bindDiagnosticSessionV1(f, handle) {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		return handle, errors.Join(ErrSignerReadV1, handle.CloseV1(cleanup))
	}
	if err = applicationSessionStartForSignerV1(ctx, s, reader); err != nil {
		s.mu.Lock()
		retired := s.retired
		s.mu.Unlock()
		if retired {
			p.mu.Lock()
			delete(p.sessions, s)
			p.mu.Unlock()
		}
		return handle, err
	}
	if accounting {
		return handle, nil
	}
	return applicationSessionBeginOwnedV1(ctx, handle)
}

// A wait is not retirement evidence. Only the original actual physical fence
// may set retired. Unknown state, an ended close attempt, or caller deadline
// returns unavailable without allocating/dialing a replacement session.
func applicationSessionWaitRetiringV1(ctx context.Context, s *applicationOwnedSessionV1) error {
	if s == nil || !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
	}
	for {
		s.mu.Lock()
		if s.retired && s.retiring == 0 {
			s.mu.Unlock()
			return nil
		}
		if (s.unknown && !s.retired) || s.retiring == 0 {
			s.mu.Unlock()
			return ErrApplicationSessionUnknownV1
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
		}
	}
}

func (h *ApplicationSessionV1) WorkStartedV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dialed && !s.observer
}
func (h *ApplicationSessionV1) RetiredV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retired
}
func (h *ApplicationSessionV1) CommitUnknownV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitUnknown
}

// WithTxV1 exposes only the fixed owned DBTX, never raw pgx.Tx/Conn/Commit.
// Every statement and Rows/Scan lifecycle is tracked even when an admission
// consumer subsequently calls its adapter outside this callback.
func (h *ApplicationSessionV1) WithTxV1(ctx context.Context, fn func(context.Context, generated.DBTX) error) error {
	if h == nil || h.state == nil || fn == nil || !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.unknown || s.ended || s.creating || s.callbackActive || s.sqlActive || s.tx == nil {
		s.mu.Unlock()
		return ErrApplicationSessionV1
	}
	s.active++
	s.callbackActive = true
	ownCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.active--
		s.callbackActive = false
		s.cancel = nil
		applicationSessionSignalV1(s)
		s.mu.Unlock()
	}()
	return fn(context.WithValue(ownCtx, applicationSessionCallbackKeyV1{}, s), &applicationOwnedDBTXV1{session: s})
}
func (h *ApplicationSessionV1) NewAdmissionV1(ctx context.Context) (*ApplicationAdmissionV1, error) {
	var a *ApplicationAdmissionV1
	err := h.WithTxV1(ctx, func(_ context.Context, db generated.DBTX) error {
		// One admission/loan registry belongs to this physical owner. Install inside
		// the tracked callback so repeated/copied calls cannot replace live loans.
		s := h.state
		s.mu.Lock()
		existing := s.admission
		s.mu.Unlock()
		if existing != nil {
			if !existing.valid() || existing.fence != s.fence {
				return ErrApplicationSessionV1
			}
			existing.mu.Lock()
			closed := existing.closed
			existing.mu.Unlock()
			if closed {
				return ErrApplicationSessionV1
			}
			a = existing
			return nil
		}
		var err error
		a, err = newApplicationAdmissionQueriesWithFenceV1(db, s.factory.work.ApplicationV1, s.fence)
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.admission = a
		s.mu.Unlock()
		return nil
	})
	if err == nil && ctx.Err() != nil {
		return nil, applicationSessionErrorV1(ctx, nil, nil)
	}
	return a, err
}
func applicationSessionSQLBorrowV1(ctx context.Context, s *applicationOwnedSessionV1, withinCallback bool) (context.Context, pgx.Tx, func(), error) {
	if s == nil || !applicationContextV1(ctx) {
		return nil, nil, nil, applicationSessionErrorV1(ctx, nil, nil)
	}
	s.mu.Lock()
	if s.closed || s.unknown || s.ended || s.creating || s.sqlActive || s.tx == nil || (s.callbackActive && (!withinCallback || ctx.Value(applicationSessionCallbackKeyV1{}) != s)) {
		s.mu.Unlock()
		return nil, nil, nil, ErrApplicationSessionV1
	}
	s.active++
	s.sqlActive = true
	owned, cancel := context.WithCancel(ctx)
	s.cancelSQL = cancel
	tx := s.tx
	s.mu.Unlock()
	var once sync.Once
	done := func() {
		once.Do(func() {
			cancel()
			s.mu.Lock()
			s.active--
			s.sqlActive = false
			s.cancelSQL = nil
			applicationSessionSignalV1(s)
			s.mu.Unlock()
		})
	}
	return owned, tx, done, nil
}
func (h *ApplicationSessionV1) CommitV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return ErrApplicationSessionV1
	}
	s := h.state
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, s, false)
	if err != nil {
		return err
	}
	defer done()
	s.mu.Lock()
	if s.commitAttempted {
		s.mu.Unlock()
		return ErrApplicationSessionCommitUnknownV1
	}
	s.commitAttempted = true
	s.mu.Unlock()
	err = tx.Commit(owned)
	s.mu.Lock()
	s.ended = true
	s.commitUnknown = err != nil || owned.Err() != nil
	unknown := s.commitUnknown
	s.mu.Unlock()
	if unknown {
		return applicationSessionErrorV1(ctx, ErrApplicationSessionCommitUnknownV1, err)
	}
	return nil
}
func (h *ApplicationSessionV1) RollbackV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	s := h.state
	s.mu.Lock()
	doneAlready := s.ended || s.commitAttempted
	s.mu.Unlock()
	if doneAlready {
		return nil
	}
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, s, false)
	if err != nil {
		return err
	}
	defer done()
	err = tx.Rollback(owned)
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
	if err != nil {
		return applicationSessionErrorV1(ctx, nil, err)
	}
	return nil
}

func applicationSessionWaitCallsV1(ctx context.Context, s *applicationOwnedSessionV1) error {
	for {
		s.mu.Lock()
		n, changed := s.active, s.changed
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
		}
	}
}
func (h *ApplicationSessionV1) closeClientV1(ctx context.Context) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	s := h.state
	s.mu.Lock()
	s.closed = true
	cancel, cancelSQL, socket := s.cancel, s.cancelSQL, s.socket
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if cancelSQL != nil {
		cancelSQL()
	}
	if socket != nil {
		_ = socket.Close()
	}
	if err := applicationSessionWaitCallsV1(ctx, s); err != nil {
		return err
	}
	// pgx.Close mutates private protocol state: copied handles must join the one
	// actual close owner rather than dispatch concurrent pgx.Close calls.
	for {
		s.mu.Lock()
		if !s.closingClient {
			s.closingClient = true
			conn := s.conn
			s.mu.Unlock()
			defer func() { s.mu.Lock(); s.closingClient = false; applicationSessionSignalV1(s); s.mu.Unlock() }()
			if conn == nil {
				return ErrApplicationSessionUnknownV1
			}
			closeErr := conn.Close(ctx)
			select {
			case <-conn.PgConn().CleanupDone():
				if closeErr != nil {
					return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, closeErr)
				}
				return nil
			case <-ctx.Done():
				return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
			}
		}
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
		}
	}
}
func (h *ApplicationSessionV1) ReconcileCleanupV1(ctx context.Context) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	s := h.state
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return nil
	}
	if s.closed && s.active == 0 && !s.creating && !s.dialed && !s.observer {
		release := s.grant
		s.grant = nil
		s.retired = true
		applicationSessionSignalV1(s)
		s.mu.Unlock()
		if release != nil {
			release()
		}
		s.factory.mu.Lock()
		delete(s.factory.sessions, s)
		s.factory.mu.Unlock()
		return nil
	}
	fence := s.fence
	eligible := s.closed && s.active == 0 && !s.creating && fence != nil && !s.observer
	s.mu.Unlock()
	if !eligible {
		return ErrApplicationSessionUnknownV1
	}
	retired, err := fence.proveV1(ctx)
	if err != nil || !retired {
		return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, err)
	}
	s.mu.Lock()
	if s.releasing {
		s.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	release := s.grant
	s.releasing = true
	s.mu.Unlock()
	if release != nil {
		release()
	}
	s.mu.Lock()
	s.grant = nil
	s.retired = true
	s.releasing = false
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	s.factory.mu.Lock()
	delete(s.factory.sessions, s)
	s.factory.mu.Unlock()
	return nil
}
func (h *ApplicationSessionV1) CloseV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	if !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	if h.RetiredV1() {
		return nil
	}
	s := h.state
	s.mu.Lock()
	s.retiring++
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.retiring--; applicationSessionSignalV1(s); s.mu.Unlock() }()
	_ = h.closeClientV1(ctx)
	timer := time.NewTicker(50 * time.Millisecond)
	defer timer.Stop()
	for {
		if err := h.ReconcileCleanupV1(ctx); err == nil {
			return nil
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			return applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
		}
	}
}
func (f *ApplicationSessionFactoryV1) ReconcileCleanupV1(ctx context.Context) error {
	if f == nil || f.state == nil || !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	p := f.state
	p.mu.Lock()
	list := make([]*applicationOwnedSessionV1, 0, len(p.sessions))
	for s := range p.sessions {
		list = append(list, s)
	}
	p.mu.Unlock()
	var out error
	for _, s := range list {
		s.mu.Lock()
		closed := s.closed
		joined := s.active == 0 && !s.creating
		s.mu.Unlock()
		if closed {
			handle := &ApplicationSessionV1{state: s}
			if joined {
				_ = handle.closeClientV1(ctx)
			}
			if err := handle.ReconcileCleanupV1(ctx); err != nil {
				out = errors.Join(out, err)
			}
		}
	}
	// Retain native HTML parent/DB loans after physical session handles end.
	// Only the same actual admission and original fence may release them.
	p.mu.Lock()
	html := make([]*applicationHTMLAdmissionRegistrationV1, 0, len(p.htmlAdmissions))
	for _, registration := range p.htmlAdmissions {
		html = append(html, registration)
	}
	p.mu.Unlock()
	for _, registration := range html {
		a := registration.admission
		_, err := f.reconcileHTMLAdmissionRegistrationV1(ctx, a, registration)
		if err != nil {
			out = errors.Join(out, err)
		}
	}
	if err := f.reconcileSignerPackageMemberReadsV1(ctx); err != nil {
		out = errors.Join(out, err)
	}
	if err := f.reconcileSignerReadersV1(ctx); err != nil {
		out = errors.Join(out, err)
	}
	if err := f.reconcileSignerScopesV1(ctx); err != nil {
		out = errors.Join(out, err)
	}
	f.reconcileHTMLSendRecoveryScansV1()
	out = errors.Join(out, f.reconcilePackageSendRecoveryBatchesV1(ctx))
	f.reconcileCatalogMaintenanceV1()
	out = errors.Join(out, f.reconcileDocumentPackageOperationsV1(ctx))
	out = errors.Join(out, f.reconcileDocumentAIAccountingsV1(ctx))
	return out
}

// The global sweep and an actual operation use the same identity-safe
// registration retirement. Only this admission's real consumers/fence may
// establish pending0; a newer registration cannot be removed by an old close.
func (f *ApplicationSessionFactoryV1) reconcileHTMLAdmissionRegistrationV1(ctx context.Context, a *ApplicationAdmissionV1, registration *applicationHTMLAdmissionRegistrationV1) (int, error) {
	if f == nil || f.state == nil || a == nil || (registration != nil && registration.admission != a) {
		return 0, ErrApplicationSessionUnknownV1
	}
	pending, err := a.ReconcileCleanupV1(ctx)
	if err == nil && pending == 0 && registration != nil {
		p := f.state
		p.mu.Lock()
		if p.htmlAdmissions[a] == registration {
			delete(p.htmlAdmissions, a)
		}
		p.mu.Unlock()
	}
	return pending, err
}

// CloseV1 stops work, closes/join-reconciles every registered work session, then
// closes the private observers. Their final grant remains charged: the only
// observer cannot prove itself gone. Return pending ownership; no last-observer
// bool, grace period, socket Close or process exit is converted to server proof.
func (f *ApplicationSessionFactoryV1) CloseV1(ctx context.Context) error {
	if f == nil || f.state == nil {
		return nil
	}
	if !applicationContextV1(ctx) {
		return applicationSessionErrorV1(ctx, nil, nil)
	}
	p := f.state
	p.mu.Lock()
	p.closing = true
	packageOperations := p.documentPackageOperations
	packageRecoveryBatches := p.packageRecoveryBatches
	packageMemberReads := p.signerPackageMemberReads
	accountings := p.documentAIAccountings
	list := make([]*applicationOwnedSessionV1, 0, len(p.sessions))
	for s := range p.sessions {
		list = append(list, s)
	}
	p.mu.Unlock()
	// Cancel every registered producer before waiting for any one cleanup.
	for _, accounting := range accountings {
		if accounting != nil {
			(&ApplicationDocumentAIAccountingV1{state: accounting}).CloseConsumerV1()
		}
	}
	for _, member := range packageMemberReads {
		if member != nil {
			(&ApplicationSignerPackageMemberReadV1{state: member}).CloseConsumerV1()
		}
	}
	for _, batch := range packageRecoveryBatches {
		if batch != nil {
			(&ApplicationPackageSendRecoveryBatchV1{state: batch}).CloseConsumerV1()
		}
	}
	for _, operation := range packageOperations {
		if operation != nil {
			operation.cancel()
		}
	}
	var out error
	for _, member := range packageMemberReads {
		if member != nil {
			out = errors.Join(out, member.reconcileV1(ctx))
		}
	}
	for _, operation := range packageOperations {
		if operation != nil {
			out = errors.Join(out, (&ApplicationDocumentPackageOperationV1{state: operation}).CloseV1(ctx))
		}
	}
	for _, s := range list {
		if err := (&ApplicationSessionV1{state: s}).CloseV1(ctx); err != nil {
			out = errors.Join(out, err)
		}
	}
	if out != nil {
		return out
	}
	if err := f.ReconcileCleanupV1(ctx); err != nil {
		return err
	}
	p.mu.Lock()
	// Actual HTTP/canonical consumers retire themselves only after their route
	// returns. Shutdown fences new work without refunding executing producers.
	htmlPending := len(p.htmlCatalogMaintenance) + len(p.sendRecoveryScans) + len(p.htmlAdmissions) + len(p.signerScopes) + len(p.signerReaders) + len(p.htmlInputProducers) + len(p.htmlCanonicalConsumers)
	for _, operation := range p.documentPackageOperations {
		if operation != nil {
			htmlPending++
		}
	}
	for _, batch := range p.packageRecoveryBatches {
		if batch != nil {
			htmlPending++
		}
	}
	for _, member := range p.signerPackageMemberReads {
		if member != nil {
			htmlPending++
		}
	}
	for _, accounting := range p.documentAIAccountings {
		if accounting != nil {
			htmlPending++
		}
	}
	p.mu.Unlock()
	if htmlPending != 0 {
		return ErrApplicationSessionUnknownV1
	}
	p.mu.Lock()
	orgs := p.controlsV1Locked()
	p.mu.Unlock()
	for _, o := range orgs {
		o.mu.Lock()
		s := o.observer
		o.mu.Unlock()
		if s != nil {
			_ = (&ApplicationSessionV1{state: s}).closeClientV1(ctx)
			s.mu.Lock()
			pending := s.grant != nil
			s.mu.Unlock()
			if pending {
				out = errors.Join(out, ErrApplicationSessionUnknownV1)
			}
		}
	}
	return out
}

// Only this fixed narrow wrapper reaches the private actual pgx transaction.
// It grants no arbitrary raw connection, transaction completion or fake proof.
type applicationOwnedDBTXV1 struct{ session *applicationOwnedSessionV1 }

func (d *applicationOwnedDBTXV1) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, d.session, true)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	defer done()
	tag, err := tx.Exec(owned, sql, args...)
	if err != nil {
		return tag, applicationSessionErrorV1(ctx, nil, err)
	}
	return tag, nil
}
func (d *applicationOwnedDBTXV1) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return &applicationOwnedRowV1{db: d, ctx: ctx, sql: sql, args: args}
}

type applicationOwnedRowV1 struct {
	db      *applicationOwnedDBTXV1
	ctx     context.Context
	sql     string
	args    []any
	mu      sync.Mutex
	scanned bool
}

func (r *applicationOwnedRowV1) Scan(dest ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.scanned {
		return ErrApplicationSessionV1
	}
	r.scanned = true
	owned, tx, done, err := applicationSessionSQLBorrowV1(r.ctx, r.db.session, true)
	if err != nil {
		return err
	}
	defer done()
	writePhase := applicationInternalWriteStatementPhaseV1(r.sql)
	err = tx.QueryRow(owned, r.sql, r.args...).Scan(dest...)
	r.args = nil
	r.sql = ""
	if err != nil {
		return applicationInternalWriteErrorV1(r.ctx, writePhase, applicationSessionErrorV1(r.ctx, nil, err))
	}
	return nil
}
func (d *applicationOwnedDBTXV1) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	owned, tx, done, err := applicationSessionSQLBorrowV1(ctx, d.session, true)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(owned, sql, args...)
	if err != nil {
		if rows != nil {
			rows.Close()
		}
		done()
		return nil, applicationSessionErrorV1(ctx, nil, err)
	}
	return &applicationOwnedRowsV1{state: &applicationOwnedRowsStateV1{rows: rows, done: done, ctx: ctx}}, nil
}

// Like pgx.Rows, methods must be consumed serially. Session Close independently
// cancels/unblocks actual I/O and cannot credit this loan until its Rows closes.
// Copies of the narrow handle share the one Rows/loan completion owner.
type applicationOwnedRowsV1 struct{ state *applicationOwnedRowsStateV1 }
type applicationOwnedRowsStateV1 struct {
	rows pgx.Rows
	done func()
	ctx  context.Context
	once sync.Once
}

func (r *applicationOwnedRowsV1) Close() {
	r.state.once.Do(func() { r.state.rows.Close(); r.state.done() })
}
func (r *applicationOwnedRowsV1) Err() error {
	if err := r.state.rows.Err(); err != nil {
		return applicationSessionErrorV1(r.state.ctx, nil, err)
	}
	return nil
}
func (r *applicationOwnedRowsV1) CommandTag() pgconn.CommandTag { return r.state.rows.CommandTag() }
func (r *applicationOwnedRowsV1) FieldDescriptions() []pgconn.FieldDescription {
	return r.state.rows.FieldDescriptions()
}
func (r *applicationOwnedRowsV1) Next() bool {
	next := r.state.rows.Next()
	if !next {
		r.Close()
	}
	return next
}
func (r *applicationOwnedRowsV1) Scan(dest ...any) error {
	if err := r.state.rows.Scan(dest...); err != nil {
		return applicationSessionErrorV1(r.state.ctx, nil, err)
	}
	return nil
}
func (r *applicationOwnedRowsV1) Values() ([]any, error) {
	values, err := r.state.rows.Values()
	if err != nil {
		return nil, applicationSessionErrorV1(r.state.ctx, nil, err)
	}
	return values, nil
}
func (r *applicationOwnedRowsV1) RawValues() [][]byte { return r.state.rows.RawValues() }
func (r *applicationOwnedRowsV1) Conn() *pgx.Conn     { return nil }

var _ generated.DBTX = (*applicationOwnedDBTXV1)(nil)
var _ pgx.Rows = (*applicationOwnedRowsV1)(nil)
