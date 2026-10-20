//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgconn"
)

// This sink retains one actual log consumer, not SQL/retirement authority.
// Test labels exercise formatting only; the original browser proves HTTP phase.
type ownedSignerDiagnosticSinkV1 struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
	values  [27]int64
	count   int
	valid   bool
}

func (*ownedSignerDiagnosticSinkV1) Enabled(context.Context, slog.Level) bool { return true }
func (h *ownedSignerDiagnosticSinkV1) Handle(ctx context.Context, r slog.Record) error {
	if r.Message != "owned signer read refused" {
		return nil
	}
	h.once.Do(func() {
		keys := [...]string{"route", "operation", "phase", "atomic_decision", "reason", "dimension", "requested_sql", "global_sql_before", "org_sql_before", "global_sql_limit", "org_sql_limit", "global_grants_before", "org_grants_before", "global_grant_limit", "org_grant_limit", "model_step", "model_outcome", "requested_resource", "global_resource_before", "org_resource_before", "global_resource_limit", "org_resource_limit", "model_error_class", "model_context_state", "session_start_phase", "session_start_error_class", "session_start_context_state"}
		h.valid = true
		r.Attrs(func(a slog.Attr) bool {
			n := h.count
			h.count++
			if n >= len(keys) || a.Key != keys[n] {
				h.valid = false
				return true
			}
			switch a.Value.Kind() {
			case slog.KindInt64:
				h.values[n] = a.Value.Int64()
			case slog.KindBool:
				if a.Value.Bool() {
					h.values[n] = 1
				}
			default:
				h.valid = false
			}
			return true
		})
		close(h.started)
		select {
		case <-h.release:
		case <-ctx.Done():
		}
	})
	return nil
}
func (h *ownedSignerDiagnosticSinkV1) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *ownedSignerDiagnosticSinkV1) WithGroup(string) slog.Handler      { return h }

func TestOwnedSignerSQLDenialAndDiagnosticLastUseE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	_, parties := q.createSentV1(t)
	// Start the actual process observer once and close this real lookup.
	rc := q.lookupV1(t, parties[0].Token)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	factory := q.runtime.SessionsV1()
	scope, err := factory.ProbeSignerScopeV1(f.ctx, auth.HashMagicToken(parties[0].Token))
	var readers []*pdfadmission.ApplicationSignerReaderV1
	var refused *pdfadmission.ApplicationSignerReaderV1
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	done := make(chan struct{})
	launched := false
	previous := slog.Default()
	// Every fatal path releases the real synchronous handler before reader close.
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(sink.release) })
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if launched {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("actual log call did not join")
			}
		}
		slog.SetDefault(previous)
		for _, r := range readers {
			if err := r.CloseV1(cleanup); err != nil {
				t.Error(err)
			}
		}
		if refused != nil {
			if err := refused.CloseV1(cleanup); err != nil {
				t.Error(err)
			}
		}
		if scope != nil {
			scope.CloseConsumerV1()
		}
		if err := factory.ReconcileCleanupV1(cleanup); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		r, openErr := factory.NewSignerReaderV1(f.ctx, scope, pdfadmission.SignerReadActiveV1)
		if r != nil {
			readers = append(readers, r)
		}
		if openErr != nil {
			t.Fatal("actual capacity-holder reader did not open", openErr)
		}
	}
	refused, err = factory.NewSignerReaderV1(f.ctx, scope, pdfadmission.SignerReadActiveV1)
	if refused == nil || !errors.Is(err, pdfadmission.ErrApplicationSessionV1) || !errors.Is(err, workguard.ErrUnavailableV1) {
		t.Fatal("actual fourth native reader did not refuse SQL admission", err)
	}
	slog.SetDefault(slog.New(sink))
	// Exercise mixed/unknown labels on this actual registered refusal owner,
	// before its one-log latch is used. A cancelled LOG context prevents a
	// broken guard from blocking the negative observation; it cancels no SQL.
	negativeLog, stopNegativeLog := context.WithCancel(f.ctx)
	stopNegativeLog()
	for _, invalid := range []struct {
		route pdfadmission.SignerReadDiagnosticRouteV1
		op    pdfadmission.SignerReadDiagnosticOperationV1
		phase pdfadmission.SignerReadDiagnosticPhaseV1
	}{
		{pdfadmission.SignerReadDiagnosticOtherV1, pdfadmission.SignerReadDiagnosticLookupV1, pdfadmission.SignerReadDiagnosticOpenV1},
		{pdfadmission.SignerReadDiagnosticFieldsV1, pdfadmission.SignerReadDiagnosticViewMutationV1, pdfadmission.SignerReadDiagnosticViewMutationPhaseV1},
		{pdfadmission.SignerReadDiagnosticViewV1, pdfadmission.SignerReadDiagnosticViewMutationV1, pdfadmission.SignerReadDiagnosticOpenV1},
		{pdfadmission.SignerReadDiagnosticViewV1, pdfadmission.SignerReadDiagnosticLookupV1, pdfadmission.SignerReadDiagnosticViewMutationPhaseV1},
		{pdfadmission.SignerReadDiagnosticPDFV1, pdfadmission.SignerReadDiagnosticRecheckV1, pdfadmission.SignerReadDiagnosticViewMutationPhaseV1},
		{255, pdfadmission.SignerReadDiagnosticLookupV1, pdfadmission.SignerReadDiagnosticOpenV1},
		{pdfadmission.SignerReadDiagnosticViewV1, 255, pdfadmission.SignerReadDiagnosticViewMutationPhaseV1},
		{pdfadmission.SignerReadDiagnosticViewV1, pdfadmission.SignerReadDiagnosticLookupV1, 255},
	} {
		refused.LogRefusalV1(negativeLog, invalid.route, invalid.op, invalid.phase)
	}
	if sink.count != 0 {
		t.Fatal("mixed/unknown labels consumed genuine owner's diagnostic latch")
	}
	launched = true
	go func() {
		defer close(done)
		refused.LogRefusalV1(f.ctx, pdfadmission.SignerReadDiagnosticFieldsV1, pdfadmission.SignerReadDiagnosticLookupV1, pdfadmission.SignerReadDiagnosticOpenV1)
	}()
	select {
	case <-sink.started:
	case <-f.ctx.Done():
		t.Fatal("actual denial log never started")
	}
	// All original twenty-two facts plus two closed cause/context facts are copied into test-owned
	// storage. No native log Record, body, ID or error is retained by this sink.
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 16 || sink.values[23] != 2 || sink.values[0] != 1 || sink.values[1] != 1 || sink.values[2] != 1 || sink.values[3] != 1 || sink.values[4] != int64(workguard.AdmissionOrganisationResourceV1) || sink.values[5] != int64(workguard.AdmissionSQLSessionsV1) || sink.values[6] != 1 || sink.values[7] != 5 || sink.values[8] != 4 || sink.values[9] != 8 || sink.values[10] != 4 || sink.values[15] != 0 || sink.values[16] != 0 || sink.values[17] != 1 || sink.values[18] != 5 || sink.values[19] != 4 || sink.values[20] != 8 || sink.values[21] != 4 {
		t.Fatal("actual atomic SQL denial differs from original allocation", sink.count, sink.valid, sink.values)
	}
	// End all other real reader consumers/SQL, leaving only the actual log frame.
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	for _, r := range readers {
		if err := r.CloseV1(cleanup); err != nil {
			stop()
			t.Fatal(err)
		}
	}
	readers = nil
	scope.CloseConsumerV1()
	if err := refused.CloseV1(cleanup); !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
		stop()
		t.Fatal("close credited an active diagnostic consumer", err)
	}
	stop()
	pending := factory.PendingV1()
	before := q.snapshotV1(t)
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 || pending.SignerReaders != 1 || pending.SignerScopes != 1 || before.Global.SQLSessions != 2 || before.Organisation.SQLSessions != 1 || before.Global.ParentBytes != 8<<20 || before.Global.DBStagingBytes != 8<<20 || before.GlobalGrants != 3 || before.OrganisationGrants != 1 || before.Organisation.ParentBytes != 0 || before.Organisation.DBStagingBytes != 0 {
		t.Fatal("genuine synchronous log frame did not retain exact process scope", pending, before)
	}
	t.Log("actual SQL denial: organisation-resource dimension=SQL requested=1 before=4 limit=4; synchronous log consumer retains original8MiB scope after SQL retirement")
	releaseOnce.Do(func() { close(sink.release) })
	cleanup, stop = context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	select {
	case <-done:
	case <-cleanup.Done():
		t.Fatal("original log consumer did not join")
	}
	if err := refused.CloseV1(cleanup); err != nil {
		t.Fatal(err)
	}
	refused = nil
	if err := factory.ReconcileCleanupV1(cleanup); err != nil {
		t.Fatal(err)
	}
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	t.Log("actual diagnostic last use, reader/scope/registry cleanup joined; exact observer-only debt remains")
}

// This is a genuine final-recheck query refusal, not a forged owner or a
// synthetic diagnostic label. The fixture-control row lock owns no application
// admission and never supplies its SQL connection to the application.
func TestOwnedSignerModelRecheckDiagnosticActualLockTimeoutE2E(t *testing.T) {
	testOwnedSignerModelRecheckDiagnosticActualLockTimeoutV1(t, pdfadmission.SignerReadDiagnosticFieldsV1)
}

func TestOwnedSignerPDFModelRecheckDiagnosticActualLockTimeoutE2E(t *testing.T) {
	testOwnedSignerModelRecheckDiagnosticActualLockTimeoutV1(t, pdfadmission.SignerReadDiagnosticPDFV1)
}

func testOwnedSignerModelRecheckDiagnosticActualLockTimeoutV1(t *testing.T, route pdfadmission.SignerReadDiagnosticRouteV1) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	var rc *sign.RecipientContext
	var err error
	label := "fields"
	switch route {
	case pdfadmission.SignerReadDiagnosticFieldsV1:
		rc, err = f.s.Sign.LookupSignerFieldsByTokenV1(f.ctx, auth.HashMagicToken(parties[0].Token))
	case pdfadmission.SignerReadDiagnosticPDFV1:
		label = "PDF"
		rc, err = f.s.Sign.LookupSignerPDFByTokenV1(f.ctx, auth.HashMagicToken(parties[0].Token))
	default:
		t.Fatal("unexpected fixed diagnostic test route")
	}
	if err != nil || rc == nil {
		t.Fatal("actual signer lookup did not open", err)
	}
	t.Cleanup(func() {
		if err := rc.CloseReadV1(); err != nil {
			t.Error(err)
		}
	})
	control, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	controlClosed := false
	t.Cleanup(func() {
		if !controlClosed {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := control.Rollback(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	var locked int
	if err := control.QueryRow(f.ctx, "SELECT 1 FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", doc.ID, f.org).Scan(&locked); err != nil || locked != 1 {
		t.Fatal("actual control row lock not held", err)
	} //nolint:rawsql -- isolated negative row-lock stimulus only
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release) // Capture synchronously without extending actual last use.
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	t.Cleanup(func() { slog.SetDefault(previous) })
	called := false
	err = f.s.Sign.RecheckRecipientReadV1(f.ctx, rc, func(*sign.RecipientContext) error {
		called = true
		return nil
	})
	var databaseError *pgconn.PgError
	if !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || !errors.As(err, &databaseError) || databaseError.Code != "55P03" || called {
		t.Fatal("actual recheck did not preserve original lock-timeout refusal and callback ordering")
	}
	// Exact numeric labels: original route/recheck/models/document-header/query-error.
	// Every original SQL fact remains zero: SQL was admitted, then the query failed.
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 12 || sink.values[23] != 2 || sink.values[0] != int64(route) || sink.values[1] != 2 || sink.values[2] != 2 || sink.values[15] != 3 || sink.values[16] != 3 {
		t.Fatal("actual final-recheck query branch was not diagnosed", sink.count, sink.valid, sink.values)
	}
	for _, value := range append(sink.values[3:15:15], sink.values[17:22]...) {
		if value != 0 {
			t.Fatal("query timeout falsely claimed atomic SQL denial")
		}
	}
	if route == pdfadmission.SignerReadDiagnosticPDFV1 {
		// Also traverse the actual PDF handler's initial lookup. The held row is
		// the same real stimulus, and the generic public error stays unchanged.
		initial := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
		close(initial.release)
		slog.SetDefault(slog.New(initial))
		response := q.requestV1(parties[0].Token, "/pdf")
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"signer access is temporarily unavailable\"}\n" {
			t.Fatal("actual PDF route did not preserve its generic availability response")
		}
		if initial.count != 27 || initial.values[24] != 0 || initial.values[25] != 0 || initial.values[26] != 0 || !initial.valid || initial.values[22] != 12 || initial.values[23] != 2 || initial.values[0] != 2 || initial.values[1] != 1 || initial.values[2] != 2 || initial.values[15] != 3 || initial.values[16] != 3 {
			t.Fatal("actual PDF handler did not diagnose its original lookup query branch", initial.count, initial.valid, initial.values)
		}
		for _, value := range append(initial.values[3:15:15], initial.values[17:22]...) {
			if value != 0 {
				t.Fatal("actual PDF query timeout falsely claimed atomic SQL denial")
			}
		}
		t.Log("actual PDF GET lookup: generic503 and document-header query diagnostic; no private error or SQL denial published")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := control.Rollback(cleanup); err != nil {
		t.Fatal(err)
	}
	controlClosed = true
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	t.Logf("actual final %s recheck: document-header query lock timeout; fixed numeric model branch, no SQL denial, original policy callback uncalled, observers-only cleanup joined", label)
}

// Retained bodies and scopes are genuine completed native lookups. Their
// actual lifetime creates a body-only shortage without changing any limit,
// forging an owner or holding SQL/locks to manufacture the rejecting branch.
func TestOwnedSignerPDFBodyAdmissionDiagnosticActualCapacityE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	_, parties := q.createSentV1(t)
	bootstrap := q.lookupV1(t, parties[0].Token)
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	factory := q.runtime.SessionsV1()
	var leases []*sign.RecipientContext
	var extras []*pdfadmission.ApplicationSignerScopeV1
	t.Cleanup(func() {
		for _, rc := range leases {
			if err := rc.CloseReadV1(); err != nil {
				t.Error(err)
			}
		}
		for _, extra := range extras {
			extra.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := factory.ReconcileCleanupV1(cleanup); err != nil {
			t.Error(err)
		}
	})
	for i := 0; i < 7; i++ {
		rc, err := f.s.Sign.LookupSignerPDFByTokenV1(f.ctx, auth.HashMagicToken(parties[0].Token))
		if err != nil || rc == nil {
			t.Fatal("actual PDF capacity-holder lookup did not complete", err)
		}
		leases = append(leases, rc)
	}
	var err error
	for i := 0; i < 4; i++ {
		extra, openErr := factory.ProbeSignerScopeV1(f.ctx, auth.HashMagicToken(parties[0].Token))
		if openErr != nil || extra == nil {
			t.Fatal("actual extra process scope did not complete", openErr)
		}
		extras = append(extras, extra)
	}
	before := q.snapshotV1(t)
	pending := factory.PendingV1()
	const header, limit = int64(32 << 20), int64(384 << 20)
	if pending.SignerReaders != 7 || pending.SignerScopes != 11 || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 ||
		before.Global.SQLSessions != 2 || before.Organisation.SQLSessions != 1 ||
		before.Global.DBStagingBytes-before.Organisation.DBStagingBytes != 88<<20 ||
		before.Global.ParentBytes-before.Organisation.ParentBytes != 88<<20 ||
		before.Global.DBStagingBytes+header > limit || before.Global.DBStagingBytes+2*header <= limit {
		t.Fatal("genuine retained consumers did not establish body-only admission window", pending, before)
	}
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	defer slog.SetDefault(previous)
	called := false
	err = f.s.Sign.RecheckRecipientReadV1(f.ctx, leases[0], func(*sign.RecipientContext) error { called = true; return nil })
	if !errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) || called {
		t.Fatal("actual PDF recheck did not refuse before policy callback", err, called)
	}
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 23 || sink.values[23] != 2 || sink.values[0] != 2 || sink.values[1] != 2 || sink.values[2] != 2 || sink.values[3] != 1 ||
		sink.values[4] != int64(workguard.AdmissionGlobalResourceV1) || sink.values[5] != int64(workguard.AdmissionDBStagingBytesV1) ||
		sink.values[6] != 0 || sink.values[7] != 3 || sink.values[8] != 2 || sink.values[9] != 8 || sink.values[10] != 4 ||
		sink.values[11] != before.GlobalGrants+2 || sink.values[12] != before.OrganisationGrants+2 ||
		sink.values[15] != 10 || sink.values[16] != 2 || sink.values[17] <= header ||
		sink.values[18] != before.Global.DBStagingBytes+header || sink.values[19] != before.Organisation.DBStagingBytes+header ||
		sink.values[20] != limit || sink.values[21] != limit ||
		sink.values[18]+sink.values[17] <= sink.values[20] || sink.values[19]+sink.values[17] > sink.values[21] {
		t.Fatal("actual atomic body denial differs from source-sized request and original coordinator", sink.count, sink.valid, sink.values, before)
	}
	// The failed reader and its native SQL/header loans must really retire;
	// the seven original consumers and four extra scopes still own their exact debt.
	q.reconcileV1(t)
	if after := q.snapshotV1(t); after != before {
		t.Fatal("failed recheck did not restore genuine original retained debt", after, before)
	}
	if after := factory.PendingV1(); after != pending {
		t.Fatal("failed recheck retained a new reader/session/registry", after, pending)
	}
	t.Logf("actual PDF body denial: requested=%d global_before=%d org_before=%d global_limit=%d org_limit=%d; SQL admitted; policy uncalled", sink.values[17], sink.values[18], sink.values[19], sink.values[20], sink.values[21])
	for _, rc := range leases {
		if err := rc.CloseReadV1(); err != nil {
			t.Fatal(err)
		}
	}
	leases = nil
	for _, extra := range extras {
		extra.CloseConsumerV1()
	}
	extras = nil
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	t.Log("actual body denial and all genuine consumers joined; observer-only debt remains")
}

// The actual public comments GET must attribute its initial access-query
// refusal without disclosing private errors or borrowing a fake native owner.
func TestOwnedSignerCommentsLookupDiagnosticActualLockTimeoutE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	bootstrap := q.lookupV1(t, parties[0].Token)
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	control, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	controlClosed := false
	t.Cleanup(func() {
		if !controlClosed {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := control.Rollback(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	var locked int
	if err := control.QueryRow(f.ctx, "SELECT 1 FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", doc.ID, f.org).Scan(&locked); err != nil || locked != 1 {
		t.Fatal("actual comments access control row lock not held", err)
	} //nolint:rawsql -- isolated negative lock stimulus only
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	defer slog.SetDefault(previous)
	response := q.requestV1(parties[0].Token, "/comments")
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"signer access is temporarily unavailable\"}\n" {
		t.Fatal("actual comments access lookup did not preserve generic503")
	}
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 12 || sink.values[23] != 2 || sink.values[0] != 3 || sink.values[1] != 1 || sink.values[2] != 2 || sink.values[15] != 3 || sink.values[16] != 3 {
		t.Fatal("actual comments GET did not attribute initial document-header query refusal", sink.count, sink.valid, sink.values)
	}
	for _, value := range append(sink.values[3:15:15], sink.values[17:22]...) {
		if value != 0 {
			t.Fatal("actual comments query refusal falsely claimed atomic resource denial")
		}
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := control.Rollback(cleanup); err != nil {
		t.Fatal(err)
	}
	controlClosed = true
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	t.Log("actual comments GET initial lookup: generic503, fixed route3/models/document-header/query labels, no private error or atomic-denial claim; real rollback and observer-only drain")
}

func TestOwnedSignerViewLookupDiagnosticActualLockTimeoutE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	bootstrap := q.lookupV1(t, parties[0].Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(parties[0].Token, ""), bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrap.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	control, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	controlClosed := false
	t.Cleanup(func() {
		if !controlClosed {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := control.Rollback(cleanup); err != nil {
				t.Error(err)
			}
		}
	})
	var locked int
	if err := control.QueryRow(f.ctx, "SELECT 1 FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", doc.ID, f.org).Scan(&locked); err != nil || locked != 1 {
		t.Fatal("actual view access control row lock not held", err)
	} //nolint:rawsql -- actual independent negative lock stimulus only
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	previous := slog.Default()
	slog.SetDefault(slog.New(sink))
	defer slog.SetDefault(previous)
	r := httptest.NewRequest(http.MethodPost, "/sign/"+parties[0].Token+"/view", strings.NewReader(`{}`)).WithContext(f.ctx)
	r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, r)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"signer access is temporarily unavailable\"}\n" {
		t.Fatal("actual view access lookup did not preserve generic503")
	}
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 12 || sink.values[23] != 2 || sink.values[0] != 4 || sink.values[1] != 1 || sink.values[2] != 2 || sink.values[15] != 3 || sink.values[16] != 3 {
		t.Fatal("actual view POST did not attribute initial document-header query refusal", sink.count, sink.valid, sink.values)
	}
	for _, value := range append(sink.values[3:15:15], sink.values[17:22]...) {
		if value != 0 {
			t.Fatal("actual view lookup query refusal falsely claimed atomic resource denial")
		}
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := control.Rollback(cleanup); err != nil {
		t.Fatal(err)
	}
	controlClosed = true
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	t.Log("actual view POST initial lookup: generic503, fixed route4/lookup/models/document-header/query labels; real rollback and observer-only drain")
}

func TestOwnedSignerViewMutationDiagnosticActualAuditLockTimeoutE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	party := parties[0]
	rc := q.lookupV1(t, party.Token)
	notice, err := f.s.signerPrivacyNotice(signerReadRequestE2E(party.Token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	var originalStatus string
	if err := f.pool.QueryRow(f.ctx, "SELECT status FROM recipients WHERE id=$1", party.RecipientID).Scan(&originalStatus); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual rollback baseline
	held, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	closed, launched, joined := false, false, false
	call, cancel := context.WithCancel(f.ctx)
	result := make(chan *httptest.ResponseRecorder, 1)
	joinDeadline := time.Now().Add(15 * time.Second)
	sink := &ownedSignerDiagnosticSinkV1{started: make(chan struct{}), release: make(chan struct{})}
	close(sink.release)
	previous := slog.Default()
	// Register before launch. Every fatal path cancels, rolls back the actual
	// control lock, joins the request and only then restores the logger.
	t.Cleanup(func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if !closed {
			if err := held.Rollback(cleanup); err != nil {
				t.Error(err)
			}
			closed = true
		}
		if launched && !joined {
			timer := time.NewTimer(max(time.Until(joinDeadline), time.Nanosecond))
			defer timer.Stop()
			select {
			case <-result:
				joined = true
			case <-timer.C:
				t.Error("actual view diagnostic request did not join original cleanup deadline")
			}
		}
		slog.SetDefault(previous)
	})
	if err := f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	var holder int32
	if err := held.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&holder); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual blocker identity
	r := httptest.NewRequest(http.MethodPost, "/sign/"+party.Token+"/view", strings.NewReader(`{}`)).WithContext(call)
	r.Header.Set(signerNoticeDigestHeader, notice.NoticeDigest)
	slog.SetDefault(slog.New(sink))
	launched = true
	go func() { w := httptest.NewRecorder(); f.s.Routes().ServeHTTP(w, r); result <- w }()
	ownedReadWaitV1(t, q, holder, "AcquireOrgChainLock")
	// Hold the genuine advisory lock until the unchanged native lock timeout.
	timer := time.NewTimer(max(time.Until(joinDeadline), time.Nanosecond))
	defer timer.Stop()
	select {
	case response := <-result:
		joined = true
		if response.Code != http.StatusServiceUnavailable || response.Body.String() != "{\"error\":\"signer access is temporarily unavailable\"}\n" {
			t.Fatal("actual view audit wait did not preserve generic503", response.Code)
		}
	case <-timer.C:
		t.Fatal("actual view audit timeout did not join original request deadline")
	}
	if sink.count != 27 || sink.values[24] != 0 || sink.values[25] != 0 || sink.values[26] != 0 || !sink.valid || sink.values[22] != 0 || sink.values[23] != 0 || sink.values[0] != 4 || sink.values[1] != 3 || sink.values[2] != 5 {
		t.Fatal("actual view mutation refusal was not distinguished from initial lookup", sink.count, sink.valid, sink.values)
	}
	for _, value := range sink.values[3:] {
		if value != 0 {
			t.Fatal("successful lookup frame falsely claimed mutation model/resource diagnosis")
		}
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := held.Rollback(cleanup); err != nil {
		t.Fatal(err)
	}
	closed = true
	cancel()
	slog.SetDefault(previous)
	q.assertObserversOnlyV1(t)
	var status string
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT r.status,(SELECT count(*) FROM events WHERE document_id=$2 AND recipient_id=r.id AND kind='document.viewed') FROM recipients r WHERE r.id=$1`, party.RecipientID, doc.ID).Scan(&status, &events); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual recipient/event rollback witness
	if status != originalStatus || events != 0 {
		t.Fatal("refused native view committed status or audit evidence", status, events)
	}
	t.Log("actual view POST mutation: observed real audit advisory blocker, unchanged timeout generic503 and fixed4/3/5 labels; no mutation resource claim, recipient/event rollback and observer-only drain")
}
