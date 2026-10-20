// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These synthetic values exercise only scalar/parser/ownership contracts.
// No backend, credential, administrator, retirement or quota proof is created.
func recordedBackendShapeFixtureV1() RecordedApplicationBackendIdentityV1 {
	return RecordedApplicationBackendIdentityV1{PID: 1234, BackendStart: pgtype.Timestamptz{Time: time.Date(2026, 10, 13, 21, 0, 0, 0, time.UTC), Valid: true}, DatabaseOID: 42, UserOID: 43, ServerAddress: "192.0.2.10", ServerPort: 5432, PostmasterStart: pgtype.Timestamptz{Time: time.Date(2026, 10, 13, 20, 0, 0, 0, time.UTC), Valid: true}}
}
func TestRecordedBackendScalarShapeV1(t *testing.T) {
	for _, name := range []string{"ipv4", "ipv6", "unix", "uint32-max"} {
		t.Run(name, func(t *testing.T) {
			r := recordedBackendShapeFixtureV1()
			switch name {
			case "ipv6":
				r.ServerAddress = "2001:db8::1"
			case "unix":
				r.ServerAddress = ""
				r.ServerPort = 0
			case "uint32-max":
				r.DatabaseOID = 4294967295
				r.UserOID = 4294967295
			}
			v, valid := recordedApplicationBackendIdentityV1(r)
			if !valid || v.pid != r.PID || v.databaseOID != r.DatabaseOID || v.userOID != r.UserOID || v.address != r.ServerAddress || v.port != r.ServerPort || !v.backendStart.Equal(r.BackendStart.Time) || !v.postmasterStart.Equal(r.PostmasterStart.Time) {
				t.Fatal("valid bounded scalar identity lost")
			}
		})
	}
	for _, name := range []string{"zero-pid", "negative-pid", "zero-database", "negative-user", "large-database", "large-user", "missing-backend-start", "missing-postmaster-start", "zero-backend-time", "infinite-time", "year-out-of-range", "address-over-limit", "address-hostname", "address-zone", "address-whitespace", "address-nul", "address-noncanonical", "empty-tcp-address", "tcp-zero-port", "negative-port", "large-port"} {
		t.Run(name, func(t *testing.T) {
			r := recordedBackendShapeFixtureV1()
			switch name {
			case "zero-pid":
				r.PID = 0
			case "negative-pid":
				r.PID = -1
			case "zero-database":
				r.DatabaseOID = 0
			case "negative-user":
				r.UserOID = -1
			case "large-database":
				r.DatabaseOID = 4294967296
			case "large-user":
				r.UserOID = 4294967296
			case "missing-backend-start":
				r.BackendStart.Valid = false
			case "missing-postmaster-start":
				r.PostmasterStart.Valid = false
			case "zero-backend-time":
				r.BackendStart.Time = time.Time{}
			case "infinite-time":
				r.BackendStart.InfinityModifier = pgtype.InfinityModifier(1)
			case "year-out-of-range":
				r.PostmasterStart.Time = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "address-over-limit":
				r.ServerAddress = strings.Repeat("x", 129)
			case "address-hostname":
				r.ServerAddress = "db.example.invalid"
			case "address-zone":
				r.ServerAddress = "fe80::1%fixture"
			case "address-whitespace":
				r.ServerAddress = " 192.0.2.10"
			case "address-nul":
				r.ServerAddress = "192.0.2.10" + string(byte(0))
			case "address-noncanonical":
				r.ServerAddress = "2001:0db8::1"
			case "empty-tcp-address":
				r.ServerAddress = ""
			case "tcp-zero-port":
				r.ServerPort = 0
			case "negative-port":
				r.ServerPort = -1
			case "large-port":
				r.ServerPort = 65536
			}
			if _, valid := recordedApplicationBackendIdentityV1(r); valid {
				t.Fatal("malformed recorded identity admitted")
			}
		})
	}
}
func TestRecordedBackendOpaqueCancellationAndCauseOwnershipV1(t *testing.T) {
	cause := errors.New("synthetic private cancellation identity")
	driver := errors.New("synthetic private driver details")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	err := recordedApplicationBackendErrorV1(ctx, errors.Join(ErrApplicationSessionUnknownV1, driver))
	if err.Error() != ErrRecordedApplicationBackendV1.Error() || strings.Contains(err.Error(), cause.Error()) || strings.Contains(err.Error(), driver.Error()) {
		t.Fatal("public error disclosed private details")
	}
	if !errors.Is(err, ErrRecordedApplicationBackendV1) || !errors.Is(err, ErrApplicationSessionUnknownV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || errors.Is(err, driver) {
		t.Fatal("safe cancellation identity or private driver boundary lost")
	}
	unwrapper, ok := err.(interface{ Unwrap() []error })
	if !ok {
		t.Fatal("opaque error lost cause contract")
	}
	out := unwrapper.Unwrap()
	if len(out) < 1 {
		t.Fatal("missing causes")
	}
	out[0] = driver
	if !errors.Is(err, ErrRecordedApplicationBackendV1) || errors.Is(err, driver) {
		t.Fatal("cause accessor aliases stored ownership")
	}
	err = recordedApplicationBackendErrorV1(nil, errors.Join(driver, context.DeadlineExceeded))
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, driver) || strings.Contains(err.Error(), driver.Error()) {
		t.Fatal("safe internal deadline/private cause boundary lost")
	}
}
func TestRecordedBackendMetadataCopiesAndEmptyResultV1(t *testing.T) {
	var empty *RecordedApplicationBackendMetadataV1
	if empty.OrgIDV1() != uuid.Nil || empty.StateV1() != "" || empty.IdentityV1().PID != 0 {
		t.Fatal("nil result supplied observation")
	}
	// Direct construction is a package-private accessor fixture, not an observed
	// backend or a way for a caller to mint a session/resource retirement permit.
	org := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	m := &RecordedApplicationBackendMetadataV1{orgID: org, identity: recordedBackendShapeFixtureV1(), state: RecordedApplicationBackendPresentV1}
	got := m.IdentityV1()
	got.PID++
	got.ServerAddress = "changed"
	got.BackendStart.Time = time.Time{}
	if m.OrgIDV1() != org || m.StateV1() != RecordedApplicationBackendPresentV1 || m.IdentityV1().PID != 1234 || m.IdentityV1().ServerAddress != "192.0.2.10" || m.IdentityV1().BackendStart.Time.IsZero() {
		t.Fatal("scalar metadata getter aliases returned data")
	}
}
func TestRecordedBackendZeroFactoryCancellationRefusalV1(t *testing.T) {
	cause := errors.New("synthetic private request cancellation")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	var factory *ApplicationSessionFactoryV1
	result, err := factory.ObserveRecordedBackendMetadataV1(ctx, uuid.MustParse("11111111-1111-4111-8111-111111111111"), recordedBackendShapeFixtureV1())
	if result != nil || !errors.Is(err, ErrRecordedApplicationBackendV1) || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("zero factory manufactured result or disclosed cancellation")
	}
}

func TestRecordedBackendOwnedCallbackRefusesBeforeObserverAdmissionV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// This incomplete private factory is deliberately only an invalid-dispatch
	// witness. It cannot create a real observer or supply any retirement proof.
	state := &applicationSessionFactoryStateV1{organisations: make(map[uuid.UUID]*applicationSessionOrganisationV1)}
	factory := &ApplicationSessionFactoryV1{state: state}
	ctx = context.WithValue(ctx, applicationSessionCallbackKeyV1{}, struct{}{})
	result, err := factory.ObserveRecordedBackendMetadataV1(ctx, uuid.MustParse("11111111-1111-4111-8111-111111111111"), recordedBackendShapeFixtureV1())
	if result != nil || !errors.Is(err, ErrRecordedApplicationBackendV1) || len(state.organisations) != 0 {
		t.Fatal("owned callback entered observer/admission instead of refusing")
	}
}
