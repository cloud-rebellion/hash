// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrRecordedApplicationBackendV1 = errors.New("pdfadmission: recorded backend metadata unavailable")

// RecordedApplicationBackendIdentityV1 is inert scalar data. A trusted adapter
// must read it from the exact immutable scoped90 header. A caller can fabricate
// these values; neither this input nor an observation supplies credential,
// transaction-disposition, resource-credit, worker/provider or Sign authority.
// No connection string, credential override or retired/expiry boolean exists.
type RecordedApplicationBackendIdentityV1 struct {
	PID                  int32
	BackendStart         pgtype.Timestamptz
	DatabaseOID, UserOID int64
	ServerAddress        string
	ServerPort           int32
	PostmasterStart      pgtype.Timestamptz
}

type RecordedApplicationBackendStateV1 string

const (
	RecordedApplicationBackendPresentV1          RecordedApplicationBackendStateV1 = "metadata-present"
	RecordedApplicationBackendAbsentOrReplacedV1 RecordedApplicationBackendStateV1 = "metadata-absent-or-replaced"
)

// RecordedApplicationBackendMetadataV1 describes only the fixed observer's
// result for the supplied data. It is deliberately not a session retirement
// receipt or permit: no WORK-session retirement fence/loan/debt is credited.
// The shared observer retains its normal tracked active/session-permit lifetime.
// OrgID is the caller's admission scope, not a database proof of PID ownership.
type RecordedApplicationBackendMetadataV1 struct {
	orgID    uuid.UUID
	identity RecordedApplicationBackendIdentityV1
	state    RecordedApplicationBackendStateV1
}

func (m *RecordedApplicationBackendMetadataV1) OrgIDV1() uuid.UUID {
	if m == nil {
		return uuid.Nil
	}
	return m.orgID
}
func (m *RecordedApplicationBackendMetadataV1) IdentityV1() RecordedApplicationBackendIdentityV1 {
	if m == nil {
		return RecordedApplicationBackendIdentityV1{}
	}
	return m.identity
}
func (m *RecordedApplicationBackendMetadataV1) StateV1() RecordedApplicationBackendStateV1 {
	if m == nil {
		return ""
	}
	return m.state
}

// The public facade preserves only fixed sentinels and standard cancellation.
// Internal pgx/dial errors and SQL/configuration are not retained. Cancellation
// identity remains available through opaque public text and copied causes.
type recordedApplicationBackendFailureV1 struct{ causes []error }

func (*recordedApplicationBackendFailureV1) Error() string {
	return ErrRecordedApplicationBackendV1.Error()
}
func (e *recordedApplicationBackendFailureV1) Unwrap() []error {
	return append([]error(nil), e.causes...)
}
func recordedApplicationBackendErrorV1(ctx context.Context, internal error) error {
	causes := []error{ErrRecordedApplicationBackendV1}
	if errors.Is(internal, ErrApplicationSessionUnknownV1) {
		causes = append(causes, ErrApplicationSessionUnknownV1)
	}
	for _, standard := range []error{context.Canceled, context.DeadlineExceeded} {
		if errors.Is(internal, standard) || (ctx != nil && errors.Is(ctx.Err(), standard)) {
			causes = append(causes, standard)
		}
	}
	if ctx != nil && ctx.Err() != nil {
		if cause := context.Cause(ctx); cause != nil && cause != ctx.Err() {
			causes = append(causes, cause)
		}
	}
	return &recordedApplicationBackendFailureV1{causes: causes}
}

func recordedApplicationBackendIdentityV1(v RecordedApplicationBackendIdentityV1) (applicationBackendIdentityV1, bool) {
	if !applicationStampV1(v.BackendStart) || !applicationStampV1(v.PostmasterStart) || len(v.ServerAddress) > 128 || v.ServerPort < 0 || v.ServerPort > 65535 {
		return applicationBackendIdentityV1{}, false
	}
	if v.ServerAddress == "" {
		if v.ServerPort != 0 {
			return applicationBackendIdentityV1{}, false
		}
	} else {
		address, err := netip.ParseAddr(v.ServerAddress)
		if err != nil || address.Zone() != "" || address.String() != v.ServerAddress || v.ServerPort == 0 {
			return applicationBackendIdentityV1{}, false
		}
	}
	identity := applicationBackendIdentityV1{pid: v.PID, backendStart: v.BackendStart.Time, databaseOID: v.DatabaseOID, userOID: v.UserOID, address: v.ServerAddress, port: v.ServerPort, postmasterStart: v.PostmasterStart.Time}
	return identity, applicationIdentityValidV1(identity)
}

// ObserveRecordedBackendMetadataV1 supports application-process restart by
// observing a recorded original SQL backend on the exact server/principal.
// Call outside entity/account locks, from a trusted scoped journal adapter.
// Only the factory's original fixed config and shared coordinator are used.
// The actual bounded observer owns its session/permit, and uncertain startup
// stays quarantined in the factory. This API never replaces or retires work.
//
// A database/postmaster incarnation mismatch remains unknown. PID absence or a
// readable different backend_start can describe old SQL backend disappearance;
// it never determines COMMIT/rollback or a whole-process/worker/provider result.
// Durable body/debt reconciliation and current original-credential checks are
// separate and mandatory. Supplying copied caller metadata cannot satisfy them.
func (f *ApplicationSessionFactoryV1) ObserveRecordedBackendMetadataV1(ctx context.Context, orgID uuid.UUID, record RecordedApplicationBackendIdentityV1) (*RecordedApplicationBackendMetadataV1, error) {
	if f == nil || f.state == nil || orgID == uuid.Nil || !applicationContextV1(ctx) || ctx.Value(applicationSessionCallbackKeyV1{}) != nil {
		return nil, recordedApplicationBackendErrorV1(ctx, nil)
	}
	old, valid := recordedApplicationBackendIdentityV1(record)
	if !valid {
		return nil, recordedApplicationBackendErrorV1(ctx, nil)
	}
	// This bounds admission/startup/guard wait; the shared control probe already
	// has its fixed one-second join budget even after caller cancellation.
	owned, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	organisation, err := f.organisationV1(owned, orgID)
	if err != nil {
		return nil, recordedApplicationBackendErrorV1(owned, err)
	}
	if err = organisation.ensureObserverV1(owned); err != nil {
		return nil, recordedApplicationBackendErrorV1(owned, err)
	}
	if owned.Err() != nil {
		return nil, recordedApplicationBackendErrorV1(owned, nil)
	}
	gone, err := organisation.observeV1(owned, old)
	if err != nil || owned.Err() != nil || ctx.Err() != nil {
		return nil, recordedApplicationBackendErrorV1(owned, err)
	}
	f.state.mu.Lock()
	closing := f.state.closing
	f.state.mu.Unlock()
	if owned.Err() != nil || ctx.Err() != nil {
		return nil, recordedApplicationBackendErrorV1(owned, nil)
	}
	if closing {
		return nil, recordedApplicationBackendErrorV1(owned, ErrApplicationSessionUnknownV1)
	}
	state := RecordedApplicationBackendPresentV1
	if gone {
		state = RecordedApplicationBackendAbsentOrReplacedV1
	}
	return &RecordedApplicationBackendMetadataV1{orgID: orgID, identity: record, state: state}, nil
}
