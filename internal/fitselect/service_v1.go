// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package fitselect owns durable selection and exact-version pre-sign retention.
// It creates no signature, recipient status, audit event or completion artifact.
// Activation requires a final locked admission and atomic fitted companion.
package fitselect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var (
	ErrInvalidV1          = errors.New("fitselect: invalid selection request")
	ErrAuthorityChangedV1 = errors.New("fitselect: signing authority changed")
	ErrOutcomeUnknownV1   = errors.New("fitselect: SQL outcome requires fresh reconciliation")
	ErrNotSelectedV1      = errors.New("fitselect: preparation was not selected")
	ErrRetentionPendingV1 = errors.New("fitselect: selected retention remains incomplete")
	ErrAdmissionV1        = errors.New("fitselect: locked signing admission denied")
)

// RequestV1 names a prepared immutable set. OwnerID is its lease owner, never a
// credential substitute. Competing preparations for a ceremony cannot replace
// its stable selection; the already selected operation is returned instead.
type RequestV1 struct {
	Binding  manualfit.BindingV1
	OwnerID  uuid.UUID
	Manifest manualfit.ObjectPinV1
}

// LockedStateV1 is read in document -> recipient -> preparation order. AllFields
// includes other parties and non-signature fields. Inventory includes selected,
// unselected, attempted-unknown and cleaned objects: final signatures alone are
// insufficient for privacy/recovery or the shared document archive budget.
// Queries is transaction scoped for original credential/notice/controller/role
// checks. The callback must also enforce the full 50 MiB ordered-composition
// input bound across source, every party, base text and protocol metadata; a
// preparation for this party alone does not prove that bound. The callback
// must never perform storage writes or publication.
type LockedStateV1 struct {
	Document    *generated.Document
	Recipient   *generated.Recipient
	Preparation *generated.SignatureFitPreparation
	Objects     []*generated.SignatureFitObject
	AllFields   []*generated.DocumentField
	Inventory   []*generated.ListSignatureFitInventoryRow
	Queries     *generated.Queries
	Manifest    *manualfit.ManifestV1
}

// AdmissionV1 is deliberately constructed from a real archive budget and an
// explicit policy authorization. The seven-year epoch floor is NOT final legal
// expiry: finalization must extend every selected exact version to its stored
// completion-effective target, verify retention and bind both targets in evidence.
type AdmissionV1 struct {
	budget    ArchiveBudgetV1
	floor     time.Time
	permitted bool
}

// AuthorizeV1 is an application trust seam, not a legal determination. Invoke
// only after validating current controller instruction/notice, original public
// credential, required parties, tier/contract intent and non-signature fields.
// There is no default permission or internally invented completion timestamp.
func AuthorizeV1(budget ArchiveBudgetV1, exactFloor time.Time) (AdmissionV1, error) {
	if !budget.valid || exactFloor.IsZero() || exactFloor.Location() != time.UTC || exactFloor.Nanosecond() != 0 {
		return AdmissionV1{}, ErrAdmissionV1
	}
	return AdmissionV1{budget, exactFloor, true}, nil
}

type AdmissionFuncV1 func(context.Context, LockedStateV1) (AdmissionV1, error)

// TransactionV1 instances must use fresh independent sessions. Commit errors
// are never evidence of rollback. Service reconciliation always begins another
// transaction, and the PostgreSQL adapter opens another physical connection.
type TransactionV1 interface {
	Lock(context.Context, manualfit.BindingV1) (LockedStateV1, error)
	FindSelection(context.Context, manualfit.BindingV1) (*generated.SignatureFitSelection, error)
	MarkAttempt(context.Context, RequestV1) (*generated.SignatureFitPreparation, error)
	Select(context.Context, RequestV1, uuid.UUID) (*generated.SignatureFitSelection, error)
	MarkNotCommitted(context.Context, RequestV1) (*generated.SignatureFitPreparation, error)
	MarkRetentionStarted(context.Context, *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error)
	MarkRetentionComplete(context.Context, *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}
type StoreV1 interface {
	Begin(context.Context) (TransactionV1, error)
}
type ServiceV1 struct {
	Store    StoreV1
	Reader   manualfit.BoundedReaderV1
	Retainer manualfit.RetainerV1
	Admit    AdmissionFuncV1
}

// SelectedV1 is a verified retained byte set, not permission to publish Sign.
// FinalAdmissionV1 must run in the actual signature transaction, then creation
// of the new signature kind and companion must commit atomically with status
// and audit changes. No caller can manufacture a SelectedV1 through its API.
type SelectedV1 struct {
	row      *generated.SignatureFitSelection
	retained *manualfit.RetainedV1
}

func (s *SelectedV1) ID() uuid.UUID {
	if s == nil || s.row == nil {
		return uuid.Nil
	}
	return s.row.ID
}
func (s *SelectedV1) Binding() manualfit.BindingV1 {
	if s == nil || s.retained == nil {
		return manualfit.BindingV1{}
	}
	return s.retained.Manifest().Binding()
}
func (s *SelectedV1) ManifestObject() manualfit.ObjectPinV1 {
	if s == nil || s.retained == nil {
		return manualfit.ObjectPinV1{}
	}
	return s.retained.ManifestObject()
}
func (s *SelectedV1) Retained() *manualfit.RetainedV1 {
	if s == nil {
		return nil
	}
	return s.retained
}
func (s *SelectedV1) RetentionFloor() time.Time {
	if s == nil || s.row == nil {
		return time.Time{}
	}
	return s.row.RetainUntil.Time.UTC()
}

func (s *ServiceV1) ready(ctx context.Context) error {
	if ctx == nil || s == nil || s.Store == nil || s.Reader == nil || s.Retainer == nil || s.Admit == nil {
		return ErrInvalidV1
	}
	if ctx.Err() != nil {
		return contextualV1(ErrAdmissionV1, ctx)
	}
	return nil
}
func (s *ServiceV1) SelectV1(ctx context.Context, r RequestV1) (*SelectedV1, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if r.OwnerID == uuid.Nil || !validBinding(r.Binding) {
		return nil, ErrInvalidV1
	}
	// A stable ceremony winner always precedes the newly prepared candidate.
	row, err := s.lookup(ctx, r.Binding)
	if err == nil {
		if !sameCeremonyAuthority(row, r.Binding) {
			return nil, ErrAuthorityChangedV1
		}
		return s.resumeRow(ctx, row)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, publicError(ctx, err)
	}
	retained, err := manualfit.VerifyRetainedV1(ctx, s.Reader, r.Manifest, r.Binding)
	if err != nil {
		return nil, publicError(ctx, err)
	}
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, publicError(ctx, err)
	}
	state, err := tx.Lock(ctx, r.Binding)
	if err == nil {
		// A caller may have won after the initial read but before this parent lock.
		// Do not let the attempted-checkpoint predicate turn that stable winner
		// into a spurious denial. ReadCommitted sees the committed winner here.
		winner, e := tx.FindSelection(ctx, r.Binding)
		if e == nil {
			rollback(tx)
			if !sameCeremonyAuthority(winner, r.Binding) {
				return nil, ErrAuthorityChangedV1
			}
			return s.resumeRow(ctx, winner)
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			err = e
		}
	}
	if err == nil {
		err = s.admit(ctx, state, retained, nil)
	}
	if err == nil {
		_, err = tx.MarkAttempt(ctx, r)
	}
	if err != nil {
		rollback(tx)
		return nil, publicError(ctx, err)
	}
	err = tx.Commit(ctx)
	if err != nil {
		// Read a fresh committed checkpoint before entering any selection TX.
		if e := s.observeAttempt(ctx, r); e != nil {
			return nil, unknown(ctx, e)
		}
	}
	tx, err = s.Store.Begin(ctx)
	if err != nil {
		return nil, unknown(ctx, err)
	}
	state, err = tx.Lock(ctx, r.Binding)
	if err == nil {
		err = s.admit(ctx, state, retained, nil)
	}
	var chosen *generated.SignatureFitSelection
	if err == nil {
		chosen, err = tx.Select(ctx, r, uuid.New())
	}
	if err != nil {
		rollback(tx)
	} else {
		err = tx.Commit(ctx)
	}
	if err != nil {
		// Even an INSERT error may be a competing committed winner. Negative SQL
		// reconciliation is durable under parent lock; no storage cleanup occurs.
		chosen, err = s.reconcile(ctx, r)
		if err != nil {
			return nil, err
		}
	}
	return s.resumeRow(ctx, chosen)
}

// ResumeV1 never calls a renderer, span generator, PUT or mutable font assets.
// It reads the stable SQL selection, archived manifest and exact object pins.
func (s *ServiceV1) ResumeV1(ctx context.Context, b manualfit.BindingV1) (*SelectedV1, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	if !validBinding(b) {
		return nil, ErrInvalidV1
	}
	row, err := s.lookup(ctx, b)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotSelectedV1
	}
	if err != nil {
		return nil, publicError(ctx, err)
	}
	if !sameCeremonyAuthority(row, b) {
		return nil, ErrAuthorityChangedV1
	}
	return s.resumeRow(ctx, row)
}
func (s *ServiceV1) lookup(ctx context.Context, b manualfit.BindingV1) (*generated.SignatureFitSelection, error) {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	return tx.FindSelection(ctx, b)
}
func (s *ServiceV1) observeAttempt(ctx context.Context, r RequestV1) error {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollback(tx)
	state, err := tx.Lock(ctx, r.Binding)
	if err != nil {
		return err
	}
	if state.Preparation == nil || !state.Preparation.SelectionCommitAttemptedAt.Valid || state.Preparation.SelectionNotCommittedAt.Valid || state.Preparation.OwnerID != r.OwnerID {
		return ErrOutcomeUnknownV1
	}
	return nil
}
func (s *ServiceV1) reconcile(ctx context.Context, r RequestV1) (*generated.SignatureFitSelection, error) {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, unknown(ctx, err)
	}
	_, err = tx.Lock(ctx, r.Binding)
	if err != nil {
		rollback(tx)
		return nil, unknown(ctx, err)
	}
	chosen, err := tx.FindSelection(ctx, r.Binding)
	if err == nil {
		rollback(tx)
		if !sameCeremonyAuthority(chosen, r.Binding) {
			return nil, ErrAuthorityChangedV1
		}
		return chosen, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		rollback(tx)
		return nil, unknown(ctx, err)
	}
	_, err = tx.MarkNotCommitted(ctx, r)
	if err != nil {
		rollback(tx)
		return nil, unknown(ctx, err)
	}
	if err = tx.Commit(ctx); err != nil {
		check, e := s.Store.Begin(ctx)
		if e != nil {
			return nil, unknown(ctx, e)
		}
		defer rollback(check)
		state, e := check.Lock(ctx, r.Binding)
		if e != nil || state.Preparation == nil || !state.Preparation.SelectionNotCommittedAt.Valid {
			return nil, unknown(ctx, e)
		}
	}
	return nil, ErrNotSelectedV1
}
func (s *ServiceV1) resumeRow(ctx context.Context, row *generated.SignatureFitSelection) (*SelectedV1, error) {
	b, pin, err := selectionPins(row)
	if err != nil {
		return nil, err
	}
	retained, err := manualfit.VerifyRetainedV1(ctx, s.Reader, pin, b)
	if err != nil {
		return nil, publicError(ctx, err)
	}
	if row.RetentionCompletedAt.Valid {
		if err = s.checkAdmitted(ctx, row, retained); err != nil {
			return nil, err
		}
		return &SelectedV1{cloneSelection(row), retained}, nil
	}
	// Commit and positively observe the start checkpoint before irreversible IO.
	row, err = s.retentionCheckpoint(ctx, row, retained, false)
	if err != nil {
		return nil, err
	}
	retained, err = manualfit.RetainVerifiedV1(ctx, s.Reader, s.Retainer, pin, b, row.RetainUntil.Time.UTC())
	if err != nil {
		return nil, errors.Join(ErrRetentionPendingV1, publicError(ctx, err))
	}
	row, err = s.retentionCheckpoint(ctx, row, retained, true)
	if err != nil {
		return nil, err
	}
	return &SelectedV1{cloneSelection(row), retained}, nil
}
func (s *ServiceV1) checkAdmitted(ctx context.Context, row *generated.SignatureFitSelection, r *manualfit.RetainedV1) error {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return publicError(ctx, err)
	}
	defer rollback(tx)
	state, err := tx.Lock(ctx, r.Manifest().Binding())
	if err != nil {
		return publicError(ctx, err)
	}
	fresh, err := tx.FindSelection(ctx, r.Manifest().Binding())
	if err != nil || !sameSelection(fresh, row) {
		return ErrAuthorityChangedV1
	}
	return s.admit(ctx, state, r, fresh)
}
func (s *ServiceV1) retentionCheckpoint(ctx context.Context, row *generated.SignatureFitSelection, r *manualfit.RetainedV1, complete bool) (*generated.SignatureFitSelection, error) {
	tx, err := s.Store.Begin(ctx)
	if err != nil {
		return nil, unknown(ctx, err)
	}
	state, err := tx.Lock(ctx, r.Manifest().Binding())
	if err == nil {
		var fresh *generated.SignatureFitSelection
		fresh, err = tx.FindSelection(ctx, r.Manifest().Binding())
		if err == nil && !sameSelection(row, fresh) {
			err = ErrAuthorityChangedV1
		}
		if err == nil {
			row = fresh
		}
	}
	if err == nil {
		err = s.admit(ctx, state, r, row)
	}
	var marked *generated.SignatureFitSelection
	if err == nil {
		if complete {
			marked, err = tx.MarkRetentionComplete(ctx, row)
		} else {
			marked, err = tx.MarkRetentionStarted(ctx, row)
		}
	}
	if err != nil {
		rollback(tx)
		return nil, publicError(ctx, err)
	}
	if err = tx.Commit(ctx); err == nil {
		return marked, nil
	}
	fresh, e := s.lookup(ctx, r.Manifest().Binding())
	if e != nil || !sameSelection(row, fresh) || (!complete && !fresh.RetentionStartedAt.Valid) || (complete && !fresh.RetentionCompletedAt.Valid) {
		return nil, unknown(ctx, e)
	}
	return fresh, nil
}
func (s *ServiceV1) admit(ctx context.Context, state LockedStateV1, r *manualfit.RetainedV1, row *generated.SignatureFitSelection) error {
	if err := ctx.Err(); err != nil {
		return contextualV1(ErrAdmissionV1, ctx)
	}
	if r == nil {
		return ErrInvalidV1
	}
	m := r.Manifest()
	if err := ValidateLockedAuthorityV1(state, m, r.ManifestObject()); err != nil {
		return err
	}
	state.Manifest = m
	a, err := s.Admit(ctx, state)
	if err != nil {
		return publicError(ctx, err)
	}
	floor := retentionFloor(m.Binding().CeremonyEpoch)
	if row != nil {
		if _, _, err := selectionPins(row); err != nil {
			return err
		}
		floor = row.RetainUntil.Time.UTC()
	}
	if err := ValidateLockedAuthorityV1(state, m, r.ManifestObject()); err != nil {
		return err
	}
	if !a.permitted || !a.floor.Equal(floor) || !a.budget.matches(state) {
		return ErrAdmissionV1
	}
	if ctx.Err() != nil {
		return contextualV1(ErrAdmissionV1, ctx)
	}
	return nil
}
func retentionFloor(epoch time.Time) time.Time { return storage.EvidenceRetentionDeadline(epoch, 7) }
func rollback(tx TransactionV1) {
	if tx == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func publicError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return contextualV1(ErrAdmissionV1, ctx)
	}
	for _, sentinel := range []error{ErrInvalidV1, ErrAuthorityChangedV1, ErrOutcomeUnknownV1, ErrNotSelectedV1, ErrRetentionPendingV1, ErrAdmissionV1, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, sentinel) {
			return errors.Join(ErrAdmissionV1, sentinel)
		}
	}
	return ErrAdmissionV1
}
func unknown(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return contextualV1(ErrOutcomeUnknownV1, ctx)
	}
	if errors.Is(err, context.Canceled) {
		return errors.Join(ErrOutcomeUnknownV1, context.Canceled)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(ErrOutcomeUnknownV1, context.DeadlineExceeded)
	}
	return ErrOutcomeUnknownV1
}
func validBinding(b manualfit.BindingV1) bool {
	_, e := decodeDigest(b.AuthoritySHA256)
	return e == nil && b.OperationID != uuid.Nil && b.OrgID != uuid.Nil && b.DocumentID != uuid.Nil && b.RecipientID != uuid.Nil && !b.CeremonyEpoch.IsZero() && b.CeremonyEpoch.Year() >= 1 && b.CeremonyEpoch.Year() <= 9999
}
func decodeDigest(s string) ([]byte, error) {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != sha256.Size || hex.EncodeToString(b) != s || s == strings.Repeat("0", 64) {
		return nil, ErrInvalidV1
	}
	return b, nil
}
func sameCeremonyAuthority(row *generated.SignatureFitSelection, b manualfit.BindingV1) bool {
	return row != nil && row.OrgID == b.OrgID && row.DocumentID == b.DocumentID && row.RecipientID == b.RecipientID && row.CeremonyEpoch.Valid && row.CeremonyEpoch.Time.Equal(b.CeremonyEpoch) && hex.EncodeToString(row.AuthoritySha256) == b.AuthoritySHA256
}
func selectionPins(row *generated.SignatureFitSelection) (manualfit.BindingV1, manualfit.ObjectPinV1, error) {
	if row == nil || row.ID == uuid.Nil || !row.CeremonyEpoch.Valid || !row.RetainUntil.Valid || row.RetainUntil.Time.IsZero() || row.RetainUntil.Time.Nanosecond() != 0 || !row.RetainUntil.Time.Equal(retentionFloor(row.CeremonyEpoch.Time)) {
		return manualfit.BindingV1{}, manualfit.ObjectPinV1{}, ErrInvalidV1
	}
	b := manualfit.BindingV1{OperationID: row.PreparationID, OrgID: row.OrgID, DocumentID: row.DocumentID, RecipientID: row.RecipientID, CeremonyEpoch: row.CeremonyEpoch.Time.UTC(), AuthoritySHA256: hex.EncodeToString(row.AuthoritySha256)}
	if !validBinding(b) || len(row.ManifestSha256) != 32 || len(row.SpanSha256) != 32 || len(row.SourceSha256) != 32 || len(row.GeometrySha256) != 32 || row.ManifestBytes < 1 || row.ManifestBytes > manualfit.MaxManifestBytesV1 || row.ManifestStorageKey != manualfit.ObjectPrefixV1(b.OperationID, b.OrgID, b.DocumentID)+"manifest.json" {
		return b, manualfit.ObjectPinV1{}, ErrInvalidV1
	}
	return b, manualfit.ObjectPinV1{Key: row.ManifestStorageKey, VersionID: row.ManifestVersionID, SHA256: hex.EncodeToString(row.ManifestSha256), Bytes: row.ManifestBytes, ContentType: "application/json"}, nil
}
func cloneSelection(row *generated.SignatureFitSelection) *generated.SignatureFitSelection {
	if row == nil {
		return nil
	}
	v := *row
	v.AuthoritySha256 = bytes.Clone(row.AuthoritySha256)
	v.SourceSha256 = bytes.Clone(row.SourceSha256)
	v.GeometrySha256 = bytes.Clone(row.GeometrySha256)
	v.SpanSha256 = bytes.Clone(row.SpanSha256)
	v.ManifestSha256 = bytes.Clone(row.ManifestSha256)
	return &v
}
func sameSelection(a, b *generated.SignatureFitSelection) bool {
	if a == nil || b == nil {
		return false
	}
	ap, am, ae := selectionPins(a)
	bp, bm, be := selectionPins(b)
	return ae == nil && be == nil && a.ID == b.ID && ap == bp && am == bm && a.SourceStorageKey == b.SourceStorageKey && a.SourceVersionID == b.SourceVersionID && bytes.Equal(a.SourceSha256, b.SourceSha256) && a.SourceBytes == b.SourceBytes && bytes.Equal(a.GeometrySha256, b.GeometrySha256) && a.SpanStorageKey == b.SpanStorageKey && a.SpanVersionID == b.SpanVersionID && bytes.Equal(a.SpanSha256, b.SpanSha256) && a.SpanBytes == b.SpanBytes && a.RetainUntil.Time.Equal(b.RetainUntil.Time)
}

// Preserve caller cancellation identity for errors.Is without rendering a
// private cancellation cause in logs or public error text.
type contextFailureV1 struct{ kind, ctxErr, cause error }

func (e contextFailureV1) Error() string   { return e.kind.Error() + ": " + e.ctxErr.Error() }
func (e contextFailureV1) Unwrap() []error { return []error{e.kind, e.ctxErr, e.cause} }
func contextualV1(kind error, ctx context.Context) error {
	return contextFailureV1{kind, ctx.Err(), context.Cause(ctx)}
}
