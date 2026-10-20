// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrFittedOutputJournalV1       = errors.New("sign: fitted output journal unavailable")
	ErrFittedOutputAuthorityV1     = errors.New("sign: fitted output journal authority changed")
	ErrFittedOutputAttemptExistsV1 = errors.New("sign: original fitted output attempt requires read-only recovery")
	ErrFittedOutputSQLUnknownV1    = errors.New("sign: fitted output SQL outcome or physical cleanup remains unresolved")
	ErrFittedOutputResourcesV1     = errors.New("sign: fitted output resources not admitted")
)

type fittedOutputErrorTypeV1 struct {
	phase  error
	causes []error
}

func (e fittedOutputErrorTypeV1) Error() string { return ErrFittedOutputJournalV1.Error() }
func (e fittedOutputErrorTypeV1) Unwrap() []error {
	out := []error{ErrFittedOutputJournalV1}
	if e.phase != nil {
		out = append(out, e.phase)
	}
	return append(out, e.causes...)
}
func fittedOutputErrorV1(ctx context.Context, phase error) error {
	e := fittedOutputErrorTypeV1{phase: phase}
	if ctx != nil && ctx.Err() != nil {
		e.causes = append(e.causes, ctx.Err())
		if c := context.Cause(ctx); c != nil && c != ctx.Err() {
			e.causes = append(e.causes, c)
		}
	}
	return e
}

type FittedOutputRequestV1 struct {
	Reservation storage.FittedFinalizationReservationV1
	OwnerID     uuid.UUID
}

// Admission reserves shared application memory/capacity, not signing rights.
// The permit must remain owned until release even if its context is canceled.
// Producer allocation before calling ReserveOriginalV1 and full expanded ZIP
// admission remain independent mandatory orchestration gates.
type FittedOutputResourceRequestV1 struct {
	OrgID, DocumentID, PreparationID uuid.UUID
	Kind                             string
	BodyBytes, WorkingBytes          int64
}
type FittedOutputAdmissionFuncV1 func(context.Context, FittedOutputResourceRequestV1) (release func(), err error)
type FittedOutputStorageV1 interface {
	PutFittedFinalizationReservedV1(context.Context, storage.FittedFinalizationReservationV1, []byte) (storage.StoredObject, error)
	ResolveFittedFinalizationVersionV1(context.Context, storage.FittedFinalizationReservationV1, string) (storage.FittedFinalizationObservationV1, error)
}

var _ FittedOutputStorageV1 = (*storage.Client)(nil)

// Receipt has no original body, private provider error, credential or name.
// A positive version survives late provider/SQL failure and caller cancellation.
// Verified describes this bounded storage observation, not publication/legal
// effect. SQLUncertain and AttemptCommitted never authorize another PUT.
type FittedOutputReceiptV1 struct {
	object                                                                manualfit.ObjectPinV1
	request                                                               FittedOutputRequestV1
	originalKnown                                                         bool
	reserved, attemptCommitted, providerAttempted, verified, sqlUncertain bool
	observation                                                           storage.FittedFinalizationObservationStateV1
}

func (r FittedOutputReceiptV1) Object() manualfit.ObjectPinV1 { return r.object }
func (r FittedOutputReceiptV1) Reserved() bool                { return r.reserved }
func (r FittedOutputReceiptV1) AttemptCommitted() bool        { return r.attemptCommitted }
func (r FittedOutputReceiptV1) ProviderAttempted() bool       { return r.providerAttempted }
func (r FittedOutputReceiptV1) Verified() bool                { return r.verified }
func (r FittedOutputReceiptV1) SQLUncertain() bool            { return r.sqlUncertain }
func (r FittedOutputReceiptV1) Observation() storage.FittedFinalizationObservationStateV1 {
	return r.observation
}

// A returned operation can still own a quarantined physical SQL session.
// Its resource permit and temporary bodies remain owned until all actual
// joined client/server retirement witnesses arrive; logical closure never frees this budget.
type fittedOutputResourceLeaseV1 struct {
	mu                 sync.Mutex
	holds              int
	returned, released bool
	release            func()
	bodies             [][]byte
}
type fittedOutputResourceContextKeyV1 struct{}

func (l *fittedOutputResourceLeaseV1) context(ctx context.Context) context.Context {
	return context.WithValue(ctx, fittedOutputResourceContextKeyV1{}, l)
}
func (l *fittedOutputResourceLeaseV1) hold() { l.mu.Lock(); l.holds++; l.mu.Unlock() }
func (l *fittedOutputResourceLeaseV1) ownBody(body []byte) {
	l.mu.Lock()
	l.bodies = append(l.bodies, body)
	l.mu.Unlock()
}
func (l *fittedOutputResourceLeaseV1) releaseOwner() {
	l.mu.Lock()
	l.returned = true
	l.mu.Unlock()
	l.maybeRelease()
}
func (l *fittedOutputResourceLeaseV1) releasePhysical() {
	l.mu.Lock()
	if l.holds > 0 {
		l.holds--
	}
	l.mu.Unlock()
	l.maybeRelease()
}
func (l *fittedOutputResourceLeaseV1) maybeRelease() {
	l.mu.Lock()
	if l.released || !l.returned || l.holds != 0 {
		l.mu.Unlock()
		return
	}
	l.released = true
	bodies, release := l.bodies, l.release
	l.bodies = nil
	l.mu.Unlock()
	for _, body := range bodies {
		clear(body)
	}
	release()
}

type fittedOutputOperationV1 struct {
	id, org, document, owner                                                                                                 uuid.UUID
	status, documentStatus                                                                                                   string
	epoch, completion, retain, lease                                                                                         pgtype.Timestamptz
	leaseCurrent                                                                                                             bool
	attempts                                                                                                                 int32
	basePages                                                                                                                []int32
	baseLimit, finalLimit, indexLimit, certificatePDFLimit, certificatePayloadLimit, certificateSignatureLimit, archiveLimit int64
	retentionStarted, retentionCompleted                                                                                     pgtype.Timestamptz
	auditBytes, certificateInputBytes                                                                                        int64
	auditSHA, certificateInputSHA                                                                                            []byte
}
type fittedOutputTransactionV1 interface {
	Lock(context.Context, FittedOutputRequestV1) (*fittedOutputOperationV1, *generated.ListFittedFinalizationOutputsRow, error)
	Reserve(context.Context, FittedOutputRequestV1, []byte) (*generated.ListFittedFinalizationOutputsRow, error)
	ParentStart(context.Context, FittedOutputRequestV1) (pgtype.Timestamptz, error)
	RowStart(context.Context, FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error)
	Attempt(context.Context, FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error)
	Body(context.Context, FittedOutputRequestV1) ([]byte, error)
	Pin(context.Context, FittedOutputRequestV1, string) (*generated.ListFittedFinalizationOutputsRow, error)
	Readback(context.Context, FittedOutputRequestV1, string) (*generated.ListFittedFinalizationOutputsRow, error)
	Retained(context.Context, FittedOutputRequestV1, string) (*generated.ListFittedFinalizationOutputsRow, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}
type fittedOutputBackendV1 interface {
	Begin(context.Context, uuid.UUID, uuid.UUID) (fittedOutputTransactionV1, error)
	Drain(context.Context, bool) error
}
type FittedOutputJournalV1 struct {
	backend fittedOutputBackendV1
	storage FittedOutputStorageV1
	admit   FittedOutputAdmissionFuncV1
}

// Keep one adapter for the application lifetime and join it on shutdown.
// Fresh sessions use only the saved pool configuration; this does not close or
// replace the caller-owned pool, grant scope, select renderer bytes, or Sign.
func NewFittedOutputJournalV1(pool *pgxpool.Pool, store FittedOutputStorageV1, admit FittedOutputAdmissionFuncV1, work *pdfadmission.WorkAdmissionV1, profile pdfadmission.ApplicationSessionProfileV1) (*FittedOutputJournalV1, error) {
	if pool == nil || fittedRecoveryNilV1(store) || admit == nil || work == nil || pool.Config().MaxConns < 1 {
		return nil, ErrFittedOutputJournalV1
	}
	factory, err := pdfadmission.NewApplicationSessionFactoryV1(pool.Config().ConnConfig.Copy(), work, profile)
	if err != nil {
		return nil, ErrFittedOutputJournalV1
	}
	return &FittedOutputJournalV1{backend: newFittedOutputPostgresV1(factory), storage: store, admit: admit}, nil
}
func (j *FittedOutputJournalV1) ReconcileCleanupV1(ctx context.Context) error {
	if j == nil || j.backend == nil {
		return ErrFittedOutputJournalV1
	}
	return j.backend.Drain(ctx, false)
}
func (j *FittedOutputJournalV1) CloseV1(ctx context.Context) error {
	if j == nil || j.backend == nil {
		return ErrFittedOutputJournalV1
	}
	return j.backend.Drain(ctx, true)
}
func fittedOutputReceiptV1(r FittedOutputRequestV1) FittedOutputReceiptV1 {
	return FittedOutputReceiptV1{request: r, object: manualfit.ObjectPinV1{Key: r.Reservation.Key, SHA256: hex.EncodeToString(r.Reservation.SHA256[:]), Bytes: r.Reservation.Bytes, ContentType: r.Reservation.ContentType}, observation: storage.FittedFinalizationUnresolvedV1}
}

func fittedOutputSameRequestV1(a, b FittedOutputRequestV1) bool {
	x, y := a.Reservation, b.Reservation
	return a.OwnerID == b.OwnerID && x.OrgID == y.OrgID && x.DocumentID == y.DocumentID && x.PreparationID == y.PreparationID && x.Kind == y.Kind && x.Page == y.Page && x.Key == y.Key && x.SHA256 == y.SHA256 && x.Bytes == y.Bytes && x.ContentType == y.ContentType && x.CompletionEffectiveAt.Equal(y.CompletionEffectiveAt) && x.RetainUntil.Equal(y.RetainUntil)
}

func fittedOutputRequestValidV1(r FittedOutputRequestV1) bool {
	v := r.Reservation
	if r.OwnerID == uuid.Nil || v.OrgID == uuid.Nil || v.DocumentID == uuid.Nil || v.PreparationID == uuid.Nil || v.SHA256 == [32]byte{} || v.CompletionEffectiveAt.IsZero() || v.CompletionEffectiveAt.UTC().Year() < 1 || v.CompletionEffectiveAt.UTC().Year() > 9999 || !v.RetainUntil.Equal(storage.EvidenceRetentionDeadline(v.CompletionEffectiveAt, article13.RetentionYearsV1)) || v.RetainUntil.UTC().Year() < 1 || v.RetainUntil.UTC().Year() > 9999 || v.RetainUntil.Nanosecond() != 0 || !fittedRecoveryKeyV1(v.Key) {
		return false
	}
	prefix := "org/" + v.OrgID.String() + "/documents/" + v.DocumentID.String() + "/"
	digest := hex.EncodeToString(v.SHA256[:])
	key, media := "", "application/pdf"
	var max int64
	switch v.Kind {
	case "base_pdf":
		if v.Page < 1 || v.Page > 500 {
			return false
		}
		key = prefix + "finalization/base/" + v.PreparationID.String() + "/page-" + strconv.Itoa(int(v.Page)) + ".pdf"
		max = manualfit.MaxArchiveBasePDFBytesV1
	case "final_pdf":
		key = prefix + "final-" + digest + ".pdf"
		max = manualfit.MaxFinalPDFBytesV1
	case "fits_index":
		key = manualfit.IndexStorageKeyV1(v.OrgID, v.DocumentID, v.PreparationID)
		media = "application/json"
		max = manualfit.MaxFitsIndexBytesV1
	case "certificate_pdf":
		key = prefix + "audit-" + digest + ".pdf"
		max = manualfit.MaxCertificatePDFBytesV1
	case "certificate_payload":
		key = prefix + "audit-payload-" + digest + ".txt"
		media = "text/plain"
		max = manualfit.MaxCertificatePayloadBytesV1
	case "certificate_signature":
		key = prefix + "audit-signature-" + digest + ".txt"
		media = "text/plain"
		max = manualfit.MaxCertificateSignatureBytesV1
	default:
		return false
	}
	return v.Key == key && v.ContentType == media && v.Bytes > 0 && v.Bytes <= max && (v.Kind == "base_pdf" || v.Page == 0)
}
func (j *FittedOutputJournalV1) admission(ctx context.Context, r FittedOutputRequestV1) (*fittedOutputResourceLeaseV1, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, fittedOutputErrorV1(ctx, nil)
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return nil, fittedOutputErrorV1(ctx, ErrFittedOutputResourcesV1)
	}
	if j == nil || fittedRecoveryNilV1(j.backend) || fittedRecoveryNilV1(j.storage) || j.admit == nil || !fittedOutputRequestValidV1(r) {
		return nil, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	v := r.Reservation
	// Driver/body/SDK/readback copies plus bounded legacy parent-return bytes.
	release, err := j.admit(ctx, FittedOutputResourceRequestV1{OrgID: v.OrgID, DocumentID: v.DocumentID, PreparationID: v.PreparationID, Kind: v.Kind, BodyBytes: v.Bytes, WorkingBytes: 4*v.Bytes + 11*(1<<20)})
	if err != nil || release == nil || ctx.Err() != nil {
		if release != nil {
			release()
		}
		return nil, fittedOutputErrorV1(ctx, ErrFittedOutputResourcesV1)
	}
	return &fittedOutputResourceLeaseV1{release: release}, nil
}
func fittedOutputValidateOperationV1(p *fittedOutputOperationV1, r FittedOutputRequestV1, write bool) error {
	v := r.Reservation
	if p == nil || p.id != v.PreparationID || p.org != v.OrgID || p.document != v.DocumentID || !finiteFittedTimeV1(p.epoch) || !finiteFittedTimeV1(p.completion) || !finiteFittedTimeV1(p.retain) || !p.completion.Time.Equal(v.CompletionEffectiveAt) || !p.retain.Time.Equal(v.RetainUntil) || !p.completion.Time.After(p.epoch.Time) || p.attempts < 1 || p.attempts > 8 || len(p.basePages) > 500 || p.archiveLimit < 1 || p.archiveLimit > manualfit.MaxEvidenceBytesV1 {
		return ErrFittedOutputAuthorityV1
	}
	if (p.status != "staging" && p.status != "prepared" && p.status != "published") || (p.documentStatus != "finalizing" && p.documentStatus != "completed") || (p.status == "published") != (p.documentStatus == "completed") {
		return ErrFittedOutputAuthorityV1
	}
	if p.retentionStarted.Valid && !finiteFittedTimeV1(p.retentionStarted) || p.retentionCompleted.Valid && (!finiteFittedTimeV1(p.retentionCompleted) || !p.retentionStarted.Valid || p.retentionCompleted.Time.Before(p.retentionStarted.Time)) || p.status == "staging" && p.retentionCompleted.Valid {
		return ErrFittedOutputAuthorityV1
	}
	if write && (p.owner != r.OwnerID || !p.leaseCurrent || !finiteFittedTimeV1(p.lease) || p.status == "published" || p.documentStatus != "finalizing") {
		return ErrFittedOutputAuthorityV1
	}
	var max int64
	switch v.Kind {
	case "base_pdf":
		max = p.baseLimit
		found := false
		last := int32(0)
		for _, page := range p.basePages {
			if page <= last || page > 500 {
				return ErrFittedOutputAuthorityV1
			}
			last = page
			if page == v.Page {
				found = true
			}
		}
		if !found {
			return ErrFittedOutputAuthorityV1
		}
	case "final_pdf":
		max = p.finalLimit
	case "fits_index":
		max = p.indexLimit
	case "certificate_pdf":
		max = p.certificatePDFLimit
	case "certificate_payload":
		max = p.certificatePayloadLimit
	case "certificate_signature":
		max = p.certificateSignatureLimit
	}
	if max < 1 || v.Bytes > max || p.auditBytes < 1 || p.auditBytes > 4<<20 || len(p.auditSHA) != 32 {
		return ErrFittedOutputAuthorityV1
	}
	if v.Kind == "certificate_pdf" || v.Kind == "certificate_payload" || v.Kind == "certificate_signature" {
		if p.certificateInputBytes < 1 || p.certificateInputBytes > 4<<20 || len(p.certificateInputSHA) != 32 {
			return ErrFittedOutputAuthorityV1
		}
	}
	if v.Kind == "certificate_payload" && (p.certificateInputBytes != v.Bytes || !bytes.Equal(p.certificateInputSHA, v.SHA256[:])) {
		return ErrFittedOutputAuthorityV1
	}
	return nil
}
func fittedOutputValidateRowV1(o *generated.ListFittedFinalizationOutputsRow, r FittedOutputRequestV1) error {
	v := r.Reservation
	if o == nil || o.PreparationID != v.PreparationID || o.Kind != v.Kind || o.Page != v.Page || o.StorageKey != v.Key || o.Bytes != v.Bytes || o.ContentType != v.ContentType || !bytes.Equal(o.Sha256, v.SHA256[:]) {
		return ErrFittedOutputAuthorityV1
	}
	if o.RetentionStartedAt.Valid && !finiteFittedTimeV1(o.RetentionStartedAt) || o.UploadAttemptedAt.Valid && (!finiteFittedTimeV1(o.UploadAttemptedAt) || !o.RetentionStartedAt.Valid || o.UploadAttemptedAt.Time.Before(o.RetentionStartedAt.Time) || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) == uuid.Nil) || !o.UploadAttemptedAt.Valid && (o.UploadOwnerID.Valid || o.VersionID.Valid || o.ReadbackVerifiedAt.Valid || o.RetentionCompletedAt.Valid) {
		return ErrFittedOutputAuthorityV1
	}
	if o.VersionID.Valid && !manualfit.ValidObjectVersionV1(o.VersionID.String) || !o.VersionID.Valid && o.VersionID.String != "" || o.ReadbackVerifiedAt.Valid && (!finiteFittedTimeV1(o.ReadbackVerifiedAt) || !o.VersionID.Valid || o.ReadbackVerifiedAt.Time.Before(o.UploadAttemptedAt.Time)) || o.RetentionCompletedAt.Valid && (!finiteFittedTimeV1(o.RetentionCompletedAt) || !o.RetentionStartedAt.Valid || !o.ReadbackVerifiedAt.Valid || o.RetentionCompletedAt.Time.Before(o.ReadbackVerifiedAt.Time) || o.RetentionCompletedAt.Time.Before(o.RetentionStartedAt.Time)) {
		return ErrFittedOutputAuthorityV1
	}
	return nil
}
func fittedOutputObserveRowV1(receipt *FittedOutputReceiptV1, o *generated.ListFittedFinalizationOutputsRow) {
	receipt.reserved = true
	receipt.attemptCommitted = o.UploadAttemptedAt.Valid
	if o.VersionID.Valid && manualfit.ValidObjectVersionV1(o.VersionID.String) {
		receipt.object.VersionID = o.VersionID.String
		receipt.originalKnown = true
	}
}
func fittedOutputRollbackV1(tx fittedOutputTransactionV1) error {
	if tx == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}
func fittedOutputAbortV1(ctx context.Context, tx fittedOutputTransactionV1, receipt *FittedOutputReceiptV1, phase error) error {
	if fittedOutputRollbackV1(tx) != nil {
		receipt.sqlUncertain = true
		return fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	return fittedOutputErrorV1(ctx, phase)
}
func fittedOutputCleanupResultV1(ctx context.Context, tx fittedOutputTransactionV1, receipt *FittedOutputReceiptV1, retErr *error) {
	if fittedOutputRollbackV1(tx) != nil {
		receipt.sqlUncertain = true
		safe := fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		if *retErr != nil {
			safe = fittedOutputErrorTypeV1{phase: ErrFittedOutputSQLUnknownV1, causes: []error{*retErr, safe}}
		}
		*retErr = safe
	}
}
func fittedOutputFinishV1(ctx context.Context, receipt *FittedOutputReceiptV1, retErr *error) {
	if errors.Is(*retErr, ErrFittedOutputSQLUnknownV1) {
		receipt.sqlUncertain = true
	}
	if ctx != nil && ctx.Err() != nil {
		safe := fittedOutputErrorV1(ctx, nil)
		if *retErr != nil {
			safe = fittedOutputErrorTypeV1{causes: []error{*retErr, safe}}
		}
		*retErr = safe
	}
}

func (j *FittedOutputJournalV1) beginLocked(ctx context.Context, r FittedOutputRequestV1, write bool) (fittedOutputTransactionV1, *fittedOutputOperationV1, *generated.ListFittedFinalizationOutputsRow, error) {
	tx, err := j.backend.Begin(ctx, r.Reservation.OrgID, r.Reservation.DocumentID)
	if err != nil {
		return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	p, o, err := tx.Lock(ctx, r)
	if err != nil || ctx.Err() != nil || fittedOutputValidateOperationV1(p, r, write) != nil {
		if fittedOutputRollbackV1(tx) != nil {
			return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
		return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	if o != nil && o.RetentionStartedAt.Valid && (!p.retentionStarted.Valid || o.RetentionStartedAt.Time.Before(p.retentionStarted.Time)) {
		if fittedOutputRollbackV1(tx) != nil {
			return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
		return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	if o != nil && fittedOutputValidateRowV1(o, r) != nil {
		if fittedOutputRollbackV1(tx) != nil {
			return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
		return nil, nil, nil, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	return tx, p, o, nil
}

// ReserveOriginalV1 preserves the producer's exact once-created bytes before
// any attempt. Existing metadata is reconciled without body overwrite/copy.
// A failed/unknown commit performs no provider IO and never regenerates bytes.
func (j *FittedOutputJournalV1) ReserveOriginalV1(ctx context.Context, r FittedOutputRequestV1, payload []byte) (receipt FittedOutputReceiptV1, retErr error) {
	receipt = fittedOutputReceiptV1(r)
	defer fittedOutputFinishV1(ctx, &receipt, &retErr)
	permit, err := j.admission(ctx, r)
	if err != nil {
		return receipt, err
	}
	defer permit.releaseOwner()
	ctx = permit.context(ctx)
	if int64(len(payload)) != r.Reservation.Bytes || sha256.Sum256(payload) != r.Reservation.SHA256 {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	tx, p, o, err := j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	defer fittedOutputCleanupResultV1(ctx, tx, &receipt, &retErr)
	if o != nil {
		fittedOutputObserveRowV1(&receipt, o)
		return receipt, nil
	}
	if p.status != "staging" {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	original := bytes.Clone(payload)
	permit.ownBody(original)
	if ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, nil)
	}
	o, err = tx.Reserve(ctx, r, original)
	if err != nil || ctx.Err() != nil || fittedOutputValidateRowV1(o, r) != nil || o.UploadAttemptedAt.Valid {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	if err = tx.Commit(ctx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	fittedOutputObserveRowV1(&receipt, o)
	if ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, nil)
	}
	return receipt, nil
}

// UploadOriginalV1 is the sole original dispatch. It cannot consume a marker
// left by any previous invocation, even if provider history is currently empty.
// Only its own NEW attempt update + acknowledged commit + physical cleanup can
// mint permission. A fresh locked session fences concurrent reservation/owner
// changes during original-body retrieval, dispatch and exact checkpoints.
func (j *FittedOutputJournalV1) UploadOriginalV1(ctx context.Context, r FittedOutputRequestV1) (receipt FittedOutputReceiptV1, retErr error) {
	receipt = fittedOutputReceiptV1(r)
	defer fittedOutputFinishV1(ctx, &receipt, &retErr)
	permit, err := j.admission(ctx, r)
	if err != nil {
		return receipt, err
	}
	defer permit.releaseOwner()
	ctx = permit.context(ctx)
	// Commit retention starts independently before the original-attempt marker.
	tx, p, o, err := j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	if o == nil || p.status != "staging" {
		return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputAuthorityV1)
	}
	fittedOutputObserveRowV1(&receipt, o)
	if o.UploadAttemptedAt.Valid {
		return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputAttemptExistsV1)
	}
	if !p.retentionStarted.Valid {
		p.retentionStarted, err = tx.ParentStart(ctx, r)
		if err != nil || !finiteFittedTimeV1(p.retentionStarted) {
			return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputAuthorityV1)
		}
	}
	if !o.RetentionStartedAt.Valid {
		o, err = tx.RowStart(ctx, r)
		if err != nil || fittedOutputValidateRowV1(o, r) != nil || !finiteFittedTimeV1(o.RetentionStartedAt) {
			return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputAuthorityV1)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	if ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, nil)
	}
	tx, p, o, err = j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	if o == nil || p.status != "staging" || o.UploadAttemptedAt.Valid || !p.retentionStarted.Valid || !o.RetentionStartedAt.Valid {
		return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputAttemptExistsV1)
	}
	o, err = tx.Attempt(ctx, r)
	if err != nil || ctx.Err() != nil || fittedOutputValidateRowV1(o, r) != nil || !o.UploadAttemptedAt.Valid || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) != r.OwnerID {
		return receipt, fittedOutputAbortV1(ctx, tx, &receipt, ErrFittedOutputSQLUnknownV1)
	}
	if err = tx.Commit(ctx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	receipt.attemptCommitted = true
	if ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, nil)
	}
	// A previous invocation can never reach this private acknowledged path.
	tx, p, o, err = j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	defer fittedOutputCleanupResultV1(ctx, tx, &receipt, &retErr)
	if o == nil || p.status != "staging" || !o.UploadAttemptedAt.Valid || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) != r.OwnerID || o.VersionID.Valid || o.ReadbackVerifiedAt.Valid || !p.retentionStarted.Valid || !o.RetentionStartedAt.Valid {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	original, err := tx.Body(ctx, r)
	if err != nil {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	permit.ownBody(original)
	if ctx.Err() != nil || int64(len(original)) != r.Reservation.Bytes || sha256.Sum256(original) != r.Reservation.SHA256 {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	// Re-evaluate the SQL server clock immediately before dispatch while holding
	// the same parent/op locks. Expired headroom cannot authorize the original PUT.
	fresh, again, err := tx.Lock(ctx, r)
	if err != nil || ctx.Err() != nil || fittedOutputValidateOperationV1(fresh, r, true) != nil || fittedOutputValidateRowV1(again, r) != nil || !again.UploadAttemptedAt.Valid || again.VersionID.Valid || uuid.UUID(again.UploadOwnerID.Bytes) != r.OwnerID {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	receipt.providerAttempted = true
	stored, putErr := j.storage.PutFittedFinalizationReservedV1(ctx, r.Reservation, original)
	positive := manualfit.ValidObjectVersionV1(stored.VersionID)
	if positive {
		receipt.object.VersionID = stored.VersionID
	}
	if !positive || stored.SHA256 != r.Reservation.SHA256 {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	receipt.originalKnown = true
	// Preserve the positively known version under a bounded uncanceled context
	// when the provider reports a late error/cancel. SQL still checks current
	// scoped owner/server lease; failure retains the known pin in this receipt.
	checkpointCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	o, err = tx.Pin(checkpointCtx, r, stored.VersionID)
	if err != nil || fittedOutputValidateRowV1(o, r) != nil || !o.VersionID.Valid || o.VersionID.String != stored.VersionID {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	if err = tx.Commit(checkpointCtx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	if putErr != nil || ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	// The known original positive is now durable even if a later SQL checkpoint
	// fails. Fresh authority and exact resolver proof precede readback markers.
	verifyTx, _, verifiedRow, err := j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	defer fittedOutputCleanupResultV1(ctx, verifyTx, &receipt, &retErr)
	if verifiedRow == nil || !verifiedRow.VersionID.Valid || verifiedRow.VersionID.String != stored.VersionID {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	observation, resolveErr := j.storage.ResolveFittedFinalizationVersionV1(ctx, r.Reservation, stored.VersionID)
	receipt.observation = observation.State
	if resolveErr != nil || ctx.Err() != nil || observation.State != storage.FittedFinalizationVerifiedV1 || observation.Object.VersionID != stored.VersionID || observation.Object.SHA256 != r.Reservation.SHA256 {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	if !verifiedRow.ReadbackVerifiedAt.Valid {
		verifiedRow, err = verifyTx.Readback(ctx, r, stored.VersionID)
		if err != nil || fittedOutputValidateRowV1(verifiedRow, r) != nil || !verifiedRow.ReadbackVerifiedAt.Valid {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
	}
	if !verifiedRow.RetentionCompletedAt.Valid {
		verifiedRow, err = verifyTx.Retained(ctx, r, stored.VersionID)
		if err != nil || fittedOutputValidateRowV1(verifiedRow, r) != nil || !verifiedRow.RetentionCompletedAt.Valid {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
	}
	if err = verifyTx.Commit(ctx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	receipt.verified = true
	receipt.observation = storage.FittedFinalizationVerifiedV1
	return receipt, nil
}

// ResolveReadOnlyV1 performs no SQL mutation, original-body read, PUT, cleanup
// or compensation. Even an exact observation requires a separate current-owner
// checkpoint; empty-unresolved and a positive marker never permit reupload.
func (j *FittedOutputJournalV1) ResolveReadOnlyV1(ctx context.Context, r FittedOutputRequestV1, knownVersion string) (receipt FittedOutputReceiptV1, retErr error) {
	receipt = fittedOutputReceiptV1(r)
	defer fittedOutputFinishV1(ctx, &receipt, &retErr)
	if manualfit.ValidObjectVersionV1(knownVersion) {
		receipt.object.VersionID = knownVersion
	}
	permit, err := j.admission(ctx, r)
	if err != nil {
		return receipt, err
	}
	defer permit.releaseOwner()
	ctx = permit.context(ctx)
	if knownVersion != "" && !manualfit.ValidObjectVersionV1(knownVersion) {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	tx, _, o, err := j.beginLocked(ctx, r, false)
	if err != nil {
		return receipt, err
	}
	defer fittedOutputCleanupResultV1(ctx, tx, &receipt, &retErr)
	if o == nil || !o.UploadAttemptedAt.Valid {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAttemptExistsV1)
	}
	if o.VersionID.Valid && knownVersion != "" && o.VersionID.String != knownVersion {
		fittedOutputObserveRowV1(&receipt, o)
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	fittedOutputObserveRowV1(&receipt, o)
	observation, err := j.storage.ResolveFittedFinalizationVersionV1(ctx, r.Reservation, receipt.object.VersionID)
	if manualfit.ValidObjectVersionV1(observation.Object.VersionID) {
		receipt.object.VersionID = observation.Object.VersionID
	}
	receipt.observation = observation.State
	if err != nil || ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	if observation.State == storage.FittedFinalizationVerifiedV1 {
		if observation.Object.SHA256 != r.Reservation.SHA256 || !manualfit.ValidObjectVersionV1(observation.Object.VersionID) {
			return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
		}
		receipt.verified = true
	}
	return receipt, nil
}

// CheckpointExactV1 re-observes the provider under current scoped SQL authority;
// caller-supplied observation metadata is not verification. This never uploads.
func (j *FittedOutputJournalV1) CheckpointExactV1(ctx context.Context, r FittedOutputRequestV1, previous FittedOutputReceiptV1) (receipt FittedOutputReceiptV1, retErr error) {
	receipt = fittedOutputReceiptV1(r)
	defer fittedOutputFinishV1(ctx, &receipt, &retErr)
	knownVersion := previous.object.VersionID
	if knownVersion != "" && !fittedOutputSameRequestV1(previous.request, r) {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	if manualfit.ValidObjectVersionV1(knownVersion) {
		receipt.object.VersionID = knownVersion
		receipt.originalKnown = previous.originalKnown
	}
	permit, err := j.admission(ctx, r)
	if err != nil {
		return receipt, err
	}
	defer permit.releaseOwner()
	ctx = permit.context(ctx)
	if knownVersion != "" && !manualfit.ValidObjectVersionV1(knownVersion) {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	tx, _, o, err := j.beginLocked(ctx, r, true)
	if err != nil {
		return receipt, err
	}
	defer fittedOutputCleanupResultV1(ctx, tx, &receipt, &retErr)
	if o == nil || !o.UploadAttemptedAt.Valid {
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAttemptExistsV1)
	}
	if o.VersionID.Valid && knownVersion != "" && o.VersionID.String != knownVersion {
		fittedOutputObserveRowV1(&receipt, o)
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
	}
	fittedOutputObserveRowV1(&receipt, o)
	originalKnown := receipt.object.VersionID
	observation, resolveErr := j.storage.ResolveFittedFinalizationVersionV1(ctx, r.Reservation, originalKnown)
	positive := manualfit.ValidObjectVersionV1(observation.Object.VersionID)
	if positive {
		receipt.object.VersionID = observation.Object.VersionID
	}
	receipt.observation = observation.State
	exact := resolveErr == nil && ctx.Err() == nil && observation.State == storage.FittedFinalizationVerifiedV1 && positive && observation.Object.SHA256 == r.Reservation.SHA256
	// An unknown listing's first version is recovery information until sole
	// exact-history/body proof passes. A conflicting/unverified listing cannot
	// permanently choose this immutable original pin. Supplied/durable original
	// positives can be preserved on late resolver error/cancel without readback.
	preserve := positive && observation.Object.SHA256 == r.Reservation.SHA256 && (exact || receipt.originalKnown && originalKnown != "" && originalKnown == observation.Object.VersionID)
	if !preserve {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	checkpointCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if !o.VersionID.Valid {
		o, err = tx.Pin(checkpointCtx, r, receipt.object.VersionID)
		if err != nil || fittedOutputValidateRowV1(o, r) != nil || !o.VersionID.Valid || o.VersionID.String != receipt.object.VersionID {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
		if err = tx.Commit(checkpointCtx); err != nil {
			receipt.sqlUncertain = true
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
		receipt.originalKnown = true
		if !exact {
			return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
		}
		tx, _, o, err = j.beginLocked(ctx, r, true)
		if err != nil {
			return receipt, err
		}
		defer fittedOutputCleanupResultV1(ctx, tx, &receipt, &retErr)
		if o == nil || !o.VersionID.Valid || o.VersionID.String != receipt.object.VersionID {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
		proof, proofErr := j.storage.ResolveFittedFinalizationVersionV1(ctx, r.Reservation, receipt.object.VersionID)
		if proofErr != nil || ctx.Err() != nil || proof.State != storage.FittedFinalizationVerifiedV1 || proof.Object.VersionID != receipt.object.VersionID || proof.Object.SHA256 != r.Reservation.SHA256 {
			return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
		}
	}
	if !exact {
		return receipt, fittedOutputErrorV1(ctx, storage.ErrFittedFinalizationStorageV1)
	}
	if !o.ReadbackVerifiedAt.Valid {
		o, err = tx.Readback(ctx, r, receipt.object.VersionID)
		if err != nil || fittedOutputValidateRowV1(o, r) != nil || !o.ReadbackVerifiedAt.Valid {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
	}
	if !o.RetentionCompletedAt.Valid {
		o, err = tx.Retained(ctx, r, receipt.object.VersionID)
		if err != nil || fittedOutputValidateRowV1(o, r) != nil || !o.RetentionCompletedAt.Valid {
			return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputAuthorityV1)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		receipt.sqlUncertain = true
		return receipt, fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	receipt.originalKnown = true
	receipt.verified = true
	if ctx.Err() != nil {
		return receipt, fittedOutputErrorV1(ctx, nil)
	}
	return receipt, nil
}

// Every private work/observer session uses the one actual shared coordinator.
// The fixed production factory owns transport, query joins and same-server proof;
// no local semaphore, reaper or CleanupDone-only release remains. Observer grant
// remains charged on unproven final shutdown. The journal remains unwired to Sign.
type fittedOutputPostgresV1 struct {
	factory *pdfadmission.ApplicationSessionFactoryV1
	mu      sync.Mutex
	pending map[*pdfadmission.ApplicationSessionV1]*fittedOutputResourceLeaseV1
	closing bool
}

func newFittedOutputPostgresV1(factory *pdfadmission.ApplicationSessionFactoryV1) *fittedOutputPostgresV1 {
	return &fittedOutputPostgresV1{factory: factory, pending: make(map[*pdfadmission.ApplicationSessionV1]*fittedOutputResourceLeaseV1)}
}
func (p *fittedOutputPostgresV1) Begin(ctx context.Context, org, document uuid.UUID) (fittedOutputTransactionV1, error) {
	if p == nil || p.factory == nil || ctx == nil || org == uuid.Nil || document == uuid.Nil {
		return nil, ErrFittedOutputJournalV1
	}
	resources, _ := ctx.Value(fittedOutputResourceContextKeyV1{}).(*fittedOutputResourceLeaseV1)
	if resources == nil {
		return nil, ErrFittedOutputResourcesV1
	}
	p.mu.Lock()
	refuse := p.closing
	p.mu.Unlock()
	if refuse {
		return nil, ErrFittedOutputSQLUnknownV1
	}
	session, err := p.factory.OpenV1(ctx, org, document)
	if session != nil && session.WorkStartedV1() {
		resources.hold()
		p.mu.Lock()
		p.pending[session] = resources
		p.mu.Unlock()
	}
	if err != nil {
		if session != nil && session.WorkStartedV1() {
			_ = p.closeOwned(session)
		}
		return nil, ErrFittedOutputSQLUnknownV1
	}
	return &fittedOutputPostgresTransactionV1{owner: p, session: session}, nil
}
func (p *fittedOutputPostgresV1) releaseReady() {
	p.mu.Lock()
	var releases []*fittedOutputResourceLeaseV1
	for session, resource := range p.pending {
		if session.RetiredV1() {
			delete(p.pending, session)
			releases = append(releases, resource)
		}
	}
	p.mu.Unlock()
	for _, resource := range releases {
		resource.releasePhysical()
	}
}
func (p *fittedOutputPostgresV1) closeOwned(session *pdfadmission.ApplicationSessionV1) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := session.CloseV1(ctx)
	p.releaseReady()
	if err != nil {
		return ErrFittedOutputSQLUnknownV1
	}
	return nil
}
func (p *fittedOutputPostgresV1) Drain(ctx context.Context, closeNew bool) error {
	if p == nil || p.factory == nil || ctx == nil {
		return ErrFittedOutputJournalV1
	}
	if closeNew {
		p.mu.Lock()
		p.closing = true
		p.mu.Unlock()
		err := p.factory.CloseV1(ctx)
		p.releaseReady()
		if err != nil {
			return fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
		return nil
	}
	if _, ok := ctx.Deadline(); !ok {
		return fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
	}
	timer := time.NewTicker(100 * time.Millisecond)
	defer timer.Stop()
	for {
		err := p.factory.ReconcileCleanupV1(ctx)
		p.releaseReady()
		p.mu.Lock()
		pending := len(p.pending)
		p.mu.Unlock()
		if err == nil && pending == 0 {
			return nil
		}
		select {
		case <-timer.C:
		case <-ctx.Done():
			return fittedOutputErrorV1(ctx, ErrFittedOutputSQLUnknownV1)
		}
	}
}

type fittedOutputPostgresTransactionV1 struct {
	owner   *fittedOutputPostgresV1
	session *pdfadmission.ApplicationSessionV1
	q       *generated.Queries
	mu      sync.Mutex
	done    bool
}

func (t *fittedOutputPostgresTransactionV1) withSQL(ctx context.Context, fn func(context.Context) error) error {
	t.mu.Lock()
	done := t.done
	t.mu.Unlock()
	if done {
		return pgx.ErrTxClosed
	}
	return t.session.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) error {
		t.q = generated.New(db)
		defer func() { t.q = nil }()
		return fn(owned)
	})
}

func (t *fittedOutputPostgresTransactionV1) lockSQLV1(ctx context.Context, r FittedOutputRequestV1) (*fittedOutputOperationV1, *generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	// This bounded document read locks the real parent and rejects stale RR/SS
	// snapshots before any operation read. No HTML/name/field/UA body is copied.
	doc, err := t.q.GetFittedFinalizationRecoveryDocumentMetadata(ctx, generated.GetFittedFinalizationRecoveryDocumentMetadataParams{ID: v.DocumentID, OrgID: v.OrgID})
	if err != nil || doc.ID != v.DocumentID || doc.OrgID != v.OrgID || doc.DeletedAt.Valid || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || !doc.FitsIndexRequired || !doc.EvidenceVersionPinsRequired || !doc.Article13NoticeEpochV61Committed || !doc.CompletionEffectiveAtBound {
		return nil, nil, ErrFittedOutputAuthorityV1
	}
	p, err := t.q.GetFittedFinalizationOutputOperationMetadataForUpdate(ctx, generated.GetFittedFinalizationOutputOperationMetadataForUpdateParams{ID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	if err != nil {
		return nil, nil, ErrFittedOutputAuthorityV1
	}
	if p.DocumentStatus != doc.Status || p.DocumentDeletedAt.Valid || !finiteFittedTimeV1(doc.SentAt) || !finiteFittedTimeV1(doc.Article13NoticeEpochAt) || !finiteFittedTimeV1(doc.CompletionEffectiveAt) || !finiteFittedTimeV1(doc.FinalizationRetainUntil) || !doc.SentAt.Time.Equal(p.CeremonyEpoch.Time) || !doc.CompletionEffectiveAt.Time.Equal(p.CompletionEffectiveAt.Time) || !doc.FinalizationRetainUntil.Time.Equal(p.RetainUntil.Time) || !doc.Article13NoticeEpochAt.Time.Equal(p.CeremonyEpoch.Time) || !doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || doc.PdfStorageKey.String != p.SourceStorageKey || doc.PdfStorageVersionID.String != p.SourceVersionID || !bytes.Equal(doc.PdfSha256, p.SourceSha256) || p.SourceBytes < 1 || p.SourceBytes > manualfit.MaxFinalPDFBytesV1 || p.SourcePages < 1 || p.SourcePages > 500 || len(p.RequiredBasePages) > 500 || p.ExpectedOutputs < 5 || p.ExpectedOutputs > 505 || p.ExpectedOutputs != int32(len(p.RequiredBasePages)+5) || p.ExpectedReferences < 4 || p.ExpectedReferences > 9990 || p.FitReservedBytes < 1 || p.FitReservedBytes > manualfit.MaxEvidenceBytesV1 || !p.HasAuditSnapshot && p.AuditSnapshotBytes != 0 || !p.HasCertificateInput && p.CertificateInputBytes != 0 {
		return nil, nil, ErrFittedOutputAuthorityV1
	}
	operation := &fittedOutputOperationV1{id: p.ID, org: p.OrgID, document: p.DocumentID, owner: p.OwnerID, status: p.Status, documentStatus: doc.Status, epoch: p.CeremonyEpoch, completion: p.CompletionEffectiveAt, retain: p.RetainUntil, lease: p.LeaseUntil, leaseCurrent: p.LeaseCurrent, attempts: p.Attempts, basePages: append([]int32(nil), p.RequiredBasePages...), baseLimit: p.BaseBytesLimit, finalLimit: p.FinalPdfBytesLimit, indexLimit: p.FitsIndexBytesLimit, certificatePDFLimit: p.CertificatePdfBytesLimit, certificatePayloadLimit: p.CertificatePayloadBytesLimit, certificateSignatureLimit: p.CertificateSignatureBytesLimit, archiveLimit: p.ArchiveBudgetBytes, retentionStarted: p.RetentionStartedAt, retentionCompleted: p.RetentionCompletedAt, auditBytes: p.AuditSnapshotBytes, certificateInputBytes: p.CertificateInputBytes, auditSHA: bytes.Clone(p.AuditSnapshotSha256), certificateInputSHA: bytes.Clone(p.CertificateInputSha256)}
	output, err := t.q.GetFittedFinalizationOutputMetadata(ctx, generated.GetFittedFinalizationOutputMetadataParams{PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, Kind: v.Kind, Page: v.Page})
	if errors.Is(err, pgx.ErrNoRows) {
		return operation, nil, nil
	}
	if err != nil {
		return nil, nil, ErrFittedOutputAuthorityV1
	}
	return operation, (*generated.ListFittedFinalizationOutputsRow)(output), nil
}
func (t *fittedOutputPostgresTransactionV1) reserveSQLV1(ctx context.Context, r FittedOutputRequestV1, body []byte) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.ReserveFittedFinalizationOutput(ctx, generated.ReserveFittedFinalizationOutputParams{Kind: v.Kind, Page: v.Page, StorageKey: v.Key, Payload: body, ContentType: v.ContentType, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) parentStartSQLV1(ctx context.Context, r FittedOutputRequestV1) (pgtype.Timestamptz, error) {
	v := r.Reservation
	p, err := t.q.MarkFittedFinalizationRetentionStarted(ctx, generated.MarkFittedFinalizationRetentionStartedParams{PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	if err != nil || p == nil {
		return pgtype.Timestamptz{}, ErrFittedOutputAuthorityV1
	}
	// The existing mutation returns a bounded legacy parent row. Own those
	// temporary bytea copies through physical cleanup; never log or expose them.
	resources, _ := ctx.Value(fittedOutputResourceContextKeyV1{}).(*fittedOutputResourceLeaseV1)
	for _, body := range [][]byte{p.GeometryPagesPayload, p.FieldSnapshotPayload, p.AuditSnapshotPayload, p.CertificateInputPayload} {
		if resources != nil {
			resources.ownBody(body)
		}
	}
	if p.ID != v.PreparationID || p.OrgID != v.OrgID || p.DocumentID != v.DocumentID || p.OwnerID != r.OwnerID || !p.CompletionEffectiveAt.Time.Equal(v.CompletionEffectiveAt) || !p.RetainUntil.Time.Equal(v.RetainUntil) {
		return pgtype.Timestamptz{}, ErrFittedOutputAuthorityV1
	}
	return p.RetentionStartedAt, nil
}
func (t *fittedOutputPostgresTransactionV1) rowStartSQLV1(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.MarkFittedFinalizationOutputRetentionStarted(ctx, generated.MarkFittedFinalizationOutputRetentionStartedParams{Kind: v.Kind, Page: v.Page, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) attemptSQLV1(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.MarkFittedFinalizationOutputOriginalUploadAttempt(ctx, generated.MarkFittedFinalizationOutputOriginalUploadAttemptParams{Kind: v.Kind, Page: v.Page, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) bodySQLV1(ctx context.Context, r FittedOutputRequestV1) ([]byte, error) {
	v := r.Reservation
	o, err := t.q.GetFittedFinalizationOutput(ctx, generated.GetFittedFinalizationOutputParams{PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, Kind: v.Kind, Page: v.Page})
	if err != nil || o == nil || o.PreparationID != v.PreparationID || o.Kind != v.Kind || o.Page != v.Page || o.StorageKey != v.Key || o.Bytes != v.Bytes || o.ContentType != v.ContentType || !bytes.Equal(o.Sha256, v.SHA256[:]) {
		if o != nil {
			clear(o.Payload)
		}
		return nil, ErrFittedOutputAuthorityV1
	}
	return o.Payload, nil
}
func (t *fittedOutputPostgresTransactionV1) pinSQLV1(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.PinFittedFinalizationOutputVersion(ctx, generated.PinFittedFinalizationOutputVersionParams{VersionID: pgtype.Text{String: version, Valid: true}, Kind: v.Kind, Page: v.Page, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) readbackSQLV1(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.MarkFittedFinalizationOutputReadbackVerified(ctx, generated.MarkFittedFinalizationOutputReadbackVerifiedParams{Kind: v.Kind, Page: v.Page, VersionID: pgtype.Text{String: version, Valid: true}, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) retainedSQLV1(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	v := r.Reservation
	o, err := t.q.MarkFittedFinalizationOutputRetentionComplete(ctx, generated.MarkFittedFinalizationOutputRetentionCompleteParams{Kind: v.Kind, Page: v.Page, VersionID: pgtype.Text{String: version, Valid: true}, PreparationID: v.PreparationID, OrgID: v.OrgID, DocumentID: v.DocumentID, OwnerID: r.OwnerID})
	return (*generated.ListFittedFinalizationOutputsRow)(o), err
}
func (t *fittedOutputPostgresTransactionV1) Commit(ctx context.Context) error {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return pgx.ErrTxClosed
	}
	t.done = true
	t.mu.Unlock()
	err := t.session.CommitV1(ctx)
	closeErr := t.owner.closeOwned(t.session)
	if err != nil || closeErr != nil {
		return ErrFittedOutputSQLUnknownV1
	}
	return nil
}
func (t *fittedOutputPostgresTransactionV1) Rollback(ctx context.Context) error {
	t.mu.Lock()
	if t.done {
		t.mu.Unlock()
		return nil
	}
	t.done = true
	t.mu.Unlock()
	err := t.session.RollbackV1(ctx)
	closeErr := t.owner.closeOwned(t.session)
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) || closeErr != nil {
		return ErrFittedOutputSQLUnknownV1
	}
	return nil
}

var _ fittedOutputBackendV1 = (*fittedOutputPostgresV1)(nil)
var _ fittedOutputTransactionV1 = (*fittedOutputPostgresTransactionV1)(nil)

func (t *fittedOutputPostgresTransactionV1) Lock(ctx context.Context, r FittedOutputRequestV1) (*fittedOutputOperationV1, *generated.ListFittedFinalizationOutputsRow, error) {
	var op *fittedOutputOperationV1
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; op, row, e = t.lockSQLV1(owned, r); return e })
	return op, row, err
}

func (t *fittedOutputPostgresTransactionV1) Reserve(ctx context.Context, r FittedOutputRequestV1, body []byte) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.reserveSQLV1(owned, r, body); return e })
	return row, err
}

func (t *fittedOutputPostgresTransactionV1) ParentStart(ctx context.Context, r FittedOutputRequestV1) (pgtype.Timestamptz, error) {
	var stamp pgtype.Timestamptz
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; stamp, e = t.parentStartSQLV1(owned, r); return e })
	return stamp, err
}

func (t *fittedOutputPostgresTransactionV1) Body(ctx context.Context, r FittedOutputRequestV1) ([]byte, error) {
	var body []byte
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; body, e = t.bodySQLV1(owned, r); return e })
	return body, err
}

func (t *fittedOutputPostgresTransactionV1) RowStart(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.rowStartSQLV1(owned, r); return e })
	return row, err
}

func (t *fittedOutputPostgresTransactionV1) Attempt(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.attemptSQLV1(owned, r); return e })
	return row, err
}

func (t *fittedOutputPostgresTransactionV1) Pin(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.pinSQLV1(owned, r, version); return e })
	return row, err
}

func (t *fittedOutputPostgresTransactionV1) Readback(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.readbackSQLV1(owned, r, version); return e })
	return row, err
}

func (t *fittedOutputPostgresTransactionV1) Retained(ctx context.Context, r FittedOutputRequestV1, version string) (*generated.ListFittedFinalizationOutputsRow, error) {
	var row *generated.ListFittedFinalizationOutputsRow
	err := t.withSQL(ctx, func(owned context.Context) error { var e error; row, e = t.retainedSQLV1(owned, r, version); return e })
	return row, err
}
