// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These private transaction/storage models test orchestration boundaries, not
// actual SQL, SDK/S3, WORM, rendering, signing, expanded ZIP or legal acceptance.
// Production constructor exposes only a real pool and generated scoped SQL.
type fittedOutputBackendTestV1 struct {
	operation                             *fittedOutputOperationV1
	row                                   *generated.ListFittedFinalizationOutputsRow
	body                                  []byte
	events                                []string
	begins, commits                       int
	failCommitAt                          int
	applyUnknown                          bool
	holdUnknown                           bool
	failRollback, holdRollback            bool
	pending                               []*fittedOutputResourceLeaseV1
	hook                                  func(context.Context, string, *fittedOutputTransactionTestV1) error
	lastReservationInput, lastFetchedBody []byte
}

func fittedOutputRowCloneTestV1(o *generated.ListFittedFinalizationOutputsRow) *generated.ListFittedFinalizationOutputsRow {
	if o == nil {
		return nil
	}
	v := *o
	v.Sha256 = bytes.Clone(o.Sha256)
	return &v
}
func (b *fittedOutputBackendTestV1) Begin(ctx context.Context, orgID, documentID uuid.UUID) (fittedOutputTransactionV1, error) {
	if orgID == uuid.Nil || documentID == uuid.Nil {
		return nil, ErrFittedOutputAuthorityV1
	}
	b.begins++
	b.events = append(b.events, "begin")
	if len(b.pending) > 0 {
		return nil, ErrFittedOutputSQLUnknownV1
	}
	permit, _ := ctx.Value(fittedOutputResourceContextKeyV1{}).(*fittedOutputResourceLeaseV1)
	if permit == nil {
		return nil, ErrFittedOutputResourcesV1
	}
	permit.hold()
	p := *b.operation
	p.basePages = append([]int32(nil), p.basePages...)
	return &fittedOutputTransactionTestV1{backend: b, op: &p, row: fittedOutputRowCloneTestV1(b.row), body: b.body, resources: permit}, nil
}
func (b *fittedOutputBackendTestV1) Drain(ctx context.Context, closeNew bool) error {
	if len(b.pending) > 0 {
		return ErrFittedOutputSQLUnknownV1
	}
	return nil
}
func (b *fittedOutputBackendTestV1) cleanup() {
	for _, r := range b.pending {
		r.releasePhysical()
	}
	b.pending = nil
}

type fittedOutputTransactionTestV1 struct {
	backend   *fittedOutputBackendTestV1
	op        *fittedOutputOperationV1
	row       *generated.ListFittedFinalizationOutputsRow
	body      []byte
	resources *fittedOutputResourceLeaseV1
	done      bool
}

func (t *fittedOutputTransactionTestV1) event(ctx context.Context, s string) error {
	t.backend.events = append(t.backend.events, s)
	if t.backend.hook != nil {
		return t.backend.hook(ctx, s, t)
	}
	return nil
}
func (t *fittedOutputTransactionTestV1) Lock(ctx context.Context, r FittedOutputRequestV1) (*fittedOutputOperationV1, *generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "lock"); err != nil {
		return nil, nil, err
	}
	return t.op, fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Reserve(ctx context.Context, r FittedOutputRequestV1, body []byte) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "reserve"); err != nil {
		return nil, err
	}
	if t.row != nil {
		return nil, errors.New("overwrite refused")
	}
	v := r.Reservation
	t.backend.lastReservationInput = body
	t.body = bytes.Clone(body)
	t.row = &generated.ListFittedFinalizationOutputsRow{PreparationID: v.PreparationID, Kind: v.Kind, Page: v.Page, StorageKey: v.Key, Sha256: bytes.Clone(v.SHA256[:]), Bytes: v.Bytes, ContentType: v.ContentType}
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) ParentStart(ctx context.Context, r FittedOutputRequestV1) (pgtype.Timestamptz, error) {
	if err := t.event(ctx, "parent-start"); err != nil {
		return pgtype.Timestamptz{}, err
	}
	t.op.retentionStarted = fittedRecoveryStampTestV1(t.op.completion.Time.Add(time.Minute))
	return t.op.retentionStarted, nil
}
func (t *fittedOutputTransactionTestV1) RowStart(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "row-start"); err != nil {
		return nil, err
	}
	if t.row == nil || !t.op.retentionStarted.Valid {
		return nil, errors.New("missing earlier parent start")
	}
	t.row.RetentionStartedAt = fittedRecoveryStampTestV1(t.op.retentionStarted.Time.Add(time.Second))
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Attempt(ctx context.Context, r FittedOutputRequestV1) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "attempt"); err != nil {
		return nil, err
	}
	if t.row == nil || t.row.UploadAttemptedAt.Valid || !t.row.RetentionStartedAt.Valid {
		return nil, errors.New("attempt already consumed")
	}
	t.row.UploadAttemptedAt = fittedRecoveryStampTestV1(t.row.RetentionStartedAt.Time.Add(time.Second))
	t.row.UploadOwnerID = pgtype.UUID{Bytes: r.OwnerID, Valid: true}
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Body(ctx context.Context, r FittedOutputRequestV1) ([]byte, error) {
	if err := t.event(ctx, "body"); err != nil {
		return nil, err
	}
	t.backend.lastFetchedBody = bytes.Clone(t.body)
	return t.backend.lastFetchedBody, nil
}
func (t *fittedOutputTransactionTestV1) Pin(ctx context.Context, r FittedOutputRequestV1, v string) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "pin"); err != nil {
		return nil, err
	}
	if t.row == nil || !t.row.UploadAttemptedAt.Valid || t.row.VersionID.Valid {
		return nil, errors.New("pin refuses missing attempt/overwrite")
	}
	t.row.VersionID = pgtype.Text{String: v, Valid: true}
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Readback(ctx context.Context, r FittedOutputRequestV1, v string) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "readback"); err != nil {
		return nil, err
	}
	if t.row == nil || !t.row.VersionID.Valid || t.row.VersionID.String != v {
		return nil, errors.New("readback refuses missing exact pin")
	}
	t.row.ReadbackVerifiedAt = fittedRecoveryStampTestV1(t.row.UploadAttemptedAt.Time.Add(time.Second))
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Retained(ctx context.Context, r FittedOutputRequestV1, v string) (*generated.ListFittedFinalizationOutputsRow, error) {
	if err := t.event(ctx, "retention-complete"); err != nil {
		return nil, err
	}
	if t.row == nil || !t.row.ReadbackVerifiedAt.Valid {
		return nil, errors.New("retention refuses missing readback")
	}
	t.row.RetentionCompletedAt = fittedRecoveryStampTestV1(t.row.ReadbackVerifiedAt.Time.Add(time.Second))
	return fittedOutputRowCloneTestV1(t.row), nil
}
func (t *fittedOutputTransactionTestV1) Commit(ctx context.Context) error {
	if t.done {
		return errors.New("closed transaction")
	}
	t.done = true
	t.backend.commits++
	t.backend.events = append(t.backend.events, "commit")
	unknown := t.backend.commits == t.backend.failCommitAt
	if !unknown || t.backend.applyUnknown {
		t.backend.operation = t.op
		t.backend.row = fittedOutputRowCloneTestV1(t.row)
		t.backend.body = t.body
	}
	if unknown && t.backend.holdUnknown {
		t.backend.pending = append(t.backend.pending, t.resources)
	} else {
		t.resources.releasePhysical()
	}
	if unknown {
		return errors.New("private commit transport error")
	}
	return nil
}
func (t *fittedOutputTransactionTestV1) Rollback(ctx context.Context) error {
	if t.done {
		return nil
	}
	t.done = true
	t.backend.events = append(t.backend.events, "rollback")
	if t.backend.failRollback {
		if t.backend.holdRollback {
			t.backend.pending = append(t.backend.pending, t.resources)
		} else {
			t.resources.releasePhysical()
		}
		return errors.New("private physical cleanup incomplete")
	}
	t.resources.releasePhysical()
	return nil
}

var _ fittedOutputBackendV1 = (*fittedOutputBackendTestV1)(nil)
var _ fittedOutputTransactionV1 = (*fittedOutputTransactionTestV1)(nil)

type fittedOutputStorageTestV1 struct {
	backend            *fittedOutputBackendTestV1
	puts, resolves     int
	putErr, resolveErr error
	putVersion         string
	state              storage.FittedFinalizationObservationStateV1
	resolveVersion     string
	onPut              func(context.Context)
	onResolve          func(context.Context)
}

func (s *fittedOutputStorageTestV1) PutFittedFinalizationReservedV1(ctx context.Context, r storage.FittedFinalizationReservationV1, body []byte) (storage.StoredObject, error) {
	s.puts++
	s.backend.events = append(s.backend.events, "put")
	if !bytes.Equal(body, s.backend.body) || sha256.Sum256(body) != r.SHA256 {
		return storage.StoredObject{}, errors.New("wrong original body")
	}
	if s.onPut != nil {
		s.onPut(ctx)
	}
	return storage.StoredObject{SHA256: r.SHA256, VersionID: s.putVersion}, s.putErr
}
func (s *fittedOutputStorageTestV1) ResolveFittedFinalizationVersionV1(ctx context.Context, r storage.FittedFinalizationReservationV1, known string) (storage.FittedFinalizationObservationV1, error) {
	s.resolves++
	s.backend.events = append(s.backend.events, "resolve")
	if s.onResolve != nil {
		s.onResolve(ctx)
	}
	v := known
	if v == "" {
		v = s.resolveVersion
	}
	if s.state == storage.FittedFinalizationEmptyUnresolvedV1 && known == "" {
		v = ""
	}
	return storage.FittedFinalizationObservationV1{Object: storage.StoredObject{SHA256: r.SHA256, VersionID: v}, State: s.state}, s.resolveErr
}
func fittedOutputFixtureTestV1(t *testing.T, kind string) (*FittedOutputJournalV1, FittedOutputRequestV1, *fittedOutputBackendTestV1, *fittedOutputStorageTestV1, []byte, *int) {
	t.Helper()
	body := []byte("synthetic original fitted output bytes; not renderer or customer evidence")
	org, doc, prep, owner := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	completion := time.Date(2026, 10, 12, 12, 0, 0, 123456000, time.UTC)
	v := storage.FittedFinalizationReservationV1{OrgID: org, DocumentID: doc, PreparationID: prep, Kind: kind, SHA256: sha256.Sum256(body), Bytes: int64(len(body)), ContentType: "application/pdf", CompletionEffectiveAt: completion, RetainUntil: storage.EvidenceRetentionDeadline(completion, article13.RetentionYearsV1)}
	prefix := "org/" + org.String() + "/documents/" + doc.String() + "/"
	digest := fittedSHA256V1(body)
	switch kind {
	case "base_pdf":
		v.Page = 1
		v.Key = prefix + "finalization/base/" + prep.String() + "/page-1.pdf"
	case "final_pdf":
		v.Key = prefix + "final-" + digest + ".pdf"
	case "fits_index":
		v.Key = prefix + "finalization/index/" + prep.String() + "/signature-fit-index.json"
		v.ContentType = "application/json"
	case "certificate_pdf":
		v.Key = prefix + "audit-" + digest + ".pdf"
	case "certificate_payload":
		v.Key = prefix + "audit-payload-" + digest + ".txt"
		v.ContentType = "text/plain"
	case "certificate_signature":
		v.Key = prefix + "audit-signature-" + digest + ".txt"
		v.ContentType = "text/plain"
	}
	request := FittedOutputRequestV1{Reservation: v, OwnerID: owner}
	b := &fittedOutputBackendTestV1{operation: &fittedOutputOperationV1{id: prep, org: org, document: doc, owner: owner, status: "staging", documentStatus: "finalizing", epoch: fittedRecoveryStampTestV1(completion.Add(-time.Hour)), completion: fittedRecoveryStampTestV1(completion), retain: fittedRecoveryStampTestV1(v.RetainUntil), lease: fittedRecoveryStampTestV1(completion.Add(time.Hour)), leaseCurrent: true, attempts: 1, basePages: []int32{1}, baseLimit: 4096, finalLimit: 4096, indexLimit: 65536, certificatePDFLimit: 4096, certificatePayloadLimit: 4096, certificateSignatureLimit: 256, archiveLimit: 32 << 20, auditBytes: 64, auditSHA: bytes.Repeat([]byte{1}, 32), certificateInputBytes: v.Bytes, certificateInputSHA: bytes.Clone(v.SHA256[:])}}
	s := &fittedOutputStorageTestV1{backend: b, putVersion: " exact positive+/opaque=version ", state: storage.FittedFinalizationVerifiedV1, resolveVersion: " recovered positive+/opaque=version "}
	released := new(int)
	j := &FittedOutputJournalV1{backend: b, storage: s, admit: func(ctx context.Context, r FittedOutputResourceRequestV1) (func(), error) {
		b.events = append(b.events, "admit")
		if r.BodyBytes != v.Bytes || r.WorkingBytes < 4*v.Bytes+10*(1<<20) {
			return nil, errors.New("insufficient declared memory")
		}
		return func() { *released++; b.events = append(b.events, "release") }, nil
	}}
	return j, request, b, s, body, released
}
func fittedOutputContextTestV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func fittedOutputReserveTestV1(t *testing.T, j *FittedOutputJournalV1, r FittedOutputRequestV1, body []byte) {
	t.Helper()
	result, err := j.ReserveOriginalV1(fittedOutputContextTestV1(t), r, body)
	if err != nil || !result.Reserved() {
		t.Fatalf("reserve fixture: %v", err)
	}
}
func fittedOutputAttemptedTestV1(b *fittedOutputBackendTestV1, r FittedOutputRequestV1) {
	b.operation.retentionStarted = fittedRecoveryStampTestV1(b.operation.completion.Time.Add(time.Minute))
	b.row.RetentionStartedAt = fittedRecoveryStampTestV1(b.operation.retentionStarted.Time.Add(time.Second))
	b.row.UploadAttemptedAt = fittedRecoveryStampTestV1(b.row.RetentionStartedAt.Time.Add(time.Second))
	b.row.UploadOwnerID = pgtype.UUID{Bytes: r.OwnerID, Valid: true}
}

func TestFittedOutputJournalSoleOriginalAllKindsV1(t *testing.T) {
	for _, kind := range []string{"base_pdf", "final_pdf", "fits_index", "certificate_pdf", "certificate_payload", "certificate_signature"} {
		t.Run(kind, func(t *testing.T) {
			j, r, b, s, body, releases := fittedOutputFixtureTestV1(t, kind)
			fittedOutputReserveTestV1(t, j, r, body)
			if s.puts != 0 || s.resolves != 0 || !bytes.Equal(b.body, body) || *releases != 1 {
				t.Fatal("reserve performed external IO or lost original body")
			}
			// Caller changes cannot alter the original durable producer output.
			expected := bytes.Clone(body)
			body[0] = '!'
			result, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
			if err != nil || !result.Verified() || !result.AttemptCommitted() || !result.ProviderAttempted() || result.Object().VersionID != s.putVersion || s.puts != 1 || s.resolves != 1 || !bytes.Equal(b.body, expected) || !b.row.RetentionCompletedAt.Valid || *releases != 2 {
				t.Fatalf("sole original bridge: %v", err)
			}
			sequence := strings.Join(b.events, ",")
			if !strings.Contains(sequence, "parent-start,row-start,commit") || !strings.Contains(sequence, "attempt,commit") || !strings.Contains(sequence, "body,lock,put,pin,commit") || !strings.Contains(sequence, "resolve,readback,retention-complete,commit") {
				t.Fatalf("durable admission/order lost: %s", sequence)
			}
			before := s.puts
			if _, err = j.UploadOriginalV1(fittedOutputContextTestV1(t), r); !errors.Is(err, ErrFittedOutputAttemptExistsV1) || s.puts != before {
				t.Fatal("existing marker permitted a second original upload")
			}
			if !bytes.Equal(b.lastFetchedBody, make([]byte, len(b.lastFetchedBody))) || !bytes.Equal(b.lastReservationInput, make([]byte, len(b.lastReservationInput))) {
				t.Fatal("temporary original body remained after known cleanup")
			}
		})
	}
}
func TestFittedOutputJournalUnknownAttemptCommitNeverDispatchesV1(t *testing.T) {
	for _, applied := range []bool{false, true} {
		t.Run(map[bool]string{false: "rolled back", true: "acknowledgement lost"}[applied], func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			b.failCommitAt = 3
			b.applyUnknown = applied
			result, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
			if !errors.Is(err, ErrFittedOutputSQLUnknownV1) || !result.SQLUncertain() || s.puts != 0 || result.ProviderAttempted() {
				t.Fatal("unknown marker commit dispatched provider IO")
			}
			if applied {
				before := b.commits
				s.state = storage.FittedFinalizationEmptyUnresolvedV1
				observed, err := j.ResolveReadOnlyV1(fittedOutputContextTestV1(t), r, "")
				if err != nil || observed.Verified() || observed.Observation() != storage.FittedFinalizationEmptyUnresolvedV1 || b.commits != before || s.puts != 0 {
					t.Fatal("empty recovery changed journal or authorized upload")
				}
				if _, err = j.UploadOriginalV1(fittedOutputContextTestV1(t), r); !errors.Is(err, ErrFittedOutputAttemptExistsV1) || s.puts != 0 {
					t.Fatal("positive marker plus empty history was replay permission")
				}
			}
		})
	}
}
func TestFittedOutputJournalUnknownReserveKeepsBodiesAndResourcesUntilCleanupV1(t *testing.T) {
	j, r, b, s, body, releases := fittedOutputFixtureTestV1(t, "final_pdf")
	b.failCommitAt = 1
	b.applyUnknown = true
	b.holdUnknown = true
	result, err := j.ReserveOriginalV1(fittedOutputContextTestV1(t), r, body)
	if !errors.Is(err, ErrFittedOutputSQLUnknownV1) || !result.SQLUncertain() || s.puts != 0 || *releases != 0 || !bytes.Equal(b.lastReservationInput, body) {
		t.Fatal("uncertain physical cleanup released admitted original body")
	}
	if _, err = j.UploadOriginalV1(fittedOutputContextTestV1(t), r); !errors.Is(err, ErrFittedOutputSQLUnknownV1) || s.puts != 0 {
		t.Fatal("another physical slot bypassed unresolved session")
	}
	b.cleanup()
	if *releases != 2 || !bytes.Equal(b.lastReservationInput, make([]byte, len(b.lastReservationInput))) {
		t.Fatal("actual cleanup did not release owned body/permits exactly once")
	}
	if !bytes.Equal(b.body, body) {
		t.Fatal("temporary clearing destroyed durable original bytes")
	}
}
func TestFittedOutputJournalPositiveProviderErrorAndCancellationV1(t *testing.T) {
	for _, mode := range []string{"late provider error", "cancel after committed PUT", "pin refusal", "pin commit unknown"} {
		t.Run(mode, func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			private := errors.New("private provider/cancellation owner")
			ctx, cancel := context.WithCancelCause(fittedOutputContextTestV1(t))
			defer cancel(nil)
			switch mode {
			case "late provider error":
				s.putErr = private
			case "cancel after committed PUT":
				s.onPut = func(context.Context) { cancel(private) }
			case "pin refusal":
				b.hook = func(ctx context.Context, phase string, _ *fittedOutputTransactionTestV1) error {
					if phase == "pin" {
						return private
					}
					return nil
				}
			case "pin commit unknown":
				b.failCommitAt = 4
				b.applyUnknown = true
			}
			result, err := j.UploadOriginalV1(ctx, r)
			if err == nil || result.Verified() || result.Object().VersionID != s.putVersion || s.puts != 1 || strings.Contains(err.Error(), private.Error()) {
				t.Fatalf("positive version was lost or private error exposed: %v", err)
			}
			if mode == "cancel after committed PUT" && (!errors.Is(err, context.Canceled) || !errors.Is(err, private)) {
				t.Fatal("distinct cancellation cause lost")
			}
			if mode == "late provider error" || mode == "cancel after committed PUT" {
				if !b.row.VersionID.Valid || b.row.VersionID.String != s.putVersion || b.row.ReadbackVerifiedAt.Valid {
					t.Fatal("late failure pin was not durably preserved without false readback")
				}
			}
			if mode == "pin commit unknown" && !result.SQLUncertain() {
				t.Fatal("unknown pin commit was hidden")
			}
		})
	}
}
func TestFittedOutputJournalOwnerLeaseAndMetadataRefuseBeforeBodyV1(t *testing.T) {
	for _, mode := range []string{"owner", "lease", "final target", "wrong original key", "unsafe MIME", "body size cap", "deletion phase", "stale server clock before PUT", "missing frozen certificate"} {
		t.Run(mode, func(t *testing.T) {
			kind := "final_pdf"
			if mode == "missing frozen certificate" {
				kind = "certificate_pdf"
			}
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, kind)
			fittedOutputReserveTestV1(t, j, r, body)
			switch mode {
			case "owner":
				b.operation.owner = uuid.New()
			case "lease":
				b.operation.leaseCurrent = false
			case "final target":
				r.Reservation.RetainUntil = r.Reservation.RetainUntil.Add(time.Second)
			case "wrong original key":
				b.row.StorageKey += "-other"
			case "unsafe MIME":
				b.row.ContentType = "text/html"
			case "body size cap":
				b.operation.finalLimit = 1
			case "deletion phase":
				b.operation.documentStatus = "canceled"
			case "missing frozen certificate":
				b.operation.certificateInputBytes = 0
			case "stale server clock before PUT":
				b.hook = func(ctx context.Context, phase string, tx *fittedOutputTransactionTestV1) error {
					if phase == "body" {
						tx.op.leaseCurrent = false
					}
					return nil
				}
			}
			result, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
			if err == nil || result.ProviderAttempted() || s.puts != 0 {
				t.Fatal("stale scoped authority dispatched original body")
			}
			if mode != "stale server clock before PUT" && bytes.Contains([]byte(strings.Join(b.events, ",")), []byte(",body")) {
				t.Fatal("metadata refusal fetched original body")
			}
		})
	}
}
func TestFittedOutputJournalResolveIsReadOnlyAndCheckpointReverifiesV1(t *testing.T) {
	j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
	fittedOutputReserveTestV1(t, j, r, body)
	fittedOutputAttemptedTestV1(b, r)
	before := b.commits
	observed, err := j.ResolveReadOnlyV1(fittedOutputContextTestV1(t), r, "")
	if err != nil || !observed.Verified() || b.commits != before || s.puts != 0 || b.row.VersionID.Valid || bytes.Contains([]byte(strings.Join(b.events, ",")), []byte(",body")) {
		t.Fatal("read-only resolver read/mutated original body")
	}
	result, err := j.CheckpointExactV1(fittedOutputContextTestV1(t), r, observed)
	if err != nil || !result.Verified() || !b.row.RetentionCompletedAt.Valid || s.resolves != 3 || s.puts != 0 {
		t.Fatalf("checkpoint failed to freshly verify and retain exact pin: %v", err)
	}
	s.state = storage.FittedFinalizationEmptyUnresolvedV1
	if _, err = j.CheckpointExactV1(fittedOutputContextTestV1(t), r, result); err == nil || s.puts != 0 {
		t.Fatal("empty exact checkpoint observation permitted replay")
	}
}
func TestFittedOutputJournalResourceAdmissionAndCancellationBeforeIOV1(t *testing.T) {
	for _, mode := range []string{"missing admission", "denied admission", "already canceled", "deadline required", "oversized key"} {
		t.Run(mode, func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			private := errors.New("private resource owner")
			ctx := fittedOutputContextTestV1(t)
			switch mode {
			case "missing admission":
				j.admit = nil
			case "denied admission":
				j.admit = func(context.Context, FittedOutputResourceRequestV1) (func(), error) { return nil, private }
			case "already canceled":
				c, cancel := context.WithCancelCause(ctx)
				cancel(private)
				ctx = c
			case "deadline required":
				ctx = context.Background()
			case "oversized key":
				r.Reservation.Key = strings.Repeat("x", 1025)
			}
			result, err := j.ReserveOriginalV1(ctx, r, body)
			if err == nil || result.Reserved() || b.begins != 0 || s.puts != 0 || s.resolves != 0 || strings.Contains(err.Error(), private.Error()) {
				t.Fatal("unadmitted request touched SQL/storage or exposed cause")
			}
			if mode == "already canceled" && (!errors.Is(err, context.Canceled) || !errors.Is(err, private)) {
				t.Fatal("cancellation identity lost")
			}
		})
	}
}

// This is a synthetic parent-loan conjunction test only. Actual server
// retirement is issued exclusively by the production owned session factory and
// is qualified by the separate real PostgreSQL fixture, never by a fake bool.
func TestFittedOutputJournalParentBodyRemainsUntilAllOwnedSessionsRetireV1(t *testing.T) {
	released := 0
	resource := &fittedOutputResourceLeaseV1{release: func() { released++ }}
	body := []byte("private temporary original")
	resource.ownBody(body)
	resource.hold()
	resource.hold()
	resource.releaseOwner()
	if released != 0 || !bytes.Equal(body, []byte("private temporary original")) {
		t.Fatal("logical owner return erased an owned session body")
	}
	resource.releasePhysical()
	if released != 0 || !bytes.Equal(body, []byte("private temporary original")) {
		t.Fatal("one retired session erased another owned session body")
	}
	resource.releasePhysical()
	resource.maybeRelease()
	if released != 1 || !bytes.Equal(body, make([]byte, len(body))) {
		t.Fatal("last owned session did not once-release parent body")
	}
}

func TestFittedOutputJournalOpaqueOriginalPositiveCanPinAfterResolverErrorV1(t *testing.T) {
	for _, cancelAfterObserve := range []bool{false, true} {
		t.Run(map[bool]string{false: "late error", true: "cancellation"}[cancelAfterObserve], func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			private := errors.New("private positive original/provider owner")
			b.hook = func(ctx context.Context, phase string, _ *fittedOutputTransactionTestV1) error {
				if phase == "pin" {
					return private
				}
				return nil
			}
			original, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
			if err == nil || !original.originalKnown || b.row.VersionID.Valid || s.puts != 1 {
				t.Fatal("fixture did not retain opaque own SDK positive")
			}
			b.hook = nil
			s.state = storage.FittedFinalizationUnresolvedV1
			s.resolveErr = private
			ctx, cancel := context.WithCancelCause(fittedOutputContextTestV1(t))
			defer cancel(nil)
			if cancelAfterObserve {
				s.resolveErr = nil
				s.onResolve = func(context.Context) { cancel(private) }
			}
			receipt, err := j.CheckpointExactV1(ctx, r, original)
			if err == nil || receipt.Object().VersionID != s.putVersion || receipt.Verified() || !b.row.VersionID.Valid || b.row.VersionID.String != s.putVersion || b.row.ReadbackVerifiedAt.Valid || s.puts != 1 || strings.Contains(err.Error(), private.Error()) {
				t.Fatalf("known original positive pin lost/conflated with exact proof: %v", err)
			}
			if cancelAfterObserve && (!errors.Is(err, context.Canceled) || !errors.Is(err, private)) {
				t.Fatal("late checkpoint cancellation cause lost")
			}
		})
	}
}
func TestFittedOutputJournalUnknownListingOrStringHintCannotMintPinAuthorityV1(t *testing.T) {
	for _, hint := range []string{"", " invented positive version "} {
		t.Run(hint, func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			fittedOutputAttemptedTestV1(b, r)
			s.state = storage.FittedFinalizationUnresolvedV1
			s.resolveErr = errors.New("private multi-history/incomplete verification")
			observed, err := j.ResolveReadOnlyV1(fittedOutputContextTestV1(t), r, hint)
			if err == nil || observed.Object().VersionID == "" || observed.originalKnown || b.row.VersionID.Valid {
				t.Fatal("unknown listing acquired original provenance")
			}
			before := b.commits
			result, err := j.CheckpointExactV1(fittedOutputContextTestV1(t), r, observed)
			if err == nil || result.Object().VersionID == "" || result.Verified() || b.row.VersionID.Valid || b.commits != before || s.puts != 0 {
				t.Fatal("unverified listing/string hint permanently froze an immutable original pin")
			}
		})
	}
}
func TestFittedOutputJournalOpaqueReceiptCannotCrossScopeV1(t *testing.T) {
	j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
	fittedOutputReserveTestV1(t, j, r, body)
	original, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
	if err != nil {
		t.Fatal(err)
	}
	before := b.begins
	resolves := s.resolves
	changed := r
	changed.OwnerID = uuid.New()
	if _, err = j.CheckpointExactV1(fittedOutputContextTestV1(t), changed, original); err == nil || b.begins != before || s.resolves != resolves {
		t.Fatal("opaque receipt reused under another authority")
	}
}
func TestFittedOutputJournalReadSuccessReportsPendingPhysicalCleanupV1(t *testing.T) {
	for _, mode := range []string{"existing reserve", "read-only resolve"} {
		t.Run(mode, func(t *testing.T) {
			j, r, b, s, body, releases := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			fittedOutputAttemptedTestV1(b, r)
			b.failRollback = true
			b.holdRollback = true
			var result FittedOutputReceiptV1
			var err error
			if mode == "existing reserve" {
				result, err = j.ReserveOriginalV1(fittedOutputContextTestV1(t), r, body)
			} else {
				result, err = j.ResolveReadOnlyV1(fittedOutputContextTestV1(t), r, "")
			}
			if !errors.Is(err, ErrFittedOutputSQLUnknownV1) || !result.SQLUncertain() || *releases != 1 || len(b.pending) != 1 || s.puts != 0 {
				t.Fatal("apparently successful read hid physical cleanup uncertainty")
			}
			if mode == "read-only resolve" && (result.Object().VersionID == "" || !result.Verified()) {
				t.Fatal("cleanup error discarded positive verified observation")
			}
			b.cleanup()
			if *releases != 2 {
				t.Fatal("late actual cleanup did not release admitted read resources")
			}
		})
	}
}

func TestFittedOutputJournalReadbackFailureCannotRollBackKnownPositiveV1(t *testing.T) {
	for _, phase := range []string{"resolve", "readback", "retention-complete"} {
		t.Run(phase, func(t *testing.T) {
			j, r, b, s, body, _ := fittedOutputFixtureTestV1(t, "final_pdf")
			fittedOutputReserveTestV1(t, j, r, body)
			private := errors.New("private subsequent verification failure")
			if phase == "resolve" {
				s.resolveErr = private
			} else {
				b.hook = func(ctx context.Context, at string, _ *fittedOutputTransactionTestV1) error {
					if at == phase {
						return private
					}
					return nil
				}
			}
			result, err := j.UploadOriginalV1(fittedOutputContextTestV1(t), r)
			if err == nil || result.Verified() || result.Object().VersionID != s.putVersion || !b.row.VersionID.Valid || b.row.VersionID.String != s.putVersion || b.row.ReadbackVerifiedAt.Valid || s.puts != 1 || strings.Contains(err.Error(), private.Error()) {
				t.Fatal("later checkpoint failure rolled back the durable original positive pin")
			}
		})
	}
}
