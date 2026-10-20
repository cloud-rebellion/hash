// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Prepare stages one stable operation. It is deliberately serial: all owned
// effects are bounded by the caller deadline (at most 30 minutes) and each
// renderer call already has its own 60-second ceiling. No detached work, retry
// loop, automatic replacement operation or compensating delete is started.
func (p *PreparerV1) Prepare(ctx context.Context, r RequestV1) (*PreparedV1, error) {
	if ctx == nil || p == nil || nilV1(p.Journal) || nilV1(p.Objects) || nilV1(p.Inspector) || r.Admission == nil || r.OperationID == uuid.Nil || r.OwnerID == uuid.Nil || r.Authority == nil {
		return nil, ErrPreparationV1
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	authority, err := manualfit.DecodeAuthorityV1(r.Authority.CanonicalJSON())
	if err != nil || authority.SHA256() != r.Authority.SHA256() {
		return nil, ErrIdentityV1
	}
	in := authority.Input()
	if in.CeremonyEpoch.Nanosecond()%1000 != 0 {
		return nil, ErrIdentityV1
	} // PostgreSQL stores microseconds.
	budget, err := r.Admission(ctx, authority)
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	if err := budget.validate(in.Source.Bytes); err != nil {
		return nil, err
	}
	span := bytes.Clone(r.Span)
	var spanLease *OriginalPayloadV1
	defer func() {
		if spanLease != nil {
			spanLease.Close()
		} else {
			clear(span)
		}
	}()
	if len(span) > 0 && (digestV1(span) != in.SpanSHA256 || int64(len(span)) > manualfit.MaxSpanBytesV1 || manualfit.ValidateArchivedSpanV1(span, in.TypedName, in.Font) != nil) {
		return nil, ErrIdentityV1
	}
	// Capture optional original payloads before waiting. Unknown keys cannot cause
	// provider work, and aggregate memory is bounded by this operation's ceiling.
	originals := make(map[ObjectIDV1][]byte, len(r.OriginalPayloads))
	var originalBytes int64
	defer func() {
		for _, raw := range originals {
			clear(raw)
		}
	}()
	pageIDs := make(map[int32]bool, len(authority.Pages()))
	for _, page := range authority.Pages() {
		pageIDs[int32(page.Plan.Page)] = true
	}
	for id, raw := range r.OriginalPayloads {
		if !pageIDs[id.Page] || id.Kind != "page" || id.Page < 1 || id.Page > 500 || len(raw) < 1 || len(raw) > signaturefit.MaxPackageBytes || int64(len(raw)) > budget.FitBytes-originalBytes {
			return nil, ErrOriginalPayloadV1
		}
		originals[id] = bytes.Clone(raw)
		originalBytes += int64(len(raw))
	}
	row, err := p.Journal.Get(ctx, generated.GetSignatureFitPreparationParams{ID: r.OperationID, OrgID: in.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		if len(span) == 0 {
			return nil, ErrOriginalPayloadV1
		}
		if !futureLeaseV1(r.LeaseUntil) {
			return nil, ErrLeaseV1
		}
		reservation := generated.ReserveSignatureFitPreparationParams{ID: r.OperationID, OrgID: in.OrgID, DocumentID: in.DocumentID, RecipientID: in.RecipientID,
			CeremonyEpoch: timestampV1(in.CeremonyEpoch), AuthoritySha256: digestBytesV1(authority.SHA256()), SourceStorageKey: in.Source.Key, SourceVersionID: in.Source.VersionID,
			SourceSha256: digestBytesV1(in.Source.SHA256), SourceBytes: in.Source.Bytes, GeometrySha256: digestBytesV1(authority.Geometry().GeometrySHA256), SpanSha256: digestBytesV1(in.SpanSHA256),
			ReservedBytes: budget.FitBytes, ExpectedObjects: int32(len(authority.Pages()) + 2), OwnerID: r.OwnerID, LeaseUntil: timestampV1(r.LeaseUntil)}
		if !nilV1(p.Originals) {
			row, err = p.Originals.Reserve(ctx, reservation, authority, span)
		} else {
			row, err = p.Journal.Reserve(ctx, reservation)
		}
		if err != nil {
			return nil, uncertainErrorV1(ctx, err)
		}
	} else if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	if !preparationEqualV1(row, r.OperationID, authority, budget.FitBytes) {
		return nil, ErrIdentityV1
	}
	if row.Status != "staging" && row.Status != "prepared" {
		return nil, ErrPreparationV1
	}
	if row.SelectionNotCommittedAt.Valid {
		return nil, ErrPreparationV1
	}
	if row.Status == "staging" && (row.OwnerID != r.OwnerID || !row.LeaseUntil.Valid || !row.LeaseUntil.Time.After(time.Now())) {
		if !r.TakeoverExpiredLease || !row.LeaseUntil.Valid || row.LeaseUntil.Time.After(time.Now()) || !futureLeaseV1(r.LeaseUntil) {
			return nil, ErrLeaseV1
		}
		row, err = p.Journal.Claim(ctx, generated.ClaimSignatureFitPreparationLeaseParams{ID: r.OperationID, OrgID: in.OrgID, OwnerID: r.OwnerID, LeaseUntil: timestampV1(r.LeaseUntil)})
		if err != nil {
			return nil, uncertainErrorV1(ctx, err)
		}
		if !preparationEqualV1(row, r.OperationID, authority, budget.FitBytes) || row.OwnerID != r.OwnerID || !row.LeaseUntil.Time.After(time.Now()) {
			return nil, ErrLeaseV1
		}
	}
	if row.Status == "staging" && row.SelectionCommitAttemptedAt.Valid {
		return nil, ErrPreparationV1
	}
	if !nilV1(p.Originals) {
		captured, captureErr := p.Originals.Authority(ctx, row)
		if captureErr != nil {
			if captured != nil {
				captured.Close()
			}
			return nil, safeErrorV1(ctx, captureErr)
		}
		if captured == nil || captured.Authority() == nil || captured.Authority().SHA256() != authority.SHA256() {
			if captured != nil {
				captured.Close()
			}
			return nil, safeErrorV1(ctx, ErrIdentityV1)
		}
		captured.Close()
		if err := ctx.Err(); err != nil {
			return nil, safeErrorV1(ctx, err)
		}
	}
	objects, err := p.Journal.Objects(ctx, generated.ListSignatureFitObjectsParams{ID: r.OperationID, OrgID: in.OrgID})
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	index, err := inventoryV1(row, authority, objects)
	if err != nil {
		return nil, err
	}
	if !nilV1(p.Originals) {
		id := ObjectIDV1{Kind: "span", Page: 0}
		if existing := index[id]; existing == nil || !existing.UploadAttemptedAt.Valid {
			spanLease, err = p.loadOriginalV1(ctx, row, id, span, true)
			if err != nil {
				return nil, objectErrorV1(ctx, id, err)
			}
			clear(span)
			span = spanLease.Bytes()
			if digestV1(span) != in.SpanSHA256 || manualfit.ValidateArchivedSpanV1(span, in.TypedName, in.Font) != nil {
				return nil, ErrIdentityV1
			}
		}
	}
	// Read exact source only AFTER the operation is durably reserved. The worker
	// independently rechecks all geometry pages, including pages without targets.
	source, err := p.Objects.GetVerifiedVersionBounded(ctx, in.Source.Key, in.Source.VersionID, digestBytesV1(in.Source.SHA256), in.Source.Bytes)
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	if int64(len(source)) != in.Source.Bytes || digestV1(source) != in.Source.SHA256 {
		clear(source)
		return nil, ErrIdentityV1
	}
	if err := ctx.Err(); err != nil {
		clear(source)
		return nil, safeErrorV1(ctx, err)
	}
	observed, err := p.Inspector.Source(ctx, source)
	clear(source)
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	gotGeometry, _ := json.Marshal(observed)
	wantGeometry, _ := json.Marshal(authority.Geometry())
	if !bytes.Equal(gotGeometry, wantGeometry) {
		return nil, ErrIdentityV1
	}
	prefix := manualfit.ObjectPrefixV1(r.OperationID, in.OrgID, in.DocumentID)
	spanRow, spanStored, err := p.object(ctx, row, index, ObjectIDV1{Kind: "span", Page: 0}, prefix+"span.html", "text/html", span)
	clear(spanStored)
	if spanLease != nil {
		spanLease.Close()
		spanLease = nil
		span = nil
	}
	if err != nil {
		return nil, err
	}
	spanPin := pinV1(spanRow)
	pages := make([]manualfit.PageArtifactV1, 0, len(authority.Pages()))
	var pdfBytes int64
	for _, page := range authority.Pages() {
		artifact, n, err := p.preparePageV1(ctx, row, index, page, originals[ObjectIDV1{Kind: "page", Page: int32(page.Plan.Page)}], budget, pdfBytes)
		if err != nil {
			return nil, err
		}
		pdfBytes += n
		pages = append(pages, artifact)
	}

	manifest, err := manualfit.NewManifestV1(r.OperationID, authority, spanPin, pages)
	if err != nil {
		return nil, ErrIdentityV1
	}
	if manifest.AggregateBytes() > budget.FitBytes {
		return nil, ErrBudgetV1
	}
	manifestRaw := manifest.CanonicalJSON()
	defer clear(manifestRaw)
	manifestRow, stored, err := p.object(ctx, row, index, ObjectIDV1{"manifest", 0}, manifest.ManifestKey(), "application/json", manifestRaw)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stored, manifestRaw) {
		clear(stored)
		return nil, ErrIdentityV1
	}
	clear(stored)
	manifestPin := pinV1(manifestRow)
	verified, err := manualfit.VerifyRetainedV1(ctx, p.Objects, manifestPin, manifest.Binding())
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	if !bytes.Equal(verified.Manifest().CanonicalJSON(), manifestRaw) {
		return nil, ErrIdentityV1
	}
	// Read-only prepared recovery also works after selection made the rows
	// immutable; do not attempt to mutate their upload or prepared checkpoints.
	if row.Status == "staging" {
		row, err = p.Journal.Prepared(ctx, generated.MarkSignatureFitPreparationPreparedParams{ID: r.OperationID, OrgID: in.OrgID, OwnerID: r.OwnerID})
		if err != nil {
			return nil, uncertainErrorV1(ctx, err)
		}
		if !preparationEqualV1(row, r.OperationID, authority, budget.FitBytes) || row.Status != "prepared" {
			return nil, ErrIdentityV1
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	return &PreparedV1{verified.Manifest(), manifestPin}, nil
}

// preparePageV1 limits each borrowed original lease to this page's consumption.
// A captured body with no 85 object row is recovered before any renderer call.
func (p *PreparerV1) preparePageV1(ctx context.Context, row *generated.SignatureFitPreparation, index map[ObjectIDV1]*generated.SignatureFitObject, page manualfit.PagePlanV1, supplied []byte, budget BudgetV1, pdfBytes int64) (manualfit.PageArtifactV1, int64, error) {
	id := ObjectIDV1{Kind: "page", Page: int32(page.Plan.Page)}
	existing := index[id]
	var raw []byte
	var lease *OriginalPayloadV1
	defer func() {
		if lease != nil {
			lease.Close()
		} else {
			clear(raw)
		}
	}()
	if !nilV1(p.Originals) && (existing == nil || !existing.UploadAttemptedAt.Valid) {
		var err error
		lease, err = p.loadOriginalV1(ctx, row, id, supplied, existing != nil)
		if err != nil {
			return manualfit.PageArtifactV1{}, 0, objectErrorV1(ctx, id, err)
		}
		if lease != nil {
			raw = lease.Bytes()
		}
	}
	if existing != nil {
		if !existing.UploadAttemptedAt.Valid && nilV1(p.Originals) {
			raw = supplied
			if len(raw) == 0 {
				return manualfit.PageArtifactV1{}, 0, ErrOriginalPayloadV1
			}
		}
	} else if len(raw) == 0 {
		if nilV1(p.Renderer) {
			return manualfit.PageArtifactV1{}, 0, ErrPreparationV1
		}
		rendered, err := p.Renderer.PrepareManualSignaturePageV1(ctx, page.Plan)
		if err != nil {
			return manualfit.PageArtifactV1{}, 0, safeErrorV1(ctx, err)
		}
		if rendered == nil {
			return manualfit.PageArtifactV1{}, 0, ErrPreparationV1
		}
		raw = rendered.Bytes()
		if !nilV1(p.Originals) && len(supplied) > 0 && !bytes.Equal(supplied, raw) {
			return manualfit.PageArtifactV1{}, 0, ErrOriginalPayloadV1
		}
	}
	var beforeUpload *signaturefit.Package
	if len(raw) > 0 {
		admitted, err := admitPackageV1(ctx, p.Inspector, raw, page.Plan)
		if err != nil {
			return manualfit.PageArtifactV1{}, 0, err
		}
		n := int64(admitted.PDFByteCount())
		if n > sanitize.MaxPDFBytes-budget.ProcessingOtherBytes-pdfBytes {
			return manualfit.PageArtifactV1{}, 0, ErrBudgetV1
		}
		beforeUpload = admitted
	}
	prefix := manualfit.ObjectPrefixV1(row.ID, row.OrgID, row.DocumentID)
	object, stored, err := p.object(ctx, row, index, id, prefix+"page-"+strconv.Itoa(page.Plan.Page)+".fit", signaturefit.MediaType, raw)
	if lease != nil {
		lease.Close()
		lease = nil
	} else {
		clear(raw)
	}
	raw = nil
	if err != nil {
		return manualfit.PageArtifactV1{}, 0, err
	}
	var pkg *signaturefit.Package
	if beforeUpload != nil {
		pkg, err = signaturefit.Decode(stored, page.Plan)
		if err != nil {
			err = ErrIdentityV1
		}
	} else {
		pkg, err = admitPackageV1(ctx, p.Inspector, stored, page.Plan)
	}
	clear(stored)
	if err != nil {
		return manualfit.PageArtifactV1{}, 0, err
	}
	n := int64(pkg.PDFByteCount())
	if n > sanitize.MaxPDFBytes-budget.ProcessingOtherBytes-pdfBytes {
		return manualfit.PageArtifactV1{}, 0, ErrBudgetV1
	}
	d := pkg.Digests()
	return manualfit.PageArtifactV1{Page: page.Plan.Page, InputSHA256: page.InputSHA256, Package: pinV1(object), PDFSHA256: d.PDFSHA256,
		ReportSHA256: d.ReportSHA256, HTMLSHA256: d.HTMLSHA256, FontSHA256: d.FontSHA256, SnapshotSHA256: d.SnapshotSHA256}, n, nil
}

func admitPackageV1(ctx context.Context, inspector InspectorV1, raw []byte, plan signaturefit.Plan) (*signaturefit.Package, error) {
	pkg, err := signaturefit.Decode(raw, plan)
	if err != nil {
		return nil, ErrIdentityV1
	}
	width, err := strconv.ParseFloat(plan.WidthPoints, 64)
	if err != nil {
		return nil, ErrIdentityV1
	}
	height, err := strconv.ParseFloat(plan.HeightPoints, 64)
	if err != nil {
		return nil, ErrIdentityV1
	}
	pdf := pkg.PDF()
	defer clear(pdf)
	admitted, err := inspector.Fragment(ctx, pdf, width, height)
	if err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	rawAdmission, err := json.Marshal(admitted)
	if err != nil {
		return nil, ErrIdentityV1
	}
	admitted, err = sanitize.DecodePDFManualFragmentAdmission(rawAdmission)
	if err != nil || admitted.PDFSHA256 != pkg.PDFSHA256() || admitted.PDFBytes != int64(len(pdf)) || admitted.WidthPoints != width || admitted.HeightPoints != height {
		return nil, ErrIdentityV1
	}
	if err := ctx.Err(); err != nil {
		return nil, safeErrorV1(ctx, err)
	}
	return pkg, nil
}

func timestampV1(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t.UTC().Round(0), Valid: true}
}
func futureLeaseV1(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0 && t.After(time.Now())
}
func digestV1(raw []byte) string        { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func digestBytesV1(value string) []byte { raw, _ := hex.DecodeString(value); return raw }
func nilV1(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

// sanitizedErrorV1 keeps cancellation identity available to errors.Is without
// printing a private caller-supplied cancellation cause or provider response.
// The public error contains only the package's fixed, known sentinels.
type sanitizedErrorV1 struct {
	public error
	causes []error
}

func (e *sanitizedErrorV1) Error() string   { return e.public.Error() }
func (e *sanitizedErrorV1) Unwrap() []error { return append([]error(nil), e.causes...) }

func safeErrorV1(ctx context.Context, cause error) error {
	public := []error{ErrPreparationV1}
	var ctxErr, ctxCause error
	if ctx != nil {
		ctxErr = ctx.Err()
		if ctxErr != nil {
			ctxCause = context.Cause(ctx)
		}
	}
	for _, sentinel := range []error{context.Canceled, context.DeadlineExceeded, ErrIdentityV1, ErrBudgetV1, ErrLeaseV1, ErrOriginalPayloadV1, ErrUncertainIOV1} {
		if errors.Is(cause, sentinel) || errors.Is(ctxErr, sentinel) {
			public = append(public, sentinel)
		}
	}
	visible := errors.Join(public...)
	if ctxErr == nil {
		return visible
	}
	// Keep the original context errors in the unwrap tree, while its printable
	// representation remains the sanitized set above. In particular an outer
	// phase wrapper must retain both uncertain IO and a distinct cancellation cause.
	private := []error{visible, ctxErr}
	if ctxCause != nil {
		private = append(private, ctxCause)
	}
	return &sanitizedErrorV1{public: visible, causes: private}
}
func uncertainErrorV1(ctx context.Context, cause error) error {
	return errors.Join(ErrUncertainIOV1, safeErrorV1(ctx, cause))
}
func objectErrorV1(ctx context.Context, id ObjectIDV1, cause error) error {
	return fmt.Errorf("%s page %d: %w", id.Kind, id.Page, safeErrorV1(ctx, cause))
}
