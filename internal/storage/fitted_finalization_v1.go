// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/s3policy"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// FittedFinalizationReservationV1 describes one immutable SQL86 output. Before
// original upload, the caller MUST positively reconcile its scoped SQL authority
// and physically observe the durable original body, retention-start checkpoint
// and sole upload-attempt marker. These fields cannot prove SQL ownership or
// permission. The preparation's own smaller caps/base-page inventory and whole
// archive admission also remain caller responsibilities.
type FittedFinalizationReservationV1 struct {
	OrgID, DocumentID, PreparationID uuid.UUID
	Kind                             string
	Page                             int32
	Key                              string
	SHA256                           [sha256.Size]byte
	Bytes                            int64
	ContentType                      string
	CompletionEffectiveAt            time.Time
	RetainUntil                      time.Time
}

type FittedFinalizationObservationStateV1 string

const (
	FittedFinalizationUnresolvedV1      FittedFinalizationObservationStateV1 = "unresolved"
	FittedFinalizationEmptyUnresolvedV1 FittedFinalizationObservationStateV1 = "empty-unresolved"
	FittedFinalizationVerifiedV1        FittedFinalizationObservationStateV1 = "exact-verified"
)

// Object may carry a known or observed positive version even when State is
// unresolved. Only exact-verified permits the caller's readback/retention
// checkpoint. Empty observation is NEVER permission to upload again, compensate
// or discard SQL inventory: an original ambiguous request may still commit.
type FittedFinalizationObservationV1 struct {
	Object StoredObject
	State  FittedFinalizationObservationStateV1
}

var ErrFittedFinalizationStorageV1 = errors.New("storage: fitted finalization output unavailable")

type fittedFinalizationStorageErrorV1 struct{ cause error }

func (e fittedFinalizationStorageErrorV1) Error() string {
	return ErrFittedFinalizationStorageV1.Error()
}
func (e fittedFinalizationStorageErrorV1) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrFittedFinalizationStorageV1}
	}
	return []error{ErrFittedFinalizationStorageV1, e.cause}
}
func fittedFinalizationErrorV1(ctx context.Context, cause error) error {
	if canceled := fitObjectContextError(ctx); canceled != nil {
		cause = canceled
	}
	return fittedFinalizationStorageErrorV1{cause: cause}
}

func validFittedFinalizationTimeV1(value time.Time) bool {
	return !value.IsZero() && value.UTC().Year() >= 1 && value.UTC().Year() <= 9999
}
func validateFittedFinalizationReservationV1(r FittedFinalizationReservationV1) error {
	if r.OrgID == uuid.Nil || r.DocumentID == uuid.Nil || r.PreparationID == uuid.Nil || r.SHA256 == [sha256.Size]byte{} ||
		!validFittedFinalizationTimeV1(r.CompletionEffectiveAt) || !validFittedFinalizationTimeV1(r.RetainUntil) ||
		!r.RetainUntil.Equal(EvidenceRetentionDeadline(r.CompletionEffectiveAt, article13.RetentionYearsV1)) {
		return ErrFittedFinalizationStorageV1
	}
	if _, err := canonicalEvidenceRetainUntil(r.RetainUntil); err != nil {
		return ErrFittedFinalizationStorageV1
	}
	prefix := "org/" + r.OrgID.String() + "/documents/" + r.DocumentID.String() + "/"
	digest := hex.EncodeToString(r.SHA256[:])
	var key, media string
	var limit int64
	switch r.Kind {
	case "base_pdf":
		if r.Page < 1 || r.Page > 500 {
			return ErrFittedFinalizationStorageV1
		}
		key = prefix + "finalization/base/" + r.PreparationID.String() + "/page-" + strconv.Itoa(int(r.Page)) + ".pdf"
		media, limit = "application/pdf", manualfit.MaxArchiveBasePDFBytesV1
	case "fits_index":
		key = manualfit.IndexStorageKeyV1(r.OrgID, r.DocumentID, r.PreparationID)
		media, limit = "application/json", manualfit.MaxFitsIndexBytesV1
	case "final_pdf":
		key = prefix + "final-" + digest + ".pdf"
		media, limit = "application/pdf", manualfit.MaxFinalPDFBytesV1
	case "certificate_pdf":
		key = prefix + "audit-" + digest + ".pdf"
		media, limit = "application/pdf", manualfit.MaxCertificatePDFBytesV1
	case "certificate_payload":
		key = prefix + "audit-payload-" + digest + ".txt"
		media, limit = "text/plain", manualfit.MaxCertificatePayloadBytesV1
	case "certificate_signature":
		key = prefix + "audit-signature-" + digest + ".txt"
		media, limit = "text/plain", manualfit.MaxCertificateSignatureBytesV1
	default:
		return ErrFittedFinalizationStorageV1
	}
	if (r.Kind != "base_pdf" && r.Page != 0) || r.Key != key || r.ContentType != media || r.Bytes <= 0 || r.Bytes > limit {
		return ErrFittedFinalizationStorageV1
	}
	return nil
}

func (c *Client) validateFittedFinalizationClientV1() error {
	if c == nil || c.mc == nil || c.bucket == "" || !c.requireEvidenceLock || c.writeServerSideEncryption == nil {
		return ErrFittedFinalizationStorageV1
	}
	switch c.sseMode {
	case s3policy.SSEModeS3:
		if c.writeServerSideEncryption.Type() != encrypt.S3 {
			return ErrFittedFinalizationStorageV1
		}
	case s3policy.SSEModeC:
		if c.writeServerSideEncryption.Type() != encrypt.SSEC || c.readServerSideEncryption == nil || c.readServerSideEncryption.Type() != encrypt.SSEC {
			return ErrFittedFinalizationStorageV1
		}
	default:
		return ErrFittedFinalizationStorageV1
	}
	return nil
}

func (c *Client) verifyFittedFinalizationObjectV1(ctx context.Context, r FittedFinalizationReservationV1, version string) error {
	if err := fitObjectContextError(ctx); err != nil {
		return err
	}
	info, err := c.mc.StatObject(ctx, c.bucket, r.Key, c.statOpts(version))
	if err != nil {
		return fittedFinalizationErrorV1(ctx, err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return err
	}
	if info.VersionID != version || info.Size != r.Bytes || info.ContentType != r.ContentType {
		return ErrFittedFinalizationStorageV1
	}
	// Reuse the existing exact-version SSE metadata contract. Customer-key
	// enforcement is accepted separately by the owned data-plane canary; this
	// path does not probe customer evidence with deliberately wrong keys.
	switch c.sseMode {
	case s3policy.SSEModeS3:
		if info.Metadata.Get(encrypt.SseGenericHeader) != "AES256" {
			return ErrFittedFinalizationStorageV1
		}
	case s3policy.SSEModeC:
		if info.Metadata.Get(encrypt.SseCustomerAlgorithm) != "AES256" {
			return ErrFittedFinalizationStorageV1
		}
	default:
		return ErrFittedFinalizationStorageV1
	}
	body, err := c.GetVerifiedVersionBounded(ctx, r.Key, version, r.SHA256[:], r.Bytes)
	if err != nil {
		return fittedFinalizationErrorV1(ctx, err)
	}
	validSize := int64(len(body)) == r.Bytes
	clear(body)
	if !validSize {
		return ErrFittedFinalizationStorageV1
	}
	if err := fitObjectContextError(ctx); err != nil {
		return err
	}
	if err := c.verifyEvidenceRetention(ctx, r.Key, version, r.RetainUntil); err != nil {
		return fittedFinalizationErrorV1(ctx, err)
	}
	return fitObjectContextError(ctx)
}

// PutFittedFinalizationReservedV1 invokes SDK PutObject at most once, with
// DisableMultipart, after an empty exact-key inventory. SDK transport retries
// may still occur; shadow history refuses. The durable caller preconditions
// above are mandatory, including after an empty recovery observation. There is
// no reuse-latest, retention rewrite, compensating delete or upload retry here.
// The caller must reserve global processing/archive resources before retrieving
// this body and its bounded clone. This API enforces one output cap, not total
// producer/process memory, and must not be invoked a second time after an attempt.
func (c *Client) PutFittedFinalizationReservedV1(ctx context.Context, r FittedFinalizationReservationV1, data []byte) (StoredObject, error) {
	if err := validateFittedFinalizationReservationV1(r); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	if err := c.validateFittedFinalizationClientV1(); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	if int64(len(data)) != r.Bytes || sha256.Sum256(data) != r.SHA256 {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, ErrFittedFinalizationStorageV1)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.Key, ""); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	payload := append([]byte(nil), data...)
	defer clear(payload)
	if sha256.Sum256(payload) != r.SHA256 {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, ErrFittedFinalizationStorageV1)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, fittedFinalizationErrorV1(ctx, err)
	}
	opts := c.evidencePutOpts(r.ContentType, r.RetainUntil.UTC())
	opts.DisableMultipart = true
	info, err := c.mc.PutObject(ctx, c.bucket, r.Key, bytes.NewReader(payload), r.Bytes, opts)
	stored := StoredObject{SHA256: r.SHA256}
	// A positive SDK identity remains useful even when PUT reports a late error.
	// Never replace an unknown/unversioned response with a local sentinel.
	if validFitVersionID(info.VersionID) {
		stored.VersionID = info.VersionID
	}
	if err != nil {
		return stored, fittedFinalizationErrorV1(ctx, err)
	}
	if stored.VersionID == "" {
		return stored, fittedFinalizationErrorV1(ctx, ErrFittedFinalizationStorageV1)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return stored, fittedFinalizationErrorV1(ctx, err)
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.Key, stored.VersionID); err != nil {
		return stored, fittedFinalizationErrorV1(ctx, err)
	}
	if err := c.verifyFittedFinalizationObjectV1(ctx, r, stored.VersionID); err != nil {
		return stored, fittedFinalizationErrorV1(ctx, err)
	}
	return stored, nil
}

// ResolveFittedFinalizationVersionV1 is entirely read-only. knownVersion is the
// positive identity already observed/persisted by the original caller, or empty
// after an unknown PUT outcome. Only a sole exact version with complete bounded
// byte/media/SSE/COMPLIANCE-retention verification becomes exact-verified.
func (c *Client) ResolveFittedFinalizationVersionV1(ctx context.Context, r FittedFinalizationReservationV1, knownVersion string) (FittedFinalizationObservationV1, error) {
	observation := FittedFinalizationObservationV1{State: FittedFinalizationUnresolvedV1}
	if validFitVersionID(knownVersion) {
		observation.Object = StoredObject{SHA256: r.SHA256, VersionID: knownVersion}
	}
	if err := validateFittedFinalizationReservationV1(r); err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	if knownVersion != "" && !validFitVersionID(knownVersion) {
		return observation, fittedFinalizationErrorV1(ctx, ErrFittedFinalizationStorageV1)
	}
	observation.Object = StoredObject{SHA256: r.SHA256, VersionID: knownVersion}
	if err := c.validateFittedFinalizationClientV1(); err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	found := false
	err := scanExactKeyVersions(ctx, c.mc, c.bucket, r.Key, 2, func(_ context.Context, item minio.ObjectInfo) (bool, error) {
		if found || item.IsDeleteMarker || item.Size != r.Bytes || !validFitVersionID(item.VersionID) || (knownVersion != "" && item.VersionID != knownVersion) {
			return false, ErrFittedFinalizationStorageV1
		}
		found = true
		observation.Object.VersionID = item.VersionID
		return false, nil
	})
	if err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	if !found {
		observation.State = FittedFinalizationEmptyUnresolvedV1
		if knownVersion != "" {
			return observation, fittedFinalizationErrorV1(ctx, ErrFittedFinalizationStorageV1)
		}
		return observation, nil
	}
	if err := c.verifyFittedFinalizationObjectV1(ctx, r, observation.Object.VersionID); err != nil {
		return observation, fittedFinalizationErrorV1(ctx, err)
	}
	observation.State = FittedFinalizationVerifiedV1
	return observation, nil
}
