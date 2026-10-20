// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

// FitTransientReservation must already be durably reserved by the preparation
// saga before storage is used. This adapter proves object identity, not SQL
// ownership, authorization, selection or permission to compensate an upload.
type FitTransientReservation struct {
	Key         string
	SHA256      [sha256.Size]byte
	Bytes       int64
	ContentType string
}

// Keep cancellation identity available to internal recovery without exposing
// caller-supplied cause text in an error returned through an application path.
type fitObjectCancellation struct{ canceled, cause error }

func (e *fitObjectCancellation) Error() string   { return e.canceled.Error() }
func (e *fitObjectCancellation) Unwrap() []error { return []error{e.canceled, e.cause} }
func fitObjectContextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &fitObjectCancellation{canceled: err, cause: context.Cause(ctx)}
	}
	return nil
}

// A version listing does not contain authoritative media-type metadata. Check
// the same immutable encrypted version before reading its body or pinning it.
func (c *Client) verifyFitTransientMetadata(ctx context.Context, r FitTransientReservation, version string) error {
	if err := fitObjectContextError(ctx); err != nil {
		return err
	}
	info, err := c.mc.StatObject(ctx, c.bucket, r.Key, c.statOpts(version))
	if err != nil {
		if canceled := fitObjectContextError(ctx); canceled != nil {
			return canceled
		}
		return fmt.Errorf("fit object metadata: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return err
	}
	if info.VersionID != version || info.Size != r.Bytes || info.ContentType != r.ContentType {
		return errors.New("fit object metadata: version, size or media type mismatch")
	}
	return nil
}

func validFitVersionID(value string) bool {
	trimmed := strings.TrimSpace(value)
	if len(value) == 0 || len(value) > maxPersistedVersionIDBytes || !utf8.ValidString(value) || trimmed == "" || trimmed == "null" || trimmed == DevelopmentVersionID {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true // Preserve accepted opaque provider bytes; never trim them.
}

func validateFitTransientReservation(r FitTransientReservation) error {
	p := strings.Split(r.Key, "/")
	if len(p) != 8 || p[0] != "org" || p[2] != "documents" || p[4] != "signatures" || p[5] != "fit" {
		return errors.New("fit object: operation-owned key is required")
	}
	for _, i := range []int{1, 3, 6} {
		id, err := uuid.Parse(p[i])
		if err != nil || id == uuid.Nil || id.String() != p[i] {
			return errors.New("fit object: canonical operation identity is required")
		}
	}
	var limit int64
	switch p[7] {
	case "span.html":
		limit = 1 << 20
		if r.ContentType != "text/html" {
			return errors.New("fit object: invalid span media type")
		}
	case "manifest.json":
		limit = 2 << 20
		if r.ContentType != "application/json" {
			return errors.New("fit object: invalid manifest media type")
		}
	default:
		pageText := strings.TrimSuffix(strings.TrimPrefix(p[7], "page-"), ".fit")
		page, err := strconv.Atoi(pageText)
		if err != nil || page < 1 || page > 500 || p[7] != "page-"+strconv.Itoa(page)+".fit" || r.ContentType != signaturefit.MediaType {
			return errors.New("fit object: invalid page artifact")
		}
		limit = signaturefit.MaxPackageBytes
	}
	if r.Bytes < 1 || r.Bytes > limit || r.SHA256 == [sha256.Size]byte{} {
		return errors.New("fit object: invalid reserved bytes or digest")
	}
	return nil
}

type fitObjectCloseFailureV1 struct{ cause error }

func (e *fitObjectCloseFailureV1) Error() string {
	return "bounded object read: response cleanup failed"
}
func (e *fitObjectCloseFailureV1) Unwrap() error { return e.cause }

// GetVerifiedVersionBounded enforces a caller's narrower part budget before
// reading body bytes. It neither resolves latest nor searches historical
// versions. SSE policy and exact provider VersionId checks match legal reads.
// Use the synchronous Core response API: the high-level Object.Close merely
// cancels an internal goroutine without joining its response-body cleanup.
// This function owns and closes the actual GET response before returning. That
// is local response ownership, not remote-server/whole-transport retirement.
func (c *Client) GetVerifiedVersionBounded(ctx context.Context, key, versionID string, expectedSHA256 []byte, limit int64) (body []byte, retErr error) {
	if c == nil || c.mc == nil || c.bucket == "" {
		return nil, errors.New("bounded object read: storage is unavailable")
	}
	if key == "" || key != strings.TrimSpace(key) || strings.ContainsAny(key, "\x00\r\n\t") || !validFitVersionID(versionID) || len(expectedSHA256) != sha256.Size || limit < 1 || limit > maxStoredObjectBytes {
		return nil, errors.New("bounded object read: invalid commitment or size limit")
	}
	var expected [sha256.Size]byte
	copy(expected[:], expectedSHA256)
	if err := c.validatePinnedVersionID(versionID); err != nil {
		return nil, fmt.Errorf("bounded object read: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return nil, err
	}
	providerVersion := versionID
	ctx = withObjectResponseLimitV1(ctx, limit)
	// Preserve the cheap HEAD admission gate: oversized or wrong-version metadata
	// refuses before GET/body transfer. Both requests use the exact immutable pin.
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(providerVersion))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fitObjectContextError(ctx)
		}
		return nil, fmt.Errorf("bounded object stat: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return nil, err
	}
	if info.VersionID != providerVersion || info.Size < 0 || info.Size > limit {
		return nil, errors.New("bounded object read: provider version or size mismatch")
	}
	var ownedBody []byte
	response, received, _, err := (minio.Core{Client: c.mc}).GetObject(ctx, c.bucket, key, c.getOpts(providerVersion))
	if response != nil {
		defer func() {
			closeErr := response.Close()
			if closeErr != nil {
				retErr = errors.Join(retErr, &fitObjectCloseFailureV1{cause: closeErr})
			}
			if canceled := fitObjectContextError(ctx); canceled != nil {
				retErr = errors.Join(retErr, canceled)
			}
			if retErr != nil {
				clear(ownedBody)
				body = nil
			}
		}()
	}
	if err != nil {
		if ctx.Err() != nil {
			return nil, fitObjectContextError(ctx)
		}
		return nil, fmt.Errorf("bounded object read: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return nil, err
	}
	if response == nil || received.VersionID != providerVersion || received.Size != info.Size || received.Size < 0 || received.Size > limit {
		return nil, errors.New("bounded object read: provider version or size mismatch")
	}
	// Retain even a partial/error body until the synchronous response Close has
	// returned. Limit+1 distinguishes an oversized stream without unbounded reads.
	ownedBody, err = io.ReadAll(io.LimitReader(response, limit+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, fitObjectContextError(ctx)
		}
		return nil, fmt.Errorf("bounded object read: %w", err)
	}
	if int64(len(ownedBody)) > limit {
		return nil, errors.New("bounded object read: object exceeds size limit")
	}
	if err := fitObjectContextError(ctx); err != nil {
		return nil, err
	}
	actual := sha256.Sum256(ownedBody)
	if int64(len(ownedBody)) != info.Size || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		return nil, errors.New("bounded object read: size or digest mismatch")
	}
	return ownedBody, nil
}

// ResolveFitTransientVersion reconciles only a durably reserved operation key.
// A complete empty history is distinguished from one matching exact version.
// Shadow versions, delete markers and conflicting bytes refuse. It does not
// delete, scan by digest, choose latest, apply retention or rewrite evidence.
// An empty observation after an attempted upload does not prove that upload
// cannot commit later; its durable uncertain inventory must remain pending.
func (c *Client) ResolveFitTransientVersion(ctx context.Context, r FitTransientReservation) (StoredObject, bool, error) {
	if err := validateFitTransientReservation(r); err != nil {
		return StoredObject{}, false, err
	}
	if c == nil || c.mc == nil || c.bucket == "" {
		return StoredObject{}, false, errors.New("fit reconciliation: storage is unavailable")
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, false, err
	}
	var found *minio.ObjectInfo
	err := scanExactKeyVersions(ctx, c.mc, c.bucket, r.Key, 2, func(_ context.Context, item minio.ObjectInfo) (bool, error) {
		if found != nil || item.IsDeleteMarker || item.Size != r.Bytes || !validFitVersionID(item.VersionID) {
			return false, errors.New("fit reconciliation: unexpected object history")
		}
		if err := c.validatePinnedVersionID(item.VersionID); err != nil {
			return false, fmt.Errorf("fit reconciliation: %w", err)
		}
		copyItem := item
		found = &copyItem
		return false, nil
	})
	if err != nil {
		if canceled := fitObjectContextError(ctx); canceled != nil {
			return StoredObject{}, false, canceled
		}
		return StoredObject{}, false, err
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, false, err
	}
	if found == nil {
		return StoredObject{}, false, nil
	}
	if err := c.verifyFitTransientMetadata(ctx, r, found.VersionID); err != nil {
		return StoredObject{}, false, err
	}
	body, err := c.GetVerifiedVersionBounded(ctx, r.Key, found.VersionID, r.SHA256[:], r.Bytes)
	if err != nil {
		return StoredObject{}, false, err
	}
	defer clear(body)
	if int64(len(body)) != r.Bytes {
		return StoredObject{}, false, errors.New("fit reconciliation: reserved size mismatch")
	}
	return StoredObject{VersionID: found.VersionID, SHA256: r.SHA256}, true, nil
}

// PutFitTransientReserved performs at most one upload call after proving empty
// history. Before calling it, persist upload_attempted; any ambiguous result
// must use ResolveFitTransientVersion before another call or compensation.
// MinIO transport may internally retry a provider request: any resulting shadow
// history is detected and refuses. This is never a WORM write.
func (c *Client) PutFitTransientReserved(ctx context.Context, r FitTransientReservation, data []byte) (StoredObject, error) {
	if err := validateFitTransientReservation(r); err != nil {
		return StoredObject{}, err
	}
	if int64(len(data)) != r.Bytes || sha256.Sum256(data) != r.SHA256 {
		return StoredObject{}, errors.New("fit upload: reserved payload mismatch")
	}
	payload := append([]byte(nil), data...)
	defer clear(payload)
	if sha256.Sum256(payload) != r.SHA256 {
		return StoredObject{}, errors.New("fit upload: payload changed during capture")
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, err
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.Key, ""); err != nil {
		if canceled := fitObjectContextError(ctx); canceled != nil {
			return StoredObject{}, canceled
		}
		return StoredObject{}, fmt.Errorf("fit upload: empty owned history required: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{}, err
	}
	opts := c.putOpts(r.ContentType)
	opts.DisableMultipart = true // Bounded parts fit one PUT; no abandoned multipart upload.
	info, err := c.mc.PutObject(ctx, c.bucket, r.Key, bytes.NewReader(payload), r.Bytes, opts)
	if err != nil {
		if canceled := fitObjectContextError(ctx); canceled != nil {
			return StoredObject{SHA256: r.SHA256}, fmt.Errorf("fit upload outcome requires reconciliation: %w", canceled)
		}
		return StoredObject{SHA256: r.SHA256}, fmt.Errorf("fit upload outcome requires reconciliation: %w", err)
	}
	version, err := c.persistableVersionID(r.Key, info.VersionID)
	if err != nil {
		return StoredObject{SHA256: r.SHA256}, err
	}
	if !validFitVersionID(version) {
		return StoredObject{SHA256: r.SHA256}, errors.New("fit upload: an immutable provider version is required")
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{SHA256: r.SHA256, VersionID: version}, fmt.Errorf("fit upload outcome requires reconciliation: %w", err)
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.Key, version); err != nil {
		if canceled := fitObjectContextError(ctx); canceled != nil {
			return StoredObject{SHA256: r.SHA256, VersionID: version}, fmt.Errorf("fit upload history requires reconciliation: %w", canceled)
		}
		return StoredObject{SHA256: r.SHA256, VersionID: version}, fmt.Errorf("fit upload history requires reconciliation: %w", err)
	}
	if err := fitObjectContextError(ctx); err != nil {
		return StoredObject{SHA256: r.SHA256, VersionID: version}, err
	}
	if err := c.verifyFitTransientMetadata(ctx, r, version); err != nil {
		return StoredObject{SHA256: r.SHA256, VersionID: version}, fmt.Errorf("fit upload metadata requires reconciliation: %w", err)
	}
	body, err := c.GetVerifiedVersionBounded(ctx, r.Key, version, r.SHA256[:], r.Bytes)
	clear(body)
	if err != nil {
		return StoredObject{SHA256: r.SHA256, VersionID: version}, err
	}
	return StoredObject{SHA256: r.SHA256, VersionID: version}, nil
}
