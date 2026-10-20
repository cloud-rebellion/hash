// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/minio/minio-go/v7"
)

// Send uses the SAME first-party client and bounded transport, but owns the
// actual synchronous HTTP body through Close. minio.Object.Close only signals
// its background request goroutine; it cannot witness this owner's last local
// provider use. Core.GetObject exposes the underlying concrete response body.
// Exact HEAD/version/ETag, digest, legacy search and retention decisions below
// remain the original client policy; this API supplies no work/byte authority.
func (c *Client) getObjectVersionForSendV1(ctx context.Context, key, versionID string) ([]byte, error) {
	if versionID == DevelopmentVersionID {
		if c.requireEvidenceLock {
			return nil, fmt.Errorf("get %q: development object version sentinel is forbidden in production", key)
		}
		versionID = ""
	}
	opts := c.getOpts(versionID)
	if versionID != "" {
		info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(versionID))
		if err != nil {
			return nil, fmt.Errorf("stat %q version %q: %w", key, versionID, err)
		}
		if info.VersionID != versionID {
			return nil, fmt.Errorf("get %q version %q: provider returned version %q", key, versionID, info.VersionID)
		}
		if info.ETag != "" {
			if err = opts.SetMatchETag(info.ETag); err != nil {
				return nil, fmt.Errorf("get %q version %q: %w", key, versionID, err)
			}
		}
	}
	reader, info, _, err := (minio.Core{Client: c.mc}).GetObject(withObjectResponseLimitV1(ctx, maxStoredObjectBytes), c.bucket, key, opts)
	if err != nil {
		return nil, fmt.Errorf("get %q version %q: %w", key, versionID, err)
	}
	if reader == nil {
		return nil, fmt.Errorf("get %q version %q: missing response body", key, versionID)
	}
	if versionID != "" && info.VersionID != versionID {
		closeErr := reader.Close()
		return nil, errors.Join(fmt.Errorf("get %q version %q: provider returned version %q", key, versionID, info.VersionID), closeErr)
	}
	body, readErr := readBounded(reader, maxStoredObjectBytes)
	// Actual response Close is synchronous and its bounded body joins any active
	// Read. Preserve close failure/cancellation as unavailable, never success.
	closeErr := reader.Close()
	if err = errors.Join(readErr, closeErr); err != nil {
		clear(body)
		return nil, fmt.Errorf("get %q version %q: %w", key, versionID, err)
	}
	return body, nil
}

func (c *Client) GetVerifiedVersionForSendV1(ctx context.Context, key, versionID string, expectedSHA256 []byte) ([]byte, error) {
	if len(expectedSHA256) != sha256.Size {
		return nil, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(versionID); err != nil {
		return nil, fmt.Errorf("verify stored object %q: %w", key, err)
	}
	return c.getVersionVerifiedForSendV1(ctx, key, versionID, expectedSHA256)
}

func (c *Client) getVersionVerifiedForSendV1(ctx context.Context, key, versionID string, expectedSHA256 []byte) ([]byte, error) {
	body, err := c.getObjectVersionForSendV1(ctx, key, versionID)
	if err != nil {
		return nil, err
	}
	actual := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(actual[:], expectedSHA256) != 1 {
		return nil, fmt.Errorf("verify stored object %q version %q: SHA-256 mismatch", key, versionID)
	}
	return body, nil
}

func (c *Client) ResolveVerifiedLegacyForSendV1(ctx context.Context, key string, expectedSHA256 []byte) ([]byte, StoredObject, error) {
	body, versionID, err := c.resolveCommittedVersionForSendV1(ctx, key, expectedSHA256)
	stored := StoredObject{VersionID: versionID}
	if len(expectedSHA256) == sha256.Size {
		copy(stored.SHA256[:], expectedSHA256)
	}
	if err != nil {
		return nil, stored, err
	}
	return body, stored, nil
}

// resolveLatestMatchingVersion is the idempotency check for deterministic
// legal writes. It deliberately inspects only the exact current version: a
// same-digest retry reuses its VersionId, while different bytes create a new
// intentional version. History search remains exclusive to explicitly legacy
// database rows, so a writer cannot make a new write depend on an unbounded
// number of attacker-created shadow versions.

func (c *Client) resolveCommittedVersionForSendV1(ctx context.Context, key string, expectedSHA256 []byte) ([]byte, string, error) {
	if len(expectedSHA256) != sha256.Size {
		return nil, "", errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	var latestVersionID string
	var latestErr error
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(""))
	if err != nil {
		if !isObjectNotFound(err) {
			return nil, "", fmt.Errorf("verify stored object %q: stat latest: %w", key, err)
		}
		latestErr = err
	} else {
		latestVersionID, err = c.persistableVersionID(key, info.VersionID)
		if err != nil {
			return nil, "", fmt.Errorf("verify stored object %q: latest version identity: %w", key, err)
		}
		body, readErr := c.getObjectVersionForSendV1(ctx, key, latestVersionID)
		if readErr == nil {
			actual := sha256.Sum256(body)
			if subtle.ConstantTimeCompare(actual[:], expectedSHA256) == 1 {
				return body, latestVersionID, nil
			}
			latestErr = errors.New("latest object version has a different SHA-256")
		} else {
			return nil, "", fmt.Errorf("verify stored object %q latest version %q: %w", key, latestVersionID, readErr)
		}
	}

	// Disposable development buckets need not enable versioning. There is no
	// older immutable version to recover in that mode.
	if !c.requireEvidenceLock {
		return nil, "", fmt.Errorf("verify stored object %q: %w: %v", key, errStoredVersionNotFound, latestErr)
	}

	candidates := 0
	var matchedBody []byte
	var matchedVersionID string
	err = scanExactKeyVersions(ctx, c.mc, c.bucket, key, maxCommittedVersionCandidates+1, func(searchCtx context.Context, version minio.ObjectInfo) (bool, error) {
		candidates++
		if candidates > maxCommittedVersionCandidates {
			return false, fmt.Errorf("more than %d candidate versions", maxCommittedVersionCandidates)
		}
		if version.IsDeleteMarker || version.VersionID == latestVersionID {
			return false, nil
		}
		candidateVersionID, versionErr := c.persistableVersionID(key, version.VersionID)
		if versionErr != nil {
			return false, fmt.Errorf("listed version identity: %w", versionErr)
		}
		body, readErr := c.getObjectVersionForSendV1(searchCtx, key, candidateVersionID)
		if readErr != nil {
			return false, fmt.Errorf("version %q: %w", candidateVersionID, readErr)
		}
		actual := sha256.Sum256(body)
		if subtle.ConstantTimeCompare(actual[:], expectedSHA256) == 1 {
			matchedBody = body
			matchedVersionID = candidateVersionID
			return true, nil
		}
		clear(body)
		return false, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("verify stored object %q: %w", key, err)
	}
	if matchedVersionID != "" {
		return matchedBody, matchedVersionID, nil
	}
	return nil, "", fmt.Errorf("verify stored object %q: %w: %v", key, errStoredVersionNotFound, latestErr)
}

func (c *Client) RetainEvidenceVersionForSendV1(ctx context.Context, key, versionID string, expectedSHA256 []byte, retainUntil time.Time) error {
	if key == "" {
		return nil
	}
	if len(expectedSHA256) != sha256.Size {
		return errors.New("retain immutable evidence: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(versionID); err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	retainUntil, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if !c.requireEvidenceLock {
		_, err := c.GetVerifiedVersionForSendV1(ctx, key, versionID, expectedSHA256)
		return err
	}
	// COMPLIANCE retention cannot be shortened. A prior attempt (or legacy
	// buggy retry) may already have installed an equal or later deadline, so
	// read first and avoid an illegal shortening request when the durable target
	// is already satisfied.
	if err := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); err == nil {
		_, err := c.GetVerifiedVersionForSendV1(ctx, key, versionID, expectedSHA256)
		return err
	}
	mode := minio.Compliance
	if err := c.mc.PutObjectRetention(ctx, c.bucket, key, minio.PutObjectRetentionOptions{
		Mode: &mode, RetainUntilDate: &retainUntil, VersionID: versionID,
	}); err != nil {
		// Another writer may have lengthened the same version between our read and
		// write. Accept the provider error only when a fresh read proves the exact
		// durable minimum is nevertheless satisfied.
		if verifyErr := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); verifyErr == nil {
			_, readErr := c.GetVerifiedVersionForSendV1(ctx, key, versionID, expectedSHA256)
			return readErr
		}
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if err := c.verifyEvidenceRetention(ctx, key, versionID, retainUntil); err != nil {
		return err
	}
	_, err = c.GetVerifiedVersionForSendV1(ctx, key, versionID, expectedSHA256)
	return err
}
