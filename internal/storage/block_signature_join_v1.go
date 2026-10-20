// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/render"
	"time"
)

// The caller's SAME native request owns one shared provider slot and bounded
// object/metadata/header staging through this complete synchronous operation.
// This API supplies no resource, source, tenant or signing permission.
func (c *Client) PutBlockSignatureEvidenceV1(ctx context.Context, key string, data []byte, retainUntil time.Time) (StoredObject, error) {
	stored := StoredObject{SHA256: sha256.Sum256(data)}
	if c == nil || len(data) == 0 || len(data) > render.MaxArchivedSignatureSpanBytes {
		return stored, errors.New("signature span exceeds original archived span bound")
	}
	retainUntil, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return stored, err
	}
	body, version, err := c.resolveCommittedVersionForSendV1(ctx, key, stored.SHA256[:])
	clear(body)
	body = nil
	if err == nil {
		stored.VersionID = version
		if err = c.RetainEvidenceVersionForSendV1(ctx, key, version, stored.SHA256[:], retainUntil); err != nil {
			return stored, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
		}
		return stored, nil
	}
	if !errors.Is(err, errStoredVersionNotFound) {
		return stored, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
	}
	opts := c.putOpts("text/html")
	if c.requireEvidenceLock {
		opts = c.evidencePutOpts("text/html", retainUntil)
	}
	// The original signature span is intrinsically <=5056 bytes. A single PUT
	// avoids a multipart worker lifetime; this synchronous call joins the request
	// and bounded response before returning. No arbitrary upload cap is added.
	opts.DisableMultipart = true
	opts.NumThreads = 1
	info, err := c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		return stored, fmt.Errorf("put immutable evidence %q: %w", key, err)
	}
	stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
	if err != nil {
		return stored, err
	}
	if !c.requireEvidenceLock {
		return stored, nil
	}
	if err = c.verifyEvidenceRetention(ctx, key, stored.VersionID, opts.RetainUntilDate); err != nil {
		return stored, err
	}
	verified, err := c.GetVerifiedVersionForSendV1(ctx, key, stored.VersionID, stored.SHA256[:])
	clear(verified)
	if err != nil {
		return stored, fmt.Errorf("put immutable evidence %q: exact-version readback: %w", key, err)
	}
	return stored, nil
}
