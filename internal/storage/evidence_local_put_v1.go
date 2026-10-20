// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"io"
	"net/http"
	"strings"
	"time"
)

// PutEvidenceVersionedLocalOwnedV1 is only the concrete native finalization
// PUT/reuse/readback lane, using the original Client's authenticated constructor
// policy. The caller already owns its real source and native organisation scope.
// This local owner grants no SQL/source/READY authority and exposes no Grant.
// Every nonnil handle, including error returns, must be kept until the actual
// result/error consumer ends and then closed. Only a real local IO join credits
// ProviderStreams; its independent Parent retains output/error aliases longer.
func (c *Client) PutEvidenceVersionedLocalOwnedV1(ctx context.Context, key, contentType string, data []byte, retainUntil time.Time, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalPutV1, error) {
	if ctx == nil || ctx.Err() != nil || coordinator == nil || org == uuid.Nil {
		return nil, ErrEvidenceLocalIOV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrEvidenceLocalIOV1
	}
	profile, err := c.evidenceLocalProfileV1()
	if err != nil {
		return nil, err
	}
	retainUntil, err = canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return nil, err
	}
	frameLimit, parent, err := evidenceLocalInitialResourcesV1(data, key, contentType, profile)
	if err != nil {
		return nil, err
	}
	grant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, errors.Join(ErrEvidenceLocalIOV1, err)
	}
	provider, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		grant.Close()
		return nil, errors.Join(ErrEvidenceLocalIOV1, err)
	}
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: grant, provider: provider, coordinator: coordinator, org: org, connections: make(map[*evidenceLocalConnV1]struct{}), bodies: make(map[*evidenceLocalResponseBodyV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), frameLimit: frameLimit, data: bytes.Clone(data), hashScratch: make([]byte, 64<<10), admission: profile.connections}
	owner.self = owner
	base := profile.base.Clone()
	transport := base.Clone()
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if transport.TLSClientConfig != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	} else {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.DialContext = owner.dialV1(base)
	transport.DialTLSContext = owner.dialTLSV1(base)
	owner.transport = transport
	profile.connections.registerV1(transport)
	localSDK, setupErr := minio.New(profile.endpoint, &minio.Options{Transport: &boundedStorageTransportV1{base: &evidenceLocalRoundTripperV1{owner: owner, transport: transport}, connections: profile.connections}, Creds: profile.creds, Secure: profile.secure, Region: profile.region, BucketLookup: profile.lookup})
	var stored StoredObject
	var putErr error
	if setupErr != nil {
		putErr = setupErr
	} else {
		local := *c
		local.mc = localSDK
		local.localProfile = nil
		stored, putErr = local.putEvidenceLocalPolicyV1(ctx, key, contentType, owner.data, retainUntil, owner.hashScratch)
	}
	owner.mu.Lock()
	owner.stored = stored
	owner.success = putErr == nil
	owner.closing = true
	owner.signalV1()
	owner.mu.Unlock()
	go owner.closeIOV1()
	handle := &EvidenceLocalPutV1{state: owner}
	select {
	case <-owner.joined:
		return handle, putErr
	case <-ctx.Done():
		return handle, errors.Join(putErr, ErrEvidenceLocalIOV1, ctx.Err())
	}
}

// PutEvidenceVersionedLocalPinnedOwnedV1 resumes an already persisted version.
// It only verifies and retains that exact version; a missing or inconsistent
// version never falls back to latest and never issues a replacement PUT. The
// original caller owns data while its digest is sampled; only the digest is
// retained by the bounded local IO owner.
func (c *Client) PutEvidenceVersionedLocalPinnedOwnedV1(ctx context.Context, key, version, contentType string, data []byte, retainUntil time.Time, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalPutV1, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || key == "" || len(data) > maxStoredObjectBytes {
		return nil, ErrEvidenceLocalIOV1
	}
	if err := c.validatePinnedVersionID(version); err != nil {
		return nil, err
	}
	until, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	owner, local, ownedKey, ownedVersion, _, err := c.newEvidenceLocalReadV1(ctx, key, version, sum[:], coordinator, org)
	if owner == nil {
		return nil, err
	}
	if err == nil {
		err = local.retainEvidenceVersionLocalV1(ctx, ownedKey, ownedVersion, owner.data, until, owner.hashScratch)
	}
	// This is the supplied persisted pin, not evidence that a new PUT occurred.
	// WithStoredV1 remains unavailable unless the exact-version operation passes.
	owner.mu.Lock()
	owner.stored = StoredObject{SHA256: sum, VersionID: ownedVersion}
	owner.mu.Unlock()
	err = finishEvidenceLocalReadV1(owner, err)
	return &EvidenceLocalPutV1{state: owner}, err
}

func (c *Client) putEvidenceLocalPolicyV1(ctx context.Context, key, contentType string, data []byte, retainUntil time.Time, scratch []byte) (StoredObject, error) {
	stored := StoredObject{SHA256: sha256.Sum256(data)}
	retainUntil, err := canonicalEvidenceRetainUntil(retainUntil)
	if err != nil {
		return stored, err
	}
	if existing, err := c.resolveLatestMatchingVersionLocalV1(ctx, key, stored.SHA256[:], scratch); err == nil {
		if err = c.retainEvidenceVersionLocalV1(ctx, key, existing.VersionID, existing.SHA256[:], retainUntil, scratch); err != nil {
			return existing, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
		}
		return existing, nil
	} else if !errors.Is(err, errStoredVersionNotFound) {
		return stored, fmt.Errorf("reuse immutable evidence %q: %w", key, err)
	}
	opts := c.putOpts(contentType)
	if c.requireEvidenceLock {
		opts = c.evidencePutOpts(contentType, retainUntil)
	}
	// The original128MiB finalization bound is below S3's single-PUT maximum.
	// NumThreads alone cannot join multipart error workers in pinned MinIO77.
	opts.DisableMultipart = true
	opts.NumThreads = 1
	info, err := c.mc.PutObject(ctx, c.bucket, key, bytes.NewReader(data), int64(len(data)), opts)
	if err != nil {
		// A positive provider identity survives a later SDK/read/close error.
		// Keep the failure, and never turn an absent error-result VersionID into
		// the development sentinel. The caller must checkpoint then verify this
		// exact version before publication; it is not a successful stored result.
		if strings.TrimSpace(info.VersionID) != "" {
			version, versionErr := c.persistableVersionID(key, info.VersionID)
			if versionErr == nil {
				stored.VersionID = strings.Clone(version)
			} else {
				err = errors.Join(err, versionErr)
			}
		}
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
	if err = c.verifyEvidenceLocalVersionV1(ctx, key, stored.VersionID, stored.SHA256[:], scratch); err != nil {
		return stored, fmt.Errorf("put immutable evidence %q: exact-version readback: %w", key, err)
	}
	return stored, nil
}

func (c *Client) resolveLatestMatchingVersionLocalV1(ctx context.Context, key string, expected []byte, scratch []byte) (StoredObject, error) {
	stored := StoredObject{}
	if len(expected) != sha256.Size {
		return stored, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	copy(stored.SHA256[:], expected)
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(""))
	if err != nil {
		if isObjectNotFound(err) {
			return stored, errStoredVersionNotFound
		}
		return stored, fmt.Errorf("stat latest object: %w", err)
	}
	stored.VersionID, err = c.persistableVersionID(key, info.VersionID)
	if err != nil {
		return stored, err
	}
	matches, err := c.hashEvidenceLocalVersionV1(ctx, key, stored.VersionID, expected, scratch)
	if err != nil {
		return stored, fmt.Errorf("read latest object version: %w", err)
	}
	if !matches {
		return stored, errStoredVersionNotFound
	}
	return stored, nil
}

// Direct Core GET owns the original real response through Read and Close.
// It hashes the same complete bounded bytes without an unnecessary returned
// body allocation: this finite API returns only the original StoredObject.
func (c *Client) hashEvidenceLocalVersionV1(ctx context.Context, key, version string, expected, scratch []byte) (matches bool, failure error) {
	if len(expected) != sha256.Size {
		return false, errors.New("verify stored object: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(version); err != nil {
		return false, fmt.Errorf("verify stored object %q: %w", key, err)
	}
	providerVersion := version
	if version == DevelopmentVersionID {
		providerVersion = ""
	}
	opts := c.getOpts(providerVersion)
	if providerVersion != "" {
		info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(providerVersion))
		if err != nil {
			return false, fmt.Errorf("stat %q version %q: %w", key, providerVersion, err)
		}
		if info.VersionID != providerVersion {
			return false, fmt.Errorf("get %q version %q: provider returned version %q", key, providerVersion, info.VersionID)
		}
		if info.ETag != "" {
			if err = opts.SetMatchETag(info.ETag); err != nil {
				return false, fmt.Errorf("get %q version %q: %w", key, providerVersion, err)
			}
		}
	}
	reader, info, _, err := (minio.Core{Client: c.mc}).GetObject(withObjectResponseLimitV1(ctx, maxStoredObjectBytes), c.bucket, key, opts)
	if reader != nil {
		defer func() {
			closeErr := reader.Close()
			if closeErr != nil {
				if failure == nil {
					failure = fmt.Errorf("get %q version %q: %w", key, providerVersion, closeErr)
				} else {
					failure = errors.Join(failure, closeErr)
				}
				matches = false
			}
			clear(scratch)
		}()
	}
	if err != nil {
		return false, fmt.Errorf("get %q version %q: %w", key, providerVersion, err)
	}
	if reader == nil {
		return false, fmt.Errorf("get %q version %q: missing response body", key, providerVersion)
	}
	if providerVersion != "" && info.VersionID != providerVersion {
		return false, fmt.Errorf("get %q version %q: provider returned version %q", key, providerVersion, info.VersionID)
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(reader, maxStoredObjectBytes+1), scratch)
	if err != nil {
		return false, fmt.Errorf("get %q version %q: %w", key, providerVersion, err)
	}
	if n > maxStoredObjectBytes {
		return false, fmt.Errorf("get %q version %q: object exceeds %d-byte safety limit", key, providerVersion, maxStoredObjectBytes)
	}
	return subtle.ConstantTimeCompare(hash.Sum(nil), expected) == 1, nil
}
func (c *Client) verifyEvidenceLocalVersionV1(ctx context.Context, key, version string, expected, scratch []byte) error {
	matches, err := c.hashEvidenceLocalVersionV1(ctx, key, version, expected, scratch)
	if err != nil {
		return err
	}
	if !matches {
		return fmt.Errorf("verify stored object %q version %q: SHA-256 mismatch", key, version)
	}
	return nil
}
func (c *Client) retainEvidenceVersionLocalV1(ctx context.Context, key, version string, expected []byte, until time.Time, scratch []byte) error {
	if key == "" {
		return nil
	}
	if len(expected) != sha256.Size {
		return errors.New("retain immutable evidence: expected SHA-256 must be 32 bytes")
	}
	if err := c.validatePinnedVersionID(version); err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	until, err := canonicalEvidenceRetainUntil(until)
	if err != nil {
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if !c.requireEvidenceLock {
		return c.verifyEvidenceLocalVersionV1(ctx, key, version, expected, scratch)
	}
	if err = c.verifyEvidenceRetention(ctx, key, version, until); err == nil {
		return c.verifyEvidenceLocalVersionV1(ctx, key, version, expected, scratch)
	}
	mode := minio.Compliance
	if err = c.mc.PutObjectRetention(ctx, c.bucket, key, minio.PutObjectRetentionOptions{Mode: &mode, RetainUntilDate: &until, VersionID: version}); err != nil {
		if verifyErr := c.verifyEvidenceRetention(ctx, key, version, until); verifyErr == nil {
			return c.verifyEvidenceLocalVersionV1(ctx, key, version, expected, scratch)
		}
		return fmt.Errorf("retain immutable evidence %q: %w", key, err)
	}
	if err = c.verifyEvidenceRetention(ctx, key, version, until); err != nil {
		return err
	}
	return c.verifyEvidenceLocalVersionV1(ctx, key, version, expected, scratch)
}
