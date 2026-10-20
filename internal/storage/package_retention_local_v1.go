// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

var ErrPackagePDFLocalRetentionV1 = errors.New("storage: exact package PDF retention unavailable")

// The namespace identifies the constructor's public storage coordinates. It
// contains no credential, encryption key, object identity or permission claim.
// Length framing and the format domain make distinct coordinates unambiguous.
func packageEvidenceNamespaceForProfileV1(p *evidenceLocalClientProfileV1) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("hash/package-evidence-namespace/v1\x00"))
	var length [8]byte
	text := func(s string) {
		binary.BigEndian.PutUint64(length[:], uint64(len(s)))
		_, _ = h.Write(length[:])
		_, _ = io.WriteString(h, s)
	}
	text(p.endpoint)
	if p.secure {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	text(p.region)
	binary.BigEndian.PutUint64(length[:], uint64(p.lookup))
	_, _ = h.Write(length[:])
	text(p.packageBucket)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (c *Client) PackageEvidenceNamespaceV1() ([sha256.Size]byte, error) {
	p, err := c.evidenceLocalProfileV1()
	if err != nil || !p.packageLock || !c.requireEvidenceLock || p.packageBucket != c.bucket || p.packageLock != c.requireEvidenceLock || p.packageNamespace != packageEvidenceNamespaceForProfileV1(p) {
		return [sha256.Size]byte{}, ErrPackagePDFLocalRetentionV1
	}
	return p.packageNamespace, nil
}

// PackagePDFLocalRetentionV1 is one joined, exact-version provider observation.
// It grants no attempt, SQL, signature or replay authority. Copies share the
// same one-shot acknowledgement and retain funding through actual callback use.
type PackagePDFLocalRetentionV1 struct {
	state *packagePDFLocalRetentionStateV1
}
type packagePDFLocalRetentionStateV1 struct {
	mu                         sync.Mutex
	self                       *packagePDFLocalRetentionStateV1
	owner                      *evidenceLocalPutStateV1
	client                     *Client
	ctx                        context.Context
	namespace                  [sha256.Size]byte
	observedUntil              time.Time
	borrowers                  int
	success, delivered, closed bool
	retired                    bool
}

// RetainPackagePDFLocalOwnedV1 accepts exact storage commitments, not caller
// permission or size credit. The native package plan must supply these values
// from its private persisted capture and close its SQL before calling storage.
func (c *Client) RetainPackagePDFLocalOwnedV1(ctx context.Context, key, version string, expected []byte, expectedBytes int64, until time.Time, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*PackagePDFLocalRetentionV1, workguard.AdmissionDenialV1, error) {
	zero := workguard.AdmissionDenialV1{}
	namespace, err := c.PackageEvidenceNamespaceV1()
	if err != nil || !c.requireEvidenceLock || !pinnedPDFOpaqueV1(key) || !pinnedPDFOpaqueV1(version) || strings.TrimSpace(version) == "null" || strings.TrimSpace(version) == DevelopmentVersionID || len(expected) != sha256.Size || expectedBytes < 1 || expectedBytes > maxPinnedPDFReadBytesV1 {
		return nil, zero, ErrPackagePDFLocalRetentionV1
	}
	if err = c.validatePinnedVersionID(version); err != nil {
		return nil, zero, errors.Join(ErrPackagePDFLocalRetentionV1, err)
	}
	canonicalUntil, err := canonicalEvidenceRetainUntil(until)
	if err != nil || !canonicalUntil.Equal(until) || !packageRetentionTimeV1(canonicalUntil) {
		return nil, zero, ErrPackagePDFLocalRetentionV1
	}
	until = canonicalUntil
	// This frame is prepaid before the wrapper/state or independent inputs exist.
	// The shared concrete lane owns its sole Provider grant and private SDK/IO.
	extra := 8*(int64(unsafe.Sizeof(PackagePDFLocalRetentionV1{}))+int64(unsafe.Sizeof(packagePDFLocalRetentionStateV1{}))) + 4096 + 32*int64(len(c.bucket))
	owner, local, ownedKey, ownedVersion, denial, err := c.newEvidenceLocalReadWithFixedParentV1(ctx, key, version, expected, coordinator, org, extra)
	if owner == nil {
		return nil, denial, errors.Join(ErrPackagePDFLocalRetentionV1, err)
	}
	s := &packagePDFLocalRetentionStateV1{owner: owner, client: c, ctx: ctx, namespace: namespace}
	s.self = s
	h := &PackagePDFLocalRetentionV1{state: s}
	if err == nil {
		s.observedUntil, err = local.retainPackagePDFVersionLocalV1(ctx, ownedKey, ownedVersion, owner.data, expectedBytes, until, owner.hashScratch)
	}
	if err == nil {
		err = ctx.Err()
	}
	err = finishEvidenceLocalReadV1(owner, err)
	s.success = err == nil
	if err != nil {
		s.observedUntil = time.Time{}
		return h, zero, errors.Join(ErrPackagePDFLocalRetentionV1, err)
	}
	return h, zero, nil
}

func packageRetentionTimeV1(t time.Time) bool {
	return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999
}

func packageRetentionSatisfiedV1(mode *minio.RetentionMode, observed *time.Time, minimum time.Time) bool {
	return mode != nil && *mode == minio.Compliance && observed != nil && packageRetentionTimeV1(*observed) && !observed.Before(minimum)
}

func (c *Client) retainPackagePDFVersionLocalV1(ctx context.Context, key, version string, expected []byte, expectedBytes int64, target time.Time, scratch []byte) (time.Time, error) {
	// No irreversible provider request precedes complete exact-byte validation.
	if err := c.verifyPackagePDFVersionLocalV1(ctx, key, version, expected, expectedBytes, scratch); err != nil {
		return time.Time{}, err
	}
	mode, observed, readErr := c.mc.GetObjectRetention(ctx, c.bucket, key, version)
	if readErr != nil {
		// An unreadable original policy cannot establish the previous deadline.
		// Refuse before mutation rather than risk requesting a shorter one.
		return time.Time{}, errors.Join(ErrPackagePDFLocalRetentionV1, readErr)
	}
	writeUntil := target
	if observed != nil && packageRetentionTimeV1(*observed) && observed.After(writeUntil) {
		writeUntil = observed.UTC()
	}
	if !packageRetentionSatisfiedV1(mode, observed, target) {
		compliance := minio.Compliance
		putErr := c.mc.PutObjectRetention(ctx, c.bucket, key, minio.PutObjectRetentionOptions{Mode: &compliance, RetainUntilDate: &writeUntil, VersionID: version})
		// An applied/lost acknowledgement, denial or concurrent extension is not
		// success. Only a fresh exact-version read can settle the desired state.
		var verifyErr error
		mode, observed, verifyErr = c.mc.GetObjectRetention(ctx, c.bucket, key, version)
		if verifyErr != nil || !packageRetentionSatisfiedV1(mode, observed, writeUntil) {
			return time.Time{}, errors.Join(ErrPackagePDFLocalRetentionV1, putErr, verifyErr)
		}
	}
	if !packageRetentionSatisfiedV1(mode, observed, target) {
		return time.Time{}, ErrPackagePDFLocalRetentionV1
	}
	if err := c.verifyPackagePDFVersionLocalV1(ctx, key, version, expected, expectedBytes, scratch); err != nil {
		return time.Time{}, err
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return observed.UTC(), nil
}

// This stream uses the actual persisted package member size, rather than the
// generic128MiB evidence ceiling. HEAD and GET must echo the exact version and
// size; only then can the private64KiB hash stream read at most size+1 bytes.
func (c *Client) verifyPackagePDFVersionLocalV1(ctx context.Context, key, version string, expected []byte, expectedBytes int64, scratch []byte) (failure error) {
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(version))
	if err != nil {
		return fmt.Errorf("verify package PDF: exact-version HEAD: %w", err)
	}
	if info.VersionID != version || info.Size != expectedBytes {
		return ErrPackagePDFLocalRetentionV1
	}
	opts := c.getOpts(version)
	if info.ETag != "" {
		if err = opts.SetMatchETag(info.ETag); err != nil {
			return err
		}
	}
	reader, actual, _, err := (minio.Core{Client: c.mc}).GetObject(withObjectResponseLimitV1(ctx, expectedBytes), c.bucket, key, opts)
	if reader != nil {
		defer func() {
			failure = errors.Join(failure, reader.Close(), ctx.Err())
			clear(scratch)
		}()
	}
	if err != nil {
		return fmt.Errorf("verify package PDF: exact-version GET: %w", err)
	}
	if reader == nil || actual.VersionID != version || actual.Size != expectedBytes {
		return ErrPackagePDFLocalRetentionV1
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, io.LimitReader(reader, expectedBytes+1), scratch)
	if err != nil {
		return fmt.Errorf("verify package PDF: exact body: %w", err)
	}
	if n != expectedBytes || subtle.ConstantTimeCompare(hash.Sum(nil), expected) != 1 {
		return ErrPackagePDFLocalRetentionV1
	}
	return ctx.Err()
}

func (h *PackagePDFLocalRetentionV1) WithRetainedV1(consume func(observedUntil time.Time) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrPackagePDFLocalRetentionV1
	}
	s := h.state
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	if s.self != s || s.closed || s.delivered || !s.success || s.owner == nil || s.client == nil || s.ctx == nil || s.ctx.Err() != nil {
		return ErrPackagePDFLocalRetentionV1
	}
	namespace, err := s.client.PackageEvidenceNamespaceV1()
	if err != nil || !s.client.requireEvidenceLock || namespace != s.namespace {
		return ErrPackagePDFLocalRetentionV1
	}
	observed := s.observedUntil
	return withEvidenceLocalAcknowledgementV1(s.owner, func() error {
		s.delivered = true
		s.borrowers++
		locked = false
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.borrowers--
			s.clearClosedV1()
			s.mu.Unlock()
		}()
		return consume(observed)
	})
}

func (s *packagePDFLocalRetentionStateV1) clearClosedV1() {
	if s.closed && s.borrowers == 0 {
		// The exact owner is retained until RetiredV1 proves its real release.
		// Cancellation and consumer close alone cannot prove a local IO join.
		s.client, s.ctx = nil, nil
		s.namespace = [sha256.Size]byte{}
		s.observedUntil = time.Time{}
	}
}

// RetiredV1 reports actual consumer and IO retirement, never context expiry.
// It cannot mint a successful retention observation. Invalid/nil handles fail
// closed; ordinary handle copies share this exact owner and retirement state.
func (h *PackagePDFLocalRetentionV1) RetiredV1() bool {
	if h == nil || h.state == nil {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || !s.closed || s.borrowers != 0 {
		return false
	}
	if s.retired {
		return true
	}
	owner := s.owner
	if owner == nil {
		return false
	}
	owner.mu.Lock()
	retired := owner.self == owner && owner.consumerClosed && owner.ioJoined && owner.active == 0 && owner.released && owner.grant == nil && owner.provider == nil
	owner.mu.Unlock()
	if !retired {
		return false
	}
	s.retired = true
	s.owner = nil
	s.clearClosedV1()
	return true
}

func (h *PackagePDFLocalRetentionV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s {
		s.mu.Unlock()
		return
	}
	s.closed = true
	owner := s.owner
	s.clearClosedV1()
	s.mu.Unlock()
	if owner != nil {
		(&EvidenceLocalPutV1{state: owner}).CloseConsumerV1()
	}
	_ = h.RetiredV1()
}
