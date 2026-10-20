// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

var ErrPackagePDFLocalReadV1 = errors.New("storage: exact package PDF read unavailable")

// PackagePDFLocalReadV1 owns one complete, verified exact-version body. It is
// only storage evidence: the native caller must resolve private capture pins,
// retire SQL before provider IO, and freshly recheck authority before delivery.
// It grants no recipient, document, attempt, SQL or signature authority.
// Handle copies share one one-shot borrower and the same actual IO retirement.
type PackagePDFLocalReadV1 struct {
	state *packagePDFLocalReadStateV1
}

type packagePDFLocalReadStateV1 struct {
	mu                                  sync.Mutex
	self                                *packagePDFLocalReadStateV1
	owner                               *evidenceLocalPutStateV1
	client                              *Client
	ctx                                 context.Context
	namespace                           [sha256.Size]byte
	body                                []byte
	borrowers                           int
	success, delivered, closed, retired bool
}

// ReadPackagePDFLocalOwnedV1 accepts exact persisted storage commitments, not
// caller permission or a claimed budget. The complete body and typed controls
// are prepaid before allocation or provider IO. The shared constructor-owned
// local lane owns the sole Provider grant; no outer provider loan is needed.
// Every nonnil handle, including errors, must be closed and retained until its
// actual RetiredV1 observation. Cancellation alone cannot establish retirement.
func (c *Client) ReadPackagePDFLocalOwnedV1(ctx context.Context, key, version string, expected []byte, expectedBytes int64, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*PackagePDFLocalReadV1, workguard.AdmissionDenialV1, error) {
	zero := workguard.AdmissionDenialV1{}
	namespace, err := c.PackageEvidenceNamespaceV1()
	if err != nil || !c.requireEvidenceLock || !pinnedPDFOpaqueV1(key) || !pinnedPDFOpaqueV1(version) || strings.TrimSpace(version) == "null" || strings.TrimSpace(version) == DevelopmentVersionID || len(expected) != sha256.Size || expectedBytes < 1 || expectedBytes > maxPinnedPDFReadBytesV1 {
		return nil, zero, ErrPackagePDFLocalReadV1
	}
	if err = c.validatePinnedVersionID(version); err != nil {
		return nil, zero, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	// One retained backing array, not a size estimate or a borrowed producer.
	// Shared lane costs already include the digest clone, scratch, constructor,
	// transport, SDK, original key/version and actual response/header controls.
	extra := 8*(int64(unsafe.Sizeof(PackagePDFLocalReadV1{}))+int64(unsafe.Sizeof(packagePDFLocalReadStateV1{}))) + 4096
	if !evidenceLocalAddV1(&extra, expectedBytes, 1) || !evidenceLocalAddV1(&extra, int64(len(c.bucket)), 32) {
		return nil, zero, ErrPackagePDFLocalReadV1
	}
	owner, local, ownedKey, ownedVersion, denial, err := c.newEvidenceLocalReadWithFixedParentV1(ctx, key, version, expected, coordinator, org, extra)
	if owner == nil {
		return nil, denial, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	s := &packagePDFLocalReadStateV1{owner: owner, client: c, ctx: ctx, namespace: namespace}
	s.self = s
	h := &PackagePDFLocalReadV1{state: s}
	if err == nil {
		s.body = make([]byte, int(expectedBytes))
		err = local.readPackagePDFVersionLocalV1(ctx, ownedKey, ownedVersion, owner.data, s.body)
	}
	if err == nil {
		err = ctx.Err()
	}
	err = finishEvidenceLocalReadV1(owner, err)
	s.success = err == nil
	if err != nil {
		return h, zero, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	return h, zero, nil
}

// The actual immutable member size governs both metadata checks and the exact
// body read. No latest-object lookup, metadata-only success or detached body is
// returned. A further real read must prove EOF after the complete body.
func (c *Client) readPackagePDFVersionLocalV1(ctx context.Context, key, version string, expected, body []byte) (failure error) {
	size := int64(len(body))
	info, err := c.mc.StatObject(ctx, c.bucket, key, c.statOpts(version))
	if err != nil {
		return fmt.Errorf("read package PDF: exact-version HEAD: %w", err)
	}
	if info.VersionID != version || info.Size != size {
		return ErrPackagePDFLocalReadV1
	}
	opts := c.getOpts(version)
	if info.ETag != "" {
		if err = opts.SetMatchETag(info.ETag); err != nil {
			return err
		}
	}
	reader, actual, _, err := (minio.Core{Client: c.mc}).GetObject(withObjectResponseLimitV1(ctx, size), c.bucket, key, opts)
	if reader != nil {
		defer func() { failure = errors.Join(failure, reader.Close(), ctx.Err()) }()
	}
	if err != nil {
		return fmt.Errorf("read package PDF: exact-version GET: %w", err)
	}
	if reader == nil || actual.VersionID != version || actual.Size != size {
		return ErrPackagePDFLocalReadV1
	}
	n, err := io.ReadFull(reader, body)
	if err != nil || int64(n) != size {
		return errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	var probe [1]byte
	n, err = reader.Read(probe[:])
	clear(probe[:])
	if n != 0 || err != io.EOF {
		return errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], expected) != 1 {
		return ErrPackagePDFLocalReadV1
	}
	return ctx.Err()
}

// WithPDFV1 lends the verified body synchronously once. The consumer must not
// mutate or retain it after returning; any independent copy needs independent
// admission. This callback consumes bytes and cannot acknowledge application
// authority. Parent/output funding survives fresh native checks and the actual
// writer, even if another handle copy closes the consumer during that work.
func (h *PackagePDFLocalReadV1) WithPDFV1(consume func([]byte) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrPackagePDFLocalReadV1
	}
	s := h.state
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	if s.self != s || s.closed || s.delivered || !s.success || s.owner == nil || s.client == nil || s.ctx == nil || s.ctx.Err() != nil || len(s.body) == 0 {
		return ErrPackagePDFLocalReadV1
	}
	namespace, err := s.client.PackageEvidenceNamespaceV1()
	if err != nil || namespace != s.namespace {
		return ErrPackagePDFLocalReadV1
	}
	return withEvidenceLocalAcknowledgementV1(s.owner, func() error {
		s.delivered = true
		s.borrowers++
		body := s.body
		locked = false
		s.mu.Unlock()
		defer func() {
			s.mu.Lock()
			s.borrowers--
			s.clearClosedV1()
			s.mu.Unlock()
		}()
		return consume(body)
	})
}

func (s *packagePDFLocalReadStateV1) clearClosedV1() {
	if s.closed && s.borrowers == 0 {
		clear(s.body)
		s.body = nil
		s.client, s.ctx = nil, nil
		s.namespace = [sha256.Size]byte{}
	}
}

// RetiredV1 requires the real underlying IO and consumer join, never an expired
// context or a caller acknowledgement. Invalid/nil handles fail closed.
func (h *PackagePDFLocalReadV1) RetiredV1() bool {
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

func (h *PackagePDFLocalReadV1) CloseConsumerV1() {
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
