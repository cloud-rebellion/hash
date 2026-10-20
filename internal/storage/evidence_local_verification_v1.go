// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

// These fixed native evidence consumers share the real constructor-owned local
// IO lane with PUT. They return no object body: exact-version SHA256 is streamed
// under one private64KiB frame and the original128MiB safety ceiling. Every
// nonnil handle, including errors, must survive its actual consumer last use.
// A denied first Parent/Provider acquisition returns the original error and its
// immutable numeric observation without constructing an unowned error handle.
type EvidenceLocalVerificationV1 struct{ state *evidenceLocalPutStateV1 }
type EvidenceLocalRetentionV1 struct{ state *evidenceLocalPutStateV1 }

func (c *Client) VerifyFinalizationEvidenceLocalOwnedV1(ctx context.Context, key, version string, expected []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalVerificationV1, workguard.AdmissionDenialV1, error) {
	owner, local, ownedKey, ownedVersion, denial, err := c.newEvidenceLocalReadV1(ctx, key, version, expected, coordinator, org)
	if owner == nil {
		return nil, denial, err
	}
	if err == nil {
		err = local.verifyEvidenceLocalVersionV1(ctx, ownedKey, ownedVersion, owner.data, owner.hashScratch)
	}
	err = finishEvidenceLocalReadV1(owner, err)
	return &EvidenceLocalVerificationV1{state: owner}, workguard.AdmissionDenialV1{}, err
}

func (c *Client) RetainFinalizationEvidenceLocalOwnedV1(ctx context.Context, key, version string, expected []byte, until time.Time, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalRetentionV1, workguard.AdmissionDenialV1, error) {
	owner, local, ownedKey, ownedVersion, denial, err := c.newEvidenceLocalReadV1(ctx, key, version, expected, coordinator, org)
	if owner == nil {
		return nil, denial, err
	}
	if err == nil {
		err = local.retainEvidenceVersionLocalV1(ctx, ownedKey, ownedVersion, owner.data, until, owner.hashScratch)
	}
	err = finishEvidenceLocalReadV1(owner, err)
	return &EvidenceLocalRetentionV1{state: owner}, workguard.AdmissionDenialV1{}, err
}

// The callers are fixed verification/retention consumers. No
// external producer, coordinator alias, Grant, policy callback or source/SQL
// authority is accepted. The real original constructor profile and aggregate
// eight ordinary/native physical-connection positions remain mandatory.
func (c *Client) newEvidenceLocalReadV1(ctx context.Context, key, version string, expected []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*evidenceLocalPutStateV1, *Client, string, string, workguard.AdmissionDenialV1, error) {
	return c.newEvidenceLocalReadWithFixedParentV1(ctx, key, version, expected, coordinator, org, 0)
}

// The extra frame is used only by the fixed package-retention receipt. Its
// private caller derives the complete typed cost before allocating that state.
func (c *Client) newEvidenceLocalReadWithFixedParentV1(ctx context.Context, key, version string, expected []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID, extra int64) (*evidenceLocalPutStateV1, *Client, string, string, workguard.AdmissionDenialV1, error) {
	zero := workguard.AdmissionDenialV1{}
	if ctx == nil || ctx.Err() != nil || coordinator == nil || org == uuid.Nil || extra < 0 {
		return nil, nil, "", "", zero, ErrEvidenceLocalIOV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, nil, "", "", zero, ErrEvidenceLocalIOV1
	}
	profile, err := c.evidenceLocalProfileV1()
	if err != nil {
		return nil, nil, "", "", zero, err
	}
	frameLimit, parent, err := evidenceLocalInitialResourcesV1(nil, key, "", profile)
	if err != nil {
		return nil, nil, "", "", zero, err
	}
	// Base recipe already prices actual key/endpoint/credentials and constructor/
	// SDK/transport controls. These are the only additional owned input values.
	if !evidenceLocalAddV1(&parent, int64(len(version)), 32) || !evidenceLocalAddV1(&parent, int64(len(expected)), 2) || !evidenceLocalAddV1(&parent, 1, int64(unsafe.Sizeof(EvidenceLocalVerificationV1{})+unsafe.Sizeof(EvidenceLocalRetentionV1{}))) {
		return nil, nil, "", "", zero, ErrEvidenceLocalIOV1
	}
	if !evidenceLocalAddV1(&parent, 1, extra) {
		return nil, nil, "", "", zero, ErrEvidenceLocalIOV1
	}
	grant, denial, err := coordinator.TryAcquireWithDenialV1(ctx, org, workguard.VectorV1{ParentBytes: parent})
	if err != nil {
		return nil, nil, "", "", denial, err
	}
	provider, denial, err := coordinator.TryAcquireWithDenialV1(ctx, org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		grant.Close()
		return nil, nil, "", "", denial, err
	}
	// Digest bytes are independently cloned before the original SDK producer;
	// native source/readLease closure cannot clear an active local hash input.
	// Immutable key/version copies belong to this positive Parent/error lifetime.
	ownedKey, ownedVersion := strings.Clone(key), strings.Clone(version)
	owner := &evidenceLocalPutStateV1{ctx: ctx, grant: grant, provider: provider, coordinator: coordinator, org: org, connections: make(map[*evidenceLocalConnV1]struct{}), bodies: make(map[*evidenceLocalResponseBodyV1]struct{}), changed: make(chan struct{}), joined: make(chan struct{}), frameLimit: frameLimit, data: bytes.Clone(expected), hashScratch: make([]byte, 64<<10), admission: profile.connections}
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
	localSDK, err := minio.New(profile.endpoint, &minio.Options{Transport: &boundedStorageTransportV1{base: &evidenceLocalRoundTripperV1{owner: owner, transport: transport}, connections: profile.connections}, Creds: profile.creds, Secure: profile.secure, Region: profile.region, BucketLookup: profile.lookup})
	if err != nil {
		return owner, nil, ownedKey, ownedVersion, zero, err
	}
	local := *c
	local.mc = localSDK
	local.localProfile = nil
	return owner, &local, ownedKey, ownedVersion, zero, nil
}

func finishEvidenceLocalReadV1(owner *evidenceLocalPutStateV1, failure error) error {
	owner.mu.Lock()
	owner.success = failure == nil
	owner.closing = true
	owner.signalV1()
	owner.mu.Unlock()
	go owner.closeIOV1()
	select {
	case <-owner.joined:
		return failure
	case <-owner.ctx.Done():
		return errors.Join(failure, ErrEvidenceLocalIOV1, owner.ctx.Err())
	}
}

// Success callbacks borrow only an acknowledgement, never the provider body.
// Copied Close calls cannot credit Parent while the actual callback is active.
func (h *EvidenceLocalVerificationV1) WithVerifiedV1(consume func() error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrEvidenceLocalIOV1
	}
	return withEvidenceLocalAcknowledgementV1(h.state, consume)
}
func (h *EvidenceLocalRetentionV1) WithRetainedV1(consume func() error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrEvidenceLocalIOV1
	}
	return withEvidenceLocalAcknowledgementV1(h.state, consume)
}
func withEvidenceLocalAcknowledgementV1(s *evidenceLocalPutStateV1, consume func() error) error {
	s.mu.Lock()
	if s.self != s || s.consumerClosed || s.released || !s.ioJoined || !s.success || s.grant == nil {
		s.mu.Unlock()
		return ErrEvidenceLocalIOV1
	}
	s.active++
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.releaseLockedV1(); s.mu.Unlock() }()
	return consume()
}
func (h *EvidenceLocalVerificationV1) CloseConsumerV1() {
	if h == nil {
		return
	}
	(&EvidenceLocalPutV1{state: h.state}).CloseConsumerV1()
}
func (h *EvidenceLocalRetentionV1) CloseConsumerV1() {
	if h == nil {
		return
	}
	(&EvidenceLocalPutV1{state: h.state}).CloseConsumerV1()
}
