// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

// ObservePresignSourceLocalOwnedV1 obtains the size from the actual immutable
// version's HEAD and verifies its digest through the same local streamed GET.
// The later complete-body read repeats exact version/size/hash checks. A
// document or caller estimate is never substituted for this observation.
func (c *Client) ObservePresignSourceLocalOwnedV1(ctx context.Context, key, version string, expected []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalVerificationV1, int64, error) {
	owner, local, ownedKey, ownedVersion, _, err := c.newEvidenceLocalReadV1(ctx, key, version, expected, coordinator, org)
	if owner == nil {
		return nil, 0, err
	}
	var size int64
	if err == nil {
		info, e := local.mc.StatObject(ctx, local.bucket, ownedKey, local.statOpts(ownedVersion))
		err = e
		if err == nil && (info.VersionID != ownedVersion || info.Size < 1 || info.Size > 50<<20 || info.ContentType != "application/pdf") {
			err = ErrEvidenceLocalIOV1
		}
		if err == nil {
			size = info.Size
			err = local.verifyEvidenceLocalVersionV1(ctx, ownedKey, ownedVersion, owner.data, owner.hashScratch)
		}
	}
	err = finishEvidenceLocalReadV1(owner, err)
	if err != nil {
		size = 0
	}
	return &EvidenceLocalVerificationV1{state: owner}, size, err
}

// The operation is closed to the pre-sign preparation role/identity schema.
// Real local socket/response joins use the existing owned storage lane. Every
// nonnil handle, including failed calls, remains with its actual result/error
// consumer and must be closed after that consumer's last use.
func (c *Client) PutPresignTransientLocalOwnedV1(ctx context.Context, r PresignTransientReservationV1, data []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalPutV1, error) {
	if ctx == nil || ctx.Err() != nil || r.validateV1() != nil || coordinator == nil || org == uuid.Nil || r.OrgID != org || int64(len(data)) != r.Bytes {
		return nil, ErrEvidenceLocalIOV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrEvidenceLocalIOV1
	}
	profile, err := c.evidenceLocalProfileV1()
	if err != nil {
		return nil, err
	}
	frameLimit, parent, err := evidenceLocalInitialResourcesV1(data, r.KeyV1(), r.ContentTypeV1(), profile)
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
	sdk, setupErr := minio.New(profile.endpoint, &minio.Options{Transport: &boundedStorageTransportV1{base: &evidenceLocalRoundTripperV1{owner: owner, transport: transport}, connections: profile.connections}, Creds: profile.creds, Secure: profile.secure, Region: profile.region, BucketLookup: profile.lookup})
	var stored StoredObject
	var putErr error
	if setupErr != nil {
		putErr = setupErr
	} else {
		local := *c
		local.mc = sdk
		local.localProfile = nil
		stored, putErr = local.putPresignTransientV1(ctx, r, owner.data, owner.hashScratch)
	}
	owner.mu.Lock()
	owner.stored = stored
	owner.success = putErr == nil
	owner.closing = true
	owner.signalV1()
	owner.mu.Unlock()
	go owner.closeIOV1()
	h := &EvidenceLocalPutV1{state: owner}
	select {
	case <-owner.joined:
		return h, putErr
	case <-ctx.Done():
		return h, errors.Join(putErr, ErrEvidenceLocalIOV1, ctx.Err())
	}
}

func (c *Client) ResolvePresignTransientLocalOwnedV1(ctx context.Context, r PresignTransientReservationV1, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalPutV1, bool, error) {
	if r.validateV1() != nil || org != r.OrgID {
		return nil, false, ErrEvidenceLocalIOV1
	}
	owner, local, _, _, _, err := c.newEvidenceLocalReadV1(ctx, r.KeyV1(), "", r.SHA256[:], coordinator, org)
	if owner == nil {
		return nil, false, err
	}
	var stored StoredObject
	var found bool
	if err == nil {
		stored, found, err = local.resolvePresignTransientV1(ctx, r, owner.hashScratch)
	}
	owner.mu.Lock()
	owner.stored = stored
	owner.mu.Unlock()
	err = finishEvidenceLocalReadV1(owner, err)
	return &EvidenceLocalPutV1{state: owner}, found, err
}

func (c *Client) DeletePresignTransientLocalOwnedV1(ctx context.Context, r PresignTransientReservationV1, version string, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*EvidenceLocalVerificationV1, error) {
	if r.validateV1() != nil || org != r.OrgID || !validFitVersionID(version) {
		return nil, ErrEvidenceLocalIOV1
	}
	owner, local, _, _, _, err := c.newEvidenceLocalReadV1(ctx, r.KeyV1(), version, r.SHA256[:], coordinator, org)
	if owner == nil {
		return nil, err
	}
	if err == nil {
		err = local.deletePresignTransientV1(ctx, r, version, owner.hashScratch)
	}
	err = finishEvidenceLocalReadV1(owner, err)
	return &EvidenceLocalVerificationV1{state: owner}, err
}
