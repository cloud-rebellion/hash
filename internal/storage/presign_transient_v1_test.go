// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// The real public constructor, staticV4 SDK, original TLS/socket/body owner and
// real joined local lane talk to the existing bounded versioned protocol peer.
// This proves transport/reconciliation semantics, not external Object Lock or
// native SQL authority; the separate whole journey uses actual MinIO storage.
func preSignTransientClient488(t *testing.T, peer *fakeVersionedS3) (context.Context, *Client, *workguard.CoordinatorV1, uuid.UUID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hash-canary" || r.URL.Path == "/hash-canary/" {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.Method == http.MethodGet && r.URL.Query().Has("versioning") {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
				return
			}
			if r.Method == http.MethodGet && r.URL.Query().Has("object-lock") {
				w.Header().Set("Content-Type", "application/xml")
				_, _ = io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")
				return
			}
		}
		peer.serveHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	cert := filepath.Join(t.TempDir(), "presign-protocol-trust.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	client, err := New(ctx, Config{Endpoint: strings.TrimPrefix(server.URL, "https://"), Region: "eu-central-1", Bucket: "hash-canary", AccessKey: "controlled-protocol-access", SecretKey: "controlled-protocol-secret", UseSSL: true, BucketLookup: "path", RequireExistingBucket: true, RequireObjectLock: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("real pre-sign protocol constructor refused", err)
	}
	limits := workguard.VectorV1{ParentBytes: 192 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	return ctx, client, coordinator, uuid.New()
}
func preSignTransientReservation488(org uuid.UUID, raw []byte) PresignTransientReservationV1 {
	return PresignTransientReservationV1{OrgID: org, DocumentID: uuid.New(), PreparationID: uuid.New(), Role: "overlay_recipe", SHA256: sha256.Sum256(raw), Bytes: int64(len(raw))}
}
func preSignTransientJoin488(t *testing.T, ctx context.Context, h *EvidenceLocalPutV1) {
	t.Helper()
	if h == nil || h.state == nil {
		t.Fatal("actual local result/error owner missing")
	}
	select {
	case <-h.state.joined:
	case <-ctx.Done():
		t.Fatal("actual original provider/body/connection did not join")
	}
}

func TestPreSign488UnknownPUTReconcilesOriginalVersionWithoutRewriteV1(t *testing.T) {
	peer := &fakeVersionedS3{encryptionMode: encrypt.S3}
	ctx, client, coordinator, org := preSignTransientClient488(t, peer)
	call, cancel := context.WithCancel(ctx)
	defer cancel()
	peer.afterRequest = func(r *http.Request) {
		if r.Method == http.MethodPut {
			cancel()
		}
	}
	raw := []byte(`{"controlled":"unknown original PUT"}`)
	reservation := preSignTransientReservation488(org, raw)
	first, err := client.PutPresignTransientLocalOwnedV1(call, reservation, raw, coordinator, org)
	if first != nil {
		defer first.CloseConsumerV1()
	}
	if err == nil {
		t.Fatal("canceled committed provider effect was called confirmed")
	}
	preSignTransientJoin488(t, ctx, first)
	if snapshot := coordinator.SnapshotV1(org); snapshot.Global.ProviderStreams != 0 || snapshot.Global.ParentBytes <= 0 {
		t.Fatal("failed output lost retained debt or provider did not join", snapshot)
	}
	peer.mu.Lock()
	committed := bytes.Equal(peer.payload, raw)
	peer.afterRequest = nil
	peer.mu.Unlock()
	if !committed {
		t.Fatal("fault did not occur after genuine provider PUT effects")
	}
	first.CloseConsumerV1()
	resolved, found, err := client.ResolvePresignTransientLocalOwnedV1(ctx, reservation, coordinator, org)
	if resolved != nil {
		defer resolved.CloseConsumerV1()
	}
	if err != nil || !found {
		t.Fatal("fresh exact reconciliation failed", err)
	}
	var pinned StoredObject
	if err = resolved.WithStoredV1(func(value StoredObject) error { pinned = value; return nil }); err != nil || pinned.VersionID != "provider-version-1" || pinned.SHA256 != reservation.SHA256 {
		t.Fatal("fresh reconciliation adopted different provider identity", err)
	}
	resolved.CloseConsumerV1()
	repeated, err := client.PutPresignTransientLocalOwnedV1(ctx, reservation, raw, coordinator, org)
	if repeated != nil {
		defer repeated.CloseConsumerV1()
	}
	if err == nil {
		t.Fatal("surviving original history was rewritten")
	}
	preSignTransientJoin488(t, ctx, repeated)
	repeated.CloseConsumerV1()
	deleted, err := client.DeletePresignTransientLocalOwnedV1(ctx, reservation, pinned.VersionID, coordinator, org)
	if deleted != nil {
		defer deleted.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal("exact resolved transient deletion failed", err)
	}
	deleted.CloseConsumerV1()
	empty, found, err := client.ResolvePresignTransientLocalOwnedV1(ctx, reservation, coordinator, org)
	if empty != nil {
		defer empty.CloseConsumerV1()
	}
	if err != nil || found {
		t.Fatal("exact deleted version retained conflicting history", err)
	}
	empty.CloseConsumerV1()
	peer.mu.Lock()
	puts, deletes := 0, 0
	for _, request := range peer.requests {
		if request.method == http.MethodPut {
			puts++
		}
		if request.method == http.MethodDelete {
			deletes++
			if request.version != pinned.VersionID {
				t.Error("cleanup deleted a latest alias")
			}
		}
	}
	retention := peer.retentionPutCalls
	peer.mu.Unlock()
	if puts != 1 || deletes != 1 || retention != 0 {
		t.Fatal("reconciliation rewrote, compensated before resolution or retained transient evidence", puts, deletes, retention)
	}
	if snapshot := coordinator.SnapshotV1(org); snapshot.GlobalGrants != 0 {
		t.Fatal("all actual result consumers did not drain", snapshot)
	}
}

func TestPreSign488UnknownHistoryAndWrongMetadataNeverBecomePinsV1(t *testing.T) {
	raw := []byte(`{"controlled":"reserved"}`)
	wrong := "text/html"
	for _, tc := range []struct {
		name  string
		peer  *fakeVersionedS3
		empty bool
	}{
		{"empty is observation only", &fakeVersionedS3{encryptionMode: encrypt.S3}, true},
		{"shadow", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json", preexistingShadow: true}, false},
		{"delete marker", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json", logicalDeleted: true}, false},
		{"wrong digest", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: bytes.Repeat([]byte{'x'}, len(raw)), contentType: "application/json"}, false},
		{"wrong type", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json", responseContentType: &wrong}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, client, coordinator, org := preSignTransientClient488(t, tc.peer)
			reservation := preSignTransientReservation488(org, raw)
			handle, found, err := client.ResolvePresignTransientLocalOwnedV1(ctx, reservation, coordinator, org)
			if handle != nil {
				defer handle.CloseConsumerV1()
			}
			if found || (err == nil) != tc.empty {
				t.Fatal("unconfirmed history became a reserved immutable pin", found, err)
			}
			preSignTransientJoin488(t, ctx, handle)
			handle.CloseConsumerV1()
			tc.peer.mu.Lock()
			for _, request := range tc.peer.requests {
				if request.method == http.MethodPut || request.method == http.MethodDelete {
					t.Error("read-only reconciliation mutated storage")
				}
			}
			tc.peer.mu.Unlock()
			if snapshot := coordinator.SnapshotV1(org); snapshot.GlobalGrants != 0 {
				t.Fatal("refused/empty result consumer did not drain", snapshot)
			}
		})
	}
}

func TestPreSign488KnownPUTMetadataFailurePreservesReconciliationV1(t *testing.T) {
	wrong := "text/html"
	peer := &fakeVersionedS3{encryptionMode: encrypt.S3, responseContentType: &wrong}
	ctx, client, coordinator, org := preSignTransientClient488(t, peer)
	raw := []byte(`{"controlled":"metadata refusal"}`)
	reservation := preSignTransientReservation488(org, raw)
	handle, err := client.PutPresignTransientLocalOwnedV1(ctx, reservation, raw, coordinator, org)
	if handle != nil {
		defer handle.CloseConsumerV1()
	}
	if err == nil {
		t.Fatal("incorrect provider MIME became confirmed")
	}
	preSignTransientJoin488(t, ctx, handle)
	handle.state.mu.Lock()
	known := handle.state.stored
	handle.state.mu.Unlock()
	if known.VersionID != "provider-version-1" || known.SHA256 != reservation.SHA256 {
		t.Fatal("known committed version was erased on later metadata failure")
	}
	handle.CloseConsumerV1()
	peer.mu.Lock()
	peer.responseContentType = nil
	peer.mu.Unlock()
	recovered, found, err := client.ResolvePresignTransientLocalOwnedV1(ctx, reservation, coordinator, org)
	if recovered != nil {
		defer recovered.CloseConsumerV1()
	}
	if err != nil || !found {
		t.Fatal("fresh corrected metadata could not reconcile original", err)
	}
	if err = recovered.WithStoredV1(func(value StoredObject) error {
		if value != known {
			t.Error("fresh recovery replaced original committed version")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	recovered.CloseConsumerV1()
	peer.mu.Lock()
	puts := 0
	for _, request := range peer.requests {
		if request.method == http.MethodPut {
			puts++
		}
		if request.method == http.MethodDelete {
			t.Error("metadata refusal compensated an uncertain effect")
		}
	}
	peer.mu.Unlock()
	if puts != 1 {
		t.Fatal("metadata recovery rewrote original PUT", puts)
	}
	if snapshot := coordinator.SnapshotV1(org); snapshot.GlobalGrants != 0 {
		t.Fatal("metadata failure output did not drain", snapshot)
	}
}
