// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7/pkg/encrypt"
)

const fitTestKey = "org/11111111-1111-4111-8111-111111111111/documents/22222222-2222-4222-8222-222222222222/signatures/fit/33333333-3333-4333-8333-333333333333/manifest.json"

func fitTestReservation(raw []byte) FitTransientReservation {
	return FitTransientReservation{Key: fitTestKey, SHA256: sha256.Sum256(raw), Bytes: int64(len(raw)), ContentType: "application/json"}
}

func TestFitTransientUploadReconcilesOnePinnedEncryptedVersion(t *testing.T) {
	for _, mode := range []encrypt.Type{encrypt.S3, encrypt.SSEC} {
		t.Run(string(mode), func(t *testing.T) {
			fake := &fakeVersionedS3{encryptionMode: mode}
			client, _ := newFakeDataPlaneClient(t, fake)
			raw := []byte(`{"synthetic":"fit-manifest"}`)
			r := fitTestReservation(raw)
			obj, err := client.PutFitTransientReserved(context.Background(), r, raw)
			if err != nil || obj.VersionID != "provider-version-1" || obj.SHA256 != r.SHA256 {
				t.Fatalf("upload: %v, %v", obj, err)
			}
			got, exists, err := client.ResolveFitTransientVersion(context.Background(), r)
			if err != nil || !exists || got != obj {
				t.Fatalf("resolve: %v %v %v", got, exists, err)
			}
			body, err := client.GetVerifiedVersionBounded(context.Background(), r.Key, obj.VersionID, r.SHA256[:], r.Bytes)
			if err != nil || !bytes.Equal(body, raw) {
				t.Fatalf("exact read: %v", err)
			}
			if _, err := client.PutFitTransientReserved(context.Background(), r, raw); err == nil {
				t.Fatal("a repeated upload must reconcile rather than rewrite")
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			puts := 0
			for _, req := range fake.requests {
				if req.method == http.MethodPut {
					puts++
					if req.serverEncryption == "" && !req.hasCustomerKey {
						t.Fatal("upload lost encryption")
					}
				}
				if req.method == http.MethodDelete {
					t.Fatal("reconciliation must not compensate")
				}
			}
			if puts != 1 || fake.retentionMode != "" || fake.retentionPutCalls != 0 {
				t.Fatal("transient upload rewrote or retained evidence")
			}
		})
	}
}

func TestFitTransientReconciliationRefusesUnknownOrConflictingHistory(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	for _, tc := range []struct {
		name string
		fake *fakeVersionedS3
		ok   bool
	}{
		{"empty", &fakeVersionedS3{encryptionMode: encrypt.S3}, true},
		{"shadow", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, preexistingShadow: true}, false},
		{"delete-marker", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, logicalDeleted: true}, false},
		{"wrong-size", &fakeVersionedS3{encryptionMode: encrypt.S3, payload: append(append([]byte(nil), raw...), 'x')}, false},
		{"wrong-digest", &fakeVersionedS3{encryptionMode: encrypt.S3, contentType: "application/json", payload: bytes.Repeat([]byte{'x'}, len(raw))}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := newFakeDataPlaneClient(t, tc.fake)
			_, found, err := client.ResolveFitTransientVersion(context.Background(), fitTestReservation(raw))
			if (err == nil) != tc.ok || found {
				t.Fatalf("history: found=%v err=%v", found, err)
			}
			tc.fake.mu.Lock()
			defer tc.fake.mu.Unlock()
			for _, req := range tc.fake.requests {
				if req.method == http.MethodPut || req.method == http.MethodDelete {
					t.Fatal("read-only resolver mutated history")
				}
			}
		})
	}
}

func TestFitTransientExactPrefixScanStopsWithoutFollowingCollisionPages(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json", prefixCollisionPages: 10000, prefixCollisionExact: true}
	client, _ := newFakeDataPlaneClient(t, fake)
	obj, found, err := client.ResolveFitTransientVersion(context.Background(), fitTestReservation(raw))
	if err != nil || !found || obj.VersionID != "provider-version-1" {
		t.Fatalf("exact prefix: %v %v %v", obj, found, err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.versionListCalls != 1 {
		t.Fatal("unrelated prefix pages amplified reconciliation")
	}
}

func TestFitTransientMetadataRefusalDoesNotReadOrMutateBody(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	for _, mediaType := range []string{"", "application/octet-stream", "text/html", "application/json; charset=utf-8"} {
		t.Run("type="+mediaType, func(t *testing.T) {
			fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json", responseContentType: &mediaType}
			client, _ := newFakeDataPlaneClient(t, fake)
			obj, found, err := client.ResolveFitTransientVersion(context.Background(), fitTestReservation(raw))
			if err == nil || found || obj.VersionID != "" {
				t.Fatal("unreserved provider media type was pinned")
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.requests) != 1 || fake.requests[0].method != http.MethodHead || fake.requests[0].version != "provider-version-1" || fake.retentionGetCalls != 0 || fake.retentionPutCalls != 0 {
				t.Fatal("metadata refusal read body or mutated storage")
			}
		})
	}
}

func TestFitTransientUploadMetadataRefusalKeepsKnownVersionForReconciliation(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	wrong := "text/html"
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, responseContentType: &wrong}
	client, _ := newFakeDataPlaneClient(t, fake)
	r := fitTestReservation(raw)
	obj, err := client.PutFitTransientReserved(context.Background(), r, raw)
	if err == nil || obj.VersionID != "provider-version-1" || obj.SHA256 != r.SHA256 {
		t.Fatal("uncertain metadata lost known committed object identity")
	}
	if _, found, err := client.ResolveFitTransientVersion(context.Background(), r); err == nil || found {
		t.Fatal("incorrect provider media type reconciled")
	}
	if _, err := client.PutFitTransientReserved(context.Background(), r, raw); err == nil {
		t.Fatal("metadata failure rewrote the object")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	puts := 0
	for _, req := range fake.requests {
		if req.method == http.MethodPut {
			puts++
			continue
		}
		if req.method != http.MethodHead || req.version != obj.VersionID {
			t.Fatal("metadata failure read/deleted/latest-resolved object")
		}
	}
	if puts != 1 || fake.retentionGetCalls != 0 || fake.retentionPutCalls != 0 {
		t.Fatal("metadata refusal changed upload or retention count")
	}
}

func TestBoundedExactVersionReadPreservesPrivateCancellationIdentity(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw, contentType: "application/json"}
	client, _ := newFakeDataPlaneClient(t, fake)
	cause := errors.New("PRIVATE_PROVIDER_CANCELLATION_REASON")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	r := fitTestReservation(raw)
	_, err := client.GetVerifiedVersionBounded(ctx, r.Key, "provider-version-1", r.SHA256[:], r.Bytes)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("cancellation identity or private error handling changed")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.requests) != 0 || fake.versionListCalls != 0 {
		t.Fatal("canceled read reached provider")
	}
}

func TestFitTransientCancellationDuringProviderIOPreservesRecovery(t *testing.T) {
	raw := []byte(`{"synthetic":"reserved"}`)
	for _, phase := range []string{"resolve-list", "upload-list", "upload-PUT"} {
		t.Run(phase, func(t *testing.T) {
			cause := errors.New("PRIVATE_CALLER_PROVIDER_IO_CAUSE")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			fake := &fakeVersionedS3{encryptionMode: encrypt.S3, contentType: "application/json"}
			if phase == "resolve-list" {
				fake.payload = bytes.Clone(raw)
			}
			fake.afterRequest = func(req *http.Request) {
				if phase == "upload-PUT" {
					if req.Method == http.MethodPut {
						cancel(cause)
					}
				} else if req.Method == http.MethodGet && req.URL.Query().Has("versions") {
					cancel(cause)
				}
			}
			client, _ := newFakeDataPlaneClient(t, fake)
			r := fitTestReservation(raw)
			var err error
			if phase == "resolve-list" {
				_, found, e := client.ResolveFitTransientVersion(ctx, r)
				err = e
				if found {
					t.Fatal("canceled listing claimed a reconciled version")
				}
			} else {
				_, err = client.PutFitTransientReserved(ctx, r, raw)
			}
			if !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
				t.Fatal("provider cancellation lost private cause identity")
			}
			fake.mu.Lock()
			puts := 0
			for _, req := range fake.requests {
				if req.method == http.MethodPut {
					puts++
				} else {
					t.Error("canceled provider phase performed additional body/metadata/deletion request")
				}
			}
			if fake.retentionGetCalls != 0 || fake.retentionPutCalls != 0 {
				t.Error("canceled provider phase changed retention")
			}
			committed := bytes.Equal(fake.payload, raw)
			fake.mu.Unlock()
			if phase == "upload-PUT" {
				if puts != 1 || !committed {
					t.Fatal("cancellation witness did not preserve one committed unknown PUT")
				}
				obj, found, e := client.ResolveFitTransientVersion(context.Background(), r)
				if e != nil || !found || obj.VersionID != "provider-version-1" || obj.SHA256 != r.SHA256 {
					t.Fatal("fresh caller could not reconcile exact committed version")
				}
			} else if puts != 0 {
				t.Fatal("canceled listing reached upload")
			}
		})
	}
}

func TestBoundedExactVersionReadRejectsBeforeBodyAndPreservesCancellation(t *testing.T) {
	raw := []byte(`{"synthetic":"bounded"}`)
	fake := &fakeVersionedS3{encryptionMode: encrypt.S3, payload: raw}
	client, _ := newFakeDataPlaneClient(t, fake)
	sum := sha256.Sum256(raw)
	if _, err := client.GetVerifiedVersionBounded(context.Background(), fitTestKey, "provider-version-1", sum[:], int64(len(raw)-1)); err == nil {
		t.Fatal("oversized HEAD accepted")
	}
	fake.mu.Lock()
	for _, req := range fake.requests {
		if req.method == http.MethodGet {
			t.Fatal("oversized metadata reached body read")
		}
	}
	fake.mu.Unlock()
	wrong := sha256.Sum256([]byte("wrong"))
	if b, err := client.GetVerifiedVersionBounded(context.Background(), fitTestKey, "provider-version-1", wrong[:], int64(len(raw))); err == nil || b != nil {
		t.Fatal("wrong exact digest returned bytes")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.GetVerifiedVersionBounded(ctx, fitTestKey, "provider-version-1", sum[:], int64(len(raw))); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel cause: %v", err)
	}
}

func TestFitTransientInvalidReservationsRefuseBeforeProviderAccess(t *testing.T) {
	raw := []byte("synthetic")
	base := fitTestReservation(raw)
	for _, change := range []func(*FitTransientReservation){
		func(r *FitTransientReservation) { r.Key = "org/foreign/manifest.json" },
		func(r *FitTransientReservation) {
			r.Key = strings.Replace(r.Key, "/manifest.json", "/../manifest.json", 1)
		},
		func(r *FitTransientReservation) {
			r.Key = strings.Replace(r.Key, "33333333-3333-4333-8333-333333333333", "00000000-0000-0000-0000-000000000000", 1)
		},
		func(r *FitTransientReservation) { r.Key = strings.Replace(r.Key, "manifest.json", "page-01.fit", 1) },
		func(r *FitTransientReservation) { r.ContentType = "text/html" },
		func(r *FitTransientReservation) { r.Bytes = 2<<20 + 1 },
		func(r *FitTransientReservation) { r.SHA256 = [sha256.Size]byte{} },
	} {
		r := base
		change(&r)
		client := &Client{}
		if _, _, err := client.ResolveFitTransientVersion(context.Background(), r); err == nil {
			t.Fatal("invalid reservation reached resolution")
		}
		if _, err := client.PutFitTransientReserved(context.Background(), r, raw); err == nil {
			t.Fatal("invalid reservation reached upload")
		}
	}
	if _, err := (&Client{}).GetVerifiedVersionBounded(context.Background(), fitTestKey, "", make([]byte, 32), 0); err == nil {
		t.Fatal("empty commitment accepted")
	}
}

func TestFitVersionIDsPreserveOpaqueBytesAndRefuseUnversionedAliases(t *testing.T) {
	for _, id := range []string{"provider-version-1", " exact+/opaque=version ", "opaque Å version"} {
		if !validFitVersionID(id) {
			t.Fatal("valid opaque version refused")
		}
	}
	for _, id := range []string{"", " ", "null", " null ", "\u00a0null\u00a0", DevelopmentVersionID, " " + DevelopmentVersionID + " ", "version\x85", "version\n", string([]byte{0xff}), strings.Repeat("v", 1025)} {
		if validFitVersionID(id) {
			t.Fatal("invalid or unversioned identity accepted")
		}
	}
}
