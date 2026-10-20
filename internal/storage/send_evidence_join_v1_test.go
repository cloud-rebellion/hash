// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type sendEvidenceRoundTripV1 func(*http.Request) (*http.Response, error)

func (f sendEvidenceRoundTripV1) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type sendEvidenceCloseBarrierV1 struct {
	*bytes.Reader
	entered, release chan struct{}
	once             sync.Once
	closes           atomic.Int64
}

func (b *sendEvidenceCloseBarrierV1) Close() error {
	b.closes.Add(1)
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return nil
}
func sendEvidenceResponseHeadersV1(n int) http.Header {
	h := make(http.Header)
	h.Set("Content-Length", strconv.Itoa(n))
	h.Set("Content-Type", "application/pdf")
	h.Set("Last-Modified", "Wed, 15 Oct 2025 00:00:00 GMT")
	h.Set("ETag", "\"fixed-etag\"")
	h.Set("X-Amz-Version-Id", "version-one")
	return h
}
func TestSendEvidenceJoinedReadDoesNotReturnBeforeActualHTTPBodyCloseV1(t *testing.T) {
	for _, cancelAtClose := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancelAtClose), func(t *testing.T) {
			// Concrete pinned SDK + actual bounded transport, with synthetic HTTP
			// receipts/Close barrier. This is local SDK lifecycle, not public New,
			// network/provider Object Lock, native admission or remote retirement proof.
			body := []byte("synthetic exact-version evidence")
			digest := sha256.Sum256(body)
			barrier := &sendEvidenceCloseBarrierV1{Reader: bytes.NewReader(body), entered: make(chan struct{}), release: make(chan struct{})}
			var unblock sync.Once
			release := func() { unblock.Do(func() { close(barrier.release) }) }
			t.Cleanup(release)
			transport := &boundedStorageTransportV1{base: sendEvidenceRoundTripV1(func(r *http.Request) (*http.Response, error) {
				reader := io.ReadCloser(io.NopCloser(strings.NewReader("")))
				if r.Method == http.MethodGet {
					reader = barrier
				}
				return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: sendEvidenceResponseHeadersV1(len(body)), ContentLength: int64(len(body)), Body: reader, Request: r}, nil
			})}
			mc, err := minio.New("send-evidence.invalid", &minio.Options{Region: "us-east-1", Creds: credentials.NewStaticV4("synthetic", "synthetic-secret", ""), Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			client := &Client{mc: mc, bucket: "send-evidence"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			type result struct {
				body []byte
				err  error
			}
			done := make(chan result, 1)
			go func() {
				b, e := client.GetVerifiedVersionForSendV1(ctx, "object.pdf", "version-one", digest[:])
				done <- result{b, e}
			}()
			joined := false
			t.Cleanup(func() {
				release()
				if !joined {
					select {
					case <-done:
					case <-time.After(5 * time.Second):
						t.Error("actual joined SDK call did not return")
					}
				}
			})
			select {
			case <-barrier.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("concrete response Close was not reached")
			}
			select {
			case <-done:
				joined = true
				t.Fatal("Send read returned while the real response Close still used its body")
			default:
			}
			if cancelAtClose {
				cancel()
			}
			release()
			var actual result
			select {
			case actual = <-done:
				joined = true
			case <-time.After(5 * time.Second):
				t.Fatal("joined response Close did not finish")
			}
			if cancelAtClose {
				if actual.body != nil || !errors.Is(actual.err, context.Canceled) {
					t.Fatal("canceled actual close was reported as successful evidence", actual.err)
				}
			} else if actual.err != nil || !bytes.Equal(actual.body, body) {
				t.Fatal("exact concrete read changed", actual.err)
			}
			if barrier.closes.Load() != 1 {
				t.Fatal("actual response Close not joined exactly once", barrier.closes.Load())
			}
		})
	}
}
func TestSendEvidenceJoinedMethodsMatchOriginalFirstPartyProtocolV1(t *testing.T) {
	payload := []byte("actual synthetic S3 protocol bytes")
	digest := sha256.Sum256(payload)
	var mu sync.Mutex
	var calls []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		mu.Unlock()
		if r.URL.Path == "/send-evidence" || r.URL.Path == "/send-evidence/" {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		if r.URL.Path != "/send-evidence/object.pdf" {
			http.Error(w, "unexpected synthetic path", 400)
			return
		}
		if v := r.URL.Query().Get("versionId"); v != "" && v != "version-one" {
			http.Error(w, "wrong exact version", 404)
			return
		}
		for k, v := range sendEvidenceResponseHeadersV1(len(payload)) {
			for _, value := range v {
				w.Header().Add(k, value)
			}
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(payload)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := New(ctx, Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "send-evidence", AccessKey: "synthetic", SecretKey: "synthetic-secret", BucketLookup: "path", RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	original, err := client.GetVerifiedVersion(ctx, "object.pdf", "version-one", digest[:])
	if err != nil {
		t.Fatal(err)
	}
	joined, err := client.GetVerifiedVersionForSendV1(ctx, "object.pdf", "version-one", digest[:])
	if err != nil || !bytes.Equal(original, joined) {
		t.Fatal("joined exact-version behavior differs", err)
	}
	body, object, err := client.ResolveVerifiedLegacyForSendV1(ctx, "object.pdf", digest[:])
	if err != nil || !bytes.Equal(body, payload) || object.VersionID != "version-one" || object.SHA256 != digest {
		t.Fatal("legacy actual digest/version proof changed", err)
	}
	// Original retention validates the durable whole-second deadline even in
	// disposable development storage, before the nonlocking exact-version read.
	retainUntil := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	if err = client.RetainEvidenceVersion(ctx, "object.pdf", "version-one", digest[:], retainUntil); err != nil {
		t.Fatal("original nonlocking development retention oracle failed", err)
	}
	if err = client.RetainEvidenceVersionForSendV1(ctx, "object.pdf", "version-one", digest[:], retainUntil); err != nil {
		t.Fatal("original nonlocking development retention/read semantics changed", err)
	}
	for _, tc := range []struct {
		name  string
		until time.Time
	}{{"missing deadline", time.Time{}}, {"fractional deadline", retainUntil.Add(time.Nanosecond)}} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			before := len(calls)
			mu.Unlock()
			originalErr := client.RetainEvidenceVersion(ctx, "object.pdf", "version-one", digest[:], tc.until)
			joinedErr := client.RetainEvidenceVersionForSendV1(ctx, "object.pdf", "version-one", digest[:], tc.until)
			if originalErr == nil || joinedErr == nil || originalErr.Error() != joinedErr.Error() {
				t.Fatalf("joined retention changed original invalid deadline refusal: original=%v joined=%v", originalErr, joinedErr)
			}
			mu.Lock()
			after := len(calls)
			mu.Unlock()
			if after != before {
				t.Fatal("invalid durable deadline contacted the provider before refusal", before, after)
			}
		})
	}
	bad := digest
	bad[0] ^= 1
	if _, err = client.GetVerifiedVersionForSendV1(ctx, "object.pdf", "version-one", bad[:]); err == nil {
		t.Fatal("different digest admitted")
	}
	if _, err = client.GetVerifiedVersionForSendV1(ctx, "object.pdf", "", digest[:]); err == nil {
		t.Fatal("missing exact version admitted")
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil || limits.ObjectBytes != 128<<20 || limits.MetadataBytes != 8<<20 || limits.HeaderBytes != 64<<10 || limits.VersionIDBytes != 1024 || limits.VersionCandidates != 100 {
		t.Fatal("limits detached from real original fixed client", limits, err)
	}
	if _, err = (*Client)(nil).SendEvidenceLimitsV1(); err == nil {
		t.Fatal("nil client supplied protocol provenance")
	}
	if _, err = (&Client{}).SendEvidenceLimitsV1(); err == nil {
		t.Fatal("zero client supplied protocol provenance")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) < 8 {
		t.Fatal("first-party client protocol not exercised", calls)
	}
}
