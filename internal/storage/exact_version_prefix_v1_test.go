// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// This test compiles against original S as well as the proposed fix. It holds
// the consumer until the real SDK has attempted the next page; this forces the
// cancellation race without relying on scheduler timing or sleeps.
func TestExactKeyVersionPrefixDispatchStopsBufferedSDKPrefetchV1(t *testing.T) {
	const key = "org/test/documents/source.pdf"
	const bucket = "hash-prefix-test"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	attempted := make(chan struct{})
	var once sync.Once
	var baseCalls atomic.Int32
	bounded := &boundedStorageTransportV1{base: boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
		call := baseCalls.Add(1)
		if r.Method != http.MethodGet || !r.URL.Query().Has("versions") || r.URL.Query().Get("prefix") != key {
			return nil, fmt.Errorf("unexpected synthetic request")
		}
		truncated, marker, contents := "false", "", ""
		if call == 1 {
			truncated, marker = "true", key+"~collision"
			contents = "<Version><Key>" + key + "</Key><VersionId>provider-version-1</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:00Z</LastModified><ETag>fixture</ETag><Size>1</Size></Version>" +
				"<Version><Key>" + key + "~collision</Key><VersionId>collision-version</VersionId><IsLatest>true</IsLatest><LastModified>2026-09-09T00:00:00Z</LastModified><ETag>fixture</ETag><Size>1</Size></Version>"
		}
		body := "<ListVersionsResult><Name>" + bucket + "</Name><Prefix>" + key + "</Prefix><MaxKeys>2</MaxKeys><IsTruncated>" + truncated + "</IsTruncated><NextKeyMarker>" + marker + "</NextKeyMarker>" + contents + "</ListVersionsResult>"
		return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: http.Header{"Content-Type": {"application/xml"}}, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
	})}
	outer := boundedStorageRoundTripTestV1(func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Has("versions") && r.URL.Query().Get("key-marker") != "" {
			// Release the visitor only AFTER the attempted dispatch returns.
			// Otherwise cancellation could win before the unfenced base call,
			// making the original implementation pass this control by chance.
			response, err := bounded.RoundTrip(r)
			once.Do(func() { close(attempted) })
			return response, err
		}
		return bounded.RoundTrip(r)
	})
	sdk, err := minio.New("exact-prefix.invalid", &minio.Options{Region: "eu-central-1", BucketLookup: minio.BucketLookupPath, Creds: credentials.NewStaticV4("synthetic-access", "synthetic-secret", ""), Transport: outer})
	if err != nil {
		t.Fatal(err)
	}
	visited := 0
	err = scanExactKeyVersions(ctx, sdk, bucket, key, 2, func(_ context.Context, item minio.ObjectInfo) (bool, error) {
		visited++
		if item.Key != key || item.VersionID != "provider-version-1" {
			return false, fmt.Errorf("unexpected exact-key visitor input")
		}
		select {
		case <-attempted:
			return false, nil
		case <-ctx.Done():
			return false, fmt.Errorf("real SDK did not reach forced prefetch: %w", ctx.Err())
		}
	})
	if err != nil || visited != 1 {
		t.Fatalf("exact-key scan: visited=%d err=%v", visited, err)
	}
	if calls := baseCalls.Load(); calls != 1 {
		t.Fatalf("provider version-list calls = %d, want 1", calls)
	}
	select {
	case <-attempted:
	default:
		t.Fatal("control did not force an actual SDK continuation attempt")
	}
}
