// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// This isolated original-protocol/error test adds a true response Close error
// after closing the real TLS body. The custom test transport is never accepted
// as native constructor/localIO authority and grants no resource credit.
type evidenceOriginalCloseErrorTransportV1 struct {
	base    http.RoundTripper
	failure error
	closes  *atomic.Int64
}

func (t *evidenceOriginalCloseErrorTransportV1) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err == nil && response != nil && response.Body != nil && r.Method == http.MethodGet {
		response.Body = &evidenceOriginalCloseErrorBodyV1{ReadCloser: response.Body, failure: t.failure, closes: t.closes}
	}
	return response, err
}

type evidenceOriginalCloseErrorBodyV1 struct {
	io.ReadCloser
	failure error
	closes  *atomic.Int64
}

func (b *evidenceOriginalCloseErrorBodyV1) Close() error {
	err := b.ReadCloser.Close()
	b.closes.Add(1)
	return errors.Join(err, b.failure)
}

func TestEvidenceLocalStreamedVerificationV1PreservesOriginalActualCloseError(t *testing.T) {
	ctx, client, _, coordinator, org := evidenceLocalTestClientV1(t)
	body := []byte("actual complete TLS object before response Close")
	expected := sha256.Sum256(body)
	until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	stored, err := client.PutEvidenceVersionedLocalOwnedV1(ctx, "actual-close.pdf", "application/pdf", body, until, coordinator, org)
	if stored != nil {
		defer stored.CloseConsumerV1()
	}
	if err != nil {
		t.Fatal(err)
	}
	var version string
	if err = stored.WithStoredV1(func(value StoredObject) error { version = strings.Clone(value.VersionID); return nil }); err != nil {
		t.Fatal(err)
	}
	stored.CloseConsumerV1()
	profile, err := client.evidenceLocalProfileV1()
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("actual TLS response Close refused")
	var closes atomic.Int64
	base := profile.base.Clone()
	defer base.CloseIdleConnections()
	sdk, err := minio.New(profile.endpoint, &minio.Options{Transport: &evidenceOriginalCloseErrorTransportV1{base: base, failure: sentinel, closes: &closes}, Creds: profile.creds, Secure: profile.secure, Region: profile.region, BucketLookup: profile.lookup})
	if err != nil {
		t.Fatal(err)
	}
	isolated := *client
	isolated.mc = sdk
	isolated.localProfile = nil
	originalBody, originalErr := isolated.GetVerifiedVersionForSendV1(ctx, "actual-close.pdf", version, expected[:])
	clear(originalBody)
	matches, streamedErr := isolated.hashEvidenceLocalVersionV1(ctx, "actual-close.pdf", version, expected[:], make([]byte, 64<<10))
	if matches || !errors.Is(originalErr, sentinel) || !errors.Is(streamedErr, sentinel) || originalErr.Error() != streamedErr.Error() {
		t.Fatal("original complete-read Close identity/prefix/ordering changed", matches, originalErr, streamedErr)
	}
	if closes.Load() < 2 {
		t.Fatal("actual response Close not observed on both original and streamed methods", closes.Load())
	}
}
