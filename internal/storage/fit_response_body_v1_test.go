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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// This controlled synchronous response body proves ownership/Close ordering.
// It is not a remote provider, complete transport or live retention proof.
type fitOwnedBodyForTestV1 struct {
	reader                    *bytes.Reader
	closeEntered, finishClose chan struct{}
	once                      sync.Once
	closeCalls                atomic.Int32
	lastRead                  []byte
	closeErr                  error
}

func (b *fitOwnedBodyForTestV1) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if n > 0 {
		b.lastRead = p[:n]
	}
	return n, err
}
func (b *fitOwnedBodyForTestV1) Close() error {
	b.closeCalls.Add(1)
	b.once.Do(func() { close(b.closeEntered) })
	<-b.finishClose
	return b.closeErr
}

type fitResponseTransportForTestV1 struct {
	body        *fitOwnedBodyForTestV1
	version     string
	size        int64
	getVersion  string
	getSize     int64
	heads, gets atomic.Int32
}

func (t *fitResponseTransportForTestV1) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Query().Get("versionId") != t.version {
		return nil, errors.New("missing immutable test pin")
	}
	h := http.Header{"X-Amz-Version-Id": {t.version}, "Etag": {"\"synthetic-etag\""}, "Last-Modified": {"Mon, 12 Oct 2026 00:00:00 GMT"}, "Content-Type": {"application/pdf"}, "Content-Length": {strconv.FormatInt(t.size, 10)}}
	body := io.ReadCloser(io.NopCloser(strings.NewReader("")))
	size := t.size
	switch r.Method {
	case http.MethodHead:
		t.heads.Add(1)
	case http.MethodGet:
		t.gets.Add(1)
		body = t.body
		if t.getVersion != "" {
			h.Set("X-Amz-Version-Id", t.getVersion)
		}
		if t.getSize > 0 {
			size = t.getSize
			h.Set("Content-Length", strconv.FormatInt(size, 10))
		}
	default:
		return nil, errors.New("unexpected provider mutation")
	}
	return &http.Response{StatusCode: http.StatusOK, Header: h, Body: body, ContentLength: size, Request: r}, nil
}
func fitOwnedClientForTestV1(t *testing.T, transport *fitResponseTransportForTestV1) *Client {
	t.Helper()
	// Fixed synthetic credentials; the custom transport performs no network I/O.
	mc, err := minio.New("owned-response.invalid", &minio.Options{Creds: credentials.NewStaticV4("synthetic-access", "synthetic-secret", ""), Region: "us-east-1", Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{mc: mc, bucket: "hash-owned-test"}
}

func TestExactVersionReadOwnsResponseCloseBeforeReturnV1(t *testing.T) {
	for _, mode := range []string{"success", "digest-mismatch", "cancel-during-close", "close-error"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("%PDF-synthetic-owned-response-shape")
			sum := sha256.Sum256(raw)
			if mode == "digest-mismatch" {
				sum = sha256.Sum256([]byte("different"))
			}
			b := &fitOwnedBodyForTestV1{reader: bytes.NewReader(raw), closeEntered: make(chan struct{}), finishClose: make(chan struct{})}
			privateClose := errors.New("PRIVATE_RESPONSE_CLOSE_FAILURE")
			if mode == "close-error" {
				b.closeErr = privateClose
			}
			transport := &fitResponseTransportForTestV1{body: b, version: "provider-version-1", size: int64(len(raw))}
			client := fitOwnedClientForTestV1(t, transport)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			var finish sync.Once
			joined := make(chan struct{})
			type outcome struct {
				body []byte
				err  error
			}
			result := make(chan outcome, 1)
			go func() {
				defer close(joined)
				body, err := client.GetVerifiedVersionBounded(ctx, fitTestKey, transport.version, sum[:], int64(len(raw)))
				result <- outcome{body, err}
			}()
			t.Cleanup(func() {
				cancel()
				finish.Do(func() { close(b.finishClose) })
				select {
				case <-joined:
				case <-time.After(2 * time.Second):
					t.Error("response actor did not join")
				}
			})
			select {
			case <-b.closeEntered:
			case <-time.After(2 * time.Second):
				t.Fatal("direct response close not reached")
			}
			select {
			case <-joined:
				t.Fatal("returned before response Close completed")
			default:
			}
			if len(b.lastRead) == 0 || bytes.Equal(b.lastRead, make([]byte, len(b.lastRead))) {
				t.Fatal("owned buffer erased before physical Close")
			}
			if mode == "cancel-during-close" {
				cancel()
				select {
				case <-joined:
					t.Fatal("cancel detached active Close")
				default:
				}
			}
			finish.Do(func() { close(b.finishClose) })
			select {
			case <-joined:
			case <-time.After(2 * time.Second):
				t.Fatal("response actor did not return")
			}
			got := <-result
			if b.closeCalls.Load() != 1 || transport.heads.Load() != 1 || transport.gets.Load() != 1 {
				t.Fatal("unexpected request/Close lifecycle")
			}
			if mode == "success" {
				if got.err != nil || !bytes.Equal(got.body, raw) {
					t.Fatal("exact response lost", got.err)
				}
			} else {
				if got.err == nil || got.body != nil || !bytes.Equal(b.lastRead, make([]byte, len(b.lastRead))) {
					t.Fatal("error exposed or retained owned body")
				}
				if mode == "cancel-during-close" && !errors.Is(got.err, context.Canceled) {
					t.Fatal("cancellation lost")
				}
				if mode == "close-error" && (!errors.Is(got.err, privateClose) || strings.Contains(got.err.Error(), "PRIVATE")) {
					t.Fatal("Close failure identity/redaction lost")
				}
			}
		})
	}
}

func TestExactVersionReadChecksGETMetadataAndClosesBeforeRefusalV1(t *testing.T) {
	for _, mode := range []string{"changed-version", "changed-size"} {
		t.Run(mode, func(t *testing.T) {
			raw := []byte("%PDF-synthetic-exact-metadata")
			sum := sha256.Sum256(raw)
			b := &fitOwnedBodyForTestV1{reader: bytes.NewReader(raw), closeEntered: make(chan struct{}), finishClose: make(chan struct{})}
			close(b.finishClose)
			transport := &fitResponseTransportForTestV1{body: b, version: "provider-version-1", size: int64(len(raw))}
			if mode == "changed-version" {
				transport.getVersion = "foreign-version"
			} else {
				transport.getSize = int64(len(raw)) + 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			body, err := fitOwnedClientForTestV1(t, transport).GetVerifiedVersionBounded(ctx, fitTestKey, transport.version, sum[:], int64(len(raw)))
			if body != nil || err == nil || b.closeCalls.Load() != 1 || b.reader.Len() != len(raw) {
				t.Fatal("metadata mismatch read body or leaked response")
			}
		})
	}
}
