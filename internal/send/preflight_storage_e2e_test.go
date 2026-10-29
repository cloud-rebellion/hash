//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// The production concrete client performs the actual upload, exact-version
// reads and SHA verification against this bounded synthetic protocol peer.
// Provider Object Lock, SMTP and deployment acceptance remain separate.
func (f *sendAdmissionFixture) evidenceClient(t *testing.T) *storage.Client {
	t.Helper()
	const bucket = "send-admission-fixture"
	type object struct {
		body                       []byte
		version, etag, contentType string
	}
	var mu sync.Mutex
	objects := make(map[string]object)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && (r.URL.Path == "/"+bucket || r.URL.Path == "/"+bucket+"/") && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		prefix := "/" + bucket + "/"
		key := strings.TrimPrefix(r.URL.Path, prefix)
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasPrefix(key, "org/"+f.orgID.String()+"/") {
			t.Error("unexpected synthetic evidence path")
			http.Error(w, "unexpected synthetic evidence path", http.StatusBadRequest)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPut && r.URL.RawQuery == "" {
			body, err := io.ReadAll(io.LimitReader(r.Body, (16<<20)+1))
			if err != nil || len(body) > 16<<20 {
				http.Error(w, "invalid bounded synthetic upload", http.StatusBadRequest)
				return
			}
			if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
				body, err = io.ReadAll(io.LimitReader(httputil.NewChunkedReader(bytes.NewReader(body)), (16<<20)+1))
				if err != nil || len(body) > 16<<20 {
					http.Error(w, "invalid synthetic upload chunks", http.StatusBadRequest)
					return
				}
			}
			if _, exists := objects[key]; exists {
				http.Error(w, "synthetic source overwrite refused", http.StatusConflict)
				return
			}
			digest := sha256.Sum256(body)
			row := object{body: body, version: uuid.NewString(), etag: hex.EncodeToString(digest[:]), contentType: r.Header.Get("Content-Type")}
			objects[key] = row
			w.Header().Set("X-Amz-Version-Id", row.version)
			w.Header().Set("ETag", `"`+row.etag+`"`)
			w.WriteHeader(http.StatusOK)
			return
		}
		row, exists := objects[key]
		version := r.URL.Query().Get("versionId")
		if !exists || (version != "" && version != row.version) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `<Error><Code>NoSuchKey</Code><Message>synthetic source version absent</Message></Error>`)
			return
		}
		if r.Method == http.MethodDelete && version == row.version {
			delete(objects, key)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodHead && r.Method != http.MethodGet {
			t.Error("unexpected synthetic evidence method")
			http.Error(w, "unexpected synthetic evidence method", http.StatusBadRequest)
			return
		}
		if match := r.Header.Get("If-Match"); match != "" && match != `"`+row.etag+`"` {
			w.WriteHeader(http.StatusPreconditionFailed)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(row.body)))
		w.Header().Set("Content-Type", row.contentType)
		w.Header().Set("ETag", `"`+row.etag+`"`)
		w.Header().Set("X-Amz-Version-Id", row.version)
		w.Header().Set("Last-Modified", time.Unix(1700000000, 0).UTC().Format(http.TimeFormat))
		if r.Method == http.MethodGet {
			_, _ = w.Write(row.body)
		}
	}))
	t.Cleanup(peer.Close)
	client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(peer.URL, "http://"), Region: "us-east-1", Bucket: bucket, AccessKey: "synthetic-send-admission", SecretKey: "synthetic-send-admission-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, RequireExistingBucket: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func onePageSendPDF(t *testing.T) []byte {
	t.Helper()
	configuration := pdfmodel.NewDefaultConfiguration()
	configuration.ValidationMode = pdfmodel.ValidationRelaxed
	spec := fmt.Sprintf(`{"pages":{"1":{"mediaBox":"A4","content":{"text":[{"value":%q,"position":[100,700],"font":{"name":"Helvetica","size":12}}]}}}}`, "Hash send readiness")
	var out bytes.Buffer
	if err := pdfapi.Create(nil, strings.NewReader(spec), &out, configuration); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
