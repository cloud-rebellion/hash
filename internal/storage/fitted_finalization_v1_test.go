// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// Actual MinIO SDK + local TLS HTTP fixture only. It proves dispatch, metadata
// and error/pin handling, not live Object Lock, at-rest encryption, SQL ownership
// or permission to replay/compensate an upload. Credentials/keys are synthetic.
type fittedFinalizationRequestV1 struct {
	method, path, version, phase string
	mode, until                  string
	multipart                    bool
}
type fittedFinalizationS3V1 struct {
	base           *fakeVersionedS3
	mu             sync.Mutex
	version, fault string
	requests       []fittedFinalizationRequestV1
	phaseCounts    map[string]int
	after          func(string, int)
}

func (f *fittedFinalizationS3V1) setFault(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = value
}
func (f *fittedFinalizationS3V1) setAfter(fn func(string, int)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.after = fn
}
func (f *fittedFinalizationS3V1) serveHTTP(w http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	phase := "body"
	switch {
	case query.Has("versions"):
		phase = "inventory"
	case query.Has("retention"):
		phase = "retention"
	case request.Method == http.MethodPut:
		phase = "put"
	case request.Method == http.MethodHead:
		phase = "head"
	}
	f.mu.Lock()
	f.phaseCounts[phase]++
	phaseCount := f.phaseCounts[phase]
	version, fault, after := f.version, f.fault, f.after
	f.requests = append(f.requests, fittedFinalizationRequestV1{method: request.Method, path: request.URL.Path, version: query.Get("versionId"), phase: phase,
		mode: request.Header.Get("X-Amz-Object-Lock-Mode"), until: request.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"), multipart: query.Has("uploads") || query.Has("uploadId") || query.Has("partNumber")})
	f.mu.Unlock()
	if request.Method == http.MethodPost || query.Has("uploads") || query.Has("uploadId") || query.Has("partNumber") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// The existing strict fixture models one constant version. This adapter
	// changes only its wire identity to exercise actual SDK opaque encoding.
	cloned := request.Clone(request.Context())
	clonedURL := *request.URL
	cloned.URL = &clonedURL
	if query.Get("versionId") == version {
		query.Set("versionId", "provider-version-1")
		cloned.URL.RawQuery = query.Encode()
	}
	recorder := httptest.NewRecorder()
	f.base.serveHTTP(recorder, cloned)
	if phase == "put" && recorder.Code == http.StatusOK {
		until, err := time.Parse(time.RFC3339Nano, request.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
		f.base.mu.Lock()
		if err == nil {
			f.base.retentionMode = minio.RetentionMode(request.Header.Get("X-Amz-Object-Lock-Mode"))
			f.base.retentionUntil = until
		}
		switch fault {
		case "shadow":
			f.base.preexistingShadow = true
		case "retention-short":
			f.base.retentionUntil = until.Add(-time.Second)
		case "retention-governance":
			f.base.retentionMode = minio.Governance
		}
		f.base.mu.Unlock()
	}
	header := recorder.Header()
	if header.Get("X-Amz-Version-Id") == "provider-version-1" {
		header.Set("X-Amz-Version-Id", version)
	}
	if phase == "put" && fault == "missing-put-version" {
		header.Del("X-Amz-Version-Id")
	}
	if phase == "put" && fault == "unversioned-put" {
		header.Set("X-Amz-Version-Id", "null")
	}
	if phase == "head" {
		switch fault {
		case "wrong-media":
			header.Set("Content-Type", "application/octet-stream")
		case "wrong-size":
			f.base.mu.Lock()
			size := len(f.base.payload)
			f.base.mu.Unlock()
			header.Set("Content-Length", strconv.Itoa(size+1))
		case "wrong-head-version":
			header.Set("X-Amz-Version-Id", "other-positive-version")
		case "missing-sse", "missing-sse-c":
			header.Del(encrypt.SseGenericHeader)
			header.Del(encrypt.SseCustomerAlgorithm)
		}
	}
	body := recorder.Body.Bytes()
	if phase == "inventory" {
		var escaped bytes.Buffer
		_ = xml.EscapeText(&escaped, []byte(version))
		body = []byte(strings.ReplaceAll(string(body), "provider-version-1", escaped.String()))
	}
	if phase == "body" && fault == "wrong-body" && len(body) != 0 {
		body = bytes.Clone(body)
		body[0] ^= 1
	}
	for name, values := range header {
		w.Header()[name] = append([]string(nil), values...)
	}
	w.WriteHeader(recorder.Code)
	_, _ = w.Write(body)
	if after != nil {
		after(phase, phaseCount)
	}
}

func newFittedFinalizationClientV1(t *testing.T, mode encrypt.Type) (*Client, *fittedFinalizationS3V1) {
	t.Helper()
	fixture := &fittedFinalizationS3V1{base: &fakeVersionedS3{encryptionMode: mode}, version: "opaque+/version==1", phaseCounts: map[string]int{}}
	server := httptest.NewTLSServer(http.HandlerFunc(fixture.serveHTTP))
	t.Cleanup(server.Close)
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	sdk, err := minio.New(endpoint.Host, &minio.Options{Creds: credentials.NewStaticV4("test-access", "test-secret", ""), Secure: true, Region: "eu-central-1", BucketLookup: minio.BucketLookupPath, Transport: server.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{mc: sdk, bucket: "hash-canary", requireEvidenceLock: true}
	if mode == encrypt.S3 {
		client.sseMode, client.writeServerSideEncryption = "sse-s3", encrypt.NewSSE()
	} else {
		sse, err := encrypt.NewSSEC([]byte("0123456789abcdef0123456789abcdef"))
		if err != nil {
			t.Fatal(err)
		}
		client.sseMode, client.writeServerSideEncryption, client.readServerSideEncryption = "sse-c", sse, sse
	}
	return client, fixture
}
func fittedFinalizationContextV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func fittedFinalizationReservationV1(kind string, raw []byte) FittedFinalizationReservationV1 {
	r := FittedFinalizationReservationV1{
		OrgID: uuid.MustParse("30000000-0000-4000-8000-000000000001"), DocumentID: uuid.MustParse("30000000-0000-4000-8000-000000000002"), PreparationID: uuid.MustParse("30000000-0000-4000-8000-000000000003"),
		Kind: kind, SHA256: sha256.Sum256(raw), Bytes: int64(len(raw)), CompletionEffectiveAt: time.Date(2026, 10, 12, 1, 2, 3, 123456000, time.UTC),
	}
	r.RetainUntil = EvidenceRetentionDeadline(r.CompletionEffectiveAt, article13.RetentionYearsV1)
	prefix := "org/" + r.OrgID.String() + "/documents/" + r.DocumentID.String() + "/"
	digest := hex.EncodeToString(r.SHA256[:])
	switch kind {
	case "base_pdf":
		r.Page = 2
		r.Key = prefix + "finalization/base/" + r.PreparationID.String() + "/page-2.pdf"
		r.ContentType = "application/pdf"
	case "fits_index":
		r.Key = manualfit.IndexStorageKeyV1(r.OrgID, r.DocumentID, r.PreparationID)
		r.ContentType = "application/json"
	case "final_pdf":
		r.Key = prefix + "final-" + digest + ".pdf"
		r.ContentType = "application/pdf"
	case "certificate_pdf":
		r.Key = prefix + "audit-" + digest + ".pdf"
		r.ContentType = "application/pdf"
	case "certificate_payload":
		r.Key = prefix + "audit-payload-" + digest + ".txt"
		r.ContentType = "text/plain"
	case "certificate_signature":
		r.Key = prefix + "audit-signature-" + digest + ".txt"
		r.ContentType = "text/plain"
	}
	return r
}
func assertFittedFinalizationRequestsV1(t *testing.T, f *fittedFinalizationS3V1, r FittedFinalizationReservationV1, expectedPuts int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	puts := 0
	for _, request := range f.requests {
		if request.multipart || request.method == http.MethodPost || request.method == http.MethodDelete {
			t.Fatal("multipart/rewrite/delete dispatch escaped output contract")
		}
		if request.phase == "inventory" {
			if request.method != http.MethodGet {
				t.Fatal("inventory mutation")
			}
			continue
		}
		if request.path != "/hash-canary/"+r.Key {
			t.Fatal("provider dispatch escaped reserved output key")
		}
		if request.phase == "put" {
			puts++
			if request.mode != "COMPLIANCE" || request.until != r.RetainUntil.UTC().Format(time.RFC3339) {
				t.Fatal("PUT retention target differs from frozen completion commitment")
			}
		} else if request.method != http.MethodHead && request.method != http.MethodGet {
			t.Fatal("read-only resolution changed object/retention")
		} else if request.version != f.version {
			t.Fatal("exact read resolved latest or normalized opaque version")
		}
	}
	if puts != expectedPuts {
		t.Fatalf("PUT count=%d, want%d", puts, expectedPuts)
	}
	f.base.mu.Lock()
	defer f.base.mu.Unlock()
	if f.base.retentionPutCalls != 0 {
		t.Fatal("read-only reconciliation re-retained output")
	}
	for _, request := range f.base.requests {
		if request.method == http.MethodPut && request.serverEncryption == "" && !request.hasCustomerKey {
			t.Fatal("PUT omitted configured SSE")
		}
		if f.base.encryptionMode == encrypt.SSEC && (request.method == http.MethodPut || request.method == http.MethodHead || request.method == http.MethodGet) && (!request.hasCustomerKey || !request.hasCustomerMD5 || request.customerAlgorithm != "AES256") {
			t.Fatal("exact body/HEAD lost SSE-C headers")
		}
	}
}

func TestFittedFinalizationUploadsOneRetainedEncryptedVersionAndReadsRecovery(t *testing.T) {
	for _, mode := range []encrypt.Type{encrypt.S3, encrypt.SSEC} {
		for _, kind := range []string{"base_pdf", "fits_index", "final_pdf", "certificate_pdf", "certificate_payload", "certificate_signature"} {
			t.Run(string(mode)+"/"+kind, func(t *testing.T) {
				client, fake := newFittedFinalizationClientV1(t, mode)
				raw := []byte("synthetic-original-output-" + kind)
				r := fittedFinalizationReservationV1(kind, raw)
				ctx := fittedFinalizationContextV1(t)
				object, err := client.PutFittedFinalizationReservedV1(ctx, r, raw)
				if err != nil || object.VersionID != fake.version || object.SHA256 != r.SHA256 {
					t.Fatalf("original upload failed: %v", err)
				}
				observation, err := client.ResolveFittedFinalizationVersionV1(ctx, r, object.VersionID)
				if err != nil || observation.State != FittedFinalizationVerifiedV1 || observation.Object != object {
					t.Fatalf("exact recovery failed: %v", err)
				}
				if _, err := client.PutFittedFinalizationReservedV1(ctx, r, raw); err == nil {
					t.Fatal("second upload reused/rewrote output instead of refusing")
				}
				assertFittedFinalizationRequestsV1(t, fake, r, 1)
			})
		}
	}
}

func TestFittedFinalizationPostPutRefusalKeepsVersionForReadOnlyRecovery(t *testing.T) {
	for _, fault := range []string{"shadow", "wrong-media", "wrong-size", "wrong-head-version", "missing-sse", "missing-sse-c", "wrong-body", "retention-short", "retention-governance"} {
		t.Run(fault, func(t *testing.T) {
			mode := encrypt.S3
			if fault == "missing-sse-c" {
				mode = encrypt.SSEC
			}
			client, fake := newFittedFinalizationClientV1(t, mode)
			fake.setFault(fault)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1("fits_index", raw)
			ctx := fittedFinalizationContextV1(t)
			object, err := client.PutFittedFinalizationReservedV1(ctx, r, raw)
			if err == nil || object.VersionID != fake.version || object.SHA256 != r.SHA256 {
				t.Fatal("post-PUT refusal lost positive SDK pin")
			}
			observation, err := client.ResolveFittedFinalizationVersionV1(ctx, r, object.VersionID)
			if err == nil || observation.State == FittedFinalizationVerifiedV1 || observation.Object != object {
				t.Fatal("incorrect/conflicting output reconciled or known pin disappeared")
			}
			if _, err := client.PutFittedFinalizationReservedV1(ctx, r, raw); err == nil {
				t.Fatal("post-PUT refusal replayed original request")
			}
			assertFittedFinalizationRequestsV1(t, fake, r, 1)
			if fault == "shadow" || fault == "wrong-media" || fault == "wrong-size" || fault == "wrong-head-version" || strings.HasPrefix(fault, "missing-sse") {
				fake.mu.Lock()
				bodyCalls := fake.phaseCounts["body"]
				fake.mu.Unlock()
				if bodyCalls != 0 {
					t.Fatal("history/metadata/SSE refusal read output body")
				}
			}
		})
	}
}

func TestFittedFinalizationUnknownPutVersionRequiresReadOnlyReconciliation(t *testing.T) {
	for _, fault := range []string{"missing-put-version", "unversioned-put"} {
		t.Run(fault, func(t *testing.T) {
			client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
			fake.setFault(fault)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1("final_pdf", raw)
			ctx := fittedFinalizationContextV1(t)
			object, err := client.PutFittedFinalizationReservedV1(ctx, r, raw)
			if err == nil || object.VersionID != "" || object.SHA256 != r.SHA256 {
				t.Fatal("unknown SDK version became a development/latest identity")
			}
			observation, err := client.ResolveFittedFinalizationVersionV1(ctx, r, "")
			if err != nil || observation.State != FittedFinalizationVerifiedV1 || observation.Object.VersionID != fake.version {
				t.Fatal("unknown upload could not read-reconcile its sole actual version")
			}
			assertFittedFinalizationRequestsV1(t, fake, r, 1)
		})
	}
}

func TestFittedFinalizationResolverEmptyAndConflictingHistoryNeverMutates(t *testing.T) {
	for _, name := range []string{"empty", "empty-known", "shadow", "delete-marker", "wrong-size", "wrong-digest", "known-version-mismatch"} {
		t.Run(name, func(t *testing.T) {
			client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1("fits_index", raw)
			known := ""
			fake.base.contentType, fake.base.retentionMode, fake.base.retentionUntil = r.ContentType, minio.Compliance, r.RetainUntil
			if !strings.HasPrefix(name, "empty") {
				fake.base.payload = bytes.Clone(raw)
			}
			switch name {
			case "empty-known":
				known = fake.version
			case "shadow":
				fake.base.preexistingShadow = true
			case "delete-marker":
				fake.base.logicalDeleted = true
			case "wrong-size":
				fake.base.payload = append(fake.base.payload, 'x')
			case "wrong-digest":
				fake.base.payload[0] ^= 1
			case "known-version-mismatch":
				known = "another-positive-version"
			}
			observation, err := client.ResolveFittedFinalizationVersionV1(fittedFinalizationContextV1(t), r, known)
			if name == "empty" {
				if err != nil || observation.State != FittedFinalizationEmptyUnresolvedV1 {
					t.Fatal("empty observation claimed verified or replay/cleanup permission")
				}
			} else if err == nil || observation.State == FittedFinalizationVerifiedV1 {
				t.Fatal("missing/conflicting history became verified")
			}
			if known != "" && observation.Object.VersionID != known {
				t.Fatal("known version lost during reconciliation refusal")
			}
			assertFittedFinalizationRequestsV1(t, fake, r, 0)
		})
	}
}

func TestFittedFinalizationCancellationPreservesUnknownAndKnownOutcomes(t *testing.T) {
	for _, phase := range []string{"before", "empty-inventory", "after-PUT", "positive-inventory", "head", "body", "retention"} {
		t.Run(phase, func(t *testing.T) {
			client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1("fits_index", raw)
			privateCause := errors.New("private-finalization-cancellation-cause")
			ctx, cancel := context.WithCancelCause(fittedFinalizationContextV1(t))
			defer cancel(nil)
			if phase == "before" {
				cancel(privateCause)
			}
			fake.setAfter(func(observed string, count int) {
				if (phase == "empty-inventory" && observed == "inventory" && count == 1) || (phase == "positive-inventory" && observed == "inventory" && count == 2) || (phase == "after-PUT" && observed == "put") || phase == observed {
					cancel(privateCause)
				}
			})
			object, err := client.PutFittedFinalizationReservedV1(ctx, r, raw)
			if !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatal("private cancellation identity lost or disclosed")
			}
			if phase != "before" && phase != "empty-inventory" && phase != "after-PUT" && object.VersionID != fake.version {
				t.Fatal("known SDK version disappeared after cancellation")
			}
			fake.setAfter(nil)
			if phase == "before" || phase == "empty-inventory" {
				assertFittedFinalizationRequestsV1(t, fake, r, 0)
			} else {
				observation, e := client.ResolveFittedFinalizationVersionV1(fittedFinalizationContextV1(t), r, object.VersionID)
				if e != nil || observation.State != FittedFinalizationVerifiedV1 || observation.Object.VersionID != fake.version {
					t.Fatal("fresh caller could not reconcile cancelled original upload")
				}
				assertFittedFinalizationRequestsV1(t, fake, r, 1)
			}
		})
	}
}

func TestFittedFinalizationReservationAndClientRefuseBeforeProvider(t *testing.T) {
	for _, name := range []string{"org", "document", "preparation", "kind", "base-page", "nonbase-page", "key-owner", "content-address", "media", "size", "zero-sha", "retention-short", "retention-fraction", "completion-zero", "no-worm", "no-sse", "no-sse-read", "body-size", "body-digest"} {
		t.Run(name, func(t *testing.T) {
			client, fake := newFittedFinalizationClientV1(t, encrypt.SSEC)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1("final_pdf", raw)
			switch name {
			case "org":
				r.OrgID = uuid.Nil
			case "document":
				r.DocumentID = uuid.Nil
			case "preparation":
				r.PreparationID = uuid.Nil
			case "kind":
				r.Kind = "fit_page"
			case "base-page":
				r = fittedFinalizationReservationV1("base_pdf", raw)
				r.Page = 501
			case "nonbase-page":
				r.Page = 1
			case "key-owner":
				r.Key = strings.Replace(r.Key, r.DocumentID.String(), uuid.NewString(), 1)
			case "content-address":
				r.SHA256[0] ^= 1
			case "media":
				r.ContentType += "; charset=utf-8"
			case "size":
				r.Bytes = manualfit.MaxFinalPDFBytesV1 + 1
			case "zero-sha":
				r.SHA256 = [sha256.Size]byte{}
			case "retention-short":
				r.RetainUntil = r.RetainUntil.Add(-time.Second)
			case "retention-fraction":
				r.RetainUntil = r.RetainUntil.Add(time.Nanosecond)
			case "completion-zero":
				r.CompletionEffectiveAt = time.Time{}
			case "no-worm":
				client.requireEvidenceLock = false
			case "no-sse":
				client.writeServerSideEncryption = nil
			case "no-sse-read":
				client.readServerSideEncryption = nil
			case "body-size":
				raw = append(raw, 'x')
			case "body-digest":
				raw[0] ^= 1
			}
			ctx := fittedFinalizationContextV1(t)
			if _, err := client.PutFittedFinalizationReservedV1(ctx, r, raw); err == nil {
				t.Fatal("invalid original output dispatched")
			}
			if name != "body-size" && name != "body-digest" {
				observation, err := client.ResolveFittedFinalizationVersionV1(ctx, r, fake.version)
				if err == nil || observation.State == FittedFinalizationVerifiedV1 || observation.Object.VersionID != fake.version {
					t.Fatal("invalid recovery reservation lost known identity or reached provider")
				}
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.requests) != 0 {
				t.Fatal("invalid reservation/client reached provider")
			}
		})
	}
	for _, kind := range []string{"base_pdf", "fits_index", "certificate_pdf", "certificate_payload", "certificate_signature"} {
		t.Run("cap/"+kind, func(t *testing.T) {
			client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
			raw := []byte("synthetic-original-output")
			r := fittedFinalizationReservationV1(kind, raw)
			switch kind {
			case "base_pdf":
				r.Bytes = manualfit.MaxArchiveBasePDFBytesV1 + 1
			case "fits_index":
				r.Bytes = manualfit.MaxFitsIndexBytesV1 + 1
			case "certificate_pdf":
				r.Bytes = manualfit.MaxCertificatePDFBytesV1 + 1
			case "certificate_payload":
				r.Bytes = manualfit.MaxCertificatePayloadBytesV1 + 1
			case "certificate_signature":
				r.Bytes = manualfit.MaxCertificateSignatureBytesV1 + 1
			}
			if _, err := client.PutFittedFinalizationReservedV1(fittedFinalizationContextV1(t), r, raw); err == nil {
				t.Fatal("output kind cap admitted")
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if len(fake.requests) != 0 {
				t.Fatal("cap refusal reached provider")
			}
		})
	}
}

func TestFittedFinalizationKnownPinRefusalAndInvalidVersionsStayReadOnly(t *testing.T) {
	raw := []byte("synthetic-original-output")
	r := fittedFinalizationReservationV1("fits_index", raw)
	for _, version := range []string{"null", DevelopmentVersionID, "version\n", string([]byte{0xff}), strings.Repeat("v", 1025)} {
		client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
		observation, err := client.ResolveFittedFinalizationVersionV1(fittedFinalizationContextV1(t), r, version)
		if err == nil || observation.State != FittedFinalizationUnresolvedV1 || observation.Object.VersionID != "" {
			t.Fatal("invalid version reached recovery or became a pin")
		}
		fake.mu.Lock()
		calls := len(fake.requests)
		fake.mu.Unlock()
		if calls != 0 {
			t.Fatal("invalid version reached provider")
		}
	}
	client, fake := newFittedFinalizationClientV1(t, encrypt.S3)
	privateCause := errors.New("private-recovery-cancellation-cause")
	ctx, cancel := context.WithCancelCause(fittedFinalizationContextV1(t))
	cancel(privateCause)
	observation, err := client.ResolveFittedFinalizationVersionV1(ctx, r, fake.version)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, privateCause) || strings.Contains(err.Error(), privateCause.Error()) || observation.Object.VersionID != fake.version || observation.State != FittedFinalizationUnresolvedV1 {
		t.Fatal("known recovery pin/cancellation disappeared or disclosed")
	}
	var missing *Client
	observation, err = missing.ResolveFittedFinalizationVersionV1(fittedFinalizationContextV1(t), r, fake.version)
	if err == nil || observation.Object.VersionID != fake.version || observation.State != FittedFinalizationUnresolvedV1 {
		t.Fatal("missing client lost a known recovery pin")
	}
	fake.mu.Lock()
	calls := len(fake.requests)
	fake.mu.Unlock()
	if calls != 0 {
		t.Fatal("cancelled read-only recovery reached provider")
	}
}
