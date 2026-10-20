//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type packagePreviewPeer227 struct {
	q           *ownedPublicReadFixtureV1
	key         string
	old, later  []byte
	mode        string
	hold        bool
	entered     chan struct{}
	release     chan struct{}
	once        sync.Once
	signaled    sync.Once
	heads, gets atomic.Int32
}

func (p *packagePreviewPeer227) unblock() { p.once.Do(func() { close(p.release) }) }
func (p *packagePreviewPeer227) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/hash-import-fixture/"+p.key || (r.Method != http.MethodHead && r.Method != http.MethodGet) {
		p.q.storagePeer.ServeHTTP(w, r)
		return
	}
	p.q.storagePeer.requests.Add(1)
	version := r.URL.Query().Get("versionId")
	var body []byte
	switch version {
	case "import-version-1":
		body = p.old
	case "later-same-key-v2":
		body = p.later
	default:
		http.Error(w, "exact selected version required", http.StatusNotFound)
		return
	}
	if r.Method == http.MethodHead {
		p.heads.Add(1)
	} else {
		p.gets.Add(1)
		if p.hold {
			p.signaled.Do(func() { close(p.entered) })
			select {
			case <-p.release:
			case <-r.Context().Done():
				return
			}
		}
	}
	if p.mode == "missing" {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "<Error><Code>NoSuchVersion</Code></Error>")
		return
	}
	if p.mode == "digest" && r.Method == http.MethodGet {
		body = p.later
	}
	responseVersion := version
	if p.mode == "version" {
		responseVersion = "later-same-key-v2"
	}
	size := len(body)
	if p.mode == "size" && r.Method == http.MethodHead {
		size++
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Length", strconv.Itoa(size))
	w.Header().Set("X-Amz-Version-Id", responseVersion)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("ETag", "fixture-preview")
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}
func packagePreviewStorage227(t *testing.T, q *ownedPublicReadFixtureV1, member *generated.Document, mode string, hold bool) *packagePreviewPeer227 {
	t.Helper()
	q.storagePeer.mu.Lock()
	old := bytes.Clone(q.storagePeer.objects[member.PdfStorageKey.String])
	q.storagePeer.mu.Unlock()
	later := bytes.Clone(old)
	if len(later) < 10 {
		t.Fatal("fixture PDF too small")
	}
	later[len(later)/2] ^= 1
	peer := &packagePreviewPeer227{q: q, key: member.PdfStorageKey.String, old: old, later: later, mode: mode, hold: hold, entered: make(chan struct{}), release: make(chan struct{})}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	t.Cleanup(peer.unblock)
	previous := q.f.s.Storage
	client, e := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package-preview", SecretKey: "synthetic-package-preview-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if e != nil {
		t.Fatal(e)
	}
	q.f.s.Storage = client
	t.Cleanup(func() { q.f.s.Storage = previous })
	return peer
}
func packagePreviewPath227(v pdfadmission.DocumentPackageInventoryV1, member uuid.UUID) string {
	values := url.Values{"expected_updated_at": {v.UpdatedAt.UTC().Format(time.RFC3339Nano)}, "expected_package_id": {v.PackageID}, "expected_generation": {v.Generation}}
	return "/api/v1/documents/" + v.DocumentID.String() + "/attachments/" + member.String() + "/pdf?" + values.Encode()
}
func packagePreviewSelected227(t *testing.T, q *ownedPublicReadFixtureV1) ([2]*generated.Document, pdfadmission.DocumentPackageInventoryV1) {
	t.Helper()
	pair := [2]*generated.Document{packageImported220(t, q, "Preview main"), packageImported220(t, q, "Preview annex")}
	var saved map[string]any
	packageAPIReply225(t, packageAPISubmit225(q, "REST", "add_document_attachment", pair[0].ID, "", packageAPIArguments225(t, pair, "REST")), "REST", http.StatusCreated, &saved)
	return pair, packageLayoutView226(t, q, pair[0].ID)
}
func packagePreviewRefusal227(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status || w.Header().Get("Content-Type") == "application/pdf" || bytes.Contains(w.Body.Bytes(), []byte("%PDF-")) || w.Header().Get("X-Hash-PDF-SHA256") != "" {
		t.Fatalf("preview refusal %d want %d: %s", w.Code, status, w.Body.String())
	}
	for _, private := range []string{"pdf_key", "pdf_intake_report", "metadata_redaction_report", "synthetic-package-preview-secret"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("private preview field escaped", private)
		}
	}
}

type packagePreviewWriter227 struct {
	*httptest.ResponseRecorder
	entered, release chan struct{}
	once             sync.Once
}

func (w *packagePreviewWriter227) Write(body []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return w.ResponseRecorder.Write(body)
}

func TestDocumentPackageStaffPreviewV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if e := malwarescan.Configure(q.f.ctx, "", "development"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := malwarescan.Configure(context.Background(), "", "development"); e != nil {
			t.Error(e)
		}
	})
	t.Run("same-key old version survives live source replacement and deletion", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		peer := packagePreviewStorage227(t, q, pair[1], "", false)
		laterSHA := sha256.Sum256(peer.later)
		if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later source',pdf_storage_version_id='later-same-key-v2',pdf_sha256=$3,deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", pair[1].ID, q.f.org, laterSHA[:]); e != nil {
			t.Fatal(e)
		}
		before := packageFullState223(t, q)
		w := submitSessionOperationE2E(q.f.s, http.MethodGet, packagePreviewPath227(v, pair[1].ID), "", q.cookie)
		m := v.Members[0]
		if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" || !bytes.Equal(w.Body.Bytes(), peer.old) || bytes.Equal(w.Body.Bytes(), peer.later) {
			t.Fatalf("selected version response=%d %s", w.Code, w.Body.String())
		}
		headers := map[string]string{"Cache-Control": "no-store", "Content-Length": strconv.FormatInt(m.PDFBytes, 10), "X-Hash-Document-Id": v.DocumentID.String(), "X-Hash-Document-Updated-At": v.UpdatedAt.UTC().Format(time.RFC3339Nano), "X-Hash-Package-Id": v.PackageID, "X-Hash-Package-Generation": v.Generation, "X-Hash-Member-Document-Id": m.DocumentID.String(), "X-Hash-PDF-Version": base64.RawURLEncoding.EncodeToString([]byte(m.PDFVersionID)), "X-Hash-PDF-SHA256": m.PDFSHA256, "X-Hash-PDF-Bytes": strconv.FormatInt(m.PDFBytes, 10), "X-Hash-PDF-Pages": strconv.FormatInt(int64(m.PDFPages), 10)}
		for k, want := range headers {
			if w.Header().Get(k) != want {
				t.Fatal("incoherent preview header", k, w.Header().Get(k), want)
			}
		}
		actual := sha256.Sum256(w.Body.Bytes())
		if hex.EncodeToString(actual[:]) != m.PDFSHA256 || peer.heads.Load() != 1 || peer.gets.Load() != 1 || packageFullState223(t, q) != before {
			t.Fatal("preview not exact read-only one HEAD/GET")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("stale and unselected observations refuse before provider", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		bad := []string{packagePreviewPath227(v, uuid.New()), strings.Replace(packagePreviewPath227(v, pair[1].ID), "expected_generation=2", "expected_generation=3", 1), strings.Replace(packagePreviewPath227(v, pair[1].ID), v.PackageID, uuid.NewString(), 1)}
		stale := v
		stale.UpdatedAt = stale.UpdatedAt.Add(-time.Microsecond)
		bad = append(bad, packagePreviewPath227(stale, pair[1].ID))
		for _, path := range bad {
			packagePreviewRefusal227(t, submitSessionOperationE2E(q.f.s, http.MethodGet, path, "", q.cookie), http.StatusConflict)
		}
		if requests != q.storagePeer.requests.Load() || packageFullState223(t, q) != before {
			t.Fatal("stale preview fetched or changed state")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("initial viewer cannot fetch selected bytes", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: q.f.user.Role}); e != nil {
				t.Error(e)
			}
		})
		w := submitSessionOperationE2E(q.f.s, http.MethodGet, packagePreviewPath227(v, pair[1].ID), "", q.cookie)
		packagePreviewRefusal227(t, w, http.StatusForbidden)
		if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: q.f.user.Role}); e != nil {
			t.Fatal(e)
		}
		if requests != q.storagePeer.requests.Load() || packageFullState223(t, q) != before {
			t.Fatal("viewer preview fetched or mutated")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	t.Run("strict bounded preview query", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		before := packageFullState223(t, q)
		requests := q.storagePeer.requests.Load()
		path := packagePreviewPath227(v, pair[1].ID)
		for _, badPath := range []string{packagePreviewPath227(v, v.DocumentID), packagePreviewPath227(v, uuid.Nil), strings.Replace(packagePreviewPath227(v, pair[1].ID), v.DocumentID.String(), uuid.Nil.String(), 1)} {
			packagePreviewRefusal227(t, submitSessionOperationE2E(q.f.s, http.MethodGet, badPath, "", q.cookie), http.StatusBadRequest)
		}
		for _, bad := range []string{path + "&expected_generation=2", path + "&pdf_key=caller", strings.Replace(path, "expected_generation=2", "expected_generation=02", 1), strings.Replace(path, "expected_generation=2", "expected_generation=9223372036854775808", 1), path + strings.Repeat("x", 1025)} {
			packagePreviewRefusal227(t, submitSessionOperationE2E(q.f.s, http.MethodGet, bad, "", q.cookie), http.StatusBadRequest)
		}
		if requests != q.storagePeer.requests.Load() || packageFullState223(t, q) != before {
			t.Fatal("strict preview fetched or mutated")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	for _, mode := range []string{"size", "version", "digest", "missing"} {
		t.Run("provider "+mode+" mismatch refuses without fallback", func(t *testing.T) {
			pair, v := packagePreviewSelected227(t, q)
			peer := packagePreviewStorage227(t, q, pair[1], mode, false)
			before := packageFullState223(t, q)
			w := submitSessionOperationE2E(q.f.s, http.MethodGet, packagePreviewPath227(v, pair[1].ID), "", q.cookie)
			packagePreviewRefusal227(t, w, http.StatusUnprocessableEntity)
			wantGET := int32(0)
			if mode == "digest" {
				wantGET = 1
			}
			if peer.heads.Load() != 1 || peer.gets.Load() != wantGET || packageFullState223(t, q) != before {
				t.Fatal("mismatch retried/fell back or mutated", peer.heads.Load(), peer.gets.Load())
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}

	t.Run("actual HTTP write retains byte credit after request cancellation", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		before := packageFullState223(t, q)
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		defer cancel()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		w := &packagePreviewWriter227{ResponseRecorder: httptest.NewRecorder(), entered: entered, release: release}
		r := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+packagePreviewPath227(v, pair[1].ID), nil).WithContext(ctx)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
		result := make(chan struct{})
		joined := false
		go func() { defer close(result); q.f.s.Routes().ServeHTTP(w, r) }()
		defer func() {
			unblock()
			if !joined {
				select {
				case <-result:
				case <-time.After(5 * time.Second):
					t.Error("HTTP response writer not joined")
				}
			}
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("actual PDF response writer not entered", ctx.Err())
		}
		beforeCredit, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil {
			t.Fatal(e)
		}
		pending := q.runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.DocumentPackageOperations != 1 || beforeCredit.Organisation.ParentBytes < v.Members[0].PDFBytes {
			t.Fatal("response lost owner or retained SQL", pending, beforeCredit)
		}
		cancel()
		afterCredit, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil || afterCredit.Organisation.ParentBytes != beforeCredit.Organisation.ParentBytes {
			t.Fatal("request cancel refunded actual blocked write", beforeCredit, afterCredit, e)
		}
		unblock()
		select {
		case <-result:
			joined = true
		case <-time.After(5 * time.Second):
			t.Fatal("actual response write did not join")
		}
		if w.Code != http.StatusOK || int64(w.Body.Len()) != v.Members[0].PDFBytes || packageFullState223(t, q) != before {
			t.Fatal("actual response data/state differs", w.Code, w.Body.Len())
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})

	t.Run("copied close and cancellation cannot refund active response borrower", func(t *testing.T) {
		pair, v := packagePreviewSelected227(t, q)
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		defer cancel()
		pkg, e := uuid.Parse(v.PackageID)
		if e != nil {
			t.Fatal(e)
		}
		gen, e := strconv.ParseInt(v.Generation, 10, 64)
		if e != nil {
			t.Fatal(e)
		}
		op, e := packageauthoring.PreviewV1(ctx, packageauthoring.DependenciesV1{Sessions: q.runtime.SessionsV1(), Storage: q.f.s.Storage}, packageActor220(t, q), pair[0].ID, pair[1].ID, pdfadmission.DocumentPackagePreviewExpectedV1{UpdatedAt: v.UpdatedAt, PackageID: pkg, Generation: gen})
		if e != nil {
			t.Fatal(e)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := op.CloseV1(cleanup); e != nil {
				t.Error(e)
			}
		}()
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		unblock := func() { once.Do(func() { close(release) }) }
		defer unblock()
		result := make(chan error, 1)
		joined := false
		defer func() {
			unblock()
			if !joined {
				select {
				case <-result:
				case <-time.After(5 * time.Second):
					t.Error("response borrower did not join")
				}
			}
		}()
		var held []byte
		go func() {
			result <- op.WithPDFV1(func(m pdfadmission.DocumentPackagePreviewMetadataV1, b []byte) error {
				held = b
				close(entered)
				<-release
				digest := sha256.Sum256(b)
				if hex.EncodeToString(digest[:]) != m.PDFSHA256 {
					return fmt.Errorf("active body changed")
				}
				return nil
			})
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("response callback not reached")
		}
		before, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil {
			t.Fatal(e)
		}
		copied := *op
		copied.CloseConsumerV1()
		cancel()
		short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
		closeErr := copied.CloseV1(short)
		stop()
		after, e := q.runtime.SnapshotV1(q.f.org)
		if e != nil || closeErr == nil || after.Organisation.ParentBytes != before.Organisation.ParentBytes || after.Organisation.ParentBytes <= 0 || q.runtime.SessionsV1().PendingV1().DocumentPackageOperations != 1 {
			t.Fatal("close intent refunded an active response", before, after, closeErr, e)
		}
		unblock()
		select {
		case e := <-result:
			joined = true
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("response did not join")
		}
		cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
		e = op.CloseV1(cleanup)
		end()
		if e != nil {
			t.Fatal(e)
		}
		for _, b := range held {
			if b != 0 {
				t.Fatal("retired response bytes not cleared")
			}
		}
		if e = op.WithPDFV1(func(pdfadmission.DocumentPackagePreviewMetadataV1, []byte) error {
			t.Error("replayed response")
			return nil
		}); e == nil {
			t.Fatal("response replay accepted")
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	for _, change := range []string{"expiry", "logout", "demotion", "layout", "privacy"} {
		t.Run("real "+change+" during held exact GET refuses publication", func(t *testing.T) {
			pair, v := packagePreviewSelected227(t, q)
			peer := packagePreviewStorage227(t, q, pair[1], "", true)
			cookie := q.cookie
			if change == "expiry" {
				cookie = dsrSessionCookieE2E(t, q.f.s, q.f.user.ID, q.f.user.SessionGeneration, time.Second)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			joined := false
			ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
			defer func() {
				cancel()
				peer.unblock()
				if !joined {
					select {
					case <-result:
					case <-time.After(5 * time.Second):
						t.Error("preview request did not join")
					}
				}
			}()
			r := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+packagePreviewPath227(v, pair[1].ID), nil).WithContext(ctx)
			r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
			go func() { w := httptest.NewRecorder(); q.f.s.Routes().ServeHTTP(w, r); result <- w }()
			select {
			case <-peer.entered:
			case <-ctx.Done():
				t.Fatal("preview did not reach actual provider GET", ctx.Err())
			}
			pending := q.runtime.SessionsV1().PendingV1()
			if pending.WorkSessions != 0 || pending.DocumentPackageOperations != 1 {
				t.Fatal("provider wait retained live native SQL or lost owner", pending)
			}
			want := http.StatusForbidden
			switch change {
			case "expiry":
				awaitSessionCookieExpiryE2E(t, q.f.s, cookie)
				want = http.StatusUnauthorized
			case "logout":
				if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1", q.f.user.ID); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=$2 WHERE id=$1", q.f.user.ID, q.f.user.SessionGeneration); e != nil {
						t.Error(e)
					}
				})
			case "demotion":
				if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); e != nil {
					t.Fatal(e)
				}
				t.Cleanup(func() {
					if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: q.f.user.Role}); e != nil {
						t.Error(e)
					}
				})
			case "layout":
				w := packageLayoutSubmit226(q, "REST", pair[0].ID, "", packageLayoutArguments226(t, v, "REST", nil))
				if w.Code != http.StatusOK {
					t.Fatal("real layout mutation blocked by preview SQL", w.Code, w.Body.String())
				}
				want = http.StatusConflict
			case "privacy":
				if _, e := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: pair[1].ID, Valid: true}, SubjectEmail: "preview@hash.example.test", SubjectName: "Synthetic preview", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage("{}")}); e != nil {
					t.Fatal("privacy mutation blocked by retired preview SQL", e)
				}
				want = http.StatusConflict
			}
			before := packageFullState223(t, q)
			peer.unblock()
			select {
			case w := <-result:
				joined = true
				packagePreviewRefusal227(t, w, want)
			case <-ctx.Done():
				t.Fatal("preview result did not join", ctx.Err())
			}
			if peer.heads.Load() != 1 || peer.gets.Load() != 1 || packageFullState223(t, q) != before {
				t.Fatal("late refusal changed state or reread")
			}
			if change == "logout" {
				if _, e := q.f.pool.Exec(q.f.ctx, "UPDATE users SET session_generation=$2 WHERE id=$1", q.f.user.ID, q.f.user.SessionGeneration); e != nil {
					t.Fatal(e)
				}
			}
			if change == "demotion" {
				if _, e := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: q.f.user.Role}); e != nil {
					t.Fatal(e)
				}
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
