//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This actual-PG journey keeps M99 intact: only the genuinely completed main
// member is readable. The original imported bytes and strict local SDK peer
// establish protocol/ownership coverage, not external-provider conformance.
// The wrapper endpoint exists before retention and the SAME constructor-owned
// client performs both native completion and recipient reads.
type signerPackageMemberPeer246 struct {
	inner                            *packageRetentionNativePeer240
	mu                               sync.Mutex
	enabled                          bool
	fault                            string
	check                            func() error
	failure                          error
	hold                             bool
	entered, release, done           chan struct{}
	enterOnce, releaseOnce, doneOnce sync.Once
}

func (p *signerPackageMemberPeer246) fail246(err error) {
	p.mu.Lock()
	if p.failure == nil {
		p.failure = err
	}
	p.mu.Unlock()
}
func (p *signerPackageMemberPeer246) release246() {
	p.releaseOnce.Do(func() { close(p.release) })
}
func (p *signerPackageMemberPeer246) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	enabled, fault, check, hold := p.enabled, p.fault, p.check, p.hold
	p.mu.Unlock()
	object := strings.HasPrefix(r.URL.Path, "/hash-import-fixture/") && r.URL.Query().Get("versionId") != "" && !r.URL.Query().Has("retention") && (r.Method == http.MethodHead || r.Method == http.MethodGet)
	if !enabled || !object {
		p.inner.ServeHTTP(w, r)
		return
	}
	if check != nil {
		if err := check(); err != nil {
			p.fail246(err)
			http.Error(w, "member provider ownership oracle failed", http.StatusInternalServerError)
			return
		}
	}
	if r.Method == http.MethodHead {
		p.inner.ServeHTTP(w, r)
		return
	}
	response := httptest.NewRecorder()
	p.inner.ServeHTTP(response, r)
	for key, values := range response.Header() {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if fault == "wrong GET version" {
		w.Header().Set("X-Amz-Version-Id", "different-recipient-version")
	}
	body := bytes.Clone(response.Body.Bytes())
	if fault == "wrong GET bytes" && len(body) > 0 {
		body[0] ^= 1
	}
	w.WriteHeader(response.Code)
	if hold {
		if flush, ok := w.(http.Flusher); ok {
			flush.Flush()
		}
		p.enterOnce.Do(func() { close(p.entered) })
		defer p.doneOnce.Do(func() { close(p.done) })
		select {
		case <-p.release:
		case <-r.Context().Done():
			return
		}
	}
	_, _ = w.Write(body)
}

type signerPackageMemberFixture246 struct {
	q           *ownedPublicReadFixtureV1
	peer        *signerPackageMemberPeer246
	client      *storage.Client
	meta        pdfadmission.HTMLSendPackageIntentMetadataV1
	recipient   uuid.UUID
	token, etag string
	raw         []byte
}

func newSignerPackageMemberFixture246(t *testing.T) *signerPackageMemberFixture246 {
	t.Helper()
	q, inner, _, m, recipient := packageCompletionNativeFixture241(t)
	peer := &signerPackageMemberPeer246{inner: inner, entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-member-package-access", SecretKey: "synthetic-member-package-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("same-namespace strict member client", err)
	}
	if namespace, err := client.PackageEvidenceNamespaceV1(); err != nil || namespace == ([32]byte{}) {
		t.Fatal("actual member namespace unavailable", err)
	}
	packageCompletionRun241(t, q, client, m, "sent")
	q.f.s.Sign.Storage = client
	root := packageLatest223(t, q, m.Capture.DocumentID)
	q.storagePeer.mu.Lock()
	original, present := q.storagePeer.objects[root.PdfStorageKey.String]
	raw := bytes.Clone(original)
	q.storagePeer.mu.Unlock()
	digest := sha256.Sum256(raw)
	if !present || int64(len(raw)) != m.Capture.PDFBytes || !bytes.Equal(digest[:], root.PdfSha256) {
		t.Fatal("genuine imported main bytes differ from capture")
	}
	f := &signerPackageMemberFixture246{q: q, peer: peer, client: client, meta: m, recipient: recipient, token: signerPackageToken242(t, q, recipient), etag: signerPackageMemberETag246(m.Capture.CanonicalSHA256, m.Capture.CommitmentSHA256), raw: raw}
	peer.mu.Lock()
	peer.enabled = true
	peer.check = func() error {
		if err := packageRetentionNativeNoWorkSQL240(q); err != nil {
			return err
		}
		snapshot, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil {
			return err
		}
		if snapshot.Global.ProviderStreams != 1 || snapshot.Organisation.ProviderStreams != 1 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.SQLSessions != 2 {
			return fmt.Errorf("member provider lacks original funded loan or SQL retirement: %+v", snapshot)
		}
		return nil
	}
	peer.mu.Unlock()
	t.Cleanup(func() {
		peer.release246()
		peer.mu.Lock()
		failure := peer.failure
		peer.mu.Unlock()
		if failure != nil {
			t.Error("actual member provider oracle", failure)
		}
	})
	return f
}
func signerPackageMemberETag246(manifest, legal [32]byte) string {
	return "\"" + hex.EncodeToString(manifest[:]) + "." + hex.EncodeToString(legal[:]) + "\""
}
func (f *signerPackageMemberFixture246) request246(ctx context.Context, token, position string, values ...string) (*httptest.ResponseRecorder, *http.Request) {
	request := httptest.NewRequest(http.MethodGet, f.q.f.s.PublicURL+"/sign/"+token+"/package/members/"+position+"/pdf", nil).WithContext(ctx)
	for _, value := range values {
		request.Header.Add("If-Match", value)
	}
	response := httptest.NewRecorder()
	return response, request
}
func (f *signerPackageMemberFixture246) drained246(t *testing.T) {
	t.Helper()
	f.q.assertObserversOnlyV1(t)
	if pending := f.q.runtime.SessionsV1().PendingV1(); pending.SignerPackageMemberReads != 0 {
		t.Fatal("captured member owner survived actual last use", pending)
	}
}
func (f *signerPackageMemberFixture246) run246(token, position string, values ...string) *httptest.ResponseRecorder {
	response, request := f.request246(f.q.f.ctx, token, position, values...)
	f.q.f.s.Routes().ServeHTTP(response, request)
	return response
}
func signerPackageMemberNoPDF246(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code == http.StatusOK || response.Header().Get("Content-Type") == "application/pdf" || bytes.HasPrefix(response.Body.Bytes(), []byte("%PDF")) || response.Header().Get("X-Hash-Package-Member-Position") != "" {
		t.Fatal("refused member request disclosed a PDF", response.Code)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("refused member response can be cached")
	}
}
func signerPackageMemberWait246(t *testing.T, ctx context.Context, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal(message, ctx.Err())
	case <-time.After(5 * time.Second):
		t.Fatal(message)
	}
}
func signerPackageMemberAsync246(t *testing.T, f *signerPackageMemberFixture246) (*httptest.ResponseRecorder, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	ctx, cancel := context.WithCancel(f.q.f.ctx)
	response, request := f.request246(ctx, f.token, "0", f.etag)
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		f.peer.release246()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		signerPackageMemberWait246(t, cleanup, done, "member HTTP response did not join")
	})
	go func() { defer close(done); f.q.f.s.Routes().ServeHTTP(response, request) }()
	return response, cancel, done
}

func TestSignerPackageMemberPDFExactV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	before := packageCompletionNativeState241(t, f.q, f.meta)
	counts := f.peer.inner.counts240()
	response := f.run246(f.token, "0", f.etag)
	sum := sha256.Sum256(response.Body.Bytes())
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), f.raw) || response.Header().Get("Content-Type") != "application/pdf" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("ETag") != f.etag || response.Header().Get("Content-Length") != strconv.Itoa(len(f.raw)) || response.Header().Get("X-Hash-Package-Member-Position") != "0" || response.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(sum[:]) || response.Header().Get("X-Hash-PDF-Bytes") != strconv.Itoa(len(f.raw)) || response.Header().Get("X-Hash-PDF-Pages") != strconv.Itoa(int(f.meta.Capture.PDFPages)) || response.Header().Get("X-Hash-Package-Manifest-SHA256") != hex.EncodeToString(f.meta.Capture.CanonicalSHA256[:]) || response.Header().Get("X-Hash-Package-Legal-Commitment-SHA256") != hex.EncodeToString(f.meta.Capture.CommitmentSHA256[:]) {
		t.Fatal("actual main response differs from exact captured bytes/commitments", response.Code)
	}
	after := f.peer.inner.counts240()
	if after[0] != counts[0]+1 || after[1] != counts[1]+1 || after[2] != counts[2] || after[3] != counts[3] || after[4] != counts[4] {
		t.Fatal("member read did not use one exact HEAD/GET or changed retention", counts, after)
	}
	if packageCompletionNativeState241(t, f.q, f.meta) != before {
		t.Fatal("member PDF GET changed original ceremony or delivery effects")
	}
	f.drained246(t)
}

func TestSignerPackageMemberPDFPreconditionsV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	staleManifest := f.meta.Capture.CanonicalSHA256
	staleManifest[0] ^= 1
	staleLegal := f.meta.Capture.CommitmentSHA256
	staleLegal[0] ^= 1
	cases := []struct {
		name, token, position string
		values                []string
		status                int
	}{
		{"missing", f.token, "0", nil, http.StatusPreconditionRequired},
		{"weak", f.token, "0", []string{"W/" + f.etag}, http.StatusBadRequest},
		{"wildcard", f.token, "0", []string{"*"}, http.StatusBadRequest},
		{"list", f.token, "0", []string{f.etag + ", " + f.etag}, http.StatusBadRequest},
		{"duplicate header", f.token, "0", []string{f.etag, f.etag}, http.StatusBadRequest},
		{"stale manifest", f.token, "0", []string{signerPackageMemberETag246(staleManifest, f.meta.Capture.CommitmentSHA256)}, http.StatusPreconditionFailed},
		{"stale legal commitment", f.token, "0", []string{signerPackageMemberETag246(f.meta.Capture.CanonicalSHA256, staleLegal)}, http.StatusPreconditionFailed},
		{"zero manifest", f.token, "0", []string{signerPackageMemberETag246([32]byte{}, f.meta.Capture.CommitmentSHA256)}, http.StatusPreconditionFailed},
		{"zero legal commitment", f.token, "0", []string{signerPackageMemberETag246(f.meta.Capture.CanonicalSHA256, [32]byte{})}, http.StatusPreconditionFailed},
		{"unknown token", strings.Repeat("x", 43), "0", []string{f.etag}, http.StatusNotFound},
		{"negative position", f.token, "-1", []string{f.etag}, http.StatusBadRequest},
		{"overflow position", f.token, "99999999999999999999", []string{f.etag}, http.StatusBadRequest},
		{"noncanonical position", f.token, "01", []string{f.etag}, http.StatusBadRequest},
		{"uncaptured annex", f.token, "1", []string{f.etag}, http.StatusNotFound},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := packageCompletionNativeState241(t, f.q, f.meta)
			counts := f.peer.inner.counts240()
			response := f.run246(c.token, c.position, c.values...)
			if response.Code != c.status {
				t.Fatal("member precondition status differs", response.Code, c.status)
			}
			signerPackageMemberNoPDF246(t, response)
			f.drained246(t)
			if f.peer.inner.counts240() != counts || packageCompletionNativeState241(t, f.q, f.meta) != before {
				t.Fatal("refused precondition reached provider or changed ceremony")
			}
		})
	}
	replacement := strings.Repeat("r", 43)
	current, err := f.q.f.q.GetRecipient(f.q.f.ctx, generated.GetRecipientParams{ID: f.recipient, OrgID: f.q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.q.f.q.RotateRecipientMagicToken(f.q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient, DocumentID: f.meta.Capture.DocumentID, MagicTokenHash: auth.HashMagicToken(replacement), MagicTokenExpiresAt: current.MagicTokenExpiresAt}); err != nil {
		t.Fatal(err)
	}
	counts := f.peer.inner.counts240()
	response := f.run246(f.token, "0", f.etag)
	if response.Code != http.StatusNotFound {
		t.Fatal("revoked original token still authenticated", response.Code)
	}
	signerPackageMemberNoPDF246(t, response)
	if _, err = f.q.f.pool.Exec(f.q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND document_id=$2", f.recipient, f.meta.Capture.DocumentID); err != nil {
		t.Fatal(err)
	}
	response = f.run246(replacement, "0", f.etag)
	if response.Code != http.StatusGone {
		t.Fatal("expired current token still authenticated", response.Code)
	}
	signerPackageMemberNoPDF246(t, response)
	if f.peer.inner.counts240() != counts {
		t.Fatal("revoked or expired token reached provider")
	}
	f.drained246(t)
}

func TestSignerPackageMemberPDFProviderRefusalV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	for _, fault := range []string{"wrong GET version", "wrong GET bytes"} {
		t.Run(fault, func(t *testing.T) {
			f.peer.mu.Lock()
			f.peer.fault = fault
			f.peer.mu.Unlock()
			before := packageCompletionNativeState241(t, f.q, f.meta)
			counts := f.peer.inner.counts240()
			response := f.run246(f.token, "0", f.etag)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("adverse actual provider response accepted", response.Code)
			}
			signerPackageMemberNoPDF246(t, response)
			after := f.peer.inner.counts240()
			if after[0] != counts[0]+1 || after[1] != counts[1]+1 {
				t.Fatal("adverse case did not reach exact actual HEAD/GET", counts, after)
			}
			if packageCompletionNativeState241(t, f.q, f.meta) != before {
				t.Fatal("refused provider read changed original ceremony")
			}
			f.drained246(t)
		})
	}
}

func TestSignerPackageMemberPDFCopiedContextV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	rc, err := f.q.f.s.Sign.LookupSignerPackageByTokenV1(f.q.f.ctx, auth.HashMagicToken(f.token))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.CloseReadV1() })
	counts := f.peer.inner.counts240()
	forged := *rc
	foreign := *rc.Document
	foreign.ID = uuid.New()
	forged.Document = &foreign
	result, err := f.q.f.s.Sign.SignerPackageMemberPDFV1(f.q.f.ctx, &forged, pdfadmission.SignerPackageMemberExpectedV1{Position: 0, ManifestSHA256: f.meta.Capture.CanonicalSHA256, LegalCommitmentSHA256: f.meta.Capture.CommitmentSHA256})
	if result != nil {
		result.CloseConsumerV1()
	}
	if err == nil || result != nil || f.peer.inner.counts240() != counts {
		t.Fatal("copied caller document became private member authority")
	}
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	org, err := f.q.f.q.CreateOrg(f.q.f.ctx, generated.CreateOrgParams{Name: "Negative duplicate member tenant", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := f.q.f.q.CreateUser(f.q.f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@negative.example.test", Name: "Negative owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := f.q.f.q.CreateBlocksDocument(f.q.f.ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "Negative duplicate only", BlocksJson: []byte("{\"version\":1,\"blocks\":[]}"), VariablesJson: []byte("{}")})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.q.f.q.CreateRecipient(f.q.f.ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Name: "Negative recipient", Email: uuid.NewString() + "@negative.example.test", Locale: "en", MagicTokenHash: auth.HashMagicToken(f.token), MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	response := f.run246(f.token, "0", f.etag)
	if response.Code != http.StatusNotFound {
		t.Fatal("cross-tenant duplicate selected one member", response.Code)
	}
	signerPackageMemberNoPDF246(t, response)
	if f.peer.inner.counts240() != counts {
		t.Fatal("ambiguous token reached provider")
	}
	f.drained246(t)
}

func TestSignerPackageMemberPDFReadRevocationV1E2E(t *testing.T) {
	for _, scenario := range []string{"token rotation", "current privacy request", "original expiry despite current extension"} {
		t.Run(scenario, func(t *testing.T) {
			f := newSignerPackageMemberFixture246(t)
			var originalExpiry time.Time
			if scenario == "original expiry despite current extension" {
				originalExpiry = time.Now().UTC().Add(3 * time.Second).Truncate(time.Microsecond)
				if _, err := f.q.f.pool.Exec(f.q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$3 WHERE id=$1 AND document_id=$2", f.recipient, f.meta.Capture.DocumentID, originalExpiry); err != nil {
					t.Fatal(err)
				}
			}
			f.peer.mu.Lock()
			f.peer.hold = true
			f.peer.mu.Unlock()
			response, _, done := signerPackageMemberAsync246(t, f)
			signerPackageMemberWait246(t, f.q.f.ctx, f.peer.entered, "actual member GET did not block")
			snapshot, pending := f.q.snapshotV1(t), f.q.runtime.SessionsV1().PendingV1()
			if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.SignerPackageMemberReads != 1 || snapshot.Global.ProviderStreams != 1 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.SQLSessions != 2 {
				t.Fatal("blocked GET lost actual provider/body loan or retained SQL", pending, snapshot)
			}
			switch scenario {
			case "token rotation":
				current, err := f.q.f.q.GetRecipient(f.q.f.ctx, generated.GetRecipientParams{ID: f.recipient, OrgID: f.q.f.org})
				if err != nil {
					t.Fatal(err)
				}
				if err = f.q.f.q.RotateRecipientMagicToken(f.q.f.ctx, generated.RotateRecipientMagicTokenParams{ID: f.recipient, DocumentID: f.meta.Capture.DocumentID, MagicTokenHash: auth.HashMagicToken(strings.Repeat("n", 43)), MagicTokenExpiresAt: current.MagicTokenExpiresAt}); err != nil {
					t.Fatal(err)
				}
			case "current privacy request":
				if _, err := f.q.f.q.CreateDataSubjectRequest(f.q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.q.f.org, DocumentID: pgtype.UUID{Bytes: f.meta.Capture.DocumentID, Valid: true}, SubjectEmail: "member-privacy@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")}); err != nil {
					t.Fatal(err)
				}
			case "original expiry despite current extension":
				if _, err := f.q.f.pool.Exec(f.q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1 AND document_id=$2", f.recipient, f.meta.Capture.DocumentID); err != nil {
					t.Fatal(err)
				}
				timer := time.NewTimer(time.Until(originalExpiry) + time.Millisecond)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-f.q.f.ctx.Done():
					t.Fatal("original credential deadline wait canceled")
				}
			}
			before := packageCompletionNativeState241(t, f.q, f.meta)
			f.peer.release246()
			signerPackageMemberWait246(t, f.q.f.ctx, done, "revoked member response did not join")
			signerPackageMemberWait246(t, f.q.f.ctx, f.peer.done, "actual member GET did not retire")
			if scenario == "current privacy request" {
				if response.Code != http.StatusConflict && response.Code != http.StatusServiceUnavailable {
					t.Fatal("current privacy did not refuse fresh delivery", response.Code)
				}
			} else if scenario == "original expiry despite current extension" {
				if response.Code != http.StatusGone {
					t.Fatal("current extension revived originally expired credential", response.Code)
				}
			} else if response.Code != http.StatusNotFound && response.Code != http.StatusGone {
				t.Fatal("rotated credential did not refuse fresh delivery", response.Code)
			}
			signerPackageMemberNoPDF246(t, response)
			if packageCompletionNativeState241(t, f.q, f.meta) != before {
				t.Fatal("refused post-provider read mutated original ceremony")
			}
			f.drained246(t)
		})
	}
}

func TestSignerPackageMemberPDFWriterLifetimeV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	before := packageCompletionNativeState241(t, f.q, f.meta)
	ctx, cancel := context.WithCancel(f.q.f.ctx)
	defer cancel()
	_, request := f.request246(ctx, f.token, "0", f.etag)
	writer := &ownedCommentPageWriter166V1{ResponseRecorder: httptest.NewRecorder(), entered: make(chan struct{}), release: make(chan struct{}), life: f.q.f.ctx}
	done := make(chan struct{})
	var release sync.Once
	t.Cleanup(func() {
		release.Do(func() { close(writer.release) })
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		signerPackageMemberWait246(t, cleanup, done, "member writer did not join")
	})
	go func() { defer close(done); f.q.f.s.Routes().ServeHTTP(writer, request) }()
	signerPackageMemberWait246(t, f.q.f.ctx, writer.entered, "actual member Write not reached")
	snapshot, pending := f.q.snapshotV1(t), f.q.runtime.SessionsV1().PendingV1()
	if writer.Code != http.StatusOK || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.SignerReaders != 1 || pending.SignerScopes != 1 || pending.SignerPackageMemberReads != 1 || snapshot.Global.ProviderStreams != 0 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.DBStagingBytes <= 0 || snapshot.Global.SQLSessions != 2 {
		t.Fatal("actual member writer lost body/reader loan or retained provider/SQL", pending, snapshot)
	}
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
	err := f.q.runtime.ReconcileCleanupV1(cleanup)
	stop()
	afterSnapshot, afterPending := f.q.snapshotV1(t), f.q.runtime.SessionsV1().PendingV1()
	if err != nil || afterSnapshot != snapshot || afterPending != pending {
		t.Fatalf("cancel refunded active member writer debt: err=%v before_snapshot=%+v after_snapshot=%+v before_pending=%+v after_pending=%+v", err, snapshot, afterSnapshot, pending, afterPending)
	}
	release.Do(func() { close(writer.release) })
	signerPackageMemberWait246(t, f.q.f.ctx, done, "member writer did not finish")
	if writer.timedOut.Load() || !bytes.Equal(writer.Body.Bytes(), f.raw) {
		t.Fatal("actual member writer lost its exact retained bytes")
	}
	if packageCompletionNativeState241(t, f.q, f.meta) != before {
		t.Fatal("member writer altered original ceremony")
	}
	f.drained246(t)
}

func TestSignerPackageMemberPDFReadCancellationV1E2E(t *testing.T) {
	f := newSignerPackageMemberFixture246(t)
	f.peer.mu.Lock()
	f.peer.hold = true
	f.peer.mu.Unlock()
	response, cancel, done := signerPackageMemberAsync246(t, f)
	signerPackageMemberWait246(t, f.q.f.ctx, f.peer.entered, "cancel fixture did not reach actual GET")
	snapshot, pending := f.q.snapshotV1(t), f.q.runtime.SessionsV1().PendingV1()
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.SignerPackageMemberReads != 1 || snapshot.Global.ProviderStreams != 1 || snapshot.Global.ParentBytes <= 0 || snapshot.Global.SQLSessions != 2 {
		t.Fatal("active GET not funded or SQL not retired", pending, snapshot)
	}
	// An independently authenticated second request cannot borrow a second stream
	// from the unchanged one-provider profile, and must not perturb the first.
	counts := f.peer.inner.counts240()
	second := f.run246(f.token, "0", f.etag)
	if second.Code != http.StatusServiceUnavailable || f.peer.inner.counts240() != counts {
		t.Fatal("concurrent request bypassed original provider grant", second.Code)
	}
	signerPackageMemberNoPDF246(t, second)
	afterSnapshot, afterPending := f.q.snapshotV1(t), f.q.runtime.SessionsV1().PendingV1()
	// Server Flush precedes the client's response-body wrapper. Its original
	// owned IO may still prepay additional Parent bytes while GET is blocked.
	// No existing funding may be refunded, and the same organisation must
	// account for every new byte. All other resources and owners stay exact.
	globalGrowth := afterSnapshot.Global.ParentBytes - snapshot.Global.ParentBytes
	orgGrowth := afterSnapshot.Organisation.ParentBytes - snapshot.Organisation.ParentBytes
	comparable := afterSnapshot
	comparable.Global.ParentBytes = snapshot.Global.ParentBytes
	comparable.Organisation.ParentBytes = snapshot.Organisation.ParentBytes
	if globalGrowth < 0 || orgGrowth < 0 || globalGrowth != orgGrowth || comparable != snapshot || afterPending != pending {
		t.Fatalf("refused concurrent request changed original GET debt: before_snapshot=%+v after_snapshot=%+v before_pending=%+v after_pending=%+v", snapshot, afterSnapshot, pending, afterPending)
	}
	cancel()
	signerPackageMemberWait246(t, f.q.f.ctx, done, "canceled member HTTP response did not join")
	signerPackageMemberWait246(t, f.q.f.ctx, f.peer.done, "canceled actual GET did not join")
	signerPackageMemberNoPDF246(t, response)
	f.drained246(t)
}
