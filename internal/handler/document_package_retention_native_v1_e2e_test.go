//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This local S3 protocol peer shares the genuinely imported/measured bytes with
// the original fixture. Actual constructor/SDK/HTTP/PG/native ownership run;
// the peer's COMPLIANCE response is not remote provider conformance, an OS
// restart, a nonempty Send ceremony or a signature/legal acceptance claim.
type packageRetentionNativePeer240 struct {
	base                                       *htmlCreationStorageE2E
	mu                                         sync.Mutex
	until                                      map[string]time.Time
	heads, gets, retentionReads, puts, applied int
	denyPut, wrongVersion, wrongBody, blockGET bool
	failure                                    error
	afterPut                                   func() error
	entered, getDone                           chan struct{}
	enterOnce, doneOnce                        sync.Once
}

func (p *packageRetentionNativePeer240) reject240(w http.ResponseWriter, message string) {
	p.mu.Lock()
	if p.failure == nil {
		p.failure = errors.New(message)
	}
	p.mu.Unlock()
	http.Error(w, message, http.StatusBadRequest)
}

func (p *packageRetentionNativePeer240) counts240() [5]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return [5]int{p.heads, p.gets, p.retentionReads, p.puts, p.applied}
}

func (p *packageRetentionNativePeer240) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const prefix = "/hash-import-fixture/"
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		p.reject240(w, "strict fixture request omitted actual SDK authentication")
		return
	}
	if r.URL.Path == strings.TrimSuffix(prefix, "/") || r.URL.Path == prefix {
		if r.Method == http.MethodHead {
			p.base.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == http.MethodGet && r.URL.Query().Has("versioning"):
			_, _ = io.WriteString(w, "<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>")
		case r.Method == http.MethodGet && r.URL.Query().Has("object-lock"):
			_, _ = io.WriteString(w, "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>")
		default:
			p.reject240(w, "unexpected strict fixture bucket operation")
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix) || r.URL.Query().Get("versionId") != "import-version-1" || r.URL.Query().Has("versions") || r.URL.Query().Has("list-type") {
		p.reject240(w, "strict fixture received latest/listing or a different version")
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	p.base.mu.Lock()
	_, exists := p.base.objects[key]
	p.base.mu.Unlock()
	if !exists {
		p.reject240(w, "strict fixture object was not genuinely imported")
		return
	}
	if r.URL.Query().Has("retention") {
		if r.Method == http.MethodGet {
			p.mu.Lock()
			p.retentionReads++
			until := p.until[key]
			p.mu.Unlock()
			if until.IsZero() {
				until = time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>"+until.UTC().Format(time.RFC3339Nano)+"</RetainUntilDate></Retention>")
			return
		}
		if r.Method != http.MethodPut {
			p.reject240(w, "unexpected strict retention method")
			return
		}
		var requested struct {
			Mode  string    `xml:"Mode"`
			Until time.Time `xml:"RetainUntilDate"`
		}
		if err := xml.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&requested); err != nil || requested.Mode != "COMPLIANCE" || requested.Until.IsZero() || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
			p.reject240(w, "invalid strict COMPLIANCE request")
			return
		}
		p.mu.Lock()
		p.puts++
		denied, old := p.denyPut, p.until[key]
		if !denied {
			if !old.IsZero() && requested.Until.Before(old) {
				p.mu.Unlock()
				p.reject240(w, "strict retention shortened provider deadline")
				return
			}
			p.applied++
			p.until[key] = requested.Until.UTC()
		}
		hook := p.afterPut
		p.mu.Unlock()
		if denied {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>synthetic unapplied retention refusal</Message></Error>")
			return
		}
		if hook != nil {
			if err := hook(); err != nil {
				p.reject240(w, err.Error())
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodHead && r.Method != http.MethodGet {
		p.reject240(w, "unexpected strict object mutation")
		return
	}
	p.mu.Lock()
	if r.Method == http.MethodHead {
		p.heads++
	} else {
		p.gets++
	}
	wrongVersion, wrongBody, block := p.wrongVersion, p.wrongBody, p.blockGET
	p.mu.Unlock()
	// Preserve the original real imported object response, including size/digest
	// derived headers. Only the deliberately adverse protocol branch changes it.
	response := httptest.NewRecorder()
	p.base.ServeHTTP(response, r)
	for name, values := range response.Header() {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if wrongVersion {
		w.Header().Set("X-Amz-Version-Id", "different-provider-version")
	}
	w.WriteHeader(response.Code)
	if r.Method == http.MethodHead {
		return
	}
	if block {
		w.(http.Flusher).Flush()
		p.enterOnce.Do(func() { close(p.entered) })
		defer p.doneOnce.Do(func() { close(p.getDone) })
		<-r.Context().Done()
		return
	}
	body := append([]byte(nil), response.Body.Bytes()...)
	if wrongBody && len(body) > 0 {
		body[0] ^= 1
	}
	_, _ = w.Write(body)
}

func packageRetentionNativeClient240(t *testing.T, q *ownedPublicReadFixtureV1, peer *packageRetentionNativePeer240) *storage.Client {
	t.Helper()
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-native-package-access", SecretKey: "synthetic-native-package-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("real lock-enabled storage constructor", err)
	}
	if namespace, err := client.PackageEvidenceNamespaceV1(); err != nil || namespace == ([32]byte{}) {
		t.Fatal("strict constructor namespace unavailable", err)
	}
	return client
}

func packageRetentionNativeFixture240(t *testing.T) (*ownedPublicReadFixtureV1, *packageRetentionNativePeer240, *storage.Client, pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	q := inspectionFixturePG236(t)
	_, _, m, err := packageAttemptBirth235(t, q, false)
	if err != nil {
		t.Fatal(err)
	}
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	client := packageRetentionNativeClient240(t, q, peer)
	t.Cleanup(func() {
		peer.mu.Lock()
		failure := peer.failure
		peer.mu.Unlock()
		if failure != nil {
			t.Error("strict native S3 protocol fixture", failure)
		}
	})
	return q, peer, client, m
}

func packageRetentionNativeNoWorkSQL240(q *ownedPublicReadFixtureV1) error {
	pending := q.runtime.SessionsV1().PendingV1()
	if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.ObserverSessions != 2 {
		return fmt.Errorf("provider dispatch retained native Work SQL: %+v", pending)
	}
	var count int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND state IN ('idle in transaction','idle in transaction (aborted)')").Scan(&count); err != nil {
		return err
	}
	if count != 0 {
		return fmt.Errorf("provider dispatch observed %d unretired PostgreSQL transactions", count)
	}
	return nil
}

func packageRetentionNativeCeremonyState240(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) string {
	t.Helper()
	var out string
	err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE document_id=$1),'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE org_id=$2),'emails',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM email_deliveries e),'reminders',(SELECT jsonb_agg(to_jsonb(r) ORDER BY document_id) FROM reminders r WHERE document_id=$1))::text", m.Capture.DocumentID, m.Capture.OrgID).Scan(&out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func packageRetentionNativeRun240(t *testing.T, q *ownedPublicReadFixtureV1, client *storage.Client, m pdfadmission.HTMLSendPackageIntentMetadataV1, wantSuccess bool) {
	t.Helper()
	batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
	defer batch.CloseConsumerV1()
	called := false
	more, err := batch.WithNextRetentionV1(client, func(v pdfadmission.HTMLSendPackageRetentionObservationV1) error {
		called = true
		capture := m.Capture
		capture.RootUpdatedAt, capture.CreatedAt = capture.RootUpdatedAt.UTC(), capture.CreatedAt.UTC()
		if !wantSuccess || !v.RetentionVerified || v.Attempt.AttemptID != m.AttemptID || v.Attempt.Capture != capture || v.Attempt.Outcome != pdfadmission.HTMLSendPackageAttemptActiveV1 || !v.Attempt.RetainUntil.Equal(m.RetainUntil) || !v.Attempt.Article13NoticeEpochAt.Equal(m.Article13NoticeEpochAt) || v.Attempt.RetentionStartedAt.IsZero() || v.Attempt.RetentionCompletedAt.IsZero() {
			return errors.New("native retention delivered different or incomplete exact attempt")
		}
		return packageRetentionNativeNoWorkSQL240(q)
	})
	if !more || called != wantSuccess || (err == nil) != wantSuccess {
		t.Fatal("native retention result disagreed with actual outcome", more, called, err)
	}
	if err != nil && !errors.Is(err, pdfadmission.ErrHTMLSendPackageRetentionV1) {
		t.Fatal("native retention leaked an unowned failure", err)
	}
	batch.CloseConsumerV1()
	packageWorkerDrained239(t, q)
}

func packageRetentionNativeLedger240(t *testing.T, q *ownedPublicReadFixtureV1, client *storage.Client, m pdfadmission.HTMLSendPackageIntentMetadataV1, verified bool) {
	t.Helper()
	rows, err := q.f.q.ListDocumentPackageSendRetentionMembersV1(q.f.ctx, packageMemberRetentionList240(m))
	namespace, nsErr := client.PackageEvidenceNamespaceV1()
	if err != nil || nsErr != nil || len(rows) != 1 || !rows[0].StartedAt.Valid || rows[0].VerifiedAt.Valid != verified || !bytes.Equal(rows[0].ProviderNamespaceSha256, namespace[:]) {
		t.Fatal("native member ledger differs", err, nsErr)
	}
	if verified && (rows[0].ObservedMode.String != "COMPLIANCE" || !rows[0].ObservedRetainUntil.Valid || rows[0].ObservedRetainUntil.Time.Before(m.RetainUntil) || rows[0].VerifierProfile.String != "s3-compliance-digest-v1") {
		t.Fatal("native confirmation lacks exact strict provider receipt")
	}
	row, err := q.f.q.InspectDocumentPackageSendAttemptV1(q.f.ctx, generated.InspectDocumentPackageSendAttemptV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID})
	if err != nil || !row.HasActiveIntent || !row.RetentionStartedAt.Valid || row.RetentionCompletedAt.Valid != verified || row.TerminalOutcome.Valid || !row.RetainUntil.Time.Equal(m.RetainUntil) || !row.Article13NoticeEpochAt.Time.Equal(m.Article13NoticeEpochAt) {
		t.Fatal("native retention changed attempt identity or terminalized Send", err)
	}
	packageAttemptInspect235(t, q, m, true, "")
}

func TestDocumentPackageNativeRetentionV1E2E(t *testing.T) {
	t.Run("strict native receipt completes only retention and fresh retry skips provider", func(t *testing.T) {
		q, peer, client, m := packageRetentionNativeFixture240(t)
		before := packageRetentionNativeCeremonyState240(t, q, m)
		peer.mu.Lock()
		peer.afterPut = func() error { return packageRetentionNativeNoWorkSQL240(q) }
		peer.mu.Unlock()
		packageRetentionNativeRun240(t, q, client, m, true)
		packageRetentionNativeLedger240(t, q, client, m, true)
		if packageRetentionNativeCeremonyState240(t, q, m) != before {
			t.Fatal("retention mutated document, token, invitation, reminder or audit ceremony")
		}
		counts := peer.counts240()
		if counts[0] != 2 || counts[1] != 2 || counts[2] != 2 || counts[3] != 1 || counts[4] != 1 {
			t.Fatal("missing actual pre/post exact-byte and retention verification", counts)
		}
		state := packageMemberRetentionState240(t, q, m)
		packageRetentionNativeRun240(t, q, client, m, true)
		if peer.counts240() != counts || packageMemberRetentionState240(t, q, m) != state || packageRetentionNativeCeremonyState240(t, q, m) != before {
			t.Fatal("fresh native retry replayed provider or changed original attempt/deadline")
		}
		peer.mu.Lock()
		failure := peer.failure
		peer.mu.Unlock()
		if failure != nil {
			t.Fatal(failure)
		}
	})
	t.Run("development client refuses before durable start", func(t *testing.T) {
		q, peer, _, m := packageRetentionNativeFixture240(t)
		before, original, calls := packageMemberRetentionState240(t, q, m), packageMeasurementState232(t, q), q.storagePeer.requests.Load()
		packageRetentionNativeRun240(t, q, q.f.s.Storage, m, false)
		if packageMemberRetentionState240(t, q, m) != before || packageMeasurementState232(t, q) != original || q.storagePeer.requests.Load() != calls || peer.counts240() != ([5]int{}) {
			t.Fatal("development receipt entered retention or provider dispatch")
		}
	})
	t.Run("provider refusal preserves same job and alternate namespace cannot adopt it", func(t *testing.T) {
		q, peer, client, m := packageRetentionNativeFixture240(t)
		before := packageRetentionNativeCeremonyState240(t, q, m)
		peer.mu.Lock()
		peer.denyPut = true
		peer.mu.Unlock()
		packageRetentionNativeRun240(t, q, client, m, false)
		packageRetentionNativeLedger240(t, q, client, m, false)
		counts := peer.counts240()
		if counts[3] < 1 || counts[4] != 0 {
			t.Fatal("provider refusal fixture did not refuse actual retention", counts)
		}
		state := packageMemberRetentionState240(t, q, m)
		other := packageRetentionNativeClient240(t, q, peer)
		originalNamespace, originalErr := client.PackageEvidenceNamespaceV1()
		otherNamespace, otherErr := other.PackageEvidenceNamespaceV1()
		if originalErr != nil || otherErr != nil || originalNamespace == otherNamespace {
			t.Fatal("alternate actual endpoint did not establish a different constructor namespace", originalErr, otherErr)
		}
		// Constructor bucket preflight occurred above; no target object request may
		// occur when the persisted member belongs to the original endpoint namespace.
		packageRetentionNativeRun240(t, q, other, m, false)
		if peer.counts240() != counts || packageMemberRetentionState240(t, q, m) != state {
			t.Fatal("different provider namespace adopted started work or dispatched I/O")
		}
		peer.mu.Lock()
		peer.denyPut = false
		peer.mu.Unlock()
		packageRetentionNativeRun240(t, q, client, m, true)
		packageRetentionNativeLedger240(t, q, client, m, true)
		if packageRetentionNativeCeremonyState240(t, q, m) != before {
			t.Fatal("recovered provider work altered Send ceremony")
		}
	})
	for _, kind := range []string{"wrong bytes", "wrong version echo"} {
		t.Run(kind+" refuses before provider retention mutation", func(t *testing.T) {
			q, peer, client, m := packageRetentionNativeFixture240(t)
			before := packageRetentionNativeCeremonyState240(t, q, m)
			peer.mu.Lock()
			if kind == "wrong bytes" {
				peer.wrongBody = true
			} else {
				peer.wrongVersion = true
			}
			peer.mu.Unlock()
			packageRetentionNativeRun240(t, q, client, m, false)
			packageRetentionNativeLedger240(t, q, client, m, false)
			counts := peer.counts240()
			if counts[0] == 0 || counts[2] != 0 || counts[3] != 0 || counts[4] != 0 || packageRetentionNativeCeremonyState240(t, q, m) != before {
				t.Fatal("bad pinned source reached provider retention or Send", counts)
			}
		})
	}
	t.Run("privacy review after actual provider write refuses SQL confirmation", func(t *testing.T) {
		q, peer, client, m := packageRetentionNativeFixture240(t)
		before := packageRetentionNativeCeremonyState240(t, q, m)
		made := make(chan uuid.UUID, 1)
		peer.mu.Lock()
		peer.afterPut = func() error {
			if err := packageRetentionNativeNoWorkSQL240(q); err != nil {
				return err
			}
			dsr, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: m.Capture.DocumentID, Valid: true}, SubjectEmail: "native-package-privacy@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")})
			if err == nil {
				made <- dsr.ID
			}
			return err
		}
		peer.mu.Unlock()
		packageRetentionNativeRun240(t, q, client, m, false)
		packageRetentionNativeLedger240(t, q, client, m, false)
		counts := peer.counts240()
		if counts[4] != 1 || counts[1] != 2 || packageRetentionNativeCeremonyState240(t, q, m) != before {
			t.Fatal("postwrite privacy race did not preserve unconfirmed sealing state", counts)
		}
		select {
		case id := <-made:
			if _, err := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: id, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("actual provider hook did not create the privacy review")
		}
		peer.mu.Lock()
		failure := peer.failure
		peer.afterPut = nil
		peer.mu.Unlock()
		if failure != nil {
			t.Fatal(failure)
		}
		// The first write is irreversible. Fresh recovery re-verifies the actual
		// retained version, then acknowledges the same member without a second PUT.
		packageRetentionNativeRun240(t, q, client, m, true)
		if peer.counts240()[3] != counts[3] || peer.counts240()[4] != 1 {
			t.Fatal("privacy recovery replayed an already satisfied provider mutation")
		}
		packageRetentionNativeLedger240(t, q, client, m, true)
	})
	t.Run("cancel actual blocked provider stream keeps unverified durable work", func(t *testing.T) {
		q, peer, client, m := packageRetentionNativeFixture240(t)
		peer.mu.Lock()
		peer.blockGET = true
		peer.mu.Unlock()
		ctx, cancel := context.WithCancel(q.f.ctx)
		defer cancel()
		batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(ctx, pdfadmission.PackageSendRecoveryCursorV1{})
		if err != nil || batch == nil {
			t.Fatal(err)
		}
		defer batch.CloseConsumerV1()
		type result struct {
			more, called bool
			err          error
		}
		finished, joined := make(chan result, 1), make(chan struct{})
		defer func() {
			cancel()
			batch.CloseConsumerV1()
			select {
			case <-joined:
			case <-time.After(5 * time.Second):
				t.Error("cancelled native retention consumer did not join")
			}
		}()
		go func() {
			defer close(joined)
			called := false
			more, err := batch.WithNextRetentionV1(client, func(pdfadmission.HTMLSendPackageRetentionObservationV1) error { called = true; return nil })
			finished <- result{more: more, called: called, err: err}
		}()
		select {
		case <-peer.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("actual exact-version provider stream did not enter")
		}
		if err := packageRetentionNativeNoWorkSQL240(q); err != nil {
			t.Fatal(err)
		}
		cancel()
		batch.CloseConsumerV1()
		select {
		case out := <-finished:
			if !out.more || out.called || out.err == nil {
				t.Fatal("cancelled native provider stream delivered retention", out.more, out.called, out.err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("actual native provider cancellation did not return")
		}
		select {
		case <-peer.getDone:
		case <-time.After(5 * time.Second):
			t.Fatal("actual provider HTTP handler did not join cancellation")
		}
		packageWorkerDrained239(t, q)
		packageRetentionNativeLedger240(t, q, client, m, false)
		if counts := peer.counts240(); counts[3] != 0 || counts[4] != 0 {
			t.Fatal("cancelled preverification reached provider retention", counts)
		}
	})
}
