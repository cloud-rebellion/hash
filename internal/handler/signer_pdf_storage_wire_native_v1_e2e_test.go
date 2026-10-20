//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// This peer forwards the actual source produced, cleaned and stored by the
// owned fixture. Only the intended exact-version GET is paused after genuine
// headers and half its body have been written on a real HTTP connection.
// The failure modes either stop that body early or alter one wire byte; they
// never alter its persisted version, digest, source/history, admission or cache.
type ownedPDFStorageWire181V1 struct {
	base                       *htmlCreationStorageE2E
	path, version, mode        string
	entered, release, finished chan struct{}
	releaseOnce                sync.Once
	calls                      atomic.Int32
	invalid                    atomic.Bool
}

func (p *ownedPDFStorageWire181V1) unblockV1() { p.releaseOnce.Do(func() { close(p.release) }) }

func (p *ownedPDFStorageWire181V1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != p.path {
		p.base.ServeHTTP(w, r)
		return
	}
	if p.calls.Add(1) != 1 {
		p.invalid.Store(true)
		http.Error(w, "unexpected repeated exact source GET", http.StatusServiceUnavailable)
		return
	}
	defer close(p.finished)
	if r.URL.Query().Get("versionId") != p.version {
		p.invalid.Store(true)
		http.Error(w, "exact source version required", http.StatusBadRequest)
		return
	}
	// The original import peer caps every object at1MiB; verify that bound
	// before recording its genuine response, rather than inventing PDF bytes.
	p.base.mu.Lock()
	size := len(p.base.objects[strings.TrimPrefix(p.path, "/hash-import-fixture/")])
	p.base.mu.Unlock()
	if size < 16 || size > 1<<20 {
		p.invalid.Store(true)
		http.Error(w, "source outside fixed fixture bound", http.StatusInternalServerError)
		return
	}
	recorded := httptest.NewRecorder()
	p.base.ServeHTTP(recorded, r)
	if recorded.Code != http.StatusOK || recorded.Body.Len() != size || recorded.Header().Get("X-Amz-Version-Id") != p.version {
		p.invalid.Store(true)
		http.Error(w, "genuine source response unavailable", http.StatusInternalServerError)
		return
	}
	for name, values := range recorded.Header() {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	body := recorded.Body.Bytes()
	if p.mode == "altered_body" {
		body[len(body)-1] ^= 1 // only the independent wire copy, never the stored object
	}
	w.WriteHeader(http.StatusOK)
	half := len(body) / 2
	if _, err := w.Write(body[:half]); err != nil {
		p.invalid.Store(true)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		p.invalid.Store(true)
		return
	}
	flusher.Flush()
	close(p.entered)
	select {
	case <-p.release:
	case <-r.Context().Done():
		return
	}
	if p.mode != "truncated_body" {
		if _, err := w.Write(body[half:]); err != nil {
			p.invalid.Store(true)
		}
	}
}

// Only the handler goroutine accesses the recorder. The test observes the
// atomic byte count while real storage is paused, then inspects the response
// only after the handler and storage peer have both joined.
type ownedPDFHTTPWriter181V1 struct {
	*httptest.ResponseRecorder
	written atomic.Int64
}

func (w *ownedPDFHTTPWriter181V1) Write(body []byte) (int, error) {
	n, err := w.ResponseRecorder.Write(body)
	w.written.Add(int64(n))
	return n, err
}

func TestOwnedSignerPDFStorageWireLateChangesAndFaultsE2E(t *testing.T) {
	for _, scenario := range []string{"unchanged_source", "rotated_token", "recipient_deadline_extension", "document_deadline_extension", "printed_identity", "printed_identity_guard", "document_name", "truncated_body", "altered_body"} {
		t.Run(scenario, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			if scenario == "printed_identity" {
				// The branded HTML identity is immutable (separate guard case).
				// Exercise permitted ordinary-PDF identity changes only after
				// real public intake, field and Send writers create its source.
				source, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, doc, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID)
				if err != nil || !doc.HtmlCurrentPageCount.Valid || doc.HtmlCurrentPageCount.Int32 < 1 {
					t.Fatal("genuine source for ordinary PDF intake unavailable")
				}
				ownedCreationPrepareProPlanV1(t, q)
				actor := sendengine.Actor{UserID: &q.f.user.ID, OrgID: q.f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
					if user == nil || user.ID != q.f.user.ID || user.OrgID != q.f.org || user.Role != "owner" {
						return auth.ErrMutationPermissionRevoked
					}
					return nil
				}}
				ordinary, party, _, _, invitation := ownedRealBrowserManualAutosaveV1(t, q, source, int(doc.HtmlCurrentPageCount.Int32), actor)
				doc = ordinary
				parties = []signerBrowserPartyE2E{{Token: strings.TrimPrefix(invitation.Path, "/sign/"), RecipientID: party.ID, Name: party.Name, Role: party.Role}}
			}
			peer := &ownedPDFStorageWire181V1{base: q.storagePeer, path: "/hash-import-fixture/" + doc.PdfStorageKey.String, version: doc.PdfStorageVersionID.String, mode: scenario, entered: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			server := httptest.NewServer(peer)
			t.Cleanup(server.Close)
			t.Cleanup(peer.unblockV1)
			client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-read", SecretKey: "synthetic-owned-read-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
			if err != nil {
				t.Fatal("construct genuine exact-version storage client")
			}
			q.f.s.Storage = client
			var deadline time.Time
			if scenario == "recipient_deadline_extension" || scenario == "document_deadline_extension" {
				deadline = time.Now().Add(1500 * time.Millisecond)
				query, id, scope := "UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1 AND document_id=$3", parties[0].RecipientID, doc.ID
				if scenario == "document_deadline_extension" {
					query, id, scope = "UPDATE documents SET expires_at=$2 WHERE id=$1 AND org_id=$3", doc.ID, q.f.org
				}
				if tag, err := q.f.pool.Exec(q.f.ctx, query, id, deadline, scope); err != nil || tag.RowsAffected() != 1 {
					t.Fatal("set genuine original deadline", err)
				} //nolint:rawsql -- real scoped original credential lifetime, not cached authority
			}
			ctx, cancel := context.WithTimeout(q.f.ctx, 8*time.Second)
			writer := &ownedPDFHTTPWriter181V1{ResponseRecorder: httptest.NewRecorder()}
			request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+parties[0].Token+"/pdf", nil).WithContext(ctx)
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				peer.unblockV1()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("original HTTP PDF handler did not join")
				}
			})
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(writer, request) }()
			select {
			case <-peer.entered:
			case <-ctx.Done():
				t.Fatal("actual exact source body did not reach its wire barrier")
			}
			pending := q.runtime.SessionsV1().PendingV1()
			if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.SignerReaders != 1 || pending.SignerScopes != 1 || writer.written.Load() != 0 {
				t.Fatal("storage wait lost native consumer, SQL retirement or response boundary")
			}
			var mutation pgconn.CommandTag
			switch scenario {
			case "rotated_token":
				_, hash, mintErr := auth.MintMagicToken()
				if mintErr != nil {
					t.Fatal("mint genuine rotated credential")
				}
				mutation, err = q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_hash=$2 WHERE id=$1 AND document_id=$3", parties[0].RecipientID, hash, doc.ID)
			case "recipient_deadline_extension":
				mutation, err = q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1 AND document_id=$3", parties[0].RecipientID, time.Now().Add(time.Hour), doc.ID)
			case "document_deadline_extension":
				mutation, err = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET expires_at=$2 WHERE id=$1 AND org_id=$3", doc.ID, time.Now().Add(time.Hour), q.f.org)
			case "printed_identity":
				mutation, err = q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET email=$2 WHERE id=$1 AND document_id=$3", parties[0].RecipientID, "changed@synthetic-read.test", doc.ID)
			case "printed_identity_guard":
				guardBefore := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
				_, guardErr := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET email=$2 WHERE id=$1 AND document_id=$3", parties[0].RecipientID, "changed@synthetic-read.test", doc.ID)
				var rejected *pgconn.PgError
				if !errors.As(guardErr, &rejected) || rejected.Code != "23514" {
					t.Fatal("branded printed-identity immutability guard did not reject the actual update")
				}
				if after := nativeCommentWholeState164V1(t, q, doc, q.f.pool); after != guardBefore {
					t.Fatal("rejected branded identity change left side effects")
				}
			case "document_name":
				mutation, err = q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name=$2 WHERE id=$1 AND org_id=$3", doc.ID, "Changed synthetic read name", q.f.org)
			} //nolint:rawsql -- independently committed scalar changes while actual source body is in flight
			if err != nil {
				t.Fatal("commit genuine late change", err)
			}
			if scenario != "unchanged_source" && scenario != "printed_identity_guard" && scenario != "truncated_body" && scenario != "altered_body" && mutation.RowsAffected() != 1 {
				t.Fatal("late scalar stimulus did not change exactly its intended row")
			}
			if !deadline.IsZero() {
				expired := false
				for !expired {
					if err := q.f.pool.QueryRow(ctx, "SELECT clock_timestamp()>$1::timestamptz", deadline).Scan(&expired); err != nil {
						t.Fatal("observe original actual database deadline", err)
					} //nolint:rawsql -- database clock witness, never a replacement caller deadline
					if !expired {
						select {
						case <-time.After(10 * time.Millisecond):
						case <-ctx.Done():
							t.Fatal("original deadline did not pass within request bound")
						}
					}
				}
			}
			before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			peer.unblockV1()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("original HTTP PDF handler did not finish after source release")
			}
			select {
			case <-peer.finished:
			case <-ctx.Done():
				t.Fatal("actual storage body handler did not join")
			}
			if peer.invalid.Load() || peer.calls.Load() != 1 {
				t.Fatal("wire fault was replaced, retried or escaped its fixed source/version bound")
			}
			if scenario == "unchanged_source" || scenario == "printed_identity_guard" {
				digest := sha256.Sum256(writer.Body.Bytes())
				if writer.Code != http.StatusOK || !bytes.Equal(digest[:], doc.PdfSha256) || writer.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(doc.PdfSha256) || writer.Header().Get("X-Hash-Document-Id") != doc.ID.String() || writer.Header().Get("X-Hash-Recipient-Id") != parties[0].RecipientID.String() || !strings.Contains(writer.Header().Get("Cache-Control"), "no-store") {
					t.Fatal("unchanged genuine wire control lost exact PDF or observation")
				}
			} else if scenario == "truncated_body" || scenario == "altered_body" {
				if writer.Code != http.StatusInternalServerError {
					t.Fatalf("actual invalid source body status=%d", writer.Code)
				}
			} else if writer.Code != http.StatusConflict && writer.Code != http.StatusGone {
				t.Fatalf("actual late-change refusal status=%d", writer.Code)
			}
			if scenario != "unchanged_source" && scenario != "printed_identity_guard" {
				for _, name := range []string{"X-Hash-Document-Id", "X-Hash-Recipient-Id", "X-Hash-PDF-SHA256", "X-Hash-PDF-Pages", "X-Hash-HTML-Source-Commitment", "X-Hash-Materialization-Revision"} {
					if writer.Header().Get(name) != "" {
						t.Fatal("refused PDF read published observation headers")
					}
				}
				if strings.HasPrefix(writer.Header().Get("Content-Type"), "application/pdf") || bytes.Contains(writer.Body.Bytes(), []byte("%PDF-")) {
					t.Fatal("refused PDF read published source bytes")
				}
			}
			if after := nativeCommentWholeState164V1(t, q, doc, q.f.pool); after != before {
				t.Fatal("refused read changed document, participant, field, audit, intent or notification state")
			}
			q.assertObserversOnlyV1(t)
			if !deadline.IsZero() {
				// A genuinely fresh admission may use the committed extended
				// deadline; only the original in-flight admission must expire.
				q.f.s.Storage = q.evidence.client
				fresh := q.requestV1(parties[0].Token, "/pdf")
				if fresh.Code != http.StatusOK || !bytes.HasPrefix(fresh.Body.Bytes(), []byte("%PDF-")) {
					t.Fatalf("fresh extended admission was not usable: status=%d", fresh.Code)
				}
				q.assertObserversOnlyV1(t)
				if after := nativeCommentWholeState164V1(t, q, doc, q.f.pool); after != before {
					t.Fatal("fresh GET committed side effects")
				}
			}
			cancel()
		})
	}
}
