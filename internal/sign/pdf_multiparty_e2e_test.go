//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/render"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	pdftypes "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
)

// PostgreSQL and all lifecycle engines are real. Evidence storage is a strict
// exact-version synthetic adapter. HASH_E2E_GOTENBERG_URL optionally forwards
// rendering to a disposable real Chromium renderer; otherwise the HTTP
// renderer adapter returns valid PDF fixtures for the transaction tests.
func TestNamedPartyPDFSignsBothPartiesAndProducesBoundArtifactsE2E(t *testing.T) {
	for _, scenario := range []string{"sequential", "parallel", "render_failure_retry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMultipartyPDFE2E(t, false)
			first := f.context(t, 0)
			second := f.context(t, 1)
			if scenario == "parallel" {
				start := make(chan struct{})
				results := make(chan error, 2)
				for i, rc := range []*RecipientContext{first, second} {
					input := f.input(t, rc, i)
					go func() { <-start; _, err := f.engine.Sign(f.ctx, rc, input); results <- err }()
				}
				close(start)
				for i := 0; i < 2; i++ {
					if err := <-results; err != nil {
						t.Fatal(err)
					}
				}
			} else {
				result, err := f.engine.Sign(f.ctx, first, f.input(t, first, 0))
				if err != nil || result.Completed || result.Status != "in_progress" {
					t.Fatalf("first party result=%+v error=%v", result, err)
				}
				if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
					t.Fatal(err)
				}
				f.assertIncomplete(t, 1)
				if _, err := f.engine.Sign(f.ctx, first, f.input(t, first, 0)); !errors.Is(err, ErrAlreadySigned) {
					t.Fatalf("duplicate first signature error=%v", err)
				}
				if scenario == "render_failure_retry" {
					f.rendererFail.Store(true)
				}
				result, err = f.engine.Sign(f.ctx, second, f.input(t, second, 1))
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "render_failure_retry" {
					if result.Completed {
						t.Fatal("renderer failure completed a PDF")
					}
					f.assertIncomplete(t, 2)
					f.rendererFail.Store(false)
					if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
						t.Fatal(err)
					}
				} else if !result.Completed {
					t.Fatalf("both signatures did not complete: %+v", result)
				}
			}
			f.assertCompleted(t, scenario)
			// Concurrent recovery on an already completed document is a no-op:
			// exact historical artifacts, links, audit and mail remain unchanged.
			before := f.snapshot(t)
			var retries sync.WaitGroup
			for i := 0; i < 3; i++ {
				retries.Add(1)
				go func() {
					defer retries.Done()
					if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); err != nil {
						t.Error(err)
					}
				}()
			}
			retries.Wait()
			if before != f.snapshot(t) {
				t.Fatal("historical completion retry changed evidence, credentials, events or outbox")
			}
		})
	}
}

func TestLegacySingleSignerFillablePDFStillSignsAndCompletesE2E(t *testing.T) {
	f := newMultipartyPDFE2E(t, true)
	rc := f.context(t, 0)
	result, err := f.engine.Sign(f.ctx, rc, f.input(t, rc, 0))
	if err != nil || !result.Completed {
		t.Fatalf("legacy result=%+v error=%v", result, err)
	}
	f.assertCompleted(t, "legacy")
}

func TestNamedPartyPDFNonA4AndRotatedGeometryE2E(t *testing.T) {
	for _, page := range []struct {
		paper    string
		rotation int
	}{{"A5", 0}, {"Letter", 0}, {"A4", 90}, {"A4", 180}, {"A4", 270}} {
		label := fmt.Sprintf("%s-rotation-%d", page.paper, page.rotation)
		t.Run(label, func(t *testing.T) {
			source := multipartySourcePDF(t, page.paper, page.rotation)
			f := newMultipartyPDFE2E(t, false, source)
			for i := 0; i < 2; i++ {
				rc := f.context(t, i)
				if _, err := f.engine.Sign(f.ctx, rc, f.input(t, rc, i)); err != nil {
					t.Fatal(err)
				}
			}
			f.assertCompleted(t, label)
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
			if err != nil {
				t.Fatal(err)
			}
			final, err := f.store.GetVerifiedVersion(f.ctx, doc.FinalPdfKey.String, doc.FinalPdfVersionID.String, doc.FinalPdfSha)
			if err != nil {
				t.Fatal(err)
			}
			conf := pdfmodel.NewDefaultConfiguration()
			conf.ValidationMode = pdfmodel.ValidationRelaxed
			before, err := pdfapi.PageDims(bytes.NewReader(source), conf)
			if err != nil {
				t.Fatal(err)
			}
			expected, _, err := pdftypes.ParsePageFormat(page.paper)
			if err != nil {
				t.Fatal(err)
			}
			if page.rotation%180 != 0 {
				expected.Width, expected.Height = expected.Height, expected.Width
			}
			if len(before) != 1 || before[0] != *expected {
				t.Fatalf("source fixture has wrong requested geometry: want=%v got=%v", expected, before)
			}
			after, err := pdfapi.PageDims(bytes.NewReader(final), conf)
			if err != nil || len(after) != 1 || before[0] != after[0] {
				t.Fatalf("PDF page geometry changed: before=%v after=%v error=%v", before, after, err)
			}
		})
	}
}

func multipartySourcePDF(t *testing.T, paper string, rotation int) []byte {
	t.Helper()
	pdfapi.DisableConfigDir()
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	position := 720
	if paper == "A5" {
		position = 520
	}
	if rotation != 0 {
		// Keep source text outside the designed signature ink, even when the
		// original content is rotated by the viewer.
		position = 420
	}
	spec := fmt.Sprintf(`{"pages":{"1":{"paper":%q,"content":{"text":[{"value":"Synthetic approved B2B contract: unchanged terms","pos":[30,%d],"font":{"name":"Helvetica","size":12}}]}}}}`, paper, position)
	var body bytes.Buffer
	if err := pdfapi.Create(nil, strings.NewReader(spec), &body, conf); err != nil {
		t.Fatal(err)
	}
	if rotation == 0 {
		return body.Bytes()
	}
	var rotated bytes.Buffer
	if err := pdfapi.Rotate(bytes.NewReader(body.Bytes()), &rotated, rotation, nil, conf); err != nil {
		t.Fatal(err)
	}
	return rotated.Bytes()
}

func TestNamedPartyPDFResumeRejectsMissingOrMisboundCapturedSignatureE2E(t *testing.T) {
	for _, scenario := range []string{"missing", "other_party_field"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMultipartyPDFE2E(t, false)
			first, second := f.context(t, 0), f.context(t, 1)
			if _, err := f.engine.Sign(f.ctx, first, f.input(t, first, 0)); err != nil {
				t.Fatal(err)
			}
			f.store.failFinalRetention.Store(true)
			result, err := f.engine.Sign(f.ctx, second, f.input(t, second, 1))
			if err != nil || result.Completed {
				t.Fatalf("staged retry result=%+v error=%v", result, err)
			}
			if _, err := f.q.GetDocumentFinalizationIntent(f.ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: f.docID, OrgID: f.orgID}); err != nil {
				t.Fatalf("fixture did not reach persisted finalization intent: %v", err)
			}
			signatures, err := f.q.ListSignaturesByDocument(f.ctx, f.docID)
			if err != nil || len(signatures) != 2 {
				t.Fatal("fixture has no complete signature evidence")
			}
			if scenario == "missing" {
				_, err = f.pool.Exec(f.ctx, `DELETE FROM signatures WHERE id=$1`, signatures[1].ID) //nolint:rawsql -- corrupt only the synthetic retry fixture
			} else {
				_, err = f.pool.Exec(f.ctx, `UPDATE signatures SET field_id=$2 WHERE id=$1`, signatures[1].ID, signatures[0].FieldID) //nolint:rawsql -- corrupt only the synthetic retry fixture
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t)
			f.store.failFinalRetention.Store(false)
			if err := f.engine.FinalizeStranded(f.ctx, f.orgID, f.docID); !errors.Is(err, ErrDocumentNotReadyToFinalize) {
				t.Fatalf("corrupted retry error=%v", err)
			}
			if before != f.snapshot(t) {
				t.Fatal("corrupted retry published completion, credentials, audit or mail")
			}
		})
	}
}

func TestNamedPartyPDFSignatureRechecksOriginalTokenAndDeadlineAfterWaitsE2E(t *testing.T) {
	for _, scenario := range []string{"rotated_document_wait", "admitted_recipient_deadline_extended", "admitted_document_deadline_extended", "recipient_deadline_audit_wait", "document_deadline_audit_wait"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMultipartyPDFE2E(t, false)
			base := time.Now().UTC()
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			f.engine.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			if scenario == "recipient_deadline_audit_wait" || scenario == "admitted_recipient_deadline_extended" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE magic_token_hash=$1`, auth.HashMagicToken(f.tokens[0]), base.Add(time.Second)); err != nil { //nolint:rawsql
					t.Fatal(err)
				}
			} else if scenario == "document_deadline_audit_wait" || scenario == "admitted_document_deadline_extended" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.docID, base.Add(time.Second)); err != nil { //nolint:rawsql
					t.Fatal(err)
				}
			}
			rc := f.context(t, 0)
			input := f.input(t, rc, 0)
			held, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = held.Rollback(context.Background()) }()
			query, event := "-- name: AcquireOrgChainLock", "advisory"
			if scenario == "rotated_document_wait" || strings.HasPrefix(scenario, "admitted_") {
				if _, err := f.q.WithTx(held).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.docID, OrgID: f.orgID}); err != nil {
					t.Fatal(err)
				}
				query, event = "-- name: GetDocumentForUpdate", "transactionid"
			} else if err := f.q.WithTx(held).AcquireOrgChainLock(f.ctx, f.orgID.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { _, err := f.engine.Sign(f.ctx, rc, input); result <- err }()
			var holderPID int32
			if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
			waitUntil := time.Now().Add(3 * time.Second)
			waiting := false
			for time.Now().Before(waitUntil) {
				select {
				case err := <-result:
					t.Fatalf("signature returned before its authoritative wait: %v", err)
				default:
				}
				if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE datname=current_database()
					AND position($1 in query)>0 AND wait_event=$2 AND $3=ANY(pg_blocking_pids(a.pid)))`, query, event, holderPID).Scan(&waiting); err != nil { //nolint:rawsql
					t.Fatal(err)
				}
				if waiting {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waiting {
				t.Fatal("signature did not reach its own held lock")
			}
			if scenario == "rotated_document_wait" {
				if err := f.q.WithTx(held).RotateRecipientMagicToken(f.ctx, generated.RotateRecipientMagicTokenParams{ID: rc.Recipient.ID, DocumentID: f.docID, MagicTokenHash: auth.HashMagicToken(uuid.NewString()),
					MagicTokenExpiresAt: pgtype.Timestamptz{Time: base.Add(time.Hour), Valid: true}}); err != nil {
					t.Fatal(err)
				}
			} else {
				if scenario == "admitted_recipient_deadline_extended" {
					if _, err := held.Exec(f.ctx, `UPDATE recipients SET magic_token_expires_at=$2 WHERE id=$1`, rc.Recipient.ID, base.Add(time.Hour)); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
				} else if scenario == "admitted_document_deadline_extended" {
					if _, err := held.Exec(f.ctx, `UPDATE documents SET expires_at=$2 WHERE id=$1`, f.docID, base.Add(time.Hour)); err != nil { //nolint:rawsql
						t.Fatal(err)
					}
				}
				clock.Store(base.Add(2 * time.Second).UnixNano())
			}
			// Capture the holder's own authorized credential/deadline changes
			// before releasing the document: an incorrectly accepted request
			// must not be able to race into the baseline snapshot.
			before := negotiationCredentialSnapshot(t, f.ctx, held, f)
			if err := held.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, ErrMagicLinkExpired) {
				t.Fatalf("expired/rotated signature error=%v", err)
			}
			if before != negotiationCredentialSnapshot(t, f.ctx, f.pool, f) {
				t.Fatal("stale signature committed fields, signatures, status, events or mail")
			}
			if strings.HasPrefix(scenario, "admitted_") {
				fresh := f.context(t, 0)
				if result, err := f.engine.Sign(f.ctx, fresh, f.input(t, fresh, 0)); err != nil || result.Completed {
					t.Fatalf("newly admitted extended credential result=%+v error=%v", result, err)
				}
				f.assertIncomplete(t, 1)
			}
		})
	}
}

type multipartyPDFFixture struct {
	ctx              context.Context
	pool             *pgxpool.Pool
	q                *generated.Queries
	engine           *Engine
	orgID, docID     uuid.UUID
	sourceKey        string
	source           storage.StoredObject
	names            []string
	tokens           []string
	store            *multipartyVersionStore
	rendererFail     atomic.Bool
	rendererRequests atomic.Int64
	htmlMu           sync.Mutex
	html             []string
}

func newMultipartyPDFE2E(t *testing.T, legacy bool, sourceBodies ...[]byte) *multipartyPDFFixture {
	return newMultipartyPDFE2EWithDraft(t, legacy, nil, sourceBodies...)
}

func newMultipartyPDFE2EWithDraft(t *testing.T, legacy bool, prepare func(*multipartyPDFFixture, *generated.Document) *generated.Document, sourceBodies ...[]byte) *multipartyPDFFixture {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["application_name"] = "hash-pdf-lifecycle-" + uuid.NewString()
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatal(err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Synthetic PDF controller " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@pdf-owner.test", Name: "PDF owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	store := &multipartyVersionStore{objects: make(map[string]multipartyVersionObject)}
	body := multipartySourcePDF(t, "A4", 0)
	if len(sourceBodies) > 0 {
		body = sourceBodies[0]
	}
	key := "org/" + org.ID.String() + "/source.pdf"
	ref, err := store.PutEvidenceVersioned(ctx, key, "application/pdf", body, time.Now().UTC().AddDate(7, 0, 0))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "PDF two party " + uuid.NewString(), PdfStorageKey: pgtype.Text{String: key, Valid: true},
		PdfSha256: ref.SHA256[:], PdfStorageVersionID: pgtype.Text{String: ref.VersionID, Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	f := &multipartyPDFFixture{ctx: ctx, pool: pool, q: q, orgID: org.ID, docID: doc.ID, names: []string{"Customer Test Person", "Provider Test Person"}, store: store, sourceKey: key, source: ref}
	roles := []string{"customer", "provider"}
	if legacy {
		roles = []string{"signer"}
		f.names = f.names[:1]
	}
	num := func(value int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(value), Valid: true} }
	for i, role := range roles {
		_, hash, err := auth.MintMagicToken()
		if err != nil {
			t.Fatal(err)
		}
		row, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: role, Name: f.names[i], Email: uuid.NewString() + "@pdf-recipient.test", Locale: "en", OrderIndex: int32(i), MagicTokenHash: hash,
			MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: org.ID, RecipientID: pgtype.UUID{Bytes: row.ID, Valid: true}, Type: "signature", Page: 1,
			XPct: num(10), YPct: num(55 + int64(i)*15), WPct: num(60), HPct: num(10), Required: true, Label: pgtype.Text{String: role + " signature", Valid: true}, OptionsJson: []byte(`{}`)}); err != nil {
			t.Fatal(err)
		}
		if legacy {
			field, err := q.CreateDraftField(ctx, generated.CreateDraftFieldParams{DocumentID: doc.ID, OrgID: org.ID, RecipientID: pgtype.UUID{Bytes: row.ID, Valid: true}, Type: "text", Page: 1,
				XPct: num(10), YPct: num(35), WPct: num(40), HPct: num(5), Required: true, Label: pgtype.Text{String: "Reference", Valid: true}, OptionsJson: []byte(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `UPDATE document_fields SET value='Reviewed reference',completed_at=clock_timestamp() WHERE id=$1`, field.ID); err != nil { //nolint:rawsql
				t.Fatal(err)
			}
		}
	}
	if prepare != nil {
		doc = prepare(f, doc)
	}
	logger := audit.New(q, pool)
	sender := &sendengine.Engine{Pool: pool, Queries: q, Storage: store, Audit: logger, Mailer: dispatch.QueueingMailer{Q: q}, PublicURL: "https://hash.example.test", OrgName: org.Name}
	result, err := sender.Send(ctx, sendengine.Actor{UserID: &user.ID, OrgID: org.ID, Via: "rest", LawfulBasis: "contract", Authorize: func(context.Context, pgx.Tx, *generated.User) error { return nil }}, doc.ID)
	if err != nil || result.Status != "sent" || len(result.Links) != len(roles) {
		t.Fatalf("send result=%+v error=%v", result, err)
	}
	for _, link := range result.Links {
		f.tokens = append(f.tokens, link.URL[strings.LastIndex(link.URL, "/")+1:])
	}
	fixturePDF := onePagePDF(t, "Synthetic renderer fixture")
	target := strings.TrimRight(os.Getenv("HASH_E2E_GOTENBERG_URL"), "/")
	renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.rendererRequests.Add(1)
		if f.rendererFail.Load() {
			http.Error(w, "synthetic renderer outage", http.StatusServiceUnavailable)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			http.Error(w, "fixture read failed", 500)
			return
		}
		_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		parts := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			part, err := parts.NextPart()
			if err != nil {
				break
			}
			if part.FileName() == "index.html" {
				content, _ := io.ReadAll(part)
				f.htmlMu.Lock()
				f.html = append(f.html, string(content))
				f.htmlMu.Unlock()
			}
		}
		if target == "" {
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write(fixturePDF)
			return
		}
		request, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target+r.URL.Path, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "fixture proxy failed", 500)
			return
		}
		request.Header.Set("Content-Type", r.Header.Get("Content-Type"))
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			http.Error(w, "fixture renderer failed", 500)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(renderer.Close)
	signer, err := GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	f.engine = &Engine{Pool: pool, Queries: q, Storage: store, PDF: render.NewGotenberg(renderer.URL), Audit: logger, Mailer: dispatch.QueueingMailer{Q: q}, Signer: signer, BaseURL: "https://hash.example.test", OrgName: "Synthetic operator"}
	return f
}

func (f *multipartyPDFFixture) context(t *testing.T, index int) *RecipientContext {
	t.Helper()
	rc, err := f.engine.LookupByToken(f.ctx, auth.HashMagicToken(f.tokens[index]))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rc.CloseReadV1() })
	return rc
}

func (f *multipartyPDFFixture) input(t *testing.T, rc *RecipientContext, index int) SignInput {
	return SignInput{Font: "Caveat", TypedName: f.names[index], Notice: testArticle13NoticeEvidence(t, rc), IP: "127.0.0.1", UserAgent: "Synthetic lifecycle fixture"}
}

func (f *multipartyPDFFixture) assertIncomplete(t *testing.T, expectedSignatures int) {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
	if err != nil || doc.FinalPdfKey.Valid || doc.Status == "completed" {
		t.Fatalf("premature completion doc=%+v error=%v", doc, err)
	}
	rows, err := f.q.ListSignaturesByDocument(f.ctx, f.docID)
	if err != nil || len(rows) != expectedSignatures {
		t.Fatalf("captured signatures=%d error=%v", len(rows), err)
	}
}

func (f *multipartyPDFFixture) assertCompleted(t *testing.T, label string) {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.docID, OrgID: f.orgID})
	if err != nil || doc.Status != "completed" || !doc.FinalPdfKey.Valid || !doc.AuditCertKey.Valid || !doc.FinalPdfVersionID.Valid || !doc.AuditCertVersionID.Valid {
		t.Fatalf("completion=%+v error=%v", doc, err)
	}
	if doc.PdfStorageKey.String != f.sourceKey || doc.PdfStorageVersionID.String != f.source.VersionID || !bytes.Equal(doc.PdfSha256, f.source.SHA256[:]) {
		t.Fatal("signing changed the retained original PDF commitment")
	}
	final, err := f.store.GetVerifiedVersion(f.ctx, doc.FinalPdfKey.String, doc.FinalPdfVersionID.String, doc.FinalPdfSha)
	if err != nil || pageCount(t, final) != 1 {
		t.Fatalf("final PDF page/digest error=%v", err)
	}
	cert, err := f.store.GetVerifiedVersion(f.ctx, doc.AuditCertKey.String, doc.AuditCertVersionID.String, doc.AuditCertSha256)
	if err != nil || pageCount(t, cert) < 1 {
		t.Fatalf("certificate PDF error=%v", err)
	}
	payload, err := f.store.GetVerifiedVersion(f.ctx, doc.AuditPayloadKey.String, doc.AuditPayloadVersionID.String, doc.AuditPayloadSha256)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := f.store.GetVerifiedVersion(f.ctx, doc.AuditSignatureKey.String, doc.AuditSignatureVersionID.String, doc.AuditSignatureSha256)
	if err != nil || !Verify(f.engine.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatalf("detached certificate verification error=%v", err)
	}
	// Bind the positive real transaction to the signed certificate claims and
	// verify the full synthetic organization's contiguous audit ledger.
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.orgID, PageLimit: 1000})
	if err != nil || len(events) < 2 || len(events) >= 1000 || events[len(events)-1].Kind != audit.KindDocumentCompleted {
		t.Fatalf("completion audit ledger error=%v rows=%d", err, len(events))
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	if result := verifier.Result(); !result.OK || !result.Complete {
		t.Fatalf("completion audit chain verification: %+v", result)
	}
	head := events[len(events)-2]
	claims, err := newCertificateEvidenceClaims(doc, doc.FinalPdfSha, &generated.LatestEventChainHeadForOrgRow{RowHash: head.RowHash, CreatedAt: head.CreatedAt}, events[:len(events)-1])
	if err != nil || !strings.Contains(string(payload), claims.HTML()) {
		t.Fatalf("signed certificate does not bind the exact final artifact and pre-completion audit ledger: %v", err)
	}
	f.htmlMu.Lock()
	rendered := strings.Join(f.html, "\n")
	f.htmlMu.Unlock()
	for _, name := range f.names {
		if !strings.Contains(rendered, name) {
			t.Fatalf("final rendering omitted signing party %q", name)
		}
	}
	var signed, completed, mail int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.signed'),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind='document.completed'),
		(SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1) OR to_email=(SELECT email FROM users WHERE id=(SELECT sender_id FROM documents WHERE id=$1)))`, f.docID).Scan(&signed, &completed, &mail); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if signed != len(f.names) || completed != 1 || mail != len(f.names)*2+1 {
		t.Fatalf("signed/completed/mail=%d/%d/%d", signed, completed, mail)
	}
	for _, token := range f.tokens {
		if unexpected, err := f.engine.LookupByToken(f.ctx, auth.HashMagicToken(token)); err == nil {
			_ = unexpected.CloseReadV1()
			t.Fatal("completed PDF retained an admitted ceremony credential")
		}
	}
	if directory := os.Getenv("HASH_E2E_ARTIFACT_DIR"); directory != "" {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
		fields, err := f.q.ListFieldsByDocument(f.ctx, f.docID)
		if err != nil {
			t.Fatal(err)
		}
		recipients, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
		if err != nil {
			t.Fatal(err)
		}
		roles := map[uuid.UUID]*generated.Recipient{}
		for _, row := range recipients {
			roles[row.ID] = row
		}
		var placements []map[string]any
		for _, field := range fields {
			owner := roles[uuid.UUID(field.RecipientID.Bytes)]
			placements = append(placements, map[string]any{"id": field.ID, "recipient_id": owner.ID, "role": owner.Role, "name": owner.Name, "type": field.Type,
				"page": field.Page, "x_pct": numericPct(field.XPct), "y_pct": numericPct(field.YPct), "w_pct": numericPct(field.WPct), "h_pct": numericPct(field.HPct)})
		}
		receipt, err := json.MarshalIndent(map[string]any{"document_id": f.docID, "organization_id": f.orgID, "source": map[string]any{"key": f.sourceKey, "version_id": f.source.VersionID, "sha256": fmt.Sprintf("%x", f.source.SHA256)},
			"final_sha256": fmt.Sprintf("%x", doc.FinalPdfSha), "certificate_sha256": fmt.Sprintf("%x", doc.AuditCertSha256), "public_key": f.engine.Signer.PublicKeyBase64(), "placements": placements}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, label+"-receipt.json"), receipt, 0600); err != nil {
			t.Fatal(err)
		}
		for name, body := range map[string][]byte{label + "-final.pdf": final, label + "-audit.pdf": cert, label + "-payload.txt": payload, label + "-signature.txt": signature} {
			if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func (f *multipartyPDFFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),
		'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE document_id=$1),
		'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE document_id=$1),
		'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE document_id=$1),
		'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1)))::text`, f.docID).Scan(&state); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	return state
}

type multipartyVersionObject struct {
	body    []byte
	version string
	digest  [32]byte
}

type multipartyVersionStore struct {
	mu                 sync.Mutex
	objects            map[string]multipartyVersionObject
	failFinalRetention atomic.Bool
}

func (s *multipartyVersionStore) GetVerifiedVersion(_ context.Context, key, version string, expected []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, exists := s.objects[key+"|"+version]
	if !exists || !bytes.Equal(row.digest[:], expected) {
		return nil, errors.New("synthetic exact-version commitment mismatch")
	}
	return append([]byte(nil), row.body...), nil
}

func (*multipartyVersionStore) ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error) {
	return nil, storage.StoredObject{}, errors.New("this fixture requires exact version pins")
}

func (s *multipartyVersionStore) PutEvidenceVersioned(_ context.Context, key, _ string, body []byte, until time.Time) (storage.StoredObject, error) {
	if !until.After(time.Now()) {
		return storage.StoredObject{}, errors.New("synthetic retention deadline invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	row := multipartyVersionObject{body: append([]byte(nil), body...), version: uuid.NewString(), digest: sha256.Sum256(body)}
	s.objects[key+"|"+row.version] = row
	return storage.StoredObject{SHA256: row.digest, VersionID: row.version}, nil
}

func (s *multipartyVersionStore) RetainEvidenceVersion(ctx context.Context, key, version string, expected []byte, until time.Time) error {
	if s.failFinalRetention.Load() && strings.Contains(key, "/final-") {
		return errors.New("synthetic final retention outage")
	}
	if !until.After(time.Now()) {
		return errors.New("synthetic retention deadline invalid")
	}
	_, err := s.GetVerifiedVersion(ctx, key, version, expected)
	return err
}
