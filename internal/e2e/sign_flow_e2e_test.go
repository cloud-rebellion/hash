// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/blocks"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipientauthoring"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

// TestSendSignStampE2E drives the real send -> sign -> finalize loop against a
// live Postgres + MinIO + Gotenberg and asserts a completed document with a
// stored, downloadable final PDF + audit certificate. It is the programmatic
// twin of the browser flow (Playwright UI smoke is a follow-up).
//
// Skips unless HASH_E2E_* env is set; the hash-ci `e2e` job provides the
// service containers.
func TestSendSignStampE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	s3ep := os.Getenv("HASH_E2E_S3_ENDPOINT")
	gote := os.Getenv("HASH_E2E_GOTENBERG_URL")
	if dsn == "" || s3ep == "" || gote == "" {
		t.Skip("set HASH_E2E_DB_URL, HASH_E2E_S3_ENDPOINT, HASH_E2E_GOTENBERG_URL to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)

	// Migrations (goose, via a stdlib *sql.DB like the server does).
	cfg, err := pgxpool.ParseConfig(dsn)
	must(t, err, "parse dsn")
	migConn := stdlib.OpenDB(*cfg.ConnConfig)
	must(t, mdb.RunMigrations(migConn), "run migrations")
	_ = migConn.Close()

	pool, err := pgxpool.New(ctx, dsn)
	must(t, err, "pool")
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	auditLog := audit.New(q, pool)

	store, err := storage.New(ctx, e2eStorageConfig(t, "hash-e2e"))
	must(t, err, "storage init")
	if worker := os.Getenv("HASH_E2E_PDF_WORKER_PATH"); worker != "" {
		must(t, sanitize.ConfigurePDFWorker(ctx, worker, "production"), "configure actual PDF worker")
		t.Cleanup(func() {
			if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
				t.Error("retire PDF worker configuration", err)
			}
		})
	}
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8, ProviderStreams: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4, ProviderStreams: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	must(t, err, "create same-pool signing runtime")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.SignerScopes != 0 || pending.SignerReaders != 0 || pending.DocumentPackageOperations != 0 || pending.ObserverSessions != observers {
			t.Errorf("sign flow retained non-observer work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("sign flow observer cleanup debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error("close actual sign flow runtime", err)
		}
		snapshot, snapshotErr := runtime.SnapshotV1(uuid.New())
		if snapshotErr != nil || snapshot.Global != (workguard.VectorV1{SQLSessions: int64(observers)}) || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("sign flow leaked work or lost observer debt: %+v error=%v", snapshot, snapshotErr)
		}
	})

	// Ephemeral ed25519 audit-cert signer (deterministic verification isn't
	// asserted here; we only need finalize to produce a signed cert).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must(t, err, "generate ed25519 key")
	signer, err := sign.NewCertSigner(base64.StdEncoding.EncodeToString(priv.Seed()))
	must(t, err, "cert signer")

	gotenberg := render.NewGotenberg(gote)

	sendEng := &send.Engine{
		Pool: pool, Queries: q, WorkRuntime: runtime, Storage: store, Audit: auditLog, Mailer: dispatch.QueueingMailer{Q: q},
		PublicURL: "http://localhost:8080", OrgName: "E2E",
	}
	signEng := &sign.Engine{
		Pool: pool, Queries: q, WorkRuntime: runtime, Storage: store, PDF: gotenberg, Audit: auditLog, Mailer: dispatch.QueueingMailer{Q: q},
		Signer: signer, OrgName: "E2E", BaseURL: "http://localhost:8080",
	}
	must(t, signEng.InitializeWorkRuntimeV1(), "bind signing request journal")
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := signEng.CloseWorkRuntimeRequestsV1(cleanup); err != nil {
			t.Error("close signing request journal", err)
		}
	})

	// Seed org + owner (the org bootstrap user; "owner" is the top RBAC role
	// and can send). Role must satisfy the users.role CHECK from migration
	// 00001: one of ('owner','sender','viewer'). "admin" is not valid.
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "E2E Org", Plan: "pro"})
	must(t, err, "create org")
	user, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org.ID, Email: uniqueEmail(), Name: "Sender", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	must(t, err, "create user")
	authorize := func(_ context.Context, _ pgx.Tx, member *generated.User) error {
		if member == nil || member.ID != user.ID || member.OrgID != org.ID || member.Role != "owner" {
			return auth.ErrMutationPermissionRevoked
		}
		return nil
	}

	// Block document with one signer signature field.
	tree := blocks.Tree{Version: 1, Blocks: []blocks.Block{
		{ID: "p1", Type: blocks.TypeParagraph, Text: "This NDA is between E2E Org and the counterparty."},
		{ID: "sig1", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	blocksJSON, err := json.Marshal(tree)
	must(t, err, "marshal block tree")
	created, err := blockauthoring.CreateV1(ctx,
		blockauthoring.DependenciesV1{Sessions: runtime.SessionsV1(), Audit: auditLog},
		blockauthoring.ActorV1{OrgID: org.ID, UserID: user.ID, Authorize: authorize, Via: "rest", Tool: "create_document"},
		blockauthoring.CreateInputV1{Name: "E2E NDA", BlocksJSON: blocksJSON, VariablesJSON: json.RawMessage("{}")})
	if created != nil {
		t.Cleanup(created.CloseConsumerV1)
	}
	must(t, err, "create genuinely measured document")
	if created == nil || created.Document == nil {
		t.Fatal("native document producer returned no document")
	}
	docID := created.Document.ID
	created.CloseConsumerV1()
	doc, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: docID, OrgID: org.ID})
	must(t, err, "load created document")
	recipients := &recipientauthoring.MutationEngine{Pool: pool, Audit: auditLog}
	createdRecipient, err := recipients.CreateOwnedV1(ctx, runtime.SessionsV1(), q,
		recipientauthoring.MutationActor{OrgID: org.ID, UserID: user.ID, Authorize: authorize, Via: "rest", Tool: "add_recipient"},
		doc.ID, recipientauthoring.Values{Role: "signer", Email: uniqueEmail(), Name: "Jane Signer", OrderIndex: 0, Locale: "sv"})
	if createdRecipient != nil {
		t.Cleanup(createdRecipient.CloseConsumerV1)
	}
	must(t, err, "create genuinely measured recipient")
	if createdRecipient == nil || createdRecipient.Recipient == nil {
		t.Fatal("native recipient producer returned no recipient")
	}
	recipientID := createdRecipient.Recipient.ID
	createdRecipient.CloseConsumerV1()

	// Send (draft -> sent).
	sendRes, err := sendEng.Send(ctx, send.Actor{
		UserID: &user.ID, OrgID: org.ID, Email: user.Email, Via: "worker", LawfulBasis: "contract", Authorize: authorize,
	}, doc.ID)
	t.Cleanup(sendRes.CloseConsumerV1)
	must(t, err, "send")
	if sendRes.Status != "sent" || len(sendRes.Links) != 1 || sendRes.Links[0].RecipientID != recipientID {
		t.Fatalf("send status/links = %q/%d, want sent with the actual recipient", sendRes.Status, len(sendRes.Links))
	}
	link := sendRes.Links[0].URL
	token := strings.Clone(link[strings.LastIndex(link, "/")+1:])
	sendRes.CloseConsumerV1()

	// Admit the actual sent ceremony credential, then sign and finalize through
	// the same native request lifetime as the public single-signer flow.
	rc, err := signEng.LookupByToken(ctx, auth.HashMagicToken(token))
	must(t, err, "lookup recipient context")
	t.Cleanup(func() { _ = rc.CloseReadV1() })
	signRes, err := signEng.Sign(ctx, rc, sign.SignInput{
		TypedName: "Jane Signer", Font: "Caveat", IP: "127.0.0.1", UserAgent: "e2e",
		Notice: testArticle13NoticeEvidence(t, rc),
	})
	must(t, err, "sign")
	must(t, rc.CloseReadV1(), "retire completed signing request")
	if !signRes.Completed {
		t.Fatalf("expected completed after the only signer signed; status=%q", signRes.Status)
	}
	if signRes.FinalPDFKey == "" {
		t.Fatal("expected a final PDF key")
	}

	// The stamped final PDF is stored and is a real PDF.
	pdfBytes, err := store.Get(ctx, signRes.FinalPDFKey)
	must(t, err, "fetch final pdf")
	if len(pdfBytes) < 1000 || !strings.HasPrefix(string(pdfBytes), "%PDF-") {
		t.Fatalf("final pdf looks wrong: %d bytes, prefix %q", len(pdfBytes), safePrefix(pdfBytes))
	}

	// Document is completed with both artefact keys persisted.
	got, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
	must(t, err, "reload document")
	if got.Status != "completed" {
		t.Fatalf("document status = %q, want completed", got.Status)
	}
	if !got.FinalPdfKey.Valid || !got.AuditCertKey.Valid {
		t.Fatalf("final/cert keys not persisted: final=%v cert=%v", got.FinalPdfKey.Valid, got.AuditCertKey.Valid)
	}
}

func must(t *testing.T, err error, what string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func uniqueEmail() string { return uuid.NewString() + "@e2e.example" }

func safePrefix(b []byte) string {
	if len(b) > 8 {
		b = b[:8]
	}
	return string(b)
}
