//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// These fixtures use synthetic rows, actual PostgreSQL locks and signed
// sessions. The caller below stages a name change and real hash-chain event;
// no email worker, storage or integration is involved.
func TestDraftAdmissionRequiresOriginalAuthorityE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	before := f.snapshot(t, f.pool)
	for _, surface := range []string{"rest", "mcp", "automation", "worker", "internal"} {
		t.Run(surface, func(t *testing.T) {
			actor := f.actor(t)
			actor.Authorize = nil
			if err := f.mutate(f.ctx, actor); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Fatalf("missing original authority: %v", err)
			}
		})
	}
	for _, missing := range []string{"user", "organization"} {
		actor := f.actor(t)
		if missing == "user" {
			actor.UserID = uuid.Nil
		} else {
			actor.OrgID = uuid.Nil
		}
		if err := f.mutate(f.ctx, actor); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
	for _, guard := range []*DraftGuard{nil, {}} {
		if guard.UserID() != uuid.Nil || !errors.Is(guard.Recheck(f.ctx), auth.ErrMutationPermissionRevoked) {
			t.Fatal("empty guard grants authority")
		}
	}
	f.assertUnchanged(t, before)
}

func TestDraftAdmissionFinalGuardAndAuditFailureRollBackExactStateE2E(t *testing.T) {
	for _, failure := range []string{"final_guard", "audit"} {
		t.Run(failure, func(t *testing.T) {
			f := setupDraftAdmissionE2E(t)
			before := f.snapshot(t, f.pool)
			actor := f.actor(t)
			checks := 0
			original := actor.Authorize
			actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
				if err := original(ctx, tx, user); err != nil {
					return err
				}
				checks++
				if checks == 2 {
					var name string
					var events int
					if err := tx.QueryRow(ctx, `SELECT name,(SELECT count(*) FROM events WHERE org_id=$2) FROM documents WHERE id=$1`, f.doc.ID, f.orgID).Scan(&name, &events); err != nil {
						return err
					}
					if name != "Authorized draft change" || events != 1 {
						t.Errorf("final guard missed staged mutation/audit: name=%q events=%d", name, events)
					}
					return auth.ErrMutationCredentialExpired
				}
				return nil
			}
			want := auth.ErrMutationCredentialExpired
			if failure == "audit" {
				f.failAudit = true
				want = errDraftFixtureAudit
			}
			if err := f.mutate(f.ctx, actor); !errors.Is(err, want) {
				t.Fatalf("failure=%s returned %v", failure, err)
			}
			wantChecks := 2
			if failure == "audit" {
				wantChecks = 1
			}
			if checks != wantChecks {
				t.Fatalf("checks=%d, want %d", checks, wantChecks)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDraftAdmissionSeesLiveMemberAfterParentWaitE2E(t *testing.T) {
	for _, revocation := range []string{"demotion", "logout", "foreign_member"} {
		t.Run(revocation, func(t *testing.T) {
			f := setupDraftAdmissionE2E(t)
			actor := f.actor(t)
			if revocation == "foreign_member" {
				foreign := setupDraftAdmissionE2E(t)
				actor.UserID = foreign.user.ID
			}
			holder, pid := f.holdParent(t)
			done := make(chan error, 1)
			go func() { done <- f.mutate(f.ctx, actor) }()
			f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
			if revocation == "demotion" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID); err != nil {
					t.Fatal(err)
				}
			} else if revocation == "logout" {
				if _, err := f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, f.user.ID); err != nil {
					t.Fatal(err)
				}
			}
			before := f.snapshot(t, holder)
			if err := holder.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if err := receiveDraftAdmission(t, done); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Fatalf("live member %s returned %v", revocation, err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDraftAdmissionNaturalExpiryAfterParentWaitE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	holder, pid := f.holdParent(t)
	actor, cookie := f.actorWithTTL(t, time.Second)
	done := make(chan error, 1)
	go func() { done <- f.mutate(f.ctx, actor) }()
	f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
	f.awaitCookieExpiry(t, cookie)
	before := f.snapshot(t, holder)
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := receiveDraftAdmission(t, done); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("expired admitted session returned %v", err)
	}
	f.assertUnchanged(t, before)
}

func TestDraftAdmissionNaturalExpiryAfterAuditWaitE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	holder, pid := f.holdAudit(t)
	actor, cookie := f.actorWithTTL(t, time.Second)
	done := make(chan error, 1)
	go func() { done <- f.mutate(f.ctx, actor) }()
	f.awaitBlocked(t, pid, "-- name: AcquireOrgChainLock")
	f.awaitCookieExpiry(t, cookie)
	before := f.snapshot(t, holder)
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := receiveDraftAdmission(t, done); !errors.Is(err, auth.ErrMutationCredentialExpired) {
		t.Fatalf("expiry after staged write/audit wait returned %v", err)
	}
	f.assertUnchanged(t, before)
}

func TestDraftAdmissionParentScopeAndDeletionE2E(t *testing.T) {
	for _, state := range []string{"missing", "foreign", "voided", "deleted", "deleted_during_wait"} {
		t.Run(state, func(t *testing.T) {
			f := setupDraftAdmissionE2E(t)
			actor := f.actor(t)
			want := ErrDocumentNotFound
			switch state {
			case "missing":
				f.doc.ID = uuid.New()
			case "foreign":
				actor.OrgID = uuid.New()
			case "voided":
				seedCompleteFrozenBrandingE2E(t, f.ctx, f.pool, f.doc.ID)
				if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, f.doc.ID); err != nil {
					t.Fatal(err)
				}
				want = ErrDocumentNotDraft
			case "deleted":
				if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
					t.Fatal(err)
				}
			case "deleted_during_wait":
				holder, pid := f.holdParent(t)
				done := make(chan error, 1)
				go func() { done <- f.mutate(f.ctx, actor) }()
				f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
				if err := f.q.WithTx(holder).DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
					t.Fatal(err)
				}
				before := f.snapshot(t, holder)
				if err := holder.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if err := receiveDraftAdmission(t, done); !errors.Is(err, want) {
					t.Fatalf("deleted parent wait returned %v", err)
				}
				f.assertUnchanged(t, before)
				return
			}
			before := f.snapshot(t, f.pool)
			if err := f.mutate(f.ctx, actor); !errors.Is(err, want) {
				t.Fatalf("parent %s returned %v", state, err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDraftAdmissionPreservesCapturedEvidenceE2E(t *testing.T) {
	for _, evidence := range []string{"signature", "accepted", "empty_value", "completed_field"} {
		t.Run(evidence, func(t *testing.T) {
			f := setupDraftAdmissionE2E(t)
			switch evidence {
			case "signature":
				if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET type='signature' WHERE id=$1`, f.fieldID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: f.fieldID, Font: "synthetic", TypedName: "Synthetic captured response", ImageStorageKey: f.orgID.String() + "/fixture/signature.png", ImageSha256: make([]byte, 32), ImageVersionID: pgtype.Text{String: "synthetic-pin", Valid: true}}); err != nil {
					t.Fatal(err)
				}
			case "accepted":
				if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET status='accepted' WHERE id=$1`, f.recipient.ID); err != nil {
					t.Fatal(err)
				}
			case "empty_value":
				if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='' WHERE id=$1`, f.fieldID); err != nil {
					t.Fatal(err)
				}
			case "completed_field":
				if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET completed_at=clock_timestamp() WHERE id=$1`, f.fieldID); err != nil {
					t.Fatal(err)
				}
			}
			before := f.snapshot(t, f.pool)
			if err := f.mutate(f.ctx, f.actor(t)); !errors.Is(err, ErrDocumentHasEvidence) {
				t.Fatalf("retained %s returned %v", evidence, err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDraftAdmissionPrivacyScopeAndStatusE2E(t *testing.T) {
	for _, scope := range []string{"linked", "global", "unrelated_document", "foreign_tenant"} {
		for _, status := range []string{"open", "in_progress", "denied", "fulfilled", "withdrawn"} {
			t.Run(scope+"/"+status, func(t *testing.T) {
				f := setupDraftAdmissionE2E(t)
				subject := f
				if scope == "foreign_tenant" {
					subject = setupDraftAdmissionE2E(t)
				}
				docID := uuid.Nil
				if scope == "linked" {
					docID = f.doc.ID
				} else if scope == "unrelated_document" {
					other, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.orgID, SenderID: f.user.ID, Name: "Unrelated draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
					if err != nil {
						t.Fatal(err)
					}
					docID = other.ID
				}
				subject.privacyRequest(t, subject.q, docID, status)
				before := f.snapshot(t, f.pool)
				err := f.mutate(f.ctx, f.actor(t))
				pending := (scope == "linked" || scope == "global") && (status == "open" || status == "in_progress")
				if pending {
					if !errors.Is(err, ErrPendingPrivacyReview) {
						t.Fatalf("pending privacy returned %v", err)
					}
					f.assertUnchanged(t, before)
				} else if err != nil || f.published != 1 {
					t.Fatalf("unrelated/closed review returned %v; publications=%d", err, f.published)
				}
			})
		}
	}
}

func TestDraftAdmissionSeesLinkedReviewCommittedDuringParentWaitE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	holder, pid := f.holdParent(t)
	actor := f.actor(t)
	done := make(chan error, 1)
	go func() { done <- f.mutate(f.ctx, actor) }()
	f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
	f.privacyRequest(t, f.q.WithTx(holder), f.doc.ID, "in_progress")
	before := f.snapshot(t, holder)
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := receiveDraftAdmission(t, done); !errors.Is(err, ErrPendingPrivacyReview) {
		t.Fatalf("fresh linked privacy returned %v", err)
	}
	f.assertUnchanged(t, before)
}

func TestDraftAdmissionPrivacyFenceRefusesImmediatelyAndRetriesFreshE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	holder, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Rollback(context.Background(), holder) })
	if _, err := holder.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hash_collab_archive_dsr_lock_key($1::uuid))`, f.orgID); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t, holder)
	ctx, cancel := context.WithTimeout(f.ctx, time.Second)
	started := time.Now()
	err = f.mutate(ctx, f.actor(t))
	elapsed := time.Since(started)
	cancel()
	if !errors.Is(err, ErrPrivacyReviewChanging) || elapsed >= 900*time.Millisecond {
		t.Fatalf("fence conflict returned %v after %s", err, elapsed)
	}
	f.assertUnchanged(t, before)
	f.privacyRequest(t, f.q.WithTx(holder), uuid.Nil, "in_progress")
	before = f.snapshot(t, holder)
	if err := holder.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.mutate(f.ctx, f.actor(t)); !errors.Is(err, ErrPendingPrivacyReview) {
		t.Fatalf("retry missed global pending review: %v", err)
	}
	f.assertUnchanged(t, before)
}

func TestDraftGuardRetainsCopiedIdentityAndLocksE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	actor := f.actor(t)
	original := actor.Authorize
	checks := 0
	actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
		checks++
		if user.ID != f.user.ID || user.OrgID != f.orgID || user.Email != f.user.Email || user.Role != "sender" {
			t.Error("callback did not receive the retained live member")
		}
		if err := original(ctx, tx, user); err != nil {
			return err
		}
		user.ID, user.OrgID, user.Role, user.Email = uuid.New(), uuid.New(), "owner", "changed@example.test"
		return nil
	}
	tx := f.begin(t)
	guard, err := LockDraft(f.ctx, tx, actor, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if guard.UserID() != f.user.ID || guard.Document.ID != f.doc.ID || guard.Document.Name != f.doc.Name {
		t.Fatal("guard lost original identity or fresh document")
	}
	// The returned snapshot is editable; it must not authorize another actor.
	guard.Document.SenderID = uuid.New()
	if err := guard.Recheck(f.ctx); err != nil || checks != 2 || guard.UserID() != f.user.ID {
		t.Fatalf("copied identity/final guard: %v, checks=%d", err, checks)
	}
	contender := f.begin(t)
	var acquired bool
	if err := contender.QueryRow(f.ctx, `SELECT pg_try_advisory_xact_lock(hash_collab_archive_dsr_lock_key($1::uuid))`, f.orgID).Scan(&acquired); err != nil || acquired {
		t.Fatalf("privacy fence not retained: acquired=%t error=%v", acquired, err)
	}
	var pid int32
	if err := tx.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.user.ID)
		done <- err
	}()
	f.awaitBlocked(t, pid, "UPDATE users SET role='viewer'")
	if err := Rollback(f.ctx, tx); err != nil {
		t.Fatal(err)
	}
	if err := receiveDraftAdmission(t, done); err != nil {
		t.Fatal(err)
	}
	if err := contender.QueryRow(f.ctx, `SELECT pg_try_advisory_xact_lock(hash_collab_archive_dsr_lock_key($1::uuid))`, f.orgID).Scan(&acquired); err != nil || !acquired {
		t.Fatalf("privacy fence not released: acquired=%t error=%v", acquired, err)
	}
}

func TestDraftGuardRollbackDetachesCancelledRequestE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	before := f.snapshot(t, f.pool)
	ctx, cancel := context.WithCancel(f.ctx)
	tx := f.begin(t)
	if _, err := LockDraft(ctx, tx, f.actor(t), f.doc.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE documents SET name='Must roll back' WHERE id=$1`, f.doc.ID); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := Rollback(ctx, tx); err != nil {
		t.Fatal(err)
	}
	f.assertUnchanged(t, before)
}

func TestDraftAdmissionAuthorizedCommitPublishesCanonicalEventE2E(t *testing.T) {
	f := setupDraftAdmissionE2E(t)
	if err := f.mutate(f.ctx, f.actor(t)); err != nil {
		t.Fatal(err)
	}
	var name, kind string
	var actor, document uuid.UUID
	var events int
	if err := f.pool.QueryRow(f.ctx, `SELECT name FROM documents WHERE id=$1`, f.doc.ID).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1`, f.orgID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT kind,actor_user_id,document_id FROM events WHERE org_id=$1`, f.orgID).Scan(&kind, &actor, &document); err != nil {
		t.Fatal(err)
	}
	if name != "Authorized draft change" || events != 1 || kind != audit.KindDocumentUpdated || actor != f.user.ID || document != f.doc.ID || f.published != 1 {
		t.Fatal("authorized caller did not commit one canonical mutation and event")
	}
}

var errDraftFixtureAudit = errors.New("synthetic transactional audit failure")

type draftAdmissionFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	logger    *audit.Logger
	orgID     uuid.UUID
	user      *generated.User
	doc       *generated.Document
	recipient *generated.Recipient
	fieldID   uuid.UUID
	cookies   *auth.SignedCookie
	failAudit bool
	published int
}

func setupDraftAdmissionE2E(t *testing.T) *draftAdmissionFixture {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		_ = migrationDB.Close()
		t.Fatal(err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Draft admission " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, org.ID); err != nil {
			t.Error(err)
		}
	})
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@draft-owner.test", Name: "Synthetic sender", Role: "sender", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "Synthetic authoring draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: "signer@draft-" + org.ID.String() + ".test", Name: "Synthetic signer", Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	var fieldID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO document_fields(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json) VALUES($1,$2,'text',1,0,0,20,5,true,'Synthetic field','{}'::jsonb) RETURNING id`, doc.ID, recipient.ID).Scan(&fieldID); err != nil {
		t.Fatal(err)
	}
	cookies, err := auth.NewSignedCookie(strings.Repeat("5b", 32))
	if err != nil {
		t.Fatal(err)
	}
	return &draftAdmissionFixture{ctx: ctx, pool: pool, q: q, logger: audit.New(q, pool), orgID: org.ID, user: user, doc: doc, recipient: recipient, fieldID: fieldID, cookies: cookies}
}

func (f *draftAdmissionFixture) actor(t *testing.T) Actor {
	t.Helper()
	actor, _ := f.actorWithTTL(t, time.Hour)
	return actor
}

func (f *draftAdmissionFixture) actorWithTTL(t *testing.T, ttl time.Duration) (Actor, string) {
	t.Helper()
	session := auth.SessionPayload{UserID: f.user.ID, Generation: f.user.SessionGeneration}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	cookie := f.cookies.Mint(raw, ttl)
	return Actor{OrgID: f.orgID, UserID: f.user.ID, Authorize: auth.SessionTransactionAuthorization(f.cookies, cookie, session, f.orgID)}, cookie
}

func (f *draftAdmissionFixture) mutate(ctx context.Context, actor Actor) error {
	ctx, cancel := context.WithTimeout(ctx, MutationTimeout)
	defer cancel()
	tx, err := f.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = Rollback(ctx, tx) }()
	guard, err := LockDraft(ctx, tx, actor, f.doc.ID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE documents SET name='Authorized draft change',updated_at=clock_timestamp() WHERE id=$1`, guard.Document.ID); err != nil {
		return err
	}
	userID := guard.UserID()
	pending, err := f.logger.LogTx(ctx, tx, audit.Entry{OrgID: f.orgID, ActorUserID: &userID, DocumentID: &guard.Document.ID, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"via": "synthetic_authoring_fixture"}})
	if err != nil {
		return err
	}
	if f.failAudit {
		return errDraftFixtureAudit
	}
	if err := guard.Recheck(ctx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	f.logger.Publish(pending)
	f.published++
	return nil
}

type draftSnapshotDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (f *draftAdmissionFixture) snapshot(t *testing.T, db draftSnapshotDB) string {
	t.Helper()
	var state string
	if err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1) SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1)
	)::text`, f.orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}

func (f *draftAdmissionFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t, f.pool) != before || f.published != 0 {
		t.Fatal("refused draft mutation changed exact parent, signer credential, field, signature, privacy or audit state, or published an uncommitted event")
	}
}

func (f *draftAdmissionFixture) begin(t *testing.T) pgx.Tx {
	t.Helper()
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = Rollback(context.Background(), tx) })
	return tx
}

func (f *draftAdmissionFixture) holdParent(t *testing.T) (pgx.Tx, int32) {
	t.Helper()
	tx := f.begin(t)
	if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	return tx, draftHolderPID(t, f.ctx, tx)
}

func (f *draftAdmissionFixture) holdAudit(t *testing.T) (pgx.Tx, int32) {
	t.Helper()
	tx := f.begin(t)
	if err := f.q.WithTx(tx).AcquireOrgChainLock(f.ctx, f.orgID.String()); err != nil {
		t.Fatal(err)
	}
	return tx, draftHolderPID(t, f.ctx, tx)
}

func draftHolderPID(t *testing.T, ctx context.Context, tx pgx.Tx) int32 {
	t.Helper()
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return pid
}

func (f *draftAdmissionFixture) awaitBlocked(t *testing.T, holderPID int32, query string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE $1=ANY(pg_blocking_pids(a.pid)) AND position($2 in a.query)>0)`, holderPID, query).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("draft caller did not wait on exact holder for %s", query)
		}
	}
}

func (f *draftAdmissionFixture) awaitCookieExpiry(t *testing.T, cookie string) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := f.cookies.Verify(cookie); err != nil {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("synthetic session did not naturally expire")
		}
	}
}

func (f *draftAdmissionFixture) privacyRequest(t *testing.T, q *generated.Queries, docID uuid.UUID, status string) {
	t.Helper()
	input := generated.CreateDataSubjectRequestParams{OrgID: f.orgID, SubjectEmail: "synthetic-subject@example.test", SubjectName: "Synthetic subject", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}
	if docID != uuid.Nil {
		input.DocumentID = pgtype.UUID{Bytes: docID, Valid: true}
		if docID == f.doc.ID {
			input.RecipientID = pgtype.UUID{Bytes: f.recipient.ID, Valid: true}
		}
	}
	request, err := q.CreateDataSubjectRequest(f.ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if status != "open" {
		if _, err := q.UpdateDataSubjectRequestStatus(f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: f.orgID, ExpectedStatus: "open", Status: status, ResolutionNote: "Synthetic reviewed state"}); err != nil {
			t.Fatal(err)
		}
	}
}

func receiveDraftAdmission(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		return fmt.Errorf("draft caller did not finish after lock release")
	}
}

func seedCompleteFrozenBrandingE2E(t *testing.T, ctx context.Context, db generated.DBTX, documentID uuid.UUID) {
	t.Helper()
	_, err := db.Exec(ctx, `INSERT INTO document_branding_override (
		document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
		logo_url, logo_alt, font_heading, font_body, signature_color
	) VALUES ($1, '#0F172A', '#3B82F6', '#FFFFFF', '#0F172A', '#64748B',
	          '', '', 'Inter', 'Inter', '#0F172A')
	ON CONFLICT (document_id) DO UPDATE SET
		primary_hex=EXCLUDED.primary_hex, accent_hex=EXCLUDED.accent_hex,
		surface_hex=EXCLUDED.surface_hex, text_hex=EXCLUDED.text_hex,
		muted_hex=EXCLUDED.muted_hex, logo_url=EXCLUDED.logo_url,
		logo_alt=EXCLUDED.logo_alt, font_heading=EXCLUDED.font_heading,
		font_body=EXCLUDED.font_body, signature_color=EXCLUDED.signature_color`, documentID) //nolint:rawsql
	if err != nil {
		t.Fatalf("seed complete canonical frozen branding: %v", err)
	}
}
