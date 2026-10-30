//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These cases require an actual disposable PostgreSQL with current migrations.
// They seed a synthetic already-approved master and exercise the real registry,
// signed-session capability and audit chain. They do not render/stamp a PDF or
// claim an owner-browser approval or live CRM/provider acceptance. Authority
// evidence is deliberately retained until the isolated fixture DB is disposed.
type registryFixture struct {
	ctx                     context.Context
	pool                    *pgxpool.Pool
	q                       *generated.Queries
	engine                  *Engine
	cookies                 *auth.SignedCookie
	org, ownerID, grantorID uuid.UUID
	owner, grantor          SessionActor
	definition              WorkflowDefinition
	workflow                Outcome
	policy                  presign.Reference
}

func registrySession(t testing.TB, f registryFixture, id uuid.UUID, generation int64, ttl time.Duration) SessionActor {
	t.Helper()
	raw, _ := json.Marshal(auth.SessionPayload{UserID: id, Generation: generation})
	a, err := NewSessionActor(f.cookies, f.cookies.Mint(raw, ttl), f.org, id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func setupRegistryE2E(t testing.TB) registryFixture {
	t.Helper()
	ctx, pool := setupRegistryDatabaseE2E(t)
	return newRegistryFixtureE2E(t, ctx, pool)
}

func setupRegistryDatabaseE2E(t testing.TB) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("HASH_E2E_DB_URL is required for actual registry PostgreSQL")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("registry fixture requires a PostgreSQL URL")
	}
	name := registryDatabasesE2E.Clone(t, "hash_presign_e2e_")
	u.Path = "/" + name
	u.RawPath = ""
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal("connect registry fixture PostgreSQL")
	}
	t.Cleanup(pool.Close)
	return ctx, pool
}

func newRegistryFixtureE2E(t testing.TB, ctx context.Context, pool *pgxpool.Pool) registryFixture {
	t.Helper()
	f := registryFixture{ctx: ctx, pool: pool, q: generated.New(pool), org: uuid.New(), ownerID: uuid.New(), grantorID: uuid.New()}
	cookies, err := auth.NewSignedCookie(strings.Repeat("c4", 32))
	if err != nil {
		t.Fatal(err)
	}
	f.cookies = cookies
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name) VALUES($1,'Synthetic pre-sign registry fixture');`, f.org); err != nil {
		t.Fatal("seed registry organization")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,org_id,name,email,role) VALUES($1,$3,'Synthetic Owner',$4,'owner'),($2,$3,'Synthetic Provider',$5,'sender')`, f.ownerID, f.grantorID, f.org, "owner-"+f.ownerID.String()+"@example.test", "provider-"+f.grantorID.String()+"@example.test"); err != nil {
		t.Fatal("seed registry members")
	}
	f.owner = registrySession(t, f, f.ownerID, 0, time.Hour)
	f.grantor = registrySession(t, f, f.grantorID, 0, time.Hour)
	f.engine = NewEngine(pool, audit.New(f.q, pool), f.cookies)
	d, master, defaults := masterDefinitionFixture(t)
	d.ID = uuid.New()
	d.PolicyID = uuid.New()
	d.OrgID = f.org
	d.Template.ID = uuid.New()
	d.Template.ApprovedBy = f.ownerID
	d.Template.ApprovedAt = time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	d.Executor.UserID = f.grantorID
	if _, err := pool.Exec(ctx, `INSERT INTO templates(id,org_id,name,source_kind,html_master_json,variables_json,created_by,html_content_sha256) VALUES($1,$2,'Synthetic approved source3','html',$3::jsonb,$4::jsonb,$5,$6)`, d.Template.ID, f.org, master, defaults, f.ownerID, unhex(d.Template.ContentSHA256)); err != nil {
		t.Fatal("seed approved master head")
	}
	if _, err := pool.Exec(ctx, `INSERT INTO html_template_revisions(template_id,version,org_id,html_master_json,variables_json,content_sha256,created_by,approved_by,approved_at) VALUES($1,1,$2,$3::jsonb,$4::jsonb,$5,$6,$6,$7)`, d.Template.ID, f.org, master, defaults, unhex(d.Template.ContentSHA256), f.ownerID, d.Template.ApprovedAt); err != nil {
		t.Fatal("seed selected immutable approval")
	}
	f.definition = d
	return f
}

func approveRegistryE2E(t testing.TB, f *registryFixture) ConfirmWorkflowInput {
	t.Helper()
	in := WorkflowIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.ownerID, Definition: f.definition}
	preview, err := f.engine.PreviewWorkflow(f.ctx, f.owner, in)
	if err != nil {
		t.Fatal("preview actual registry workflow", err)
	}
	confirmed := ConfirmWorkflowInput{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}
	f.workflow, err = f.engine.ApproveWorkflow(f.ctx, f.owner, confirmed)
	if err != nil {
		t.Fatal("approve actual registry workflow", err)
	}
	view, err := f.engine.GetWorkflow(f.ctx, f.owner, f.definition.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.policy = view.PolicyReference
	return confirmed
}
func grantInputE2E(t testing.TB, f registryFixture, deadline time.Time) ConfirmGrantInput {
	t.Helper()
	in := GrantIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.grantorID, GrantID: uuid.New(), Policy: f.policy, CompanyName: f.definition.RecipientRules.ProviderCompanyName, CompanyID: f.definition.RecipientRules.ProviderCompanyID, AuthorityBasis: f.definition.RecipientRules.ProviderAuthorityBasis, Font: "Caveat", ExpiresAt: deadline, MaxUses: 2}
	preview, err := f.engine.PreviewSelfGrant(f.ctx, f.grantor, in)
	if err != nil {
		t.Fatal("preview actual self grant", err)
	}
	return ConfirmGrantInput{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}
}
func createRegistryGrantE2E(t testing.TB, f registryFixture) (ConfirmGrantInput, Outcome) {
	t.Helper()
	in := grantInputE2E(t, f, time.Now().Add(30*time.Minute))
	out, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, in)
	if err != nil {
		t.Fatal("create actual self grant", err)
	}
	return in, out
}
func registryCountE2E(t testing.TB, f registryFixture, table string) int {
	t.Helper()
	allowed := map[string]bool{"presign_workflows": true, "presign_grants": true, "presign_mutation_requests": true, "events": true}
	if !allowed[table] {
		t.Fatal("unsupported inventory table")
	}
	var n int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM `+table+` WHERE org_id=$1`, f.org).Scan(&n); err != nil {
		t.Fatal("read fixture cardinality")
	}
	return n
}

func TestPresignRegistryWorkflowAndNamedSelfGrantPersistenceE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	approval := approveRegistryE2E(t, &f)
	in, out := createRegistryGrantE2E(t, f)
	v, err := f.engine.GetOwnGrant(f.ctx, f.grantor, out.Reference.ID, 0)
	if err != nil || v.Reference != out.Reference || v.Grant.Grantor.UserID != f.grantorID || v.Grant.ExpiresAt != in.Intent.ExpiresAt || v.Grant.NotBefore != v.Grant.GrantedAt || v.Revoked || v.ConsumedUses != 0 || v.ExecutionAvailable {
		t.Fatal("named consent or unavailable execution contract changed")
	}
	w, err := f.engine.GetWorkflow(f.ctx, f.owner, f.definition.ID, 0)
	if err != nil || v.Grant.GrantedAt.Before(w.Policy.ApprovedAt) || w.Policy.ApprovedAt.Equal(f.definition.Template.ApprovedAt) {
		t.Fatal("confirmation fabricated preview/approval timestamps")
	}
	before := registryCountE2E(t, f, "events")
	again, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, ConfirmGrantInput{Intent: in.Intent, Receipt: "expired receipt deliberately ignored for committed replay", Confirmed: true})
	if err != nil || again != out || registryCountE2E(t, f, "events") != before {
		t.Fatal("committed retry created new consent or audit")
	}
	replayed, err := f.engine.ApproveWorkflow(f.ctx, f.owner, ConfirmWorkflowInput{Intent: approval.Intent, Receipt: "old receipt", Confirmed: true})
	if err != nil || replayed != f.workflow {
		t.Fatal("owner approval retry changed immutable revision")
	}
	wrong := in
	wrong.Intent.CompanyID = "different"
	if _, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, wrong); !errors.Is(err, ErrConflict) {
		t.Fatal("same nonce changed command accepted")
	}
	if _, err := f.engine.CreateSelfGrant(f.ctx, f.owner, in); !errors.Is(err, auth.ErrMutationPermissionRevoked) {
		t.Fatal("owner created consent on behalf")
	}
	if _, err := f.engine.CreateSelfGrant(f.ctx, SessionActor{}, in); err == nil {
		t.Fatal("generic API/empty actor fabricated consent")
	}
}

func TestPresignRegistryApprovedDataRulePersistenceE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	r, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: f.definition.Template.ID, OrgID: f.org, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.definition = approvedDataRules(t, f.definition, r.HtmlMasterJson)
	approveRegistryE2E(t, &f)
	v, err := f.engine.GetWorkflow(f.ctx, f.owner, f.definition.ID, 0)
	if err != nil || v.Policy.Rules.InputMode != presign.InputApprovedData || v.Definition.Kind != KindApprovedData {
		t.Fatal("approved-data content/policy not actually persisted")
	}
	for _, s := range v.Definition.DataRules.Sections {
		if s.Mode != ModeDefault && s.Mode != ModeLiteral {
			t.Fatal("unreviewed prose persisted")
		}
	}
	_, out := createRegistryGrantE2E(t, f)
	if _, err := f.engine.GetOwnGrant(f.ctx, f.grantor, out.Reference.ID, 0); err != nil {
		t.Fatal(err)
	}
}

func TestPresignRegistryStickyAuthorityTransitionsE2E(t *testing.T) {
	// These transitions each receive fresh organization/actor/nonce state in
	// one owned database. Reapplying the same migration tree for every case
	// adds no authority coverage and competes with other integration packages.
	ctx, pool := setupRegistryDatabaseE2E(t)
	for _, name := range []string{"role_loss", "name_restore", "email_restore", "organization_change", "member_removed", "session_only", "eligible_role"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistryFixtureE2E(t, ctx, pool)
			approveRegistryE2E(t, &f)
			in, out := createRegistryGrantE2E(t, f)
			var before []byte
			if err := f.pool.QueryRow(f.ctx, `SELECT canonical_grant FROM presign_grant_revisions WHERE org_id=$1 AND grant_id=$2`, f.org, out.Reference.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			var err error
			reason := ""
			switch name {
			case "role_loss":
				reason = "authority_role_lost"
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1`, f.grantorID)
				if err == nil {
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET role='sender' WHERE id=$1`, f.grantorID)
				}
			case "name_restore":
				reason = "identity_changed"
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET name='Changed synthetic provider' WHERE id=$1`, f.grantorID)
				if err == nil {
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET name='Synthetic Provider' WHERE id=$1`, f.grantorID)
				}
			case "email_restore":
				reason = "identity_changed"
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET email='changed-'||email WHERE id=$1`, f.grantorID)
				if err == nil {
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET email=substring(email from 9) WHERE id=$1`, f.grantorID)
				}
			case "organization_change":
				reason = "organization_changed"
				org := uuid.New()
				_, err = f.pool.Exec(f.ctx, `INSERT INTO orgs(id,name) VALUES($1,'Synthetic foreign organization')`, org)
				if err == nil {
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET org_id=$2 WHERE id=$1`, f.grantorID, org)
				}
			case "member_removed":
				reason = "member_removed"
				_, err = f.pool.Exec(f.ctx, `DELETE FROM users WHERE id=$1`, f.grantorID)
			case "session_only":
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, f.grantorID)
			case "eligible_role":
				_, err = f.pool.Exec(f.ctx, `UPDATE users SET role='owner' WHERE id=$1`, f.grantorID)
				if err == nil {
					_, err = f.pool.Exec(f.ctx, `UPDATE users SET role='sender' WHERE id=$1`, f.grantorID)
				}
			}
			if err != nil {
				t.Fatal("actual authority transition failed", err)
			}
			var revoked bool
			var why string
			var after []byte
			var reasons int
			err = f.pool.QueryRow(f.ctx, `SELECT g.revoked_at IS NOT NULL,coalesce(g.revoked_reason,''),r.canonical_grant,(SELECT count(*) FROM presign_grant_revocations v WHERE v.org_id=g.org_id AND v.grant_id=g.id) FROM presign_grants g JOIN presign_grant_revisions r ON r.org_id=g.org_id AND r.grant_id=g.id AND r.revision=g.current_revision WHERE g.org_id=$1 AND g.id=$2`, f.org, out.Reference.ID).Scan(&revoked, &why, &after, &reasons)
			if err != nil || revoked != (reason != "") || why != reason || reasons != map[bool]int{false: 0, true: 1}[reason != ""] || !bytes.Equal(before, after) {
				t.Fatal("sticky terminal state lost immutable consent")
			}
			if name == "role_loss" {
				replay, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, in)
				if err != nil || replay != out {
					t.Fatal("committed readback became renewed authority")
				}
				view, err := f.engine.GetOwnGrant(f.ctx, f.grantor, out.Reference.ID, 0)
				if err != nil || !view.Revoked {
					t.Fatal("promotion restored revoked grant")
				}
			}
		})
	}
}

type registryAuditGate struct {
	actual  *audit.Logger
	entered chan struct{}
	once    sync.Once
	failure error
}

func (g *registryAuditGate) LogTx(ctx context.Context, tx pgx.Tx, e audit.Entry) (audit.PendingEvent, error) {
	if g.entered != nil {
		g.once.Do(func() { close(g.entered) })
	}
	if g.failure != nil {
		return audit.PendingEvent{}, g.failure
	}
	return g.actual.LogTx(ctx, tx, e)
}
func (g *registryAuditGate) Publish(p audit.PendingEvent) { g.actual.Publish(p) }

func TestPresignRegistryAuditFailureRollsBackConsentAndOutcomeE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	approveRegistryE2E(t, &f)
	in := grantInputE2E(t, f, time.Now().Add(30*time.Minute))
	events := registryCountE2E(t, f, "events")
	requests := registryCountE2E(t, f, "presign_mutation_requests")
	f.engine.logger = &registryAuditGate{actual: audit.New(f.q, f.pool), failure: pgx.ErrNoRows}
	if _, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, in); !errors.Is(err, ErrAudit) || ErrorCode(err) != 500 {
		t.Fatal("audit missing row became a client conflict")
	}
	if registryCountE2E(t, f, "presign_grants") != 0 || registryCountE2E(t, f, "events") != events || registryCountE2E(t, f, "presign_mutation_requests") != requests {
		t.Fatal("audit failure left authority or committed outcome")
	}
}

func TestPresignRegistryNaturalDeadlineAfterActualAuditLockWaitE2E(t *testing.T) {
	ctx, pool := setupRegistryDatabaseE2E(t)
	for _, name := range []string{"grant_expiry", "original_session", "api_executor"} {
		t.Run(name, func(t *testing.T) {
			f := newRegistryFixtureE2E(t, ctx, pool)
			var submit func() error
			deadline := time.Now().Add(3 * time.Second)
			if name == "api_executor" {
				key := uuid.New()
				if _, err := f.pool.Exec(f.ctx, `INSERT INTO api_keys(id,org_id,user_id,key_prefix,key_hash,name,scopes,expires_at) VALUES($1,$2,$3,'a'||repeat('b',32),decode(repeat('a1',32),'hex'),'Synthetic finite executor',ARRAY['write:authoring','write:workflow'],$4)`, key, f.org, f.grantorID, deadline); err != nil {
					t.Fatal(err)
				}
				f.definition.Executor = presign.ExecutorIdentity{Kind: presign.ExecutorAPIKey, UserID: f.grantorID, CredentialID: key}
				intent := WorkflowIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.ownerID, Definition: f.definition}
				p, err := f.engine.PreviewWorkflow(f.ctx, f.owner, intent)
				if err != nil {
					t.Fatal(err)
				}
				submit = func() error {
					_, err := f.engine.ApproveWorkflow(f.ctx, f.owner, ConfirmWorkflowInput{Intent: p.Intent, Receipt: p.Receipt, Confirmed: true})
					return err
				}
			} else {
				approveRegistryE2E(t, &f)
				expiry := time.Now().Add(30 * time.Minute)
				if name == "grant_expiry" {
					expiry = deadline
				}
				in := grantInputE2E(t, f, expiry)
				if name == "original_session" {
					f.grantor = registrySession(t, f, f.grantorID, 0, 2*time.Second)
					p, err := f.engine.PreviewSelfGrant(f.ctx, f.grantor, in.Intent)
					if err != nil {
						t.Fatal(err)
					}
					in.Receipt = p.Receipt
				}
				submit = func() error { _, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, in); return err }
			}
			lock, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(f.ctx)
			if err := generated.New(lock).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			gate := &registryAuditGate{actual: audit.New(f.q, f.pool), entered: make(chan struct{})}
			f.engine.logger = gate
			done := make(chan error, 1)
			go func() { done <- submit() }()
			select {
			case <-gate.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("mutation never reached actual audit lock wait")
			}
			timer := time.NewTimer(time.Until(deadline.Add(time.Second)))
			defer timer.Stop()
			select {
			case <-timer.C:
			case err := <-done:
				t.Fatal("mutation escaped held audit lock", err)
			}
			if err := lock.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, auth.ErrMutationCredentialExpired) {
					t.Fatal("natural deadline passed before commit", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("bounded mutation did not terminate")
			}
			if registryCountE2E(t, f, "presign_grants") != 0 {
				t.Fatal("expired admission committed named consent")
			}
			if name == "api_executor" && registryCountE2E(t, f, "presign_workflows") != 0 {
				t.Fatal("expired executor committed approval")
			}
		})
	}
}

func TestPresignRegistryOriginalActorNonceConcurrencyAndClosureE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	approveRegistryE2E(t, &f)
	in := grantInputE2E(t, f, time.Now().Add(30*time.Minute))
	var a, b Outcome
	var ea, eb error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); a, ea = f.engine.CreateSelfGrant(f.ctx, f.grantor, in) }()
	go func() { defer wg.Done(); b, eb = f.engine.CreateSelfGrant(f.ctx, f.grantor, in) }()
	wg.Wait()
	if ea != nil || eb != nil || a != b || registryCountE2E(t, f, "presign_grants") != 1 {
		t.Fatal("concurrent original nonce duplicated consent", ea, eb)
	}
	if _, err := f.engine.GetOwnRequest(f.ctx, f.owner, in.Intent.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("another actor inspected named request")
	}
	pending := grantInputE2E(t, f, time.Now().Add(30*time.Minute))
	if _, err := f.engine.GetOwnRequest(f.ctx, f.grantor, pending.Intent.RequestID); !errors.Is(err, ErrNotFound) {
		t.Fatal("unconfirmed request became committed")
	}
	closed, err := f.engine.CloseOwnRequest(f.ctx, f.grantor, CloseRequestInput{RequestID: pending.Intent.RequestID, ExpectedOrgID: f.org, ExpectedUserID: f.grantorID, Confirmed: true})
	if err != nil || closed.State != "closed" || closed.Reference != (presign.Reference{}) {
		t.Fatal("durable original-actor stop failed")
	}
	if _, err := f.engine.CreateSelfGrant(f.ctx, f.grantor, pending); !errors.Is(err, ErrConflict) {
		t.Fatal("closed nonce resurrected consent")
	}
	if registryCountE2E(t, f, "presign_grants") != 1 {
		t.Fatal("closed request created another grant")
	}
}

func TestPresignRegistryOwnerEmergencyRevokeAndImmutableSQLGuardsE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	approveRegistryE2E(t, &f)
	_, out := createRegistryGrantE2E(t, f)
	list, err := f.engine.ListGrantsAsOwner(f.ctx, f.owner)
	if err != nil || len(list) != 1 || list[0].Reference != out.Reference {
		t.Fatal("owner cannot discover exact emergency ref")
	}
	mutation := ResourceMutationInput{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.ownerID, Reference: out.Reference, Confirmed: true}
	if _, err := f.engine.RevokeOwnGrant(f.ctx, f.owner, mutation); !errors.Is(err, ErrNotFound) {
		t.Fatal("owner fabricated another member's own revocation")
	}
	if _, err := f.engine.RevokeGrantAsOwner(f.ctx, f.owner, mutation); err != nil {
		t.Fatal(err)
	}
	v, err := f.engine.GetGrantAsOwner(f.ctx, f.owner, out.Reference.ID, 0)
	if err != nil || !v.Revoked || v.RevocationReason != "owner_revoked" {
		t.Fatal("owner revocation not terminal")
	}
	for name, query := range map[string]string{"clear_revocation": `UPDATE presign_grants SET revoked_at=NULL,revoked_reason=NULL WHERE org_id=$1`, "edit_snapshot": `UPDATE presign_grant_revisions SET canonical_grant='tampered'::bytea WHERE org_id=$1`, "consume_without_execution": `UPDATE presign_grant_revisions SET consumed_uses=1 WHERE org_id=$1`, "remove_outcome": `DELETE FROM presign_mutation_requests WHERE org_id=$1`, "edit_policy": `UPDATE presign_workflow_revisions SET canonical_policy='tampered'::bytea WHERE org_id=$1`} {
		t.Run(name, func(t *testing.T) {
			_, err := f.pool.Exec(f.ctx, query, f.org)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23514" {
				t.Fatal("immutable SQL guard did not refuse exact mutation")
			}
		})
	}
}

func TestPresignRegistryHistoricalApprovalAndOriginalCookieReceiptE2E(t *testing.T) {
	f := setupRegistryE2E(t)
	intent := WorkflowIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.ownerID, Definition: f.definition}
	preview, err := f.engine.PreviewWorkflow(f.ctx, f.owner, intent)
	if err != nil {
		t.Fatal(err)
	}
	otherSession := registrySession(t, f, f.ownerID, 0, 2*time.Hour)
	if _, err := f.engine.ApproveWorkflow(f.ctx, otherSession, ConfirmWorkflowInput{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}); !errors.Is(err, ErrConflict) {
		t.Fatal("same-user replacement cookie adopted old confirmation")
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE templates SET version=2 WHERE id=$1`, f.definition.Template.ID); err != nil {
		t.Fatal(err)
	}
	out, err := f.engine.ApproveWorkflow(f.ctx, f.owner, ConfirmWorkflowInput{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true})
	if err != nil || out.Reference.Revision != 1 {
		t.Fatal("active historical selected approval wrongly required latest head", err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE templates SET archived_at=clock_timestamp() WHERE id=$1`, f.definition.Template.ID); err != nil {
		t.Fatal(err)
	}
	v, err := f.engine.GetWorkflow(f.ctx, f.owner, f.definition.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	in := GrantIntent{RequestID: uuid.New(), ExpectedOrgID: f.org, ExpectedUserID: f.grantorID, GrantID: uuid.New(), Policy: v.PolicyReference, CompanyName: f.definition.RecipientRules.ProviderCompanyName, CompanyID: f.definition.RecipientRules.ProviderCompanyID, AuthorityBasis: f.definition.RecipientRules.ProviderAuthorityBasis, Font: "Caveat", ExpiresAt: time.Now().Add(30 * time.Minute), MaxUses: 1}
	if _, err := f.engine.PreviewSelfGrant(f.ctx, f.grantor, in); err == nil {
		t.Fatal("archived template admitted fresh named authority")
	}
}
