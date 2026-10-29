//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Real PostgreSQL only. The selected source3/PDF/image/version descriptors are
// synthetic testfixture inputs: this does not render, store, sign, authenticate
// a real user or prove provider-visible PDF, customer or production acceptance.
type executionFixture struct {
	ctx                 context.Context
	pool                *pgxpool.Pool
	q                   *generated.Queries
	logger              *audit.Logger
	org, owner, grantor uuid.UUID
	input               htmlsource.Input
	doc                 *generated.Document
	rows                []*generated.Recipient
	fields              []*generated.DocumentField
	definition          presignregistry.WorkflowDefinition
	policy              presign.Policy
	grant               presign.Grant
}

func fixtureHash(value string) string {
	s := sha256.Sum256([]byte(value))
	return hex.EncodeToString(s[:])
}
func execOK(t testing.TB, ctx context.Context, tx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatal("synthetic SQL fixture", err)
	}
}
func isolatedExecutionDB(t testing.TB) (context.Context, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("HASH_E2E_DB_URL is required for actual execution PostgreSQL")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("actual PostgreSQL URL required")
	}
	adminCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(adminCtx, dsn)
	if err != nil {
		t.Fatal("connect synthetic parent PostgreSQL")
	}
	name := "hash_presign_execution_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(adminCtx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal("create unique owned execution DB")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		// The pool's local Close can precede PostgreSQL backend retirement.
		// Independently observe this exact, uniquely owned database before DROP;
		// never terminate an uncertain connection or disguise it with FORCE.
		if executionDatabaseRetired(t, ctx, admin, name) {
			if _, err := admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
				executionCleanupError(t, "drop exact owned execution DB", err)
			}
		}
		cancel()
		closeCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if err := admin.Close(closeCtx); err != nil {
			executionCleanupError(t, "close owned execution administrator", err)
		}
	})
	u.Path = "/" + name
	u.RawPath = ""
	config, err := pgx.ParseConfig(u.String())
	if err != nil {
		t.Fatal(err)
	}
	sqlDB := stdlib.OpenDB(*config)
	sqlDB.SetMaxOpenConns(1)
	if err = db.RunMigrations(sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatal("migrate owned execution DB", err)
	}
	if err = sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(stop)
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal("connect owned execution DB")
	}
	t.Cleanup(func() {
		stop()
		pool.Close()
	})
	return ctx, pool
}

func executionCleanupError(t testing.TB, phase string, err error) {
	t.Helper()
	state := "none"
	var postgres *pgconn.PgError
	if errors.As(err, &postgres) {
		state = postgres.Code
	}
	// SQLSTATE/type are useful diagnostics without private DSN/SQL row text.
	t.Errorf("%s (type=%T sqlstate=%s cancelled=%t deadline=%t)", phase, err, state, errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded))
}

func executionDatabaseRetired(t testing.TB, ctx context.Context, admin *pgx.Conn, database string) bool {
	t.Helper()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		var remaining int64
		if err := admin.QueryRow(ctx, "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE datname=$1", database).Scan(&remaining); err != nil {
			executionCleanupError(t, "observe owned execution database backend retirement", err)
			return false
		}
		if remaining == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			t.Errorf("owned execution fixture retained %d database backends after pool close", remaining)
			return false
		case <-tick.C:
		}
	}
}
func setupExecutionE2E(t testing.TB) *executionFixture {
	t.Helper()
	return setupExecutionNoticeE2E(t, pgtype.Timestamptz{})
}
func setupExecutionNoticeE2E(t testing.TB, prior pgtype.Timestamptz) *executionFixture {
	t.Helper()
	ctx, pool := isolatedExecutionDB(t)
	in, doc, rows := testfixture.BrandedHTMLContract(t)
	doc.Article13NoticeEpochAt = prior
	if prior.Valid {
		doc.Article13NoticeSchema = "hash-a13-2026-08-31"
	}
	f := &executionFixture{ctx: ctx, pool: pool, q: generated.New(pool), org: doc.OrgID, owner: uuid.New(), grantor: doc.SenderID, input: in, doc: doc, rows: rows}
	f.logger = audit.New(f.q, pool)
	// Derive the synthetic approved-origin identity before inserting the
	// immutable revision. Never repair an approval after storing its source.
	in.TemplateApprovedBy = f.owner
	f.input = in
	var err error
	doc.HtmlSourceJson, err = htmlsource.New(in, doc)
	if err != nil {
		t.Fatal(err)
	}
	execOK(t, ctx, pool, `INSERT INTO orgs(id,name) VALUES($1,'Synthetic delegated persistence')`, f.org)
	execOK(t, ctx, pool, `INSERT INTO users(id,org_id,name,email,role) VALUES($1,$3,'Synthetic Owner','owner@example.test','owner'),($2,$3,'Synthetic Provider','provider@example.test','sender')`, f.owner, f.grantor, f.org)
	execOK(t, ctx, pool, `INSERT INTO templates(id,org_id,name,source_kind,html_master_json,variables_json,created_by,html_content_sha256) VALUES($1,$2,'Synthetic source3','html',$3::jsonb,$4::jsonb,$5,$6)`, in.TemplateID, f.org, in.MasterJSON, in.DefaultVarsJSON, f.owner, unhex(in.TemplateContentSHA256))
	execOK(t, ctx, pool, `INSERT INTO html_template_revisions(template_id,version,org_id,html_master_json,variables_json,content_sha256,created_by,approved_by,approved_at) VALUES($1,1,$2,$3::jsonb,$4::jsonb,$5,$6,$7,$8)`, in.TemplateID, f.org, in.MasterJSON, in.DefaultVarsJSON, unhex(in.TemplateContentSHA256), f.owner, in.TemplateApprovedBy, in.TemplateApprovedAt)
	f.seedDocument(t, doc, rows)
	master, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	d := presignregistry.WorkflowDefinition{Version: 1, ID: uuid.New(), PolicyID: uuid.New(), OrgID: f.org, Revision: 1, Name: "Synthetic reviewed execution", Kind: presignregistry.KindReviewedDocument,
		Template: presign.TemplatePin{ID: in.TemplateID, Version: int64(in.TemplateVersion), ContentSHA256: in.TemplateContentSHA256, ApprovedBy: f.owner, ApprovedAt: in.TemplateApprovedAt},
		Executor: presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: f.grantor}, Operation: presign.OperationPreSignAndSend,
		InputRules:              presignregistry.InputRules{Version: 1, SourceSchemaVersion: 3, Standalone: true, SignatureFieldsOnly: true, AuthorMustBeGrantor: true},
		DataRules:               presignregistry.DataRules{Version: 1, Values: []presignregistry.ValueRule{}, Sections: []presignregistry.SectionRule{}},
		RecipientRules:          presignregistry.RecipientRules{Version: 1, Provider: "named_grantor_exact", Customer: "printed_profile_exact", Mode: "parallel", ProviderCompanyName: in.Values["provider_company"], ProviderCompanyID: in.Values["provider_company_id"], ProviderAuthorityBasis: in.Values["provider_authority"]},
		MaxGrantDurationSeconds: 3600, MaxUses: 2}
	for _, v := range master.Values {
		d.DataRules.Values = append(d.DataRules.Values, presignregistry.ValueRule{Variable: v.Name, Mode: presignregistry.ModeReviewedValue})
	}
	for _, s := range master.Sections {
		d.DataRules.Sections = append(d.DataRules.Sections, presignregistry.SectionRule{Section: s.Name, Mode: presignregistry.ModeReviewedValue})
	}
	raw, h, rules, err := presignregistry.CanonicalDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	d, err = presignregistry.DecodeDefinition(raw)
	if err != nil {
		t.Fatal(err)
	}
	f.definition = d
	now := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	f.policy, err = presign.NewPolicy(presign.PolicySnapshot{SchemaVersion: 1, ID: d.PolicyID, OrgID: f.org, Revision: 1, Template: d.Template,
		Workflow: presign.WorkflowPin{ID: d.ID, Revision: 1, ContentSHA256: h, ApprovedBy: f.owner, ApprovedAt: now}, Executor: d.Executor, Operation: d.Operation, Rules: rules, MaxGrantDurationSeconds: 3600, MaxUses: 2, ApprovedBy: f.owner, ApprovedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	fontSHA, err := render.SignatureFontSHA256("Caveat")
	if err != nil {
		t.Fatal(err)
	}
	f.grant, err = presign.NewGrant(presign.GrantSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: f.org, Revision: 1, Policy: f.policy.Reference(),
		Grantor:   presign.NamedRepresentative{UserID: f.grantor, Name: in.Values["provider_name"], Email: in.Values["provider_email"], CompanyName: in.Values["provider_company"], CompanyID: in.Values["provider_company_id"], AuthorityBasis: in.Values["provider_authority"]},
		Signature: presign.SignatureStyle{Font: "Caveat", FontSHA256: fontSHA}, Disclosure: presign.CopyPin{Version: 1, SHA256: fixtureHash("synthetic app disclosure")},
		GrantedAt: now.Add(time.Second), NotBefore: now.Add(time.Second), ExpiresAt: now.Add(30 * time.Minute), MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	execOK(t, ctx, tx, `INSERT INTO presign_workflows(org_id,id,name,current_revision) VALUES($1,$2,$3,1)`, f.org, d.ID, d.Name)
	execOK(t, ctx, tx, `INSERT INTO presign_workflow_revisions(org_id,workflow_id,revision,policy_id,canonical_definition,definition_sha256,canonical_policy,policy_sha256,template_id,template_version,template_content_sha256,approved_by,approved_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,1,$9,$10,$11)`, f.org, d.ID, d.PolicyID, raw, unhex(h), f.policy.CanonicalJSON(), unhex(f.policy.Commitment()), in.TemplateID, unhex(in.TemplateContentSHA256), f.owner, now)
	f.insertGrant(t, tx, f.grant)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal("commit synthetic registry authority", err)
	}
	return f
}

func (f *executionFixture) insertGrant(t testing.TB, tx pgx.Tx, g presign.Grant) {
	t.Helper()
	s := g.Snapshot()
	if s.Revision == 1 {
		execOK(t, f.ctx, tx, `INSERT INTO presign_grants(org_id,id,grantor_user_id,current_revision) VALUES($1,$2,$3,1)`, s.OrgID, s.ID, s.Grantor.UserID)
	} else {
		execOK(t, f.ctx, tx, `UPDATE presign_grants SET current_revision=$3 WHERE org_id=$1 AND id=$2`, s.OrgID, s.ID, s.Revision)
	}
	execOK(t, f.ctx, tx, `INSERT INTO presign_grant_revisions(org_id,grant_id,revision,canonical_grant,grant_sha256,policy_id,policy_revision,policy_sha256,granted_at,not_before,expires_at,max_uses) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, s.OrgID, s.ID, s.Revision, g.CanonicalJSON(), unhex(g.Commitment()), s.Policy.ID, s.Policy.Revision, unhex(s.Policy.SHA256), s.GrantedAt, s.NotBefore, s.ExpiresAt, s.MaxUses)
}
func (f *executionFixture) seedDocument(t testing.TB, doc *generated.Document, rows []*generated.Recipient) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	execOK(t, f.ctx, tx, `INSERT INTO documents(id,org_id,template_id,name,source_kind,variables_json,pdf_storage_key,pdf_sha256,pdf_storage_version_id,sender_id,requires_signature,html_source_json,evidence_version_pins_required,article13_notice_epoch_at,article13_notice_schema) VALUES($1,$2,$3,'Synthetic source3','pdf',$4::jsonb,$5,$6,$7,$8,true,$9::jsonb,true,$10,$11)`, doc.ID, doc.OrgID, f.input.TemplateID, doc.VariablesJson, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID.String, doc.SenderID, doc.HtmlSourceJson, doc.Article13NoticeEpochAt, doc.Article13NoticeSchema)
	for _, r := range rows {
		execOK(t, f.ctx, tx, `INSERT INTO recipients(id,document_id,role,email,name,order_index,magic_token_hash,magic_token_expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '1 hour')`, r.ID, doc.ID, r.Role, r.Email, r.Name, r.OrderIndex, unhex(fixtureHash("synthetic non-routed token "+r.ID.String())))
	}
	fields := testfixture.BrandedSignatureFields(t, doc)
	for _, field := range fields {
		execOK(t, f.ctx, tx, `INSERT INTO document_fields(id,document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json) VALUES($1,$2,$3,'signature',$4,$5,$6,$7,$8,true,$9,$10::jsonb)`, field.ID, doc.ID, uuid.UUID(field.RecipientID.Bytes), field.Page, field.XPct, field.YPct, field.WPct, field.HPct, field.Label.String, field.OptionsJson)
	}
	b := testfixture.BrandedSigningPolicy().Branding
	execOK(t, f.ctx, tx, `INSERT INTO document_branding_override(document_id,primary_hex,accent_hex,surface_hex,text_hex,muted_hex,logo_url,logo_alt,font_heading,font_body,signature_color) VALUES($1,$2,$3,$4,$5,$6,'','',$7,$8,$9)`, doc.ID, b.PrimaryHex, b.AccentHex, b.SurfaceHex, b.TextHex, b.MutedHex, b.FontHeading, b.FontBody, b.SignatureColor)
	cid, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	mid := uuid.New()
	execOK(t, f.ctx, tx, `INSERT INTO html_document_materializations(id,document_id,org_id,sequence,origin_commitment,source_json,source_commitment,pdf_key,pdf_sha256,pdf_version_id,page_count,created_by) VALUES($1,$2,$3,1,$4,$5::jsonb,$4,$6,$7,$8,2,$9)`, mid, doc.ID, f.org, unhex(cid), doc.HtmlSourceJson, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID.String, f.grantor)
	execOK(t, f.ctx, tx, `UPDATE documents SET html_current_materialization_id=$2,html_current_source_json=html_source_json,html_current_materialization_sequence=1,html_current_page_count=2,html_reviewed_pdf_sha256=pdf_sha256,html_reviewed_materialization_id=$2,html_reviewed_by=$3,html_reviewed_at=clock_timestamp() WHERE id=$1`, doc.ID, mid, f.grantor)
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("commit source3 synthetic layout", err)
	}
	f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	f.rows, f.fields = rows, fields
}
func (f *executionFixture) newDraft(t testing.TB) {
	t.Helper()
	doc := *f.doc
	doc.ID = uuid.New()
	doc.Status = "draft"
	doc.HtmlCurrentSourceJson = nil
	doc.HtmlCurrentMaterializationID = pgtype.UUID{}
	doc.HtmlCurrentPageCount = pgtype.Int4{}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{}
	doc.HtmlReviewedMaterializationID = pgtype.UUID{}
	doc.HtmlReviewedPdfSha256 = nil
	doc.HtmlReviewedBy = pgtype.UUID{}
	doc.HtmlReviewedAt = pgtype.Timestamptz{}
	rows := make([]*generated.Recipient, 2)
	in := f.input
	in.PartyBindings = append([]htmlsource.PartyBinding(nil), in.PartyBindings...)
	for i, r := range f.rows {
		copy := *r
		copy.ID = uuid.New()
		copy.DocumentID = doc.ID
		rows[i] = &copy
		for j, b := range in.PartyBindings {
			if b.Slot == r.Role {
				in.PartyBindings[j].RecipientID = copy.ID
			}
		}
	}
	master, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	in.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: in.Values, Sections: in.Sections}, in.PartyBindings, in.SigningArtifact.Composition)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = htmlsource.New(in, &doc)
	if err != nil {
		t.Fatal(err)
	}
	f.input = in
	f.seedDocument(t, &doc, rows)
}
func (f *executionFixture) prepare(t testing.TB, tx pgx.Tx, requestID uuid.UUID, use int64) Record {
	t.Helper()
	q := generated.New(tx)
	key := RequestKey{OrgID: f.org, Executor: f.policy.Snapshot().Executor, RequestID: requestID}
	if err := q.LockPresignExecutionRequest(f.ctx, generated.LockPresignExecutionRequestParams{OrgID: key.OrgID, ExecutorKind: key.Executor.Kind, ExecutorUserID: key.Executor.UserID, ExecutorCredentialID: key.Executor.CredentialID, RequestID: key.RequestID}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: f.grantor, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.GetPresignGrantHeadForUpdate(f.ctx, generated.GetPresignGrantHeadForUpdateParams{OrgID: f.org, ID: f.grant.Snapshot().ID}); err != nil {
		t.Fatal(err)
	}
	doc, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	a, err := presignregistry.EvaluateExecutionData(f.definition, f.grant.Snapshot().Grantor, doc, nil, time.Now().UTC())
	if err != nil {
		t.Fatal("actual data admission", err)
	}
	intent, err := q.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{DocumentID: doc.ID, OrgID: f.org, ActorUserID: pgtype.UUID{Bytes: f.grantor, Valid: true}, ActorEmail: f.grant.Snapshot().Grantor.Email, Via: "presign", Tool: "synthetic-persistence-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	ad := a.Snapshot()
	cid, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		t.Fatal("actual source3 signing plan", err)
	}
	d := presign.DocumentSnapshot{ID: doc.ID, OrgID: f.org, SenderID: f.grantor, Kind: "pdf", SourceSchemaVersion: 3, RequiresSignature: true, SigningMode: "parallel", Template: f.policy.Snapshot().Template,
		Materialization:   presign.MaterializationPin{ID: uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes), Revision: int64(doc.HtmlCurrentMaterializationSequence.Int32), SourceCommitment: cid},
		BasePDF:           presign.PDFPin{Artifact: presign.ArtifactPin{StorageKey: doc.PdfStorageKey.String, VersionID: doc.PdfStorageVersionID.String, SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: 1000}, Pages: 2},
		SigningPlanSHA256: artifact.PlanSHA256, BrandingSHA256: fixtureHash("synthetic reviewed branding"), ValuesSHA256: ad.ValuesSHA256, SectionsSHA256: ad.SectionsSHA256, ReviewEvidenceSHA256: ad.ReviewEvidenceSHA256, DataEvidenceSHA256: a.Commitment()}
	for n, slot := range []string{"customer", "provider"} {
		for _, r := range f.rows {
			if r.Role == slot {
				d.Parties[n] = presign.PartySnapshot{ID: r.ID, Slot: slot, Role: slot, Name: r.Name, Email: r.Email, CompanyName: f.input.Values[slot+"_company"], CompanyID: f.input.Values[slot+"_company_id"], AuthorityBasis: f.input.Values[slot+"_authority"]}
			}
		}
		for _, field := range f.fields {
			if uuid.UUID(field.RecipientID.Bytes) == d.Parties[n].ID {
				y := int64(420000)
				if slot == "provider" {
					y = 790000
				}
				d.Fields[n] = presign.FieldSnapshot{ID: field.ID, RecipientID: d.Parties[n].ID, Slot: slot, Type: "signature", Required: true, Page: 2, X: 100000, Y: y, W: 800000, H: 70000, SourceCommitment: cid, OptionsSHA256: fixtureHash(string(field.OptionsJson))}
			}
		}
	}
	when, err := q.GetPresignClock(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	signatureID := uuid.New()
	e, err := presign.NewExecution(presign.ExecutionSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: f.org, Policy: f.policy.Reference(), Grant: f.grant.Reference(), Executor: f.policy.Snapshot().Executor, Document: d, CeremonyEpoch: intent.Article13NoticeEpochAt.Time.UTC(), ExecutedAt: when.Time.UTC(), UseNumber: use,
		Signature:  presign.SignatureArtifact{ID: signatureID, RecipientID: d.Parties[1].ID, FieldID: d.Fields[1].ID, TypedName: f.grant.Snapshot().Grantor.Name, Style: f.grant.Snapshot().Signature, Image: presign.ArtifactPin{StorageKey: "org/" + f.org.String() + "/documents/" + doc.ID.String() + "/signature-" + signatureID.String() + ".png", VersionID: "synthetic-image-v1", SHA256: fixtureHash("synthetic provider image"), Bytes: 300}},
		VisiblePDF: presign.PDFPin{Artifact: presign.ArtifactPin{StorageKey: "org/" + f.org.String() + "/documents/" + doc.ID.String() + "/provider-visible.pdf", VersionID: "synthetic-visible-v1", SHA256: fixtureHash("synthetic visible PDF"), Bytes: 1100}, Pages: 2}, VisibleStampProofSHA256: fixtureHash("synthetic stamp descriptor")})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewCommand(CommandSnapshot{SchemaVersion: 1, OrgID: f.org, Executor: e.Snapshot().Executor, RequestID: requestID, DocumentID: doc.ID, Document: d, Policy: f.policy.Reference(), Grant: f.grant.Reference(), SourceCommitment: cid, AdmissionSHA256: a.Commitment(), OriginalCredentialSHA256: fixtureHash("synthetic originally authenticated executor")})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := AuditPayload(e, c)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.logger.LogTx(f.ctx, tx, audit.Entry{OrgID: f.org, DocumentID: &doc.ID, RecipientID: &d.Parties[1].ID, ActorUserID: &f.grantor, Kind: AuditKindCommitted, Payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRecord(f.policy, f.grant, e, c, a, pending.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func commitExecution(t testing.TB, f *executionFixture, use int64) Record {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	r := f.prepare(t, tx, uuid.New(), use)
	if _, err = r.AppendAtomic(f.ctx, tx); err != nil {
		t.Fatal("append complete atomic tuple", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("commit complete atomic tuple", err)
	}
	return r
}
func requireCheckRefusal(t testing.TB, err error) {
	t.Helper()
	var p *pgconn.PgError
	if !errors.As(err, &p) || p.Code != "23514" {
		t.Fatal("expected exact database check refusal", err)
	}
}

func TestPresignExecutionAtomicPairAndRetainedRecoveryE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	r := commitExecution(t, f, 1)
	var token []byte
	var expiry pgtype.Timestamptz
	if err := f.pool.QueryRow(f.ctx, `SELECT magic_token_hash,magic_token_expires_at FROM recipients WHERE id=$1`, r.execution.Snapshot().Signature.RecipientID).Scan(&token, &expiry); err != nil || len(token) != 0 || !expiry.Valid || expiry.InfinityModifier != pgtype.Finite || !expiry.Time.Equal(time.Unix(0, 0).UTC()) {
		t.Fatal("delegated provider did not retain exact inert token sentinel", err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	out, err := LoadOutcome(f.ctx, tx, r.command.RequestKey())
	if err != nil || out.State != "committed" || out.Record.Execution().Commitment() != r.execution.Commitment() {
		t.Fatal("committed integrity recovery failed", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	execOK(t, f.ctx, f.pool, `UPDATE users SET role='viewer' WHERE id=$1`, f.grantor)
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	out, err = LoadOutcome(f.ctx, tx, r.command.RequestKey())
	if err != nil || out.State != "committed" {
		t.Fatal("terminal grant revocation erased committed evidence", err)
	}
	var uses, consumed, sigs int64
	if err = tx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_execution_uses),(SELECT consumed_uses FROM presign_grant_revisions WHERE grant_id=$1),(SELECT count(*) FROM signatures)`, f.grant.Snapshot().ID).Scan(&uses, &consumed, &sigs); err != nil || uses != 1 || consumed != 0 || sigs != 1 {
		t.Fatal("recovery consumed another use or signature", err)
	}
	wrong := r.command.RequestKey()
	wrong.OrgID = uuid.New()
	if _, err = LoadOutcome(f.ctx, tx, wrong); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("foreign tenant readback succeeded")
	}
}

func TestPresignExecutionIncompletePairRollsBackE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	for _, name := range []string{"missing_use", "missing_signature"} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			r := f.prepare(t, tx, uuid.New(), 1)
			q := generated.New(tx)
			x := r.execution.Snapshot()
			if _, err = q.InsertPresignExecution(f.ctx, generated.InsertPresignExecutionParams{CanonicalExecution: r.execution.CanonicalJSON(), ExecutionSha256: unhex(r.execution.Commitment()), RequestID: r.command.RequestKey().RequestID, CommandCanonical: r.command.CanonicalJSON(), CommandSha256: unhex(r.command.Commitment()), OriginalCredentialSha256: unhex(r.command.Snapshot().OriginalCredentialSHA256), AdmissionCanonical: r.admission.CanonicalJSON(), AdmissionSha256: unhex(r.admission.Commitment()), AuditEventID: r.auditEventID}); err != nil {
				t.Fatal(err)
			}
			if name != "missing_use" {
				if err = q.InsertPresignExecutionUse(f.ctx, generated.InsertPresignExecutionUseParams{OrgID: f.org, ID: x.ID}); err != nil {
					t.Fatal(err)
				}
			}
			if name != "missing_signature" {
				if _, err = q.InsertPresignDelegatedSignature(f.ctx, generated.InsertPresignDelegatedSignatureParams{OrgID: f.org, ID: x.ID}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = q.MarkPresignProviderSigned(f.ctx, generated.MarkPresignProviderSignedParams{OrgID: f.org, ID: x.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err = q.BindPresignSealingIntent(f.ctx, generated.BindPresignSealingIntentParams{OrgID: f.org, ID: x.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err = q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{OrgID: f.org, ID: f.doc.ID}); err != nil {
				t.Fatal(err)
			}
			if _, err = q.InsertCommittedPresignExecutionRequest(f.ctx, generated.InsertCommittedPresignExecutionRequestParams{OrgID: f.org, ID: x.ID}); err != nil {
				t.Fatal(err)
			}
			// All other rows/statuses exist: select the precise missing relation
			// guard rather than relying on deferred-trigger ordering at COMMIT.
			if name == "missing_use" {
				_, err = tx.Exec(f.ctx, `SET CONSTRAINTS presign_execution_exact_use IMMEDIATE`)
				var p *pgconn.PgError
				if !errors.As(err, &p) || p.Code != "23503" {
					t.Fatal("missing use did not refuse exact pairing FK", err)
				}
			} else {
				_, err = tx.Exec(f.ctx, `SET CONSTRAINTS presign_execution_complete IMMEDIATE`)
				requireCheckRefusal(t, err)
			}
			if err = tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
	var count int64
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_executions)+(SELECT count(*) FROM presign_execution_uses)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM send_sealing_intents)+(SELECT count(*) FROM events)+(SELECT count(*) FROM documents WHERE status<>'draft')+(SELECT count(*) FROM recipients WHERE status<>'pending')`).Scan(&count); err != nil || count != 0 {
		t.Fatal("incomplete tuple escaped rollback", err)
	}
}

func TestPresignExecutionSelectedRevisionAllowanceE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	first := commitExecution(t, f, 1)
	f.newDraft(t)
	second := commitExecution(t, f, 2)
	f.newDraft(t)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	r := f.prepare(t, tx, uuid.New(), 2)
	if _, err = r.AppendAtomic(f.ctx, tx); !errors.Is(err, ErrConflict) {
		t.Fatal("exhausted selected revision admitted", err)
	}
	_ = tx.Rollback(f.ctx)
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	gs := f.grant.Snapshot()
	gs.Revision = 2
	gs.GrantedAt = time.Now().UTC().Truncate(time.Microsecond)
	gs.NotBefore = gs.GrantedAt
	gs.ExpiresAt = gs.GrantedAt.Add(20 * time.Minute)
	renewed, err := presign.NewGrant(gs)
	if err != nil {
		t.Fatal(err)
	}
	f.insertGrant(t, tx, renewed)
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.grant = renewed
	third := commitExecution(t, f, 1)
	if first.execution.Snapshot().UseNumber != 1 || second.execution.Snapshot().UseNumber != 2 || third.execution.Snapshot().UseNumber != 1 {
		t.Fatal("per-revision contiguous allowance changed")
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = LoadOutcome(f.ctx, tx, first.command.RequestKey()); err != nil {
		t.Fatal("renewal erased old execution", err)
	}
	var consumed int64
	if err = tx.QueryRow(f.ctx, `SELECT sum(consumed_uses) FROM presign_grant_revisions`).Scan(&consumed); err != nil || consumed != 0 {
		t.Fatal("historical immutable grant row mutated", err)
	}
}

func TestPresignExecutionOriginalNonceStopE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	key := RequestKey{OrgID: f.org, Executor: f.policy.Snapshot().Executor, RequestID: uuid.New()}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	q := generated.New(tx)
	if err = q.LockPresignExecutionRequest(f.ctx, generated.LockPresignExecutionRequestParams{OrgID: key.OrgID, ExecutorKind: key.Executor.Kind, ExecutorUserID: key.Executor.UserID, ExecutorCredentialID: key.Executor.CredentialID, RequestID: key.RequestID}); err != nil {
		t.Fatal(err)
	}
	pending, err := f.logger.LogTx(f.ctx, tx, audit.Entry{OrgID: f.org, ActorUserID: &f.grantor, Kind: AuditKindClosed, Payload: map[string]any{"request_id": key.RequestID, "executor_kind": key.Executor.Kind, "executor_user_id": key.Executor.UserID, "executor_credential_id": key.Executor.CredentialID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.InsertClosedPresignExecutionRequest(f.ctx, generated.InsertClosedPresignExecutionRequestParams{OrgID: f.org, ExecutorKind: key.Executor.Kind, ExecutorUserID: key.Executor.UserID, ExecutorCredentialID: key.Executor.CredentialID, RequestID: key.RequestID, OriginalCredentialSha256: unhex(fixtureHash("original stop credential")), AuditEventID: pending.ID}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	out, err := LoadOutcome(f.ctx, tx, key)
	if err != nil || out.State != "closed" || out.Record != nil {
		t.Fatal("closed nonce readback", err)
	}
	r := f.prepare(t, tx, key.RequestID, 1)
	if _, err = r.AppendAtomic(f.ctx, tx); !errors.Is(err, ErrConflict) {
		t.Fatal("closed nonce resurrected", err)
	}
	_ = tx.Rollback(f.ctx)
	var count int64
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_executions)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM send_sealing_intents)`).Scan(&count); err != nil || count != 0 {
		t.Fatal("closed nonce created execution effects", err)
	}
}

func TestPresignExecutionRetainsExactPairBeforeRetentionE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	r := commitExecution(t, f, 1)
	x := r.execution.Snapshot()
	for name, sql := range map[string]string{
		"execution_delete":          `DELETE FROM presign_executions WHERE document_id=$1`,
		"execution_rewrite":         `UPDATE presign_executions SET use_number=2 WHERE document_id=$1`,
		"use_delete":                `DELETE FROM presign_execution_uses WHERE execution_id=(SELECT id FROM presign_executions WHERE document_id=$1)`,
		"outcome_delete":            `DELETE FROM presign_execution_requests WHERE execution_id=(SELECT id FROM presign_executions WHERE document_id=$1)`,
		"signature_delete":          `DELETE FROM signatures WHERE document_id=$1`,
		"signature_manual_metadata": `UPDATE signatures SET signer_ua='invented portal' WHERE document_id=$1`,
		"document_reopen":           `UPDATE documents SET status='draft' WHERE id=$1`,
		"document_delete":           `DELETE FROM documents WHERE id=$1`,
		"intent_abort":              `DELETE FROM send_sealing_intents WHERE document_id=$1`,
		"intent_epoch":              `UPDATE send_sealing_intents SET article13_notice_epoch_at=article13_notice_epoch_at+interval '1 microsecond' WHERE document_id=$1`,
		"provider_token_renewal":    `UPDATE recipients SET magic_token_hash=decode(repeat('aa',32),'hex'),magic_token_expires_at=clock_timestamp()+interval '1 hour' WHERE document_id=$1 AND role='provider'`,
		"provider_downgrade":        `UPDATE recipients SET status='pending',signed_at=NULL WHERE document_id=$1 AND role='provider'`,
		"field_delete":              `DELETE FROM document_fields WHERE document_id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			_, err = tx.Exec(f.ctx, sql, x.Document.ID)
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			requireCheckRefusal(t, err)
		})
	}
	execOK(t, f.ctx, f.pool, `UPDATE send_sealing_intents SET attempts=attempts+1,last_error='synthetic bounded retry' WHERE document_id=$1`, x.Document.ID)
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	out, err := LoadOutcome(f.ctx, tx, r.command.RequestKey())
	if err != nil || !bytes.Equal(out.Record.Execution().CanonicalJSON(), r.execution.CanonicalJSON()) {
		t.Fatal("allowed retry changed immutable evidence", err)
	}
}

func TestPresignExecutionGrantHeadWaitUsesFreshAllowanceE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	firstDraft := *f
	f.newDraft(t)
	secondDraft := *f
	firstTx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer firstTx.Rollback(f.ctx)
	first := firstDraft.prepare(t, firstTx, uuid.New(), 1)
	if _, err = first.AppendAtomic(f.ctx, firstTx); err != nil {
		t.Fatal(err)
	}
	secondTx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer secondTx.Rollback(f.ctx)
	q := generated.New(secondTx)
	key := RequestKey{OrgID: f.org, Executor: f.policy.Snapshot().Executor, RequestID: uuid.New()}
	if err = q.LockPresignExecutionRequest(f.ctx, generated.LockPresignExecutionRequestParams{OrgID: key.OrgID, ExecutorKind: key.Executor.Kind, ExecutorUserID: key.Executor.UserID, ExecutorCredentialID: key.Executor.CredentialID, RequestID: key.RequestID}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: f.grantor, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := q.GetPresignGrantHeadForUpdate(f.ctx, generated.GetPresignGrantHeadForUpdateParams{OrgID: f.org, ID: f.grant.Snapshot().ID})
		finished <- err
	}()
	// Observe the actual second PostgreSQL backend blocked on the retained
	// grant head. A timer alone would not establish database contention.
	pid := secondTx.Conn().PgConn().PID()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	waiting := false
	for !waiting {
		select {
		case err := <-finished:
			t.Fatal("contending grant-head query finished before first commit", err)
		case <-deadline.C:
			t.Fatal("actual grant-head wait was not observed")
		case <-ticker.C:
			if err = f.pool.QueryRow(f.ctx, `SELECT COALESCE(wait_event_type='Lock',false) FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err = firstTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-f.ctx.Done():
		t.Fatal("contending head never released")
	}
	next, err := q.NextPresignExecutionUse(f.ctx, generated.NextPresignExecutionUseParams{OrgID: f.org, GrantID: f.grant.Snapshot().ID, GrantRevision: 1})
	if err != nil || next != 2 {
		t.Fatal("post-wait allowance missed the committed first use", err)
	}
	second := secondDraft.prepare(t, secondTx, key.RequestID, int64(next))
	if _, err = second.AppendAtomic(f.ctx, secondTx); err != nil {
		t.Fatal(err)
	}
	if err = secondTx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	var count, sum int64
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*),sum(use_number) FROM presign_execution_uses WHERE org_id=$1 AND grant_id=$2 AND grant_revision=1`, f.org, f.grant.Snapshot().ID).Scan(&count, &sum); err != nil || count != 2 || sum != 3 {
		t.Fatal("serialized selected-revision allowance was not contiguous", err)
	}
}

func TestPresignExecutionAuditPairFailureRollsBackE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	for _, name := range []string{"missing_audit", "wrong_audit_kind"} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			r := f.prepare(t, tx, uuid.New(), 1)
			if name == "missing_audit" {
				r.auditEventID = uuid.New()
			} else {
				pending, err := f.logger.LogTx(f.ctx, tx, audit.Entry{OrgID: f.org, ActorUserID: &f.grantor, Kind: "synthetic.unrelated", Payload: map[string]any{"synthetic": true}})
				if err != nil {
					t.Fatal(err)
				}
				r.auditEventID = pending.ID
			}
			_, err = r.AppendAtomic(f.ctx, tx)
			if name == "missing_audit" {
				var p *pgconn.PgError
				if !errors.As(err, &p) || p.Code != "23503" {
					t.Fatal("missing audit did not refuse its exact foreign key", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(f.ctx, `SET CONSTRAINTS presign_execution_complete IMMEDIATE`)
				requireCheckRefusal(t, err)
			}
			if err = tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			var count int64
			if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_executions)+(SELECT count(*) FROM presign_execution_uses)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM send_sealing_intents)+(SELECT count(*) FROM events)+(SELECT count(*) FROM documents WHERE status<>'draft')+(SELECT count(*) FROM recipients WHERE status<>'pending')`).Scan(&count); err != nil || count != 0 {
				t.Fatal("failed audit left delegation, sealing or ceremony effects", err)
			}
		})
	}
}

func TestPresignExecutionPriorEpochAndExactPublicationE2E(t *testing.T) {
	prior := time.Now().UTC().Truncate(time.Microsecond).Add(-2 * time.Hour)
	f := setupExecutionNoticeE2E(t, pgtype.Timestamptz{Time: prior, Valid: true})
	r := commitExecution(t, f, 1)
	epoch := r.execution.Snapshot().CeremonyEpoch
	if !epoch.After(prior) {
		t.Fatal("new committed intent did not advance the retained prior epoch")
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = LoadOutcome(f.ctx, tx, r.command.RequestKey()); err != nil {
		t.Fatal("sealing integrity refused a retained finite prior epoch", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]struct {
		sql   string
		epoch any
	}{
		"sealing_future_epoch": {`UPDATE documents SET article13_notice_epoch_at=$2 WHERE id=$1`, epoch.Add(time.Hour)},
		"published_null":       {`UPDATE documents SET status='sent',sent_at=$3,article13_notice_epoch_at=$2,article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=true WHERE id=$1`, nil},
		"published_mismatch":   {`UPDATE documents SET status='sent',sent_at=$3,article13_notice_epoch_at=$2,article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=true WHERE id=$1`, epoch.Add(time.Microsecond)},
		"published_nonfinite":  {`UPDATE documents SET status='sent',sent_at=$3,article13_notice_epoch_at=$2,article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=true WHERE id=$1`, pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity}},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			args := []any{f.doc.ID, change.epoch}
			if name != "sealing_future_epoch" {
				args = append(args, epoch)
			}
			_, err = tx.Exec(f.ctx, change.sql, args...)
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			var p *pgconn.PgError
			if !errors.As(err, &p) || (p.Code != "23514" && !(p.Code == "P0001" && strings.Contains(p.Message, "only advance during sealing-to-sent"))) {
				t.Fatal("exact epoch mutation escaped the layered publication guards", err)
			}
		})
	}
	// Synthetic publication is a state transition, never another execution
	// use, customer notice delivery or acknowledgment. Preserve migration61's
	// actual chained document.sent marker requirement in the same transaction,
	// deriving its epoch/schema from the authoritative returned document row.
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	var sentAt pgtype.Timestamptz
	var schema string
	if err = tx.QueryRow(f.ctx, `UPDATE documents SET status='sent',sent_at=$2,article13_notice_epoch_at=$2,article13_notice_schema='hash-a13-2026-08-31',article13_notice_epoch_v61_committed=true WHERE id=$1 RETURNING sent_at,article13_notice_schema`, f.doc.ID, epoch).Scan(&sentAt, &schema); err != nil || !sentAt.Valid || !sentAt.Time.Equal(epoch) || schema != article13.CurrentSchema {
		t.Fatal("authoritative synthetic publication tuple", err)
	}
	canonicalSentAt, err := article13.CanonicalSentAt(sentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.logger.LogTx(f.ctx, tx, audit.Entry{OrgID: f.org, DocumentID: &f.doc.ID, ActorUserID: &f.grantor, Kind: audit.KindDocumentSent, Payload: map[string]any{
		article13.AuditRequiredNoticeSchemaKey: schema, article13.AuditRequiredNoticeSentAtKey: canonicalSentAt, "synthetic_publication_marker": true,
	}}); err != nil {
		t.Fatal("chained synthetic publication marker", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("commit authoritative synthetic publication", err)
	}
	tx, err = f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx)
	if _, err = LoadOutcome(f.ctx, tx, r.command.RequestKey()); err != nil {
		t.Fatal("exact published epoch failed retained integrity", err)
	}
}

func TestPresignExecutionSelfConsistentCapturedPlanForgeryRefusedE2E(t *testing.T) {
	f := setupExecutionE2E(t)
	for name, mutate := range map[string]func(*presign.ExecutionSnapshot){
		"signing_plan": func(s *presign.ExecutionSnapshot) {
			s.Document.SigningPlanSHA256 = fixtureHash("forged self-consistent plan")
		},
		"customer_identity": func(s *presign.ExecutionSnapshot) {
			id := uuid.New()
			s.Document.Parties[0].ID = id
			s.Document.Fields[0].RecipientID = id
		},
		"customer_field":   func(s *presign.ExecutionSnapshot) { s.Document.Fields[0].ID = uuid.New() },
		"customer_company": func(s *presign.ExecutionSnapshot) { s.Document.Parties[0].CompanyName = "Forged Customer AB" },
		"customer_options": func(s *presign.ExecutionSnapshot) {
			s.Document.Fields[0].OptionsSHA256 = fixtureHash("forged customer options")
		},
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(f.ctx)
			r := f.prepare(t, tx, uuid.New(), 1)
			s := r.execution.Snapshot()
			mutate(&s)
			e, err := presign.NewExecution(s)
			if err != nil {
				t.Fatal("forgery was not internally well-formed", err)
			}
			command := r.command.Snapshot()
			command.Document = s.Document
			c, err := NewCommand(command)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := AuditPayload(e, c)
			if err != nil {
				t.Fatal(err)
			}
			pending, err := f.logger.LogTx(f.ctx, tx, audit.Entry{OrgID: f.org, DocumentID: &f.doc.ID, RecipientID: &s.Signature.RecipientID, ActorUserID: &f.grantor, Kind: AuditKindCommitted, Payload: payload})
			if err != nil {
				t.Fatal(err)
			}
			forged, err := NewRecord(f.policy, f.grant, e, c, r.admission, pending.ID)
			if err != nil {
				t.Fatal("typed forgery must reach actual source/row guard", err)
			}
			if _, err = forged.AppendAtomic(f.ctx, tx); err != nil {
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, `SET CONSTRAINTS presign_execution_complete IMMEDIATE`)
			requireCheckRefusal(t, err)
			if err = tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			var count int64
			if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM presign_executions)+(SELECT count(*) FROM presign_execution_uses)+(SELECT count(*) FROM signatures)+(SELECT count(*) FROM send_sealing_intents)+(SELECT count(*) FROM events)+(SELECT count(*) FROM documents WHERE status<>'draft')+(SELECT count(*) FROM recipients WHERE status<>'pending')`).Scan(&count); err != nil || count != 0 {
				t.Fatal("captured forgery left durable effects", err)
			}
		})
	}
}
