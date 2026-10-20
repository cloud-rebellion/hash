//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Schema-only tests use the existing isolated real-PG242 owner. Explicit
// synthetic rows/retention checkpoints below are NOT native signing, provider
// retention, issued evidence, complete report or production acceptance claims.
// No migration/trigger/constraint is disabled to manufacture a passing fixture.
func TestParticipantReportSchemaUpgradeAndNativeSelection404E2E(t *testing.T) {
	f := migrationPG242(t)
	reportSchemaMigrate404(t, f, 112)
	org, user := reportSchemaTenant404(t, f)
	draft := reportSchemaDocument404(t, f, org, user, "draft", uuid.Nil, 0, false)
	oldFinal := reportSchemaDocument404(t, f, org, user, "finalizing", uuid.Nil, 0, false)
	oldPrepared := reportSchemaDocument404(t, f, org, user, "finalizing", uuid.Nil, 0, false)
	if _, err := f.admin.Exec(f.ctx, `INSERT INTO document_ordinary_finalization_preparations_v1(document_id,org_id,mode,completion_effective_at,cutoff,retain_until,final_pdf_sha256) SELECT id,org_id,'signature',completion_effective_at,updated_at,finalization_retain_until,digest('old retained PDF','sha256') FROM documents WHERE id=$1`, oldPrepared); err != nil {
		t.Fatal("seed explicit old112 preparation", err)
	}
	if _, err := f.admin.Exec(f.ctx, `UPDATE document_ordinary_finalization_preparations_v1 SET certificate_render_html=convert_to('<html>old exact frozen input Å</html>','UTF8'),certificate_render_sha256=digest(convert_to('<html>old exact frozen input Å</html>','UTF8'),'sha256'),report_cutoff=cutoff,history_rows=1,report_sha256=digest('old exact report','sha256'),certificate_input_frozen=true WHERE document_id=$1`, oldPrepared); err != nil {
		t.Fatal("seed exact old112 frozen certificate input", err)
	}
	before := reportSchemaState404(t, f)
	for _, table := range []string{"documents", "document_ordinary_finalization_preparations_v1", "document_participant_reports_v1"} {
		holder := manualProposalMigrationHolder268(t, f, "LOCK TABLE public."+table+" IN SHARE MODE")
		reportSchemaRefusal404(t, f, before, mdb.RunMigrationsUpToContext(f.ctx, f.db, 113), "55P03", "")
		manualProposalMigrationRelease268(t, holder)
	}
	reportSchemaMigrate404(t, f, 113)
	after := reportSchemaState404(t, f)
	if before.data != after.data || before.oldGuards != after.oldGuards {
		t.Fatal("M113 altered old112 rows/clocks or original M108/M109/M111 guards")
	}
	for _, id := range []uuid.UUID{draft, oldFinal, oldPrepared} {
		reportSchemaPin404(t, f, id, render.ParticipantReportSchemaV1)
	}
	var oldPin string
	if err := f.admin.QueryRow(f.ctx, "SELECT report_schema FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1", oldPrepared).Scan(&oldPin); err != nil || oldPin != render.ParticipantReportSchemaV1 {
		t.Fatal("old preparation relabelled", err)
	}
	fresh := reportSchemaDocument404(t, f, org, user, "draft", uuid.Nil, 0, false)
	reportSchemaPin404(t, f, fresh, render.ParticipantReportSchemaV2)
	// Use the existing generated real Send/freeze query owners. No UPDATE of a
	// draft pin, pre-supplied future clock, or callback selects the new version.
	reportSchemaSend404(t, f, org, user, draft, nil)
	q := generated.New(f.admin)
	claimed, err := q.BeginDocumentFinalization(f.ctx, generated.BeginDocumentFinalizationParams{ID: draft, OrgID: org, RetentionYears: 7})
	if err != nil || claimed.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !claimed.CompletionEffectiveAt.Valid || claimed.UpdatedAt.Time.Before(claimed.CompletionEffectiveAt.Time) {
		t.Fatal("fresh preexisting draft did not select exact V2/clock at native freeze", err)
	}
	for _, tc := range []struct {
		name   string
		id     uuid.UUID
		schema string
	}{{"old finalizing without prep", oldFinal, render.ParticipantReportSchemaV2}, {"old prepared", oldPrepared, render.ParticipantReportSchemaV2}, {"fresh frozen root", draft, render.ParticipantReportSchemaV1}} {
		t.Run(tc.name, func(t *testing.T) {
			before := reportSchemaState404(t, f)
			_, err := f.admin.Exec(f.ctx, "UPDATE documents SET participant_report_schema=$2 WHERE id=$1", tc.id, tc.schema)
			reportSchemaRefusal404(t, f, before, err, "23514", "retained participant report selection is immutable")
		})
	}
	for _, tc := range []struct{ name, columns, value string }{{"old worker omits pin", "", ""}, {"wrong supported pin", ",report_schema", ",'hash-participant-report-v1'"}, {"unknown pin", ",report_schema", ",'unknown'"}} {
		t.Run(tc.name, func(t *testing.T) {
			before := reportSchemaState404(t, f)
			_, err := f.admin.Exec(f.ctx, `INSERT INTO document_ordinary_finalization_preparations_v1(document_id,org_id,mode,completion_effective_at,cutoff,retain_until,final_pdf_sha256`+tc.columns+`) SELECT id,org_id,'signature',completion_effective_at,updated_at,finalization_retain_until,digest('new PDF','sha256')`+tc.value+` FROM documents WHERE id=$1`, draft)
			reportSchemaRefusal404(t, f, before, err, "23514", "ordinary participant report selection differs from document")
		})
	}
	finalSHA := sha256.Sum256([]byte("new PDF"))
	if rows, err := q.CaptureOrdinaryFinalizationPreparationV1(f.ctx, generated.CaptureOrdinaryFinalizationPreparationV1Params{Mode: "signature", FinalPdfSha256: finalSHA[:], DocumentID: draft, OrgID: org, CompletionEffectiveAt: claimed.CompletionEffectiveAt, Cutoff: claimed.UpdatedAt}); err != nil || rows != 1 {
		t.Fatal("correct actual pin capture failed", rows, err)
	}
	before = reportSchemaState404(t, f)
	_, err = f.admin.Exec(f.ctx, "UPDATE document_ordinary_finalization_preparations_v1 SET report_schema=$2 WHERE document_id=$1", draft, render.ParticipantReportSchemaV1)
	reportSchemaRefusal404(t, f, before, err, "23514", "ordinary participant report selection")
	args := generated.FreezeOrdinaryFinalizationCertificateInputV1Params{RenderHtml: []byte("<html>schema-only fixture</html>"), ReportCutoff: claimed.UpdatedAt, HistoryRows: 0, ReportSha256: bytes.Repeat([]byte{3}, 32), DocumentID: draft, OrgID: org, ReportSchema: render.ParticipantReportSchemaV1}
	before = reportSchemaState404(t, f)
	if rows, err := q.FreezeOrdinaryFinalizationCertificateInputV1(f.ctx, args); err != nil || rows != 0 || reportSchemaState404(t, f) != before {
		t.Fatal("wrong private Freeze pin did not refuse by exact zero-row predicate", rows, err)
	}
	args.ReportSchema = render.ParticipantReportSchemaV2
	if rows, err := q.FreezeOrdinaryFinalizationCertificateInputV1(f.ctx, args); err != nil || rows != 1 {
		t.Fatal("correct V2 Freeze failed", rows, err)
	}
	before = reportSchemaState404(t, f)
	_, err = f.admin.Exec(f.ctx, "UPDATE document_ordinary_finalization_preparations_v1 SET report_schema=$2 WHERE document_id=$1", draft, render.ParticipantReportSchemaV1)
	reportSchemaRefusal404(t, f, before, err, "23514", "ordinary participant report selection")
	// Raw generated.Document must not create an accidental REST/MCP selector.
	raw, err := json.Marshal(claimed)
	if err != nil || bytes.Contains(raw, []byte("participant_report_schema")) || bytes.Contains(raw, []byte("ParticipantReportSchema")) || bytes.Contains(raw, []byte(render.ParticipantReportSchemaV2)) {
		t.Fatal("generated native document pin leaked through JSON", err)
	}
	manualProposalMigrationUnlocked268(t, f)
	migrationPoolRetired242(t, f, f.db, f.name)
}

func TestParticipantReportSchemaFamilyAndRetainedReceipt404E2E(t *testing.T) {
	f := migrationPG242(t)
	reportSchemaMigrate404(t, f, 112)
	org, user := reportSchemaTenant404(t, f)
	root := reportSchemaDocument404(t, f, org, user, "draft", uuid.Nil, 0, true)
	child := reportSchemaDocument404(t, f, org, user, "draft", root, 1, false)
	reportSchemaMigrate404(t, f, 113)
	q := generated.New(f.admin)
	// A child with no events still belongs to native history scope. This is a
	// schema selection witness, not a claim of a completed family ceremony.
	h, err := q.GetParticipantReportHeaderV1(f.ctx, generated.GetParticipantReportHeaderV1Params{DocumentID: root, OrgID: org, Cutoff: pgtype.Timestamptz{Time: time.Now(), Valid: true}})
	if err != nil || h.ScopeCount != 2 || h.RowCount != 0 || h.ReportSchema != render.ParticipantReportSchemaV1 {
		t.Fatal("silent child missing from header scope", err)
	}
	ids, err := q.ListParticipantReportHistoryScopeV2(f.ctx, generated.ListParticipantReportHistoryScopeV2Params{OrgID: org, DocumentID: root})
	if err != nil || len(ids) != 2 || ids[0].String() >= ids[1].String() || !((ids[0] == root && ids[1] == child) || (ids[0] == child && ids[1] == root)) {
		t.Fatal("exact sorted native scope differs", ids, err)
	}
	reportSchemaSend404(t, f, org, user, root, []uuid.UUID{child})
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	qt := q.WithTx(tx)
	if _, err = tx.Exec(f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", root, org); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(f.ctx, "SELECT id FROM documents WHERE parent_envelope_id=$1 AND org_id=$2 ORDER BY id FOR UPDATE", root, org); err != nil {
		t.Fatal(err)
	}
	claimed, err := qt.BeginDocumentFinalization(f.ctx, generated.BeginDocumentFinalizationParams{ID: root, OrgID: org, RetentionYears: 7})
	if err != nil {
		t.Fatal(err)
	}
	children, err := qt.BeginEnvelopeChildrenFinalization(f.ctx, generated.BeginEnvelopeChildrenFinalizationParams{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: org})
	if err != nil || len(children) != 1 || children[0].ID != child || children[0].ParticipantReportSchema != render.ParticipantReportSchemaV2 || !children[0].CompletionEffectiveAt.Time.Equal(claimed.CompletionEffectiveAt.Time) || !children[0].FinalizationRetainUntil.Time.Equal(claimed.FinalizationRetainUntil.Time) {
		t.Fatal("child did not inherit genuine frozen parent tuple", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	// Schema mismatch must be the NEW schema guard's refusal, not merely the
	// original M108 missing-intent or malformed-artifact guard.
	before := reportSchemaState404(t, f)
	_, err = f.admin.Exec(f.ctx, `INSERT INTO document_participant_reports_v1(document_id,org_id,completion_effective_at,schema_version,cutoff,history_rows,report_sha256,final_pdf_sha256,audit_cert_sha256,audit_payload_sha256,audit_signature_sha256) SELECT id,org_id,completion_effective_at,'hash-participant-report-v1',updated_at,0,digest('r','sha256'),digest('f','sha256'),digest('c','sha256'),digest('p','sha256'),digest('s','sha256') FROM documents WHERE id=$1`, root)
	reportSchemaRefusal404(t, f, before, err, "23514", "participant report receipt selection differs from frozen document")
	// A full synthetic four-output/intent/receipt transaction satisfies the
	// original M108/M109 deferred guards without disabling them. It establishes
	// retained DB schema evidence only, never actual signed/provider artifacts.
	reportSchemaRetainReceipt404(t, f, claimed)
	var exact bool
	if err = f.admin.QueryRow(f.ctx, `SELECT p.report_schema=d.participant_report_schema AND r.schema_version=p.report_schema AND p.staged_at IS NOT NULL AND (SELECT count(*) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=d.id AND o.version_id IS NOT NULL AND o.verified_at IS NOT NULL)=4 FROM documents d JOIN document_ordinary_finalization_preparations_v1 p ON p.document_id=d.id JOIN document_participant_reports_v1 r ON r.document_id=d.id AND r.completion_effective_at=d.completion_effective_at WHERE d.id=$1`, root).Scan(&exact); err != nil || !exact {
		t.Fatal("retained synthetic receipt did not satisfy all exact schema/old-output associations", err)
	}
	before = reportSchemaState404(t, f)
	reportSchemaRefusal404(t, f, before, mdb.RunMigrationsDownToContext(f.ctx, f.db, 112), "23514", "retained participant report V2 commitments prevent rollback")
	manualProposalMigrationUnlocked268(t, f)
	migrationPoolRetired242(t, f, f.db, f.name)
}

func TestParticipantReportSchemaRollbackAndLockRefusals404E2E(t *testing.T) {
	for _, drafts := range []bool{false, true} {
		name := "empty"
		if drafts {
			name = "draft-only defaults"
		}
		t.Run(name, func(t *testing.T) {
			f := migrationPG242(t)
			reportSchemaMigrate404(t, f, 112)
			reportSchemaMigrate404(t, f, 113)
			if drafts {
				org, user := reportSchemaTenant404(t, f)
				reportSchemaDocument404(t, f, org, user, "draft", uuid.Nil, 0, false)
			}
			before := reportSchemaState404(t, f)
			for _, table := range []string{"documents", "document_ordinary_finalization_preparations_v1", "document_participant_reports_v1"} {
				holder := manualProposalMigrationHolder268(t, f, "LOCK TABLE public."+table+" IN SHARE MODE")
				reportSchemaRefusal404(t, f, before, mdb.RunMigrationsDownToContext(f.ctx, f.db, 112), "55P03", "")
				manualProposalMigrationRelease268(t, holder)
			}
			if err := mdb.RunMigrationsDownToContext(f.ctx, f.db, 112); err != nil {
				t.Fatal("empty/uncommitted-default Down failed", err)
			}
			after := reportSchemaState404(t, f)
			if after.data != before.data || after.oldGuards != before.oldGuards {
				t.Fatal("successful metadata-only Down altered old source/clock/guards")
			}
			if got, err := mdb.GetMigrationVersionContext(f.ctx, f.db); err != nil || got != 112 {
				t.Fatal("Down head differs", got, err)
			}
			manualProposalMigrationUnlocked268(t, f)
			migrationPoolRetired242(t, f, f.db, f.name)
		})
	}
	for _, preparation := range []bool{false, true} {
		name := "committed clock without prep"
		if preparation {
			name = "retained V2 prep"
		}
		t.Run(name, func(t *testing.T) {
			f := migrationPG242(t)
			reportSchemaMigrate404(t, f, 112)
			reportSchemaMigrate404(t, f, 113)
			org, user := reportSchemaTenant404(t, f)
			id := reportSchemaDocument404(t, f, org, user, "finalizing", uuid.Nil, 0, false)
			if preparation {
				_, err := f.admin.Exec(f.ctx, `INSERT INTO document_ordinary_finalization_preparations_v1(document_id,org_id,mode,completion_effective_at,cutoff,retain_until,final_pdf_sha256,report_schema) SELECT id,org_id,'signature',completion_effective_at,updated_at,finalization_retain_until,digest('retained','sha256'),participant_report_schema FROM documents WHERE id=$1`, id)
				if err != nil {
					t.Fatal("seed exact synthetic V2 preparation", err)
				}
			}
			before := reportSchemaState404(t, f)
			reportSchemaRefusal404(t, f, before, mdb.RunMigrationsDownToContext(f.ctx, f.db, 112), "23514", "retained participant report V2 commitments prevent rollback")
			// Existing M59/M60 prohibit voiding a retained completion clock. Keep
			// those guards intact instead of manufacturing impossible voided rows.
			_, err := f.admin.Exec(f.ctx, "UPDATE documents SET status='voided' WHERE id=$1", id)
			reportSchemaRefusal404(t, f, before, err, "23514", "")
			manualProposalMigrationUnlocked268(t, f)
			migrationPoolRetired242(t, f, f.db, f.name)
		})
	}
}

type reportSchemaSnapshot404 struct{ data, pins, schema, history, oldGuards string }

func reportSchemaState404(t *testing.T, f migrationPGFixture242) reportSchemaSnapshot404 {
	t.Helper()
	var s reportSchemaSnapshot404
	err := f.admin.QueryRow(f.ctx, `SELECT jsonb_build_object(
 'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d)-'participant_report_schema' ORDER BY d.id),'[]'::jsonb) FROM documents d),
 'preparations',(SELECT coalesce(jsonb_agg(to_jsonb(p)-'report_schema' ORDER BY p.document_id),'[]'::jsonb) FROM document_ordinary_finalization_preparations_v1 p),
 'outputs',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.document_id,o.kind),'[]'::jsonb) FROM document_ordinary_finalization_outputs_v1 o),
 'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.document_id),'[]'::jsonb) FROM document_finalization_intents i),
 'reports',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.document_id,r.completion_effective_at),'[]'::jsonb) FROM document_participant_reports_v1 r),
 'deliveries',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.document_id,x.audience,x.recipient_id),'[]'::jsonb) FROM document_participant_report_deliveries_v1 x),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY e.id),'[]'::jsonb) FROM events e),
 'send_intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.document_id),'[]'::jsonb) FROM send_sealing_intents i))::text,
 jsonb_build_object('documents',(SELECT coalesce(jsonb_agg(jsonb_build_array(d.id,to_jsonb(d)->'participant_report_schema') ORDER BY d.id),'[]'::jsonb) FROM documents d),'preparations',(SELECT coalesce(jsonb_agg(jsonb_build_array(p.document_id,to_jsonb(p)->'report_schema') ORDER BY p.document_id),'[]'::jsonb) FROM document_ordinary_finalization_preparations_v1 p))::text,
 jsonb_build_object('columns',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid::regclass::text,a.attname,a.attnotnull,pg_get_expr(ad.adbin,ad.adrelid)) ORDER BY a.attrelid,a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum WHERE a.attrelid IN ('documents'::regclass,'document_ordinary_finalization_preparations_v1'::regclass) AND a.attname IN ('participant_report_schema','report_schema') AND NOT a.attisdropped),
 'constraints',(SELECT jsonb_agg(jsonb_build_array(c.conname,pg_get_constraintdef(c.oid,true)) ORDER BY c.conname) FROM pg_constraint c WHERE c.conrelid IN ('documents'::regclass,'document_ordinary_finalization_preparations_v1'::regclass,'document_participant_reports_v1'::regclass)),
 'new_functions',(SELECT coalesce(jsonb_agg(pg_get_functiondef(p.oid) ORDER BY p.proname),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('hash_guard_document_report_schema_v2','hash_guard_ordinary_report_schema_v2','hash_guard_participant_receipt_schema_v2')),
 'new_triggers',(SELECT coalesce(jsonb_agg(pg_get_triggerdef(t.oid,true) ORDER BY t.tgname),'[]'::jsonb) FROM pg_trigger t WHERE t.tgname IN ('participant_report_schema_document_v2','ordinary_report_schema_v2','participant_report_receipt_schema_v2') AND NOT t.tgisinternal))::text,
 (SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY v.id),'[]'::jsonb)::text FROM goose_db_version v),
 (SELECT jsonb_agg(pg_get_functiondef(p.oid) ORDER BY p.proname)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('hash_advance_document_update_clock','hash_guard_participant_report_intent_v1','hash_guard_participant_report_receipt_v1','hash_guard_participant_report_delivery_v1','hash_guard_participant_report_completion_v1','hash_guard_participant_report_immutable_v1','hash_guard_ordinary_finalization_preparation_v1','hash_guard_ordinary_finalization_output_v1','hash_guard_ordinary_finalization_intent_v1','hash_guard_ordinary_finalization_completion_v1','hash_ordinary_finalization_intent_matches_v1','hash_ordinary_finalization_legacy_matches_v1'))`).Scan(&s.data, &s.pins, &s.schema, &s.history, &s.oldGuards)
	if err != nil {
		t.Fatal("snapshot exact isolated M113 source/history/schema/old guards", err)
	}
	return s
}
func reportSchemaRefusal404(t *testing.T, f migrationPGFixture242, before reportSchemaSnapshot404, err error, state, message string) {
	t.Helper()
	manualProposalMigrationSQLState268(t, err, state)
	if message != "" && !strings.Contains(err.Error(), message) {
		t.Fatal("unrelated existing guard satisfied expected schema refusal", err)
	}
	if after := reportSchemaState404(t, f); after != before {
		t.Fatal("refused operation changed rows/clocks/pins/history/schema/old guards")
	}
	manualProposalMigrationUnlocked268(t, f)
}
func reportSchemaMigrate404(t *testing.T, f migrationPGFixture242, version int64) {
	t.Helper()
	if err := mdb.RunMigrationsUpToContext(f.ctx, f.db, version); err != nil {
		t.Fatal("apply actual isolated schema migration", version, err)
	}
	if got, err := mdb.GetMigrationVersionContext(f.ctx, f.db); err != nil || got != version {
		t.Fatal("actual migration head differs", got, version, err)
	}
}
func reportSchemaTenant404(t *testing.T, f migrationPGFixture242) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var org, user uuid.UUID
	if err := f.admin.QueryRow(f.ctx, "INSERT INTO orgs(name,plan) VALUES('M113 synthetic schema control','pro') RETURNING id").Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := f.admin.QueryRow(f.ctx, "INSERT INTO users(org_id,email,name,role,zitadel_sub) VALUES($1,$2,'Schema control','owner',$3) RETURNING id", org, uuid.NewString()+"@m113.test", uuid.NewString()).Scan(&user); err != nil {
		t.Fatal(err)
	}
	return org, user
}
func reportSchemaDocument404(t *testing.T, f migrationPGFixture242, org, user uuid.UUID, status string, parent uuid.UUID, position int, envelope bool) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	var parentValue any
	if parent != uuid.Nil {
		parentValue = parent
	}
	if status != "draft" && status != "finalizing" {
		t.Fatal("unsupported schema-only fixture state")
	}
	err := f.admin.QueryRow(f.ctx, `INSERT INTO documents(org_id,sender_id,name,source_kind,blocks_json,variables_json,parent_envelope_id,envelope_position,is_envelope,updated_at,metadata)
 VALUES($1,$2,'M113 explicit synthetic document','blocks','{"version":1,"blocks":[]}'::jsonb,'{}'::jsonb,$3,$4,$5,'2026-10-18 12:00:00+00','{"preserved":"Å original synthetic bytes"}'::jsonb) RETURNING id`, org, user, parentValue, position, envelope).Scan(&id)
	if err != nil {
		t.Fatal("seed explicit synthetic draft", err)
	}
	if status == "finalizing" {
		// Old112 has no schema column. Use only compatible scalar SQL here,
		// preserving branding/notice/clock guards rather than disabling them.
		seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, f.admin, id)
		q := generated.New(f.admin)
		tx, err := f.admin.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		qt := q.WithTx(tx)
		if _, err = qt.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{DocumentID: id, OrgID: org, ActorUserID: pgtype.UUID{Bytes: user, Valid: true}, ActorEmail: "schema@m113.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "m113-schema-fixture"}); err != nil {
			t.Fatal("seed original send intent", err)
		}
		if tag, err := tx.Exec(f.ctx, `UPDATE documents SET status='sealing',updated_at=now() WHERE id=$1 AND org_id=$2 AND status='draft' AND deleted_at IS NULL`, id, org); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("seed original draft-to-sealing transition", err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal("commit original synthetic sealing intent", err)
		}
		if rows, err := q.MarkSendSealingRetentionStarted(f.ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: id, OrgID: org}); err != nil || rows != 1 {
			t.Fatal("synthetic retention start checkpoint", err)
		}
		if rows, err := q.MarkSendSealingRetentionComplete(f.ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: id, OrgID: org}); err != nil || rows != 1 {
			t.Fatal("synthetic retention complete checkpoint", err)
		}
		tx, err = f.admin.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(f.ctx) }()
		var sent pgtype.Timestamptz
		// Match CompleteDocumentSendSealing with a scalar RETURNING projection:
		// generated Document projections include the not-yet-added M113 column.
		err = tx.QueryRow(f.ctx, `WITH ceremony_epoch AS MATERIALIZED (
 SELECT intent.article13_notice_epoch_at AS value FROM send_sealing_intents intent
 WHERE intent.package_send_attempt_id IS NULL AND intent.document_id=$1 AND intent.org_id=$2
 AND intent.retention_started_at IS NOT NULL AND intent.retention_completed_at IS NOT NULL
 AND intent.retain_until=hash_evidence_retain_until(intent.article13_notice_epoch_at,7)
 ) UPDATE documents SET status='sent',sent_at=ceremony_epoch.value,
 article13_notice_epoch_at=ceremony_epoch.value,article13_notice_schema='hash-a13-2026-08-31',
 article13_notice_epoch_v61_committed=TRUE,updated_at=now() FROM ceremony_epoch
 WHERE documents.id=$1 AND documents.org_id=$2 AND documents.status='sealing'
 AND documents.deleted_at IS NULL AND documents.evidence_version_pins_required=TRUE
 AND (documents.article13_notice_epoch_at IS NULL OR ceremony_epoch.value>documents.article13_notice_epoch_at)
 RETURNING documents.sent_at`, id, org).Scan(&sent)
		if err != nil {
			t.Fatal("prepare explicit synthetic active ceremony under original guards", err)
		}
		epoch, err := article13.CanonicalSentAt(sent.Time)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = audit.New(q, nil).LogTx(f.ctx, tx, audit.Entry{OrgID: org, DocumentID: &id, Kind: audit.KindDocumentSent, Payload: map[string]any{article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1, article13.AuditRequiredNoticeSentAtKey: epoch}}); err != nil {
			t.Fatal("seed original hashed synthetic notice marker", err)
		}
		if rows, err := q.WithTx(tx).DeleteSendSealingIntent(f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: id, OrgID: org}); err != nil || rows != 1 {
			t.Fatal("retire original synthetic send intent", err)
		}
		if tag, err := tx.Exec(f.ctx, "UPDATE documents SET status='in_progress' WHERE id=$1 AND org_id=$2 AND status='sent'", id, org); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("original active ceremony transition", err)
		}
		if _, err = tx.Exec(f.ctx, `WITH stamp AS MATERIALIZED(SELECT clock_timestamp() AS value)
 UPDATE documents SET status='finalizing',completion_effective_at=stamp.value,finalization_retain_until=hash_evidence_retain_until(stamp.value,7),updated_at=stamp.value
 FROM stamp WHERE id=$1::uuid`, id); err != nil {
			t.Fatal("prepare explicit synthetic finalization under original clock/selection guards", err)
		}
		if err = tx.Commit(f.ctx); err != nil {
			t.Fatal("commit explicit synthetic finalization fixture", err)
		}
	}
	return id
}
func reportSchemaPin404(t *testing.T, f migrationPGFixture242, id uuid.UUID, want string) {
	t.Helper()
	var got string
	if err := f.admin.QueryRow(f.ctx, "SELECT participant_report_schema FROM documents WHERE id=$1", id).Scan(&got); err != nil || got != want {
		t.Fatal("persisted native schema pin differs", got, want, err)
	}
}

func reportSchemaSend404(t *testing.T, f migrationPGFixture242, org, user, root uuid.UUID, children []uuid.UUID) {
	t.Helper()
	q := generated.New(f.admin)
	all := append([]uuid.UUID{root}, children...)
	for _, id := range all {
		seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, f.admin, id)
	}
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	qt := q.WithTx(tx)
	if _, err = tx.Exec(f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", root, org); err != nil {
		t.Fatal(err)
	}
	if _, err = qt.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{DocumentID: root, OrgID: org, ActorUserID: pgtype.UUID{Bytes: user, Valid: true}, ActorEmail: "schema@m113.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "m113-schema-fixture"}); err != nil {
		t.Fatal(err)
	}
	if _, err = qt.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: root, OrgID: org}); err != nil {
		t.Fatal(err)
	}
	if len(children) > 0 {
		if result, err := qt.BeginEnvelopeChildrenSendSealing(f.ctx, generated.BeginEnvelopeChildrenSendSealingParams{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: org}); err != nil || len(result) != len(children) {
			t.Fatal("actual children sealing query", err)
		}
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if rows, err := q.MarkSendSealingRetentionStarted(f.ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: root, OrgID: org}); err != nil || rows != 1 {
		t.Fatal("synthetic retention start checkpoint", err)
	}
	if rows, err := q.MarkSendSealingRetentionComplete(f.ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: root, OrgID: org}); err != nil || rows != 1 {
		t.Fatal("synthetic retention complete checkpoint", err)
	}
	tx, err = f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	qt = q.WithTx(tx)
	sent, err := qt.CompleteDocumentSendSealing(f.ctx, generated.CompleteDocumentSendSealingParams{ID: root, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if len(children) > 0 {
		if result, err := qt.CompleteEnvelopeChildrenSendSealing(f.ctx, generated.CompleteEnvelopeChildrenSendSealingParams{ParentEnvelopeID: pgtype.UUID{Bytes: root, Valid: true}, OrgID: org}); err != nil || len(result) != len(children) {
			t.Fatal("actual children send query", err)
		}
	}
	epoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range all {
		if _, err := audit.New(q, nil).LogTx(f.ctx, tx, audit.Entry{OrgID: org, DocumentID: &id, Kind: audit.KindDocumentSent, Payload: map[string]any{article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1, article13.AuditRequiredNoticeSentAtKey: epoch}}); err != nil {
			t.Fatal("genuine original hashed notice marker", err)
		}
	}
	if rows, err := qt.DeleteSendSealingIntent(f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: root, OrgID: org}); err != nil || rows != 1 {
		t.Fatal("retire synthetic send intent", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if tag, err := f.admin.Exec(f.ctx, "UPDATE documents SET status='in_progress' WHERE id=$1 AND org_id=$2 AND status='sent'", root, org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal("ordinary root progress transition", err)
	}
}

func reportSchemaRetainReceipt404(t *testing.T, f migrationPGFixture242, doc *generated.Document) {
	t.Helper()
	tx, err := f.admin.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(f.ctx) }()
	final := []byte("%PDF synthetic M113 final")
	sum := sha256.Sum256(final)
	if _, err = tx.Exec(f.ctx, `INSERT INTO document_ordinary_finalization_preparations_v1(document_id,org_id,mode,completion_effective_at,cutoff,retain_until,final_pdf_sha256,report_schema) SELECT id,org_id,'signature',completion_effective_at,updated_at,finalization_retain_until,$2,participant_report_schema FROM documents WHERE id=$1`, doc.ID, sum[:]); err != nil {
		t.Fatal("synthetic exact preparation", err)
	}
	if _, err = tx.Exec(f.ctx, `UPDATE document_ordinary_finalization_preparations_v1 SET certificate_render_html=convert_to('<html>synthetic schema certificate</html>','UTF8'),certificate_render_sha256=digest(convert_to('<html>synthetic schema certificate</html>','UTF8'),'sha256'),report_cutoff=cutoff,history_rows=0,report_sha256=digest('synthetic public report','sha256'),certificate_input_frozen=true WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal("synthetic exact frozen inputs", err)
	}
	for _, o := range []struct {
		kind, contentType, prefix, suffix string
		body                              []byte
	}{{"final_pdf", "application/pdf", "final-", ".pdf", final}, {"certificate_pdf", "application/pdf", "audit-", ".pdf", []byte("%PDF synthetic M113 certificate")}, {"certificate_payload", "text/html; charset=utf-8", "audit-payload-", ".txt", []byte("synthetic signed payload")}, {"certificate_signature", "text/plain; charset=utf-8", "audit-signature-", ".txt", []byte("synthetic signature")}} {
		if _, err = tx.Exec(f.ctx, `INSERT INTO document_ordinary_finalization_outputs_v1(document_id,org_id,kind,storage_key,sha256,bytes,content_type,payload) VALUES($1::uuid,$2::uuid,$3::text,'org/'||$2::uuid::text||'/documents/'||$1::uuid::text||'/'||$4::text||encode(digest($6::bytea,'sha256'),'hex')||$5::text,digest($6::bytea,'sha256'),octet_length($6::bytea),$7::text,$6::bytea)`, doc.ID, doc.OrgID, o.kind, o.prefix, o.suffix, o.body, o.contentType); err != nil {
			t.Fatal("synthetic original output", o.kind, err)
		}
		if _, err = tx.Exec(f.ctx, `UPDATE document_ordinary_finalization_outputs_v1 SET version_id=$3,verified_at=clock_timestamp() WHERE document_id=$1 AND kind=$2`, doc.ID, o.kind, "m113-synthetic-"+o.kind); err != nil {
			t.Fatal("synthetic exact output version", err)
		}
	}
	if _, err = tx.Exec(f.ctx, `INSERT INTO document_finalization_intents(document_id,org_id,mode,completion_effective_at,retain_until,final_pdf_key,final_pdf_sha256,final_pdf_version_id,audit_cert_key,audit_cert_sha256,audit_cert_version_id,audit_payload_key,audit_payload_sha256,audit_payload_version_id,audit_signature_key,audit_signature_sha256,audit_signature_version_id) SELECT p.document_id,p.org_id,p.mode,p.completion_effective_at,p.retain_until,f.storage_key,f.sha256,f.version_id,c.storage_key,c.sha256,c.version_id,b.storage_key,b.sha256,b.version_id,s.storage_key,s.sha256,s.version_id FROM document_ordinary_finalization_preparations_v1 p JOIN document_ordinary_finalization_outputs_v1 f ON f.document_id=p.document_id AND f.kind='final_pdf' JOIN document_ordinary_finalization_outputs_v1 c ON c.document_id=p.document_id AND c.kind='certificate_pdf' JOIN document_ordinary_finalization_outputs_v1 b ON b.document_id=p.document_id AND b.kind='certificate_payload' JOIN document_ordinary_finalization_outputs_v1 s ON s.document_id=p.document_id AND s.kind='certificate_signature' WHERE p.document_id=$1`, doc.ID); err != nil {
		t.Fatal("synthetic original intent", err)
	}
	if _, err = tx.Exec(f.ctx, `INSERT INTO document_participant_reports_v1(document_id,org_id,completion_effective_at,schema_version,cutoff,history_rows,report_sha256,final_pdf_sha256,audit_cert_sha256,audit_payload_sha256,audit_signature_sha256) SELECT p.document_id,p.org_id,p.completion_effective_at,p.report_schema,p.report_cutoff,p.history_rows,p.report_sha256,i.final_pdf_sha256,i.audit_cert_sha256,i.audit_payload_sha256,i.audit_signature_sha256 FROM document_ordinary_finalization_preparations_v1 p JOIN document_finalization_intents i ON i.document_id=p.document_id AND i.org_id=p.org_id WHERE p.document_id=$1`, doc.ID); err != nil {
		t.Fatal("synthetic exact report receipt", err)
	}
	if _, err = tx.Exec(f.ctx, "UPDATE document_ordinary_finalization_preparations_v1 SET staged_at=clock_timestamp() WHERE document_id=$1", doc.ID); err != nil {
		t.Fatal("stage all synthetic original output associations", err)
	}
	if err = tx.Commit(f.ctx); err != nil {
		t.Fatal("M108/M109 original deferred guards refused synthetic exact retained tuple", err)
	}
}
