//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// Mandatory real isolated migrated PostgreSQL component, not a native work,
// actor/credential, human review, renderer/PDF, lifecycle or capacity fixture.
// Raw bounded synthetic rows are genuine schema/API writes; no guard/cache is
// disabled, inserted by hand, repaired or converted to READY/sent/completed.
func newHTMLQueryFoundationFixtureV1(t *testing.T) (context.Context, lifecycleAuthorizationFixture) {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Fatal("HASH_E2E_DB_URL is required for SQL component qualification")
	}
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual string
		if err := f.pool.QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil {
			t.Error(err)
			return
		}
		if actual != database || !strings.HasPrefix(actual, "hash_html_e2e_") {
			t.Error("refusing cleanup outside exact synthetic database")
			return
		}
		if _, err := f.pool.Exec(ctx, "TRUNCATE orgs CASCADE"); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(f.ctx, 20*time.Second)
	t.Cleanup(cancel)
	return ctx, f
}
func rollbackHTMLQueryFixtureV1(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tx.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Error(err)
	}
}
func beginHTMLQueryFixtureV1(t *testing.T, ctx context.Context, f lifecycleAuthorizationFixture) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}
func htmlSendVerifyFixtureV1(h *generated.GetHTMLSendCollectionReadHeaderV1Row) generated.VerifyHTMLSendCollectionReadHeaderV1Params {
	return generated.VerifyHTMLSendCollectionReadHeaderV1Params{DocumentID: h.DocumentID, OrgID: h.OrgID, ExpectedRecipientCount: h.RecipientCount, ExpectedRecipientRawBytes: h.RecipientRawBytes, ExpectedFieldCount: h.FieldCount, ExpectedFieldRawBytes: h.FieldRawBytes, ExpectedFieldOptionsWireBytes: h.FieldOptionsWireBytes, ExpectedBindingCount: h.BindingCount, ExpectedBindingRawBytes: h.BindingRawBytes}
}

func TestHTMLSendGeneratedCollectionsAndInvalidationE2E(t *testing.T) {
	ctx, f := newHTMLQueryFoundationFixtureV1(t)
	// Two fixed binding rows with equal sort stamps prove count-only locking
	// does not deduplicate timestamp ties introduced by SQLC compatibility.
	if _, err := f.q.UpsertVariableBinding(ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "second", SourceKind: string(resolver.SourceAgentComputed), SourceRef: "bounded second binding"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, "UPDATE document_variable_bindings SET created_at='2026-10-15T00:00:00Z',updated_at='2026-10-15T00:00:00Z',last_error='bounded β' WHERE document_id=$1", f.doc.ID); err != nil {
		t.Fatal(err)
	}
	var zero, ten, five pgtype.Numeric
	if err := zero.Scan("0"); err != nil {
		t.Fatal(err)
	}
	if err := ten.Scan("10"); err != nil {
		t.Fatal(err)
	}
	if err := five.Scan("5"); err != nil {
		t.Fatal(err)
	}
	field, err := f.q.CreateField(ctx, generated.CreateFieldParams{DocumentID: f.doc.ID, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "signature", Page: 1, XPct: zero, YPct: zero, WPct: ten, HPct: five, Required: true, Label: pgtype.Text{String: "Å fixture", Valid: true}, OptionsJson: json.RawMessage("[]")})
	if err != nil {
		t.Fatal(err)
	}
	// Genuine freshly created field is measured by the actual intrinsic API.
	// This is component provenance, not old-row backfill or native admission.
	if _, err = f.q.MeasureSignatureFitHTMLPolicyFieldV1(ctx, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{DocumentID: f.doc.ID, OrgID: f.org, FieldID: field.ID}); err != nil {
		t.Fatal(err)
	}
	tx := beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	q := f.q.WithTx(tx)
	state, err := q.GetHTMLSendDocumentStateHeaderV1(ctx, generated.GetHTMLSendDocumentStateHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || state.ID != f.doc.ID || state.BoundedStatus != "draft" || state.HasHtmlSource {
		t.Fatalf("actual draft state header: %+v,%v", state, err)
	}
	h, err := q.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if h.RecipientCount != 1 || h.FieldCount != 1 || h.BindingCount != 2 || h.FieldMissingSizeCount != 0 || h.FieldMeasurementServerMismatchCount != 0 || h.FieldOptionsWireBytes != 2 {
		t.Fatalf("actual collection header: %+v", h)
	}
	pins, err := q.LockHTMLSendCollectionRowsV1(ctx, generated.LockHTMLSendCollectionRowsV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || pins.BindingCount != 2 || pins.FieldCacheCount != 1 || pins.RecipientCount != 1 || pins.FieldCount != 1 {
		t.Fatalf("complete fixed row pins: %+v,%v", pins, err)
	}
	if _, err = q.VerifyHTMLSendCollectionReadHeaderV1(ctx, htmlSendVerifyFixtureV1(h)); err != nil {
		t.Fatal(err)
	}
	recipients, err := q.ListHTMLSendRecipientsV1(ctx, generated.ListHTMLSendRecipientsV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedCount: h.RecipientCount, ExpectedRawBytes: h.RecipientRawBytes})
	if err != nil || len(recipients) != 1 || recipients[0].ID != f.recipient.ID {
		t.Fatalf("recipient body: %+v,%v", recipients, err)
	}
	fields, err := q.ListHTMLSendFieldsV1(ctx, generated.ListHTMLSendFieldsV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedCount: h.FieldCount, ExpectedRawBytes: h.FieldRawBytes, ExpectedOptionsWireBytes: h.FieldOptionsWireBytes})
	if err != nil || len(fields) != 1 || fields[0].ID != field.ID || string(fields[0].OptionsJson) != "[]" {
		t.Fatalf("field body: %+v,%v", fields, err)
	}
	bindings, err := q.ListHTMLSendBindingsV1(ctx, generated.ListHTMLSendBindingsV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedCount: h.BindingCount, ExpectedRawBytes: h.BindingRawBytes})
	if err != nil || len(bindings) != 2 {
		t.Fatalf("binding body: %+v,%v", bindings, err)
	}
	var bindingRaw int64
	for _, b := range bindings {
		bindingRaw += int64(len(b.VariableName) + len(b.SourceKind) + len(b.SourceRef) + len(b.SourcePath) + len(b.Fallback) + len(b.LastValue) + len(b.LastError))
	}
	if bindingRaw != h.BindingRawBytes {
		t.Fatalf("actual seven binding strings: %d!=%d", bindingRaw, h.BindingRawBytes)
	}
	wrong := htmlSendVerifyFixtureV1(h)
	wrong.ExpectedBindingRawBytes++
	if _, err = q.VerifyHTMLSendCollectionReadHeaderV1(ctx, wrong); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale scalar verify accepted: %v", err)
	}
	hidden, err := q.ListHTMLSendBindingsV1(ctx, generated.ListHTMLSendBindingsV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedCount: h.BindingCount + 1, ExpectedRawBytes: h.BindingRawBytes})
	if err != nil || len(hidden) != 0 {
		t.Fatalf("mismatched body expected count exposed rows: %d,%v", len(hidden), err)
	}
	if _, err = q.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: uuid.New()}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wrong org header accepted: %v", err)
	}
	if _, err = tx.Exec(ctx, "SAVEPOINT invalidated_field"); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "UPDATE document_fields SET options_json='[1.00]'::jsonb WHERE id=$1", field.ID); err != nil {
		t.Fatal(err)
	}
	missing, err := q.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || missing.FieldMissingSizeCount != 1 {
		t.Fatalf("cheap invalidation missing: %+v,%v", missing, err)
	}
	if _, err = q.VerifyHTMLSendCollectionReadHeaderV1(ctx, htmlSendVerifyFixtureV1(missing)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing cache gained body authority: %v", err)
	}
	refused, err := q.ListHTMLSendFieldsV1(ctx, generated.ListHTMLSendFieldsV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedCount: missing.FieldCount, ExpectedRawBytes: missing.FieldRawBytes, ExpectedOptionsWireBytes: missing.FieldOptionsWireBytes})
	if err != nil || len(refused) != 0 {
		t.Fatalf("missing cache field body exposed: %d,%v", len(refused), err)
	}
	var caches int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM field_signing_policy_sizes_v1 WHERE field_id=$1", field.ID).Scan(&caches); err != nil || caches != 0 {
		t.Fatalf("read silently refreshed cache: %d,%v", caches, err)
	}
	if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT invalidated_field"); err != nil {
		t.Fatal(err)
	}
	if _, err = q.VerifyHTMLSendCollectionReadHeaderV1(ctx, htmlSendVerifyFixtureV1(h)); err != nil {
		t.Fatal("savepoint did not restore original complete header:", err)
	}
	// Source/cache inverse lock order uses immediate NOWAIT, not a timeout.
	rollbackHTMLQueryFixtureV1(t, tx)
	blocker := beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, blocker)
	var locked uuid.UUID
	if err = blocker.QueryRow(ctx, "SELECT field_id FROM field_signing_policy_sizes_v1 WHERE field_id=$1 FOR UPDATE", field.ID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	contender := beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, contender)
	cq := f.q.WithTx(contender)
	if _, err = cq.GetHTMLSendCollectionReadHeaderV1(ctx, generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if _, err = contender.Exec(ctx, "SET LOCAL lock_timeout='2s'"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	_, err = cq.LockHTMLSendCollectionRowsV1(ctx, generated.LockHTMLSendCollectionRowsV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" || strings.Contains(pe.Message, "lock timeout") || time.Since(start) >= time.Second {
		t.Fatalf("cache pin was not immediate NOWAIT: elapsed%v err%v", time.Since(start), err)
	}
}

func htmlSendFreezeFixtureV1(h *generated.GetHTMLSendBrandingInputHeaderV1Row) generated.FreezeHTMLSendBrandingV1Params {
	b := branding.DefaultBranding()
	return generated.FreezeHTMLSendBrandingV1Params{DocumentID: h.DocumentID, OrgID: h.OrgID, ExpectedHasOrgBranding: h.HasOrgBranding, ExpectedHasDocumentBranding: h.HasDocumentBranding, ExpectedOrgBrandingRawBytes: h.OrgBrandingRawBytes, ExpectedDocumentBrandingRawBytes: h.DocumentBrandingRawBytes, DefaultPrimaryHex: b.PrimaryHex, DefaultAccentHex: b.AccentHex, DefaultSurfaceHex: b.SurfaceHex, DefaultTextHex: b.TextHex, DefaultMutedHex: b.MutedHex, DefaultLogoUrl: b.LogoURL, DefaultLogoAlt: b.LogoAlt, DefaultFontHeading: b.FontHeading, DefaultFontBody: b.FontBody, DefaultSignatureColor: b.SignatureColor}
}
func TestHTMLSendGeneratedIntentAndBrandingAbsenceE2E(t *testing.T) {
	ctx, f := newHTMLQueryFoundationFixtureV1(t)
	intent, err := f.q.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{DocumentID: f.doc.ID, OrgID: f.org, ActorUserID: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ActorEmail: "synthetic-å@example.test", ActorIp: "127.0.0.1", Via: "app", Tool: "query-component"})
	if err != nil {
		t.Fatal(err)
	}
	tx := beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	q := f.q.WithTx(tx)
	h, err := q.GetHTMLSendIntentReadHeaderV1(ctx, generated.GetHTMLSendIntentReadHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	body, err := q.ReadHTMLSendIntentV1(ctx, generated.ReadHTMLSendIntentV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil || !reflect.DeepEqual(body, intent) {
		t.Fatalf("exact original intent body: %+v,%v", body, err)
	}
	if _, err = q.ReadHTMLSendIntentV1(ctx, generated.ReadHTMLSendIntentV1Params{DocumentID: f.doc.ID, OrgID: f.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes + 1}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("under/overstated intent admitted: %v", err)
	}
	absent, err := q.GetHTMLSendBrandingInputHeaderV1(ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || absent.HasOrgBranding || absent.HasDocumentBranding {
		t.Fatalf("fresh theme absence: %+v,%v", absent, err)
	}
	// Another real connection inserts the previously absent org theme while this
	// transaction retains the document parent. Absence is never a stable pin.
	b := branding.DefaultBranding()
	b.PrimaryHex = "#112233"
	if _, err = f.q.UpsertOrgBranding(ctx, generated.UpsertOrgBrandingParams{OrgID: f.org, PrimaryHex: b.PrimaryHex, AccentHex: b.AccentHex, SurfaceHex: b.SurfaceHex, TextHex: b.TextHex, MutedHex: b.MutedHex, LogoUrl: b.LogoURL, LogoAlt: "bounded å theme", FontHeading: b.FontHeading, FontBody: b.FontBody, SignatureColor: b.SignatureColor}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.FreezeHTMLSendBrandingV1(ctx, htmlSendFreezeFixtureV1(absent)); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale absent theme froze/expanded: %v", err)
	}
	var rows int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM document_branding_override WHERE document_id=$1", f.doc.ID).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("stale freeze side effect: %d,%v", rows, err)
	}
	fresh, err := q.GetHTMLSendBrandingInputHeaderV1(ctx, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: f.doc.ID, OrgID: f.org})
	if err != nil || !fresh.HasOrgBranding || fresh.OrgBrandingRawBytes <= 0 {
		t.Fatalf("fresh real org theme not observed: %+v,%v", fresh, err)
	}
	frozen, err := q.FreezeHTMLSendBrandingV1(ctx, htmlSendFreezeFixtureV1(fresh))
	if err != nil || frozen.PrimaryHex.String != b.PrimaryHex || frozen.LogoAlt.String != "bounded å theme" {
		t.Fatalf("actual effective theme: %+v,%v", frozen, err)
	}
}

func seedHTMLClearFixtureV1(t *testing.T, ctx context.Context, f lifecycleAuthorizationFixture, q *generated.Queries) *generated.Document {
	t.Helper()
	raw, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1, HTML: "<p>Bounded unchanged original source</p>"})
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, json.RawMessage("{}"))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(canonical.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	template, err := q.CreateFreshHTMLTemplateV1(ctx, generated.CreateFreshHTMLTemplateV1Params{ID: uuid.New(), OrgID: f.org, Name: "SQL-only synthetic schema1", HtmlMasterJson: canonical.MasterJSON, VariablesJson: canonical.DefaultsJSON, CreatedBy: f.user.ID, HtmlContentSha256: digest})
	if err != nil {
		t.Fatal(err)
	}
	pdf := sha256.Sum256([]byte("synthetic tuple; no rendered PDF assertion"))
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{OrgID: f.org, TemplateID: pgtype.UUID{Bytes: template.ID, Valid: true}, Name: "SQL-only exact history", PdfStorageKey: pgtype.Text{String: "org/" + f.org.String() + "/synthetic.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "synthetic-version", Valid: true}, PdfSha256: pdf[:], SenderID: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Source markers are component data, not an assertion of actual human review.
	input := htmlsource.Input{TemplateID: template.ID, TemplateVersion: template.Version, TemplateContentSHA256: canonical.SHA256, TemplateApprovedBy: f.user.ID, TemplateApprovedAt: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC), MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON, Values: map[string]string{}, Sections: map[string]string{}}
	source, err := htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc, err = q.SetDocumentHTMLSource(ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, HtmlSourceJson: source})
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err = htmlmaterialization.RegisterOrigin(ctx, q, doc, 1, f.user.ID)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}
func htmlClearStateFixtureV1(t *testing.T, ctx context.Context, tx pgx.Tx, doc uuid.UUID) string {
	t.Helper()
	var state string
	err := tx.QueryRow(ctx, "SELECT jsonb_build_object('fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id=$1),'history',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM html_document_materialization_snapshots s WHERE document_id=$1),'source',(SELECT jsonb_build_array(html_source_json,html_current_source_json,pdf_storage_key,pdf_sha256,pdf_storage_version_id,html_current_materialization_id) FROM documents WHERE id=$1))::text", doc).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// Exact actual generated121 SQL body, separately manifest-hash-bound. The calls
// below use generated methods; this copy exists ONLY to inspect actual PG plan.
const htmlOwnedClearPlanSQLV1 = `-- name: ClearUnsignedHTMLMaterializationFieldsOwnedV1 :execrows

WITH parent AS MATERIALIZED (
 SELECT p.id,p.org_id FROM documents p
 WHERE p.id=$1::uuid AND p.org_id=$2::uuid
  AND p.status='draft' AND p.deleted_at IS NULL
  AND p.updated_at=$3::timestamptz
 FOR UPDATE OF p
), canonical_context AS MATERIALIZED (
 SELECT p.id AS document_id,c.fields_json,c.recipients_json,c.notice_context_json,c.ceremony_events_json
 FROM parent p CROSS JOIN LATERAL hash_html_materialization_snapshot_context(p.id) AS c(fields_json,recipients_json,notice_context_json,ceremony_events_json)
)
DELETE FROM document_fields f USING documents d
WHERE f.document_id = d.id AND d.id = $1 AND d.org_id = $2
    AND d.status = 'draft' AND d.deleted_at IS NULL
    AND d.updated_at = $3::timestamptz
    AND EXISTS (SELECT 1 FROM html_document_materialization_snapshots s
        CROSS JOIN canonical_context c
        WHERE c.document_id = d.id AND s.document_id = d.id AND s.org_id = d.org_id AND s.kind = 'draft_superseded'
            AND s.captured_updated_at = d.updated_at
            AND s.materialization_id IS NOT DISTINCT FROM d.html_current_materialization_id
            AND s.source_json IS NOT DISTINCT FROM COALESCE(d.html_current_source_json, d.html_source_json)
            AND s.pdf_key IS NOT DISTINCT FROM d.pdf_storage_key AND s.pdf_sha256 IS NOT DISTINCT FROM d.pdf_sha256
            AND s.pdf_version_id IS NOT DISTINCT FROM d.pdf_storage_version_id
            AND s.metadata_redaction_report IS NOT DISTINCT FROM d.metadata_redaction_report
            AND s.reviewed_pdf_sha256 IS NOT DISTINCT FROM d.html_reviewed_pdf_sha256
            AND s.reviewed_by IS NOT DISTINCT FROM d.html_reviewed_by AND s.reviewed_at IS NOT DISTINCT FROM d.html_reviewed_at
            AND s.fields_json IS NOT DISTINCT FROM c.fields_json AND s.recipients_json IS NOT DISTINCT FROM c.recipients_json
            AND s.notice_context_json IS NOT DISTINCT FROM c.notice_context_json AND s.ceremony_events_json IS NOT DISTINCT FROM c.ceremony_events_json)
    AND NOT EXISTS (SELECT 1 FROM signatures s WHERE s.document_id = d.id)
    AND NOT EXISTS (SELECT 1 FROM recipients r WHERE r.document_id = d.id AND (r.status IN ('signed','accepted') OR r.signed_at IS NOT NULL))
    AND NOT EXISTS (SELECT 1 FROM document_fields filled WHERE filled.document_id = d.id AND (filled.value IS NOT NULL OR filled.completed_at IS NOT NULL))
`

func TestHTMLRevisionGeneratedClearHistoryAndLatestIdentityE2E(t *testing.T) {
	ctx, f := newHTMLQueryFoundationFixtureV1(t)
	tx := beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	q := f.q.WithTx(tx)
	doc := seedHTMLClearFixtureV1(t, ctx, f, q)
	var zero, ten pgtype.Numeric
	if err := zero.Scan("0"); err != nil {
		t.Fatal(err)
	}
	if err := ten.Scan("10"); err != nil {
		t.Fatal(err)
	}
	for page := int32(1); page <= 3; page++ {
		if _, err := q.CreateField(ctx, generated.CreateFieldParams{DocumentID: doc.ID, Type: "text", Page: 1, XPct: zero, YPct: zero, WPct: ten, HPct: ten, Required: false, OptionsJson: json.RawMessage("[]")}); err != nil {
			t.Fatal(err)
		}
	}
	doc, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	old := generated.ClearUnsignedHTMLMaterializationFieldsParams{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt}
	owned := generated.ClearUnsignedHTMLMaterializationFieldsOwnedV1Params{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt}
	if n, err := q.ClearUnsignedHTMLMaterializationFields(ctx, old); err != nil || n != 0 {
		t.Fatalf("old unarchived clear: %d,%v", n, err)
	}
	if n, err := q.ClearUnsignedHTMLMaterializationFieldsOwnedV1(ctx, owned); err != nil || n != 0 {
		t.Fatalf("owned unarchived clear: %d,%v", n, err)
	}
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	commitmentBytes, err := hex.DecodeString(commitment)
	if err != nil {
		t.Fatal(err)
	}
	capture := func() {
		t.Helper()
		if _, err := q.CaptureHTMLRevisionSnapshotIDV1(ctx, generated.CaptureHTMLRevisionSnapshotIDV1Params{DocumentID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, Kind: "draft_superseded", SourceCommitment: commitmentBytes, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}}); err != nil {
			t.Fatal(err)
		}
	}
	capture()
	firstCapturedStamp := doc.UpdatedAt
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// SQL now() is transaction-stable. A fresh actual transaction is required
	// before the ordinary draft-details mutation supplies a distinct CAS stamp.
	// Collections may remain identical; both complete snapshots are preserved.
	tx = beginHTMLQueryFixtureV1(t, ctx, f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	q = f.q.WithTx(tx)
	if _, err = q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	if _, err = q.GetHTMLRevisionSnapshotSizeHeaderV1(ctx, generated.GetHTMLRevisionSnapshotSizeHeaderV1Params{DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	doc, err = q.UpdateDraftDocumentDetailsV1(ctx, generated.UpdateDraftDocumentDetailsV1Params{ID: doc.ID, OrgID: f.org, Name: "Second immutable SQL-only snapshot", ExpiresAt: doc.ExpiresAt})
	if err != nil {
		t.Fatal(err)
	}
	if !doc.UpdatedAt.Valid || doc.UpdatedAt.Time.Equal(firstCapturedStamp.Time) {
		t.Fatal("fresh transaction did not change the actual captured CAS stamp")
	}
	old.ExpectedUpdatedAt = doc.UpdatedAt
	owned.ExpectedUpdatedAt = doc.UpdatedAt
	capture()
	before := htmlClearStateFixtureV1(t, ctx, tx, doc.ID)
	var count int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM html_document_materialization_snapshots WHERE document_id=$1", doc.ID).Scan(&count); err != nil || count != 2 {
		t.Fatalf("complete immutable history: %d,%v", count, err)
	}
	if _, err = tx.Exec(ctx, "SAVEPOINT old_clear"); err != nil {
		t.Fatal(err)
	}
	n, err := q.ClearUnsignedHTMLMaterializationFields(ctx, old)
	if err != nil || n != 3 {
		t.Fatalf("original exact clear: %d,%v", n, err)
	}
	oldAfter := htmlClearStateFixtureV1(t, ctx, tx, doc.ID)
	if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT old_clear"); err != nil {
		t.Fatal(err)
	}
	if htmlClearStateFixtureV1(t, ctx, tx, doc.ID) != before {
		t.Fatal("old clear savepoint lost full history/source/layout")
	}
	if _, err = tx.Exec(ctx, "SAVEPOINT new_clear"); err != nil {
		t.Fatal(err)
	}
	n, err = q.ClearUnsignedHTMLMaterializationFieldsOwnedV1(ctx, owned)
	if err != nil || n != 3 {
		t.Fatalf("owned exact clear: %d,%v", n, err)
	}
	if htmlClearStateFixtureV1(t, ctx, tx, doc.ID) != oldAfter {
		t.Fatal("owned clear differs from original complete history/source/layout result")
	}
	if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT new_clear"); err != nil {
		t.Fatal(err)
	}
	var planRaw []byte
	if err = tx.QueryRow(ctx, "EXPLAIN (ANALYZE,FORMAT JSON,TIMING OFF) "+htmlOwnedClearPlanSQLV1, doc.ID, f.org, doc.UpdatedAt).Scan(&planRaw); err != nil {
		t.Fatal(err)
	}
	var plan any
	if err = json.Unmarshal(planRaw, &plan); err != nil {
		t.Fatal(err)
	}
	contexts := 0
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				visit(item)
			}
		case map[string]any:
			if x["Subplan Name"] == "CTE canonical_context" {
				contexts++
				if loops, ok := x["Actual Loops"].(float64); !ok || loops != 1 {
					t.Fatalf("canonical context actual loops: %+v", x)
				}
			}
			for _, item := range x {
				visit(item)
			}
		}
	}
	visit(plan)
	if contexts != 1 {
		t.Fatalf("complete canonical context is not exactly one materialized plan: %d %s", contexts, planRaw)
	}
	if _, err = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT new_clear"); err != nil {
		t.Fatal(err)
	}
	stale := owned
	stale.ExpectedUpdatedAt.Time = stale.ExpectedUpdatedAt.Time.Add(-time.Microsecond)
	if n, err = q.ClearUnsignedHTMLMaterializationFieldsOwnedV1(ctx, stale); err != nil || n != 0 {
		t.Fatalf("stale CAS cleared: %d,%v", n, err)
	}
	if htmlClearStateFixtureV1(t, ctx, tx, doc.ID) != before {
		t.Fatal("refusal changed complete history/source/layout")
	}
	// Original subject-only latest semantics must surface, not hide, a foreign
	// org row. No native acceptance is claimed: fixed caller MUST reject org pins.
	if _, err = q.GetHTMLRevisionLatestVersionIdentityV1(ctx, f.doc.ID); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("empty latest identity: %v", err)
	}
	other, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Version scope component", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	for version := int32(1); version <= 2; version++ {
		org := f.org
		if version == 2 {
			org = other.ID
		}
		if _, err = q.InsertDocumentVersion(ctx, generated.InsertDocumentVersionParams{DocumentID: f.doc.ID, OrgID: org, VersionNo: version, BlockTreeJson: f.doc.BlocksJson, VariablesJson: json.RawMessage("{}"), Name: "bounded version", SourceKind: "blocks", Summary: "component", CreatedVia: "human", SchemaVersion: 1}); err != nil {
			t.Fatal(err)
		}
	}
	number, err := q.GetLatestDocumentVersionNo(ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	scalar, err := q.GetHTMLRevisionLatestVersionIdentityV1(ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := q.GetLatestDocumentVersion(ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if scalar.ID != original.ID || scalar.DocumentID != f.doc.ID || scalar.OrgID != other.ID || scalar.VersionNo != number || scalar.OrgID == f.org {
		t.Fatalf("latest scope disagreement was hidden: %+v original%+v no%d", scalar, original, number)
	}
}
