// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package e2e

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/recoveryinventory"
)

func TestRecoveryInventoryDerivesExactCeremonyRetentionE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsContext(ctx, migConn), "migrate recovery-inventory fixture to latest")

	sentID := seedDocument(t, ctx, pool, "recovery inventory sent")
	progressID := seedDocument(t, ctx, pool, "recovery inventory in progress")
	parentID := seedDocument(t, ctx, pool, "recovery inventory envelope sealing")
	childID := seedEnvelopeChild(t, ctx, pool, parentID, 1)
	reversibleID := seedDocument(t, ctx, pool, "recovery inventory reversible sealing")
	deletedDraftID := seedDocument(t, ctx, pool, "recovery inventory soft-deleted draft")
	missingDeadlineID := seedDocument(t, ctx, pool, "recovery inventory corrupt terminal deadline")

	// Fixture lifecycle rows directly; this test targets the read-only recovery
	// projection rather than replaying the send engine. All table constraints
	// remain active, while unrelated transition/audit triggers are disabled only
	// inside this isolated scratch database.
	_, err := pool.Exec(ctx, `ALTER TABLE documents DISABLE TRIGGER USER`)
	must(t, err, "disable lifecycle triggers in isolated recovery fixture")
	defer func() { _, _ = pool.Exec(context.Background(), `ALTER TABLE documents ENABLE TRIGGER USER`) }()
	epoch := time.Date(2026, time.September, 9, 10, 11, 12, 0, time.UTC)
	var postSendDeadline time.Time
	must(t, pool.QueryRow(ctx, `SELECT hash_evidence_retain_until($1, 7)`, epoch).Scan(&postSendDeadline), "derive post-send deadline")
	for _, fixture := range []struct {
		id, key, version, status string
	}{
		{sentID.String(), "fixture/sent.pdf", "sent-version", "sent"},
		{progressID.String(), "fixture/in-progress.pdf", "progress-version", "in_progress"},
	} {
		_, err = pool.Exec(ctx, `UPDATE documents
			SET source_kind='pdf', blocks_json=NULL, pdf_storage_key=$2,
			    pdf_sha256=decode(repeat('ab',32),'hex'), pdf_storage_version_id=$3,
			    evidence_version_pins_required=TRUE, status=$4, sent_at=$5,
			    article13_notice_epoch_at=$5, article13_notice_schema=$6,
			    article13_notice_epoch_v61_committed=TRUE
			WHERE id=$1`, fixture.id, fixture.key, fixture.version, fixture.status, epoch, article13.SchemaV1)
		must(t, err, "seed post-send recovery object")
	}

	_, err = pool.Exec(ctx, `UPDATE documents SET is_envelope=TRUE, blocks_json=NULL, status='sealing' WHERE id=$1`, parentID)
	must(t, err, "seed sealing envelope root")
	_, err = pool.Exec(ctx, `UPDATE documents
		SET source_kind='pdf', blocks_json=NULL, pdf_storage_key='fixture/envelope-child.pdf',
		    pdf_sha256=decode(repeat('bc',32),'hex'), pdf_storage_version_id='child-version',
		    evidence_version_pins_required=TRUE, status='sealing'
		WHERE id=$1`, childID)
	must(t, err, "seed sealing envelope child")
	parentEpoch := epoch.Add(time.Hour)
	var parentDeadline time.Time
	must(t, pool.QueryRow(ctx, `SELECT hash_evidence_retain_until($1, 7)`, parentEpoch).Scan(&parentDeadline), "derive parent intent deadline")
	parentOrgID := documentOrgID(t, ctx, pool, parentID)
	_, err = pool.Exec(ctx, `INSERT INTO send_sealing_intents
		(document_id, org_id, article13_notice_epoch_at, retain_until, retention_started_at)
		VALUES ($1,$2,$3,$4,$3)`, parentID, parentOrgID, parentEpoch, parentDeadline)
	must(t, err, "seed irreversible root-envelope intent")

	_, err = pool.Exec(ctx, `UPDATE documents
		SET source_kind='pdf', blocks_json=NULL, pdf_storage_key='fixture/reversible.pdf',
		    pdf_sha256=decode(repeat('cd',32),'hex'), pdf_storage_version_id='reversible-version',
		    evidence_version_pins_required=TRUE, status='sealing'
		WHERE id=$1`, reversibleID)
	must(t, err, "seed reversible sealing document")
	reversibleEpoch := epoch.Add(2 * time.Hour)
	var reversibleDeadline time.Time
	must(t, pool.QueryRow(ctx, `SELECT hash_evidence_retain_until($1, 7)`, reversibleEpoch).Scan(&reversibleDeadline), "derive reversible intent deadline")
	_, err = pool.Exec(ctx, `INSERT INTO send_sealing_intents
		(document_id, org_id, article13_notice_epoch_at, retain_until)
		VALUES ($1,$2,$3,$4)`, reversibleID, documentOrgID(t, ctx, pool, reversibleID), reversibleEpoch, reversibleDeadline)
	must(t, err, "seed pre-retention reversible intent")
	_, err = pool.Exec(ctx, `UPDATE documents
		SET source_kind='pdf', blocks_json=NULL, pdf_storage_key='fixture/deleted-draft.pdf',
		    pdf_sha256=decode(repeat('ef',32),'hex'), pdf_storage_version_id='deleted-draft-version',
		    evidence_version_pins_required=TRUE, deleted_at=$2
		WHERE id=$1`, deletedDraftID, epoch)
	must(t, err, "seed retained soft-deleted draft row")
	_, err = pool.Exec(ctx, `UPDATE documents
		SET source_kind='pdf', blocks_json=NULL, pdf_storage_key='fixture/missing-deadline.pdf',
		    pdf_sha256=decode(repeat('fa',32),'hex'), pdf_storage_version_id='missing-deadline-version',
		    evidence_version_pins_required=TRUE, status='declined'
		WHERE id=$1`, missingDeadlineID)
	must(t, err, "seed illegal terminal object without a retention deadline")

	var recipientID, fieldID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT id FROM recipients WHERE document_id=$1 LIMIT 1`, progressID).Scan(&recipientID), "load signature fixture recipient")
	must(t, pool.QueryRow(ctx, `INSERT INTO document_fields
		(document_id, recipient_id, type, page, x_pct, y_pct, w_pct, h_pct)
		VALUES ($1,$2,'signature',1,10,10,20,5) RETURNING id`, progressID, recipientID).Scan(&fieldID), "seed signature fixture field")
	_, err = pool.Exec(ctx, `INSERT INTO signatures
		(document_id, recipient_id, field_id, font, typed_name, image_storage_key,
		 image_sha256, image_version_id)
		VALUES ($1,$2,$3,'Dancing Script','Fixture Signer','fixture/signature.png',
		        decode(repeat('de',32),'hex'),'signature-version')`, progressID, recipientID, fieldID)
	must(t, err, "seed in-progress signature image")

	inventorySQL, err := os.ReadFile(filepath.Join("..", "..", "ops", "recovery-object-inventory.sql"))
	must(t, err, "read canonical recovery inventory SQL")
	inventoryTx, err := recoveryinventory.Begin(ctx, pool)
	must(t, err, "begin canonical inventory snapshot")
	defer func() { must(t, recoveryinventory.Rollback(inventoryTx), "close canonical inventory snapshot") }()
	rows, err := inventoryTx.Query(ctx, string(inventorySQL))
	must(t, err, "execute canonical recovery inventory SQL")
	defer rows.Close()
	type result struct {
		legal    bool
		deadline string
	}
	results := map[string]result{}
	for rows.Next() {
		var keyB64, keyJSON, classes, owners, orgIDs, sha, version, deadline string
		var hashConflict, legal, versionConflict, legacy bool
		var refs int64
		must(t, rows.Scan(&keyB64, &keyJSON, &classes, &owners, &orgIDs, &sha,
			&hashConflict, &legal, &refs, &version, &versionConflict, &legacy, &deadline), "scan recovery inventory row")
		results[keyJSON] = result{legal: legal, deadline: deadline}
	}
	must(t, rows.Err(), "drain recovery inventory")
	postSend := postSendDeadline.UTC().Format(time.RFC3339)
	parentRetain := parentDeadline.UTC().Format(time.RFC3339)
	for key, want := range map[string]result{
		`"fixture/sent.pdf"`:             {true, postSend},
		`"fixture/in-progress.pdf"`:      {true, postSend},
		`"fixture/signature.png"`:        {true, postSend},
		`"fixture/envelope-child.pdf"`:   {true, parentRetain},
		`"fixture/reversible.pdf"`:       {false, "-"},
		`"fixture/missing-deadline.pdf"`: {true, "-"},
	} {
		if got, ok := results[key]; !ok || got != want {
			t.Fatalf("recovery inventory %s = %+v/%v, want %+v", key, got, ok, want)
		}
	}
	if got, present := results[`"fixture/deleted-draft.pdf"`]; !present || got != (result{legal: false, deadline: "-"}) {
		t.Fatal("retained soft-deleted draft is missing or has an incorrect legal deadline in the recovery inventory")
	}
}

func TestArticle13EpochMigrationRefusesUnmarkedActiveCeremonyE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 60), "migrate scratch database to pre-Article-13-epoch version 60")

	docID := seedDocument(t, ctx, pool, "Article 13 legacy active cutover")
	sentAt := time.Date(2026, time.August, 31, 10, 11, 12, 123456000, time.UTC)
	_, err := pool.Exec(ctx, `UPDATE documents SET status='sent', sent_at=$2 WHERE id=$1`, docID, sentAt)
	must(t, err, "seed old active sent document")
	appendArticle13SendEvent(t, ctx, pool, docID, map[string]any{"legacy": true})

	err = mdb.RunMigrationsUpToContext(ctx, migConn, 61)
	if err == nil || !strings.Contains(err.Error(), "every active sent/in_progress/changes_requested ceremony") {
		t.Fatalf("migration 00061 with markerless active ceremony = %v, want explicit drain refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 60)
	assertArticle13EpochColumns(t, ctx, pool, false)

	// Explicitly terminate the old ceremony, then apply the release. A stale
	// client cannot turn that unbound old send into a post-upgrade response:
	// the active-state constraint rejects the transition before any response
	// side effect can commit.
	_, err = pool.Exec(ctx, `UPDATE documents SET status='voided' WHERE id=$1`, docID)
	must(t, err, "terminate old active ceremony")
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 61), "apply Article 13 epoch migration after drain")
	assertAppliedMigrationVersion(t, ctx, pool, 61)
	assertArticle13EpochColumns(t, ctx, pool, true)
	if _, err := pool.Exec(ctx, `UPDATE documents SET status='in_progress' WHERE id=$1`, docID); err == nil {
		t.Fatal("post-upgrade response transition revived an old markerless ceremony")
	}
}

func TestArticle13EpochMigrationAdmitsExactSupportedActiveMarkerE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 60), "migrate supported-marker scratch database to version 60")

	docID := seedDocument(t, ctx, pool, "Article 13 supported active cutover")
	sentAt := time.Date(2026, time.August, 31, 13, 14, 15, 654321000, time.UTC)
	_, err := pool.Exec(ctx, `UPDATE documents SET status='sent', sent_at=$2 WHERE id=$1`, docID, sentAt)
	must(t, err, "seed marked active document")
	appendArticle13SendEvent(t, ctx, pool, docID, article13MarkerPayload(t, sentAt))

	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 61), "apply Article 13 epoch migration to marked active ceremony")
	var schema string
	var epoch time.Time
	var v61Committed bool
	must(t, pool.QueryRow(ctx, `SELECT article13_notice_schema, article13_notice_epoch_at,
		article13_notice_epoch_v61_committed FROM documents WHERE id=$1`, docID).Scan(
		&schema, &epoch, &v61Committed,
	), "read migrated active marker binding")
	if schema != article13.SchemaV1 || !epoch.Equal(sentAt) || v61Committed {
		t.Fatalf("migrated active binding = %q/%s/%v, want %q/%s/false", schema, epoch, v61Committed, article13.SchemaV1, sentAt)
	}
}

func TestArticle13EpochIsPinnedBeforeRetentionAndMonotonicAcrossRevisionE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 60), "migrate monotonic-epoch scratch database to version 60")

	docID := seedDocument(t, ctx, pool, "Article 13 clock rollback revision")
	// A revised draft has no active sent_at. Its last committed marker is the
	// durable lower bound after a database-clock rollback. Append a later audit
	// event carrying an older ceremony timestamp to prove the migration takes
	// the greatest valid epoch rather than blindly trusting event recency.
	historicalEpoch := time.Date(2099, time.January, 2, 3, 4, 5, 123456000, time.UTC)
	appendArticle13SendEvent(t, ctx, pool, docID, article13MarkerPayload(t, historicalEpoch))
	rolledBackEpoch := time.Date(2020, time.January, 2, 3, 4, 5, 123456000, time.UTC)
	appendArticle13SendEvent(t, ctx, pool, docID, article13MarkerPayload(t, rolledBackEpoch))
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 61), "apply Article 13 epoch migration to revised draft")

	firstIntent := beginArticle13SendSealing(t, ctx, pool, docID, false)
	if !firstIntent.Article13NoticeEpochAt.Time.After(historicalEpoch) {
		t.Fatalf("first intent epoch %s did not advance historical high-water %s", firstIntent.Article13NoticeEpochAt.Time, historicalEpoch)
	}
	assertSendIntentDeadlineMatchesEpoch(t, ctx, pool, firstIntent)
	retryIntent := readArticle13SendIntent61(t, ctx, pool, firstIntent.DocumentID, firstIntent.OrgID)
	if !retryIntent.Article13NoticeEpochAt.Time.Equal(firstIntent.Article13NoticeEpochAt.Time) ||
		!retryIntent.RetainUntil.Time.Equal(firstIntent.RetainUntil.Time) {
		t.Fatalf("retry changed pinned epoch/deadline: first=%+v retry=%+v", firstIntent, retryIntent)
	}
	if _, err := pool.Exec(ctx, `UPDATE send_sealing_intents
		SET article13_notice_epoch_at=article13_notice_epoch_at + interval '1 microsecond'
		WHERE document_id=$1`, docID); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("intent epoch rewrite = %v, want immutable commitment refusal", err)
	}
	firstSent, _ := completeArticle13SendSealing(t, ctx, pool, docID, false)
	if !firstSent.SentAt.Time.Equal(firstIntent.Article13NoticeEpochAt.Time) {
		t.Fatalf("completed sent_at %s != pre-S3 intent epoch %s", firstSent.SentAt.Time, firstIntent.Article13NoticeEpochAt.Time)
	}

	_, err := pool.Exec(ctx, `UPDATE documents SET status='changes_requested' WHERE id=$1`, docID)
	must(t, err, "pause first ceremony for revision")
	revised := reopenArticle13Document61(t, ctx, pool, docID, firstSent.OrgID)
	if revised.SentAt.Valid || !revised.Article13NoticeEpochAt.Time.Equal(firstSent.SentAt.Time) {
		t.Fatalf("revision lost high-water mark: sent=%+v epoch=%+v", revised.SentAt, revised.Article13NoticeEpochAt)
	}

	secondIntent := beginArticle13SendSealing(t, ctx, pool, docID, false)
	if !secondIntent.Article13NoticeEpochAt.Time.After(firstSent.SentAt.Time) {
		t.Fatalf("resend intent epoch %s did not advance prior ceremony %s", secondIntent.Article13NoticeEpochAt.Time, firstSent.SentAt.Time)
	}
	assertSendIntentDeadlineMatchesEpoch(t, ctx, pool, secondIntent)
	secondSent, _ := completeArticle13SendSealing(t, ctx, pool, docID, false)
	if !secondSent.SentAt.Time.Equal(secondIntent.Article13NoticeEpochAt.Time) {
		t.Fatalf("resend sent_at %s != pinned retry-stable epoch %s", secondSent.SentAt.Time, secondIntent.Article13NoticeEpochAt.Time)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents
		SET article13_notice_epoch_at=article13_notice_epoch_at - interval '1 microsecond'
		WHERE id=$1`, docID); err == nil || !strings.Contains(err.Error(), "may only advance") {
		t.Fatalf("epoch rollback rewrite = %v, want immutable monotonic refusal", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents
		SET sent_at=sent_at - interval '1 microsecond'
		WHERE id=$1`, docID); err == nil || !strings.Contains(err.Error(), "immutable within a ceremony") {
		t.Fatalf("sent_at rollback rewrite = %v, want ceremony immutability refusal", err)
	}

	err = mdb.RunMigrationsDownToContext(ctx, migConn, 60)
	if err == nil || !strings.Contains(err.Error(), "post-cutover send commitment") {
		t.Fatalf("migration 00061 down after send = %v, want irreversible commitment refusal", err)
	}
	assertAppliedMigrationVersion(t, ctx, pool, 61)
}

func TestArticle13EnvelopeChildrenShareIntentEpochAboveEveryHighWaterE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	pool, cleanup := scratchDatabase(t, ctx, dsn)
	defer cleanup()
	migConn := stdlibConn(t, pool)
	defer migConn.Close()
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 60), "migrate envelope-epoch scratch database to version 60")

	parentID := seedDocument(t, ctx, pool, "Article 13 envelope epoch")
	_, err := pool.Exec(ctx, `UPDATE documents SET is_envelope=TRUE WHERE id=$1`, parentID)
	must(t, err, "mark envelope parent")
	childOne := seedEnvelopeChild(t, ctx, pool, parentID, 1)
	childTwo := seedEnvelopeChild(t, ctx, pool, parentID, 2)
	parentOld := time.Date(2098, time.January, 1, 0, 0, 0, 0, time.UTC)
	childOneOld := parentOld.Add(time.Hour)
	childTwoOld := childOneOld.Add(time.Hour)
	appendArticle13SendEvent(t, ctx, pool, parentID, article13MarkerPayload(t, parentOld))
	appendArticle13SendEvent(t, ctx, pool, childOne, article13MarkerPayload(t, childOneOld))
	appendArticle13SendEvent(t, ctx, pool, childTwo, article13MarkerPayload(t, childTwoOld))
	must(t, mdb.RunMigrationsUpToContext(ctx, migConn, 61), "apply Article 13 epoch migration to revised envelope family")

	intent := beginArticle13SendSealing(t, ctx, pool, parentID, true)
	if !intent.Article13NoticeEpochAt.Time.After(childTwoOld) {
		t.Fatalf("envelope intent epoch %s did not exceed latest child high-water %s", intent.Article13NoticeEpochAt.Time, childTwoOld)
	}
	parent, children := completeArticle13SendSealing(t, ctx, pool, parentID, true)
	if len(children) != 2 {
		t.Fatalf("completed envelope children = %d, want 2", len(children))
	}
	for _, child := range children {
		if !child.SentAt.Time.Equal(parent.SentAt.Time) ||
			!child.Article13NoticeEpochAt.Time.Equal(parent.Article13NoticeEpochAt.Time) ||
			child.Article13NoticeSchema != parent.Article13NoticeSchema {
			t.Fatalf("child %s binding differs from parent: child=%+v parent=%+v", child.ID, child, parent)
		}
	}
}

func article13MarkerPayload(t *testing.T, sentAt time.Time) map[string]any {
	t.Helper()
	canonical, err := article13.CanonicalSentAt(sentAt)
	must(t, err, "canonicalize Article 13 marker epoch")
	return map[string]any{
		article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1,
		article13.AuditRequiredNoticeSentAtKey: canonical,
	}
}

func appendArticle13SendEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, payload map[string]any) {
	t.Helper()
	var orgID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT org_id FROM documents WHERE id=$1`, docID).Scan(&orgID), "load marker organization")
	logger := audit.New(generated.New(pool), pool)
	_, err := logger.Log(ctx, audit.Entry{
		OrgID: orgID, DocumentID: &docID, Kind: audit.KindDocumentSent, Payload: payload,
	})
	must(t, err, "append Article 13 document.sent marker")
}

// These migration fixtures intentionally stay at schema 61. Keep their SQL
// projections and transitions local: latest generated rows include later HTML,
// delegated-send and package columns that do not exist at this cutover.
type article13SendIntent61 struct {
	DocumentID, OrgID                   uuid.UUID
	Article13NoticeEpochAt, RetainUntil pgtype.Timestamptz
}
type article13Document61 struct {
	ID, OrgID                      uuid.UUID
	SentAt, Article13NoticeEpochAt pgtype.Timestamptz
	Article13NoticeSchema          string
}

func readArticle13SendIntent61(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID, orgID uuid.UUID) *article13SendIntent61 {
	t.Helper()
	intent := &article13SendIntent61{}
	err := pool.QueryRow(ctx, `SELECT document_id, org_id, article13_notice_epoch_at, retain_until
  FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2`, docID, orgID).Scan(
		&intent.DocumentID, &intent.OrgID, &intent.Article13NoticeEpochAt, &intent.RetainUntil)
	must(t, err, "reload schema-61 send intent")
	return intent
}

func reopenArticle13Document61(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID, orgID uuid.UUID) *article13Document61 {
	t.Helper()
	doc := &article13Document61{}
	err := pool.QueryRow(ctx, `UPDATE documents SET status='draft', sent_at=NULL, updated_at=now()
  WHERE id=$1 AND org_id=$2 AND status='changes_requested'
  RETURNING id, org_id, sent_at, article13_notice_epoch_at, article13_notice_schema`, docID, orgID).Scan(
		&doc.ID, &doc.OrgID, &doc.SentAt, &doc.Article13NoticeEpochAt, &doc.Article13NoticeSchema)
	must(t, err, "reopen first ceremony to draft")
	return doc
}

func beginArticle13SendSealing(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, envelope bool) *article13SendIntent61 {
	t.Helper()
	tx, err := pool.Begin(ctx)
	must(t, err, "begin send-intent transaction")
	defer func() { _ = tx.Rollback(ctx) }()
	var lockedID, orgID uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id, org_id FROM documents
  WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL FOR UPDATE`,
		docID, documentOrgID(t, ctx, pool, docID)).Scan(&lockedID, &orgID)
	must(t, err, "lock send-intent document")
	intent := &article13SendIntent61{}
	err = tx.QueryRow(ctx, `WITH next_epoch AS MATERIALIZED (
  SELECT GREATEST(
   statement_timestamp(), clock_timestamp(),
   COALESCE(parent.article13_notice_epoch_at + interval '1 microsecond', '-infinity'::timestamptz),
   COALESCE((SELECT max(child.article13_notice_epoch_at) + interval '1 microsecond'
    FROM documents child WHERE child.parent_envelope_id=parent.id AND child.org_id=parent.org_id),
    '-infinity'::timestamptz)
  ) AS value FROM documents parent
  WHERE parent.id=$1 AND parent.org_id=$2 AND parent.status='draft' AND parent.deleted_at IS NULL
 ) INSERT INTO send_sealing_intents (
  document_id, org_id, actor_user_id, actor_email, actor_ip, via, tool,
  article13_notice_epoch_at, retain_until
 ) SELECT $1, $2, NULL, 'sender@example.test', '127.0.0.1', 'e2e', 'article13-epoch',
  next_epoch.value, hash_evidence_retain_until(next_epoch.value, 7) FROM next_epoch
 RETURNING document_id, org_id, article13_notice_epoch_at, retain_until`,
		lockedID, orgID).Scan(&intent.DocumentID, &intent.OrgID, &intent.Article13NoticeEpochAt, &intent.RetainUntil)
	must(t, err, "create durable send intent with epoch")
	if !intent.Article13NoticeEpochAt.Valid || !intent.RetainUntil.Valid {
		t.Fatalf("send intent lacks epoch/deadline: %+v", intent)
	}
	if envelope {
		tag, err := tx.Exec(ctx, `UPDATE documents SET status='sealing', updated_at=now()
   WHERE parent_envelope_id=$1 AND org_id=$2 AND status='draft' AND deleted_at IS NULL`, lockedID, orgID)
		must(t, err, "begin envelope children sealing")
		if tag.RowsAffected() != 2 {
			t.Fatalf("sealed envelope children = %d, want 2", tag.RowsAffected())
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE documents SET status='sealing', updated_at=now()
  WHERE id=$1 AND org_id=$2 AND status='draft' AND deleted_at IS NULL`, lockedID, orgID)
	must(t, err, "begin parent send sealing")
	if tag.RowsAffected() != 1 {
		t.Fatalf("sealed parent documents = %d, want 1", tag.RowsAffected())
	}
	must(t, tx.Commit(ctx), "commit durable send intent")

	_, err = pool.Exec(ctx, `UPDATE documents SET evidence_version_pins_required=TRUE
  WHERE id=$1 OR parent_envelope_id=$1`, docID)
	must(t, err, "pin test evidence versions")
	tag, err = pool.Exec(ctx, `UPDATE send_sealing_intents
  SET retention_started_at=COALESCE(retention_started_at,now()), updated_at=now()
  WHERE document_id=$1 AND org_id=$2 AND retention_completed_at IS NULL
   AND retain_until=hash_evidence_retain_until(article13_notice_epoch_at,7)`, lockedID, orgID)
	must(t, err, "mark send retention started")
	if tag.RowsAffected() != 1 {
		t.Fatalf("retention-start rows = %d, want 1", tag.RowsAffected())
	}
	tag, err = pool.Exec(ctx, `UPDATE send_sealing_intents
  SET retention_completed_at=COALESCE(retention_completed_at,now()), attempts=attempts+1,
   last_error=NULL, updated_at=now()
  WHERE document_id=$1 AND org_id=$2 AND retention_started_at IS NOT NULL
   AND retain_until=hash_evidence_retain_until(article13_notice_epoch_at,7)`, lockedID, orgID)
	must(t, err, "mark send retention complete")
	if tag.RowsAffected() != 1 {
		t.Fatalf("retention-complete rows = %d, want 1", tag.RowsAffected())
	}
	return readArticle13SendIntent61(t, ctx, pool, lockedID, orgID)
}

func completeArticle13SendSealing(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID, envelope bool) (*article13Document61, []*article13Document61) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	must(t, err, "begin send completion transaction")
	defer func() { _ = tx.Rollback(ctx) }()
	orgID := documentOrgID(t, ctx, pool, docID)
	parent := &article13Document61{}
	err = tx.QueryRow(ctx, `WITH ceremony_epoch AS MATERIALIZED (
  SELECT intent.article13_notice_epoch_at AS value FROM send_sealing_intents intent
  WHERE intent.document_id=$1 AND intent.org_id=$2
   AND intent.retention_started_at IS NOT NULL AND intent.retention_completed_at IS NOT NULL
   AND intent.retain_until=hash_evidence_retain_until(intent.article13_notice_epoch_at,7)
 ) UPDATE documents SET status='sent', sent_at=ceremony_epoch.value,
  article13_notice_epoch_at=ceremony_epoch.value, article13_notice_schema='hash-a13-2026-08-31',
  article13_notice_epoch_v61_committed=TRUE, updated_at=now() FROM ceremony_epoch
 WHERE documents.id=$1 AND documents.org_id=$2 AND documents.status='sealing'
  AND documents.deleted_at IS NULL AND documents.evidence_version_pins_required=TRUE
  AND (documents.article13_notice_epoch_at IS NULL OR ceremony_epoch.value>documents.article13_notice_epoch_at)
 RETURNING documents.id, documents.org_id, documents.sent_at,
  documents.article13_notice_epoch_at, documents.article13_notice_schema`, docID, orgID).Scan(
		&parent.ID, &parent.OrgID, &parent.SentAt, &parent.Article13NoticeEpochAt, &parent.Article13NoticeSchema)
	must(t, err, "complete parent send sealing")
	var children []*article13Document61
	if envelope {
		rows, err := tx.Query(ctx, `UPDATE documents SET status='sent', sent_at=parent.sent_at,
   article13_notice_epoch_at=parent.article13_notice_epoch_at,
   article13_notice_schema=parent.article13_notice_schema,
   article13_notice_epoch_v61_committed=TRUE, updated_at=now() FROM documents parent
  WHERE documents.parent_envelope_id=$1 AND documents.org_id=$2 AND documents.status='sealing'
   AND documents.deleted_at IS NULL AND documents.evidence_version_pins_required=TRUE
   AND parent.id=$1 AND parent.org_id=$2 AND parent.status='sent' AND parent.sent_at IS NOT NULL
   AND parent.article13_notice_epoch_at=parent.sent_at AND parent.article13_notice_schema<>''
   AND parent.article13_notice_epoch_v61_committed
   AND (documents.article13_notice_epoch_at IS NULL OR parent.article13_notice_epoch_at>documents.article13_notice_epoch_at)
   AND EXISTS (SELECT 1 FROM send_sealing_intents i WHERE i.document_id=documents.parent_envelope_id
    AND i.org_id=documents.org_id AND i.article13_notice_epoch_at=parent.article13_notice_epoch_at
    AND i.retention_started_at IS NOT NULL AND i.retention_completed_at IS NOT NULL
    AND i.retain_until=hash_evidence_retain_until(i.article13_notice_epoch_at,7))
  RETURNING documents.id, documents.org_id, documents.sent_at,
   documents.article13_notice_epoch_at, documents.article13_notice_schema`, docID, orgID)
		must(t, err, "complete envelope children send sealing")
		defer rows.Close()
		for rows.Next() {
			child := &article13Document61{}
			must(t, rows.Scan(&child.ID, &child.OrgID, &child.SentAt, &child.Article13NoticeEpochAt, &child.Article13NoticeSchema), "read completed schema-61 envelope child")
			children = append(children, child)
		}
		must(t, rows.Err(), "drain completed schema-61 envelope children")
		rows.Close()
	}
	logger := audit.New(generated.New(pool), pool)
	appendMarkerTx := func(doc *article13Document61) {
		_, logErr := logger.LogTx(ctx, tx, audit.Entry{
			OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindDocumentSent,
			Payload: article13MarkerPayload(t, doc.SentAt.Time),
		})
		must(t, logErr, "append transactional Article 13 send marker")
	}
	for _, child := range children {
		appendMarkerTx(child)
	}
	appendMarkerTx(parent)
	tag, err := tx.Exec(ctx, `DELETE FROM send_sealing_intents WHERE document_id=$1 AND org_id=$2`, docID, orgID)
	must(t, err, "delete published send intent")
	if tag.RowsAffected() != 1 {
		t.Fatalf("deleted send intents = %d, want 1", tag.RowsAffected())
	}
	must(t, tx.Commit(ctx), "commit sent state and markers")
	return parent, children
}

func assertSendIntentDeadlineMatchesEpoch(t *testing.T, ctx context.Context, pool *pgxpool.Pool, intent *article13SendIntent61) {
	t.Helper()
	var expected time.Time
	must(t, pool.QueryRow(ctx, `SELECT hash_evidence_retain_until($1,7)`, intent.Article13NoticeEpochAt).Scan(&expected), "derive expected intent deadline")
	if !intent.RetainUntil.Time.Equal(expected) {
		t.Fatalf("intent retain_until %s != exact epoch-derived deadline %s", intent.RetainUntil.Time, expected)
	}
}

func seedEnvelopeChild(t *testing.T, ctx context.Context, pool *pgxpool.Pool, parentID uuid.UUID, position int32) uuid.UUID {
	t.Helper()
	var childID uuid.UUID
	must(t, pool.QueryRow(ctx, `INSERT INTO documents (
		org_id, name, status, routing_mode, source_kind, blocks_json, variables_json,
		sender_id, parent_envelope_id, envelope_position
	) SELECT org_id, 'Article 13 envelope child ' || ($2::integer)::text, 'draft', routing_mode,
	         source_kind, blocks_json, variables_json, sender_id, id, $2::integer
	    FROM documents WHERE id=$1
	RETURNING id`, parentID, position).Scan(&childID), "seed envelope child")
	return childID
}

func documentOrgID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, docID uuid.UUID) uuid.UUID {
	t.Helper()
	var orgID uuid.UUID
	must(t, pool.QueryRow(ctx, `SELECT org_id FROM documents WHERE id=$1`, docID).Scan(&orgID), "load document organization")
	return orgID
}

func assertArticle13EpochColumns(t *testing.T, ctx context.Context, pool *pgxpool.Pool, want bool) {
	t.Helper()
	var count int
	must(t, pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema='public' AND (table_name, column_name) IN (
			('documents','article13_notice_epoch_at'),
			('documents','article13_notice_schema'),
			('documents','article13_notice_epoch_v61_committed'),
			('send_sealing_intents','article13_notice_epoch_at')
		)`).Scan(&count), "inspect Article 13 epoch schema")
	wantCount := 0
	if want {
		wantCount = 4
	}
	if count != wantCount {
		t.Fatalf("Article 13 epoch column count = %d, want %d", count, wantCount)
	}
}
