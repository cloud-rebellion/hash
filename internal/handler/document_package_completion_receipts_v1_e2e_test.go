//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func packageCompletionPayload241(m pdfadmission.HTMLSendPackageIntentMetadataV1, extra map[string]any) map[string]any {
	p := map[string]any{"package_send_schema": "hash-package-send-v1", "package_send_attempt_id": m.AttemptID.String(), "package_id": m.Capture.PackageID.String(), "capture_revision": strconv.FormatInt(m.Capture.Revision, 10), "manifest_sha256": hex.EncodeToString(m.Capture.CanonicalSHA256[:]), "legal_commitment_sha256": hex.EncodeToString(m.Capture.CommitmentSHA256[:])}
	for k, v := range extra {
		p[k] = v
	}
	return p
}
func packageCompletionRecordParams241(m pdfadmission.HTMLSendPackageIntentMetadataV1) generated.RecordDocumentPackageSendCompletionV1Params {
	return generated.RecordDocumentPackageSendCompletionV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]}
}
func packageCompletionInspectParams241(m pdfadmission.HTMLSendPackageIntentMetadataV1) generated.InspectDocumentPackageSendCompletionV1Params {
	return generated.InspectDocumentPackageSendCompletionV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]}
}
func packageCompletionReceiptsState241(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) string {
	t.Helper()
	var s string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('completion',(SELECT to_jsonb(c) FROM document_package_send_completions_v1 c WHERE attempt_id=$1),'invites',(SELECT jsonb_agg(to_jsonb(i) ORDER BY recipient_id) FROM document_package_send_initial_invite_receipts_v1 i WHERE attempt_id=$1))::text", m.AttemptID).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
func packageCompletionVersionPresent241(ctx context.Context, tx pgx.Tx) (bool, error) {
	var present bool
	err := tx.QueryRow(ctx, "SELECT to_regprocedure('hash_package_send_completion_version_v1()') IS NOT NULL").Scan(&present)
	return present, err
}

// Explicit synthetic SQL protocol acknowledgement, not actual S3/native Send.
// The genuine root/attempt/capture exists; every mandatory SQL guard is active.
func packageCompletionSQLStage241(t *testing.T, q *ownedPublicReadFixtureV1, tx pgx.Tx, m pdfadmission.HTMLSendPackageIntentMetadataV1, narrowAudit bool) error {
	t.Helper()
	db := generated.New(tx)
	match := packageAttemptMatch235(m)
	root, err := db.GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: m.Capture.DocumentID, OrgID: m.Capture.OrgID})
	if err != nil {
		return err
	}
	if _, err = db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match)); err != nil {
		return err
	}
	if _, err = db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); err != nil {
		return err
	}
	if err = packageMemberRetentionSQLReceipts240(q.f.ctx, db, m); err != nil {
		return err
	}
	if _, err = db.MarkDocumentPackageSendRetentionCompleteV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionCompleteV1Params(match)); err != nil {
		return err
	}
	if _, err = db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); err != nil {
		return err
	}
	if _, err = db.PinDocumentSendEvidenceVersions(q.f.ctx, generated.PinDocumentSendEvidenceVersionsParams{ID: root.ID, OrgID: root.OrgID, PdfStorageVersionID: root.PdfStorageVersionID, RenderedPdfVersionID: root.RenderedPdfVersionID}); err != nil {
		return err
	}
	sent, err := db.CompleteDocumentPackageSendSealingV1(q.f.ctx, generated.CompleteDocumentPackageSendSealingV1Params(match))
	if err != nil {
		return err
	}
	epoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		return err
	}
	payload := map[string]any{article13.AuditRequiredNoticeSchemaKey: sent.Article13NoticeSchema, article13.AuditRequiredNoticeSentAtKey: epoch, "recipient_count": 0}
	if narrowAudit {
		payload = packageCompletionPayload241(m, payload)
	}
	_, err = q.f.s.Audit.LogTx(q.f.ctx, tx, audit.Entry{OrgID: root.OrgID, DocumentID: &root.ID, ActorUserID: &q.f.user.ID, Kind: audit.KindDocumentSent, Payload: payload})
	return err
}
func packageCompletionSQLTerminal241(ctx context.Context, db *generated.Queries, m pdfadmission.HTMLSendPackageIntentMetadataV1) error {
	match := packageAttemptMatch235(m)
	if _, err := db.TerminalizeDocumentPackageSendAttemptV1(ctx, generated.TerminalizeDocumentPackageSendAttemptV1Params{Outcome: "completed", AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: match.ExpectedManifestSha256, ExpectedLegalCommitmentSha256: match.ExpectedLegalCommitmentSha256}); err != nil {
		return err
	}
	n, err := db.DeleteDocumentPackageSealingIntentV1(ctx, match)
	if err == nil && n != 1 {
		return errors.New("synthetic completion did not delete exact intent")
	}
	return err
}
func packageCompletionSQLRefusal241(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, code string, run func(pgx.Tx, *generated.Queries) error) {
	t.Helper()
	before, requests := packageCompletionNativeState241(t, q, m), q.storagePeer.requests.Load()
	func() {
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		err := run(tx, generated.New(tx))
		if code == "no rows" {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("wrong completion selector did not refuse", err)
			}
		} else {
			packageExpectPG218(t, err, code)
		}
	}()
	if packageCompletionNativeState241(t, q, m) != before || q.storagePeer.requests.Load() != requests {
		t.Fatal("completion SQL refusal changed history or called storage")
	}
}

func TestDocumentPackageCompletionReceiptsV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	birth := func(t *testing.T) pdfadmission.HTMLSendPackageIntentMetadataV1 {
		t.Helper()
		_, _, m, err := packageAttemptBirth235(t, q, false)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	t.Run("missing immutable summary cannot terminalize completed", func(t *testing.T) {
		m := birth(t)
		packageCompletionSQLRefusal241(t, q, m, "23514", func(tx pgx.Tx, db *generated.Queries) error {
			if err := packageCompletionSQLStage241(t, q, tx, m, true); err != nil {
				return err
			}
			if err := packageCompletionSQLTerminal241(q.f.ctx, db, m); err != nil {
				return err
			}
			_, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
			return err
		})
	})
	t.Run("legacy audit marker cannot become package effect proof", func(t *testing.T) {
		m := birth(t)
		packageCompletionSQLRefusal241(t, q, m, "no rows", func(tx pgx.Tx, db *generated.Queries) error {
			if err := packageCompletionSQLStage241(t, q, tx, m, false); err != nil {
				return err
			}
			_, err := db.RecordDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionRecordParams241(m))
			return err
		})
	})
	t.Run("inserted summary still requires terminal and exact intent retirement", func(t *testing.T) {
		m := birth(t)
		packageCompletionSQLRefusal241(t, q, m, "23514", func(tx pgx.Tx, db *generated.Queries) error {
			if err := packageCompletionSQLStage241(t, q, tx, m, true); err != nil {
				return err
			}
			if _, err := db.RecordDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionRecordParams241(m)); err != nil {
				return err
			}
			_, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE")
			return err
		})
	})
	t.Run("invented invite association cannot replace real token outbox and audit", func(t *testing.T) {
		m := birth(t)
		packageCompletionSQLRefusal241(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
			_, err := tx.Exec(q.f.ctx, "INSERT INTO document_package_send_initial_invite_receipts_v1(attempt_id,org_id,document_id,recipient_id,email_delivery_id,invited_event_id,invited_event_row_sha256,token_hash,token_expires_at,message_sha256) VALUES($1,$2,$3,$4,$5,$6,sha256('synthetic'::bytea),sha256('synthetic'::bytea),clock_timestamp()+interval '1 day',sha256('synthetic'::bytea))", m.AttemptID, m.Capture.OrgID, m.Capture.DocumentID, uuid.New(), uuid.New(), uuid.New())
			return err
		})
	})
	t.Run("exact summary persists original pins and refuses rewrites deletion and foreign selectors", func(t *testing.T) {
		m := birth(t)
		if err := packageAttemptTransition235(t, q, m, "completed", false); err != nil {
			t.Fatal(err)
		}
		got, err := q.f.q.InspectDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionInspectParams241(m))
		if err != nil || got == nil || got.AttemptID != m.AttemptID || got.OrgID != m.Capture.OrgID || got.DocumentID != m.Capture.DocumentID || got.Outcome != "sent" || got.RecipientCount != 0 || got.InviteCount != 0 || !got.Article13NoticeEpochAt.Time.Equal(m.Article13NoticeEpochAt) || !got.RetainUntil.Time.Equal(m.RetainUntil) || !bytes.Equal(got.ManifestSha256, m.Capture.CanonicalSHA256[:]) || !bytes.Equal(got.LegalCommitmentSha256, m.Capture.CommitmentSHA256[:]) || len(got.EffectSha256) != 32 {
			t.Fatal("synthetic SQL summary lost exact immutable pins", err)
		}
		for _, statement := range []string{"UPDATE document_package_send_completions_v1 SET outcome=outcome WHERE attempt_id=$1", "DELETE FROM document_package_send_completions_v1 WHERE attempt_id=$1"} {
			packageCompletionSQLRefusal241(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
				_, err := tx.Exec(q.f.ctx, statement, m.AttemptID)
				return err
			})
		}
		for _, change := range []func(*generated.InspectDocumentPackageSendCompletionV1Params){func(p *generated.InspectDocumentPackageSendCompletionV1Params) { p.OrgID = uuid.New() }, func(p *generated.InspectDocumentPackageSendCompletionV1Params) { p.DocumentID = uuid.New() }, func(p *generated.InspectDocumentPackageSendCompletionV1Params) { p.AttemptID = uuid.New() }, func(p *generated.InspectDocumentPackageSendCompletionV1Params) {
			p.ExpectedManifestSha256 = make([]byte, 32)
		}, func(p *generated.InspectDocumentPackageSendCompletionV1Params) {
			p.ExpectedLegalCommitmentSha256 = make([]byte, 32)
		}} {
			p := packageCompletionInspectParams241(m)
			change(&p)
			if _, err := q.f.q.InspectDocumentPackageSendCompletionV1(q.f.ctx, p); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("foreign completion selector returned history", err)
			}
		}
	})
	t.Run("actual invitation receipt survives later mutable projection cleanup", func(t *testing.T) {
		actual, _, client, m, recipient := packageCompletionNativeFixture241(t)
		packageCompletionRun241(t, actual, client, m, "sent")
		before := packageCompletionReceiptsState241(t, actual, m)
		if _, err := actual.f.pool.Exec(actual.f.ctx, "UPDATE recipients SET magic_token_hash=sha256('synthetic-later-rotation'::bytea),magic_token_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", recipient); err != nil {
			t.Fatal(err)
		}
		if _, err := actual.f.pool.Exec(actual.f.ctx, "DELETE FROM email_deliveries"); err != nil {
			t.Fatal(err)
		}
		got, err := actual.f.q.InspectDocumentPackageSendCompletionV1(actual.f.ctx, packageCompletionInspectParams241(m))
		if err != nil || got == nil || got.InviteCount != 1 || packageCompletionReceiptsState241(t, actual, m) != before {
			t.Fatal("historical summary depended on mutable current token or outbox", err)
		}
		for _, statement := range []string{"UPDATE document_package_send_initial_invite_receipts_v1 SET token_expires_at=token_expires_at WHERE attempt_id=$1", "DELETE FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=$1"} {
			packageCompletionSQLRefusal241(t, actual, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
				_, err := tx.Exec(actual.f.ctx, statement, m.AttemptID)
				return err
			})
		}
	})
}

func TestDocumentPackageCompletionSchemaV1E2E(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		name := "empty effect tables"
		if occupied {
			name = "immutable completion history"
		}
		t.Run(name, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			m := packageLegacyAttempt619(t, q, 106)
			if occupied {
				if err := packageLegacyComplete619(t, q, m); err != nil {
					t.Fatal(err)
				}
			}
			before, requests := packageCompletionNativeState241(t, q, m), q.storagePeer.requests.Load()
			cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
			if err != nil {
				t.Fatal(err)
			}
			db := stdlib.OpenDB(*cfg)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			defer db.Close()
			if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 106 {
				t.Fatal("completion schema did not start at M106", version, err)
			}
			err = mdb.RunMigrationsDownToContext(q.f.ctx, db, 105)
			if occupied {
				packageExpectPG218(t, err, "23514")
				if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 106 {
					t.Fatal("occupied M106 rollback changed schema", version, err)
				}
			} else {
				if err != nil {
					t.Fatal("empty M106 rollback failed", err)
				}
				defer func() {
					cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
					defer stop()
					if err := mdb.RunMigrationsUpToContext(cleanup, db, 106); err != nil {
						t.Error("restore M106", err)
					}
				}()
				var missingTable, missingMarker bool
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT to_regclass('document_package_send_completions_v1') IS NULL,to_regprocedure('hash_package_send_completion_version_v1()') IS NULL").Scan(&missingTable, &missingMarker); err != nil || !missingTable || !missingMarker {
					t.Fatal("M106 Down retained completion protocol", err)
				}
				if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 106); err != nil {
					t.Fatal(err)
				}
			}
			if packageCompletionNativeState241(t, q, m) != before || q.storagePeer.requests.Load() != requests {
				t.Fatal("M106 rollback/reapply changed history or provider state")
			}
		})
	}
	t.Run("pre106 completed history is preserved without fabricated effect receipts", func(t *testing.T) {
		q := inspectionFixturePG236(t)
		m := packageLegacyAttempt619(t, q, 105)
		cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*cfg)
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		defer db.Close()
		if err := mdb.RunMigrationsDownToContext(q.f.ctx, db, 105); err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
			defer stop()
			if err := mdb.RunMigrationsUpToContext(cleanup, db, 106); err != nil {
				t.Error("restore M106 historical fixture", err)
			}
		}()
		if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 105 {
			t.Fatal("historical completion is not actually pre106", version, err)
		}

		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if err := packageLegacyCompletionStage619(t, q, tx, m, true, false); err != nil {
			t.Fatal(err)
		}
		if err := packageCompletionSQLTerminal241(q.f.ctx, generated.New(tx), m); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		before, requests := packageMeasurementState232(t, q)+packageMemberRetentionState240(t, q, m)+packageRetentionNativeCeremonyState240(t, q, m), q.storagePeer.requests.Load()
		if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 106); err != nil {
			t.Fatal(err)
		}
		packageAttemptInspect235(t, q, m, false, "completed")
		var completions, invites int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*) FROM document_package_send_completions_v1 WHERE attempt_id=$1),(SELECT count(*) FROM document_package_send_initial_invite_receipts_v1 WHERE attempt_id=$1)", m.AttemptID).Scan(&completions, &invites); err != nil || completions != 0 || invites != 0 {
			t.Fatal("M106 fabricated historical Send effects", err, completions, invites)
		}
		if _, err := q.f.q.InspectDocumentPackageSendCompletionV1(q.f.ctx, packageCompletionInspectParams241(m)); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("old history incorrectly acquired M106 completion proof", err)
		}
		if packageMeasurementState232(t, q)+packageMemberRetentionState240(t, q, m)+packageRetentionNativeCeremonyState240(t, q, m) != before || q.storagePeer.requests.Load() != requests {
			t.Fatal("M106 changed old completion or replayed provider work")
		}
	})
}
