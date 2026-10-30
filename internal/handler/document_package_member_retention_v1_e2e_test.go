//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// These SQL fixtures explicitly model protocol acknowledgements. They do not
// constitute actual provider receipts, native dispatch authority, Object Lock
// acceptance, a nonempty package ceremony or complete Send implementation.
func packageMemberRetentionNamespace240() []byte {
	sum := sha256.Sum256([]byte("hash-explicit-synthetic-sql-member-retention-fixture-v1"))
	return sum[:]
}

func packageMemberRetentionList240(m pdfadmission.HTMLSendPackageIntentMetadataV1) generated.ListDocumentPackageSendRetentionMembersV1Params {
	return generated.ListDocumentPackageSendRetentionMembersV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, PackageID: m.Capture.PackageID, CaptureRevision: m.Capture.Revision, ExpectedMemberCount: m.Capture.MemberCount, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:]}
}

func packageMemberRetentionStart240(m pdfadmission.HTMLSendPackageIntentMetadataV1, position int16, namespace []byte) generated.StartDocumentPackageSendMemberRetentionV1Params {
	return generated.StartDocumentPackageSendMemberRetentionV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:], MemberPosition: position, ProviderNamespaceSha256: namespace}
}

func packageMemberRetentionConfirm240(m pdfadmission.HTMLSendPackageIntentMetadataV1, position int16, namespace []byte, until pgtype.Timestamptz) generated.ConfirmDocumentPackageSendMemberRetentionV1Params {
	return generated.ConfirmDocumentPackageSendMemberRetentionV1Params{AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: m.Capture.CommitmentSHA256[:], MemberPosition: position, ProviderNamespaceSha256: namespace, ObservedRetainUntil: until}
}

// Used only by existing explicit SQL terminal-transition fixtures. Both the
// aggregate started marker and its exact attempt mirror must already exist in
// this transaction. No provider boolean, production bypass or fake native
// authority is introduced by creating this required synthetic protocol state.
func packageMemberRetentionSQLReceipts240(ctx context.Context, db *generated.Queries, m pdfadmission.HTMLSendPackageIntentMetadataV1) error {
	rows, err := db.ListDocumentPackageSendRetentionMembersV1(ctx, packageMemberRetentionList240(m))
	if err != nil {
		return err
	}
	if len(rows) != int(m.Capture.MemberCount) {
		return errors.New("synthetic SQL receipt fixture lost exact captured members")
	}
	namespace := packageMemberRetentionNamespace240()
	for i, member := range rows {
		if member == nil || member.AttemptID != m.AttemptID || member.OrgID != m.Capture.OrgID || member.DocumentID != m.Capture.DocumentID || member.PackageID != m.Capture.PackageID || member.CaptureRevision != m.Capture.Revision || member.MemberCount != m.Capture.MemberCount || member.MemberPosition != int16(i) || member.PdfKey == "" || member.PdfVersionID == "" || len(member.PdfSha256) != 32 || member.PdfBytes <= 0 || member.PdfPages <= 0 {
			return errors.New("synthetic SQL receipt fixture received a different member")
		}
		started, err := db.StartDocumentPackageSendMemberRetentionV1(ctx, packageMemberRetentionStart240(m, member.MemberPosition, namespace))
		if err != nil {
			return err
		}
		if started == nil || started.AttemptID != m.AttemptID || started.MemberPosition != member.MemberPosition || !started.StartedAt.Valid || !bytes.Equal(started.ProviderNamespaceSha256, namespace) {
			return errors.New("synthetic SQL receipt start differs")
		}
		confirmed, err := db.ConfirmDocumentPackageSendMemberRetentionV1(ctx, packageMemberRetentionConfirm240(m, member.MemberPosition, namespace, pgtype.Timestamptz{Time: m.RetainUntil, Valid: true}))
		if err != nil {
			return err
		}
		if confirmed == nil || confirmed.AttemptID != m.AttemptID || confirmed.MemberPosition != member.MemberPosition || !confirmed.VerifiedAt.Valid || confirmed.ObservedMode.String != "COMPLIANCE" || !confirmed.ObservedMode.Valid || !confirmed.ObservedRetainUntil.Valid || confirmed.ObservedRetainUntil.Time.Before(m.RetainUntil) || confirmed.VerifierProfile.String != "s3-compliance-digest-v1" || !confirmed.VerifierProfile.Valid {
			return errors.New("synthetic SQL receipt confirmation differs")
		}
	}
	return nil
}

func packageMemberRetentionState240(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) string {
	t.Helper()
	var out string
	err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('attempt',(SELECT to_jsonb(a) FROM document_package_send_attempts_v1 a WHERE attempt_id=$1),'intent',(SELECT to_jsonb(i) FROM send_sealing_intents i WHERE package_send_attempt_id=$1),'members',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY member_position),'[]'::jsonb) FROM document_package_send_member_retention_v1 r WHERE attempt_id=$1))::text", m.AttemptID).Scan(&out)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func packageMemberRetentionAggregateStart240(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
	defer rollbackHTMLQueryFixtureV1(t, tx)
	db := generated.New(tx)
	if _, err := db.GetDocumentForUpdate(q.f.ctx, generated.GetDocumentForUpdateParams{ID: m.Capture.DocumentID, OrgID: m.Capture.OrgID}); err != nil {
		t.Fatal(err)
	}
	match := packageAttemptMatch235(m)
	if _, err := db.MarkDocumentPackageSendRetentionStartedV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionStartedV1Params(match)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SynchronizeDocumentPackageSendRetentionV1(q.f.ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params(match)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
}

func packageMemberRetentionRefusal240(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, code string, run func(pgx.Tx, *generated.Queries) error) {
	t.Helper()
	before, original, requests := packageMemberRetentionState240(t, q, m), packageMeasurementState232(t, q), q.storagePeer.requests.Load()
	func() {
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		err := run(tx, generated.New(tx))
		if code == "no rows" {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("wrong member selector did not refuse", err)
			}
		} else {
			packageExpectPG218(t, err, code)
		}
	}()
	if packageMemberRetentionState240(t, q, m) != before || packageMeasurementState232(t, q) != original || q.storagePeer.requests.Load() != requests {
		t.Fatal("member retention refusal changed durable state or called a provider")
	}
}

func TestDocumentPackageMemberRetentionV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	namespace := packageMemberRetentionNamespace240()
	birth := func(t *testing.T) (*generated.Document, pdfadmission.HTMLSendPackageIntentMetadataV1) {
		t.Helper()
		root, _, m, err := packageAttemptBirth235(t, q, false)
		if err != nil {
			t.Fatal(err)
		}
		return root, m
	}
	t.Run("unstarted aggregate cannot authorize member progress", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionRefusal240(t, q, m, "23514", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace))
			return err
		})
	})
	t.Run("missing receipts block aggregate and direct completion", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		for _, direct := range []bool{false, true} {
			packageMemberRetentionRefusal240(t, q, m, "23514", func(tx pgx.Tx, db *generated.Queries) error {
				if direct {
					_, err := tx.Exec(q.f.ctx, "UPDATE send_sealing_intents SET retention_completed_at=clock_timestamp() WHERE package_send_attempt_id=$1", m.AttemptID)
					return err
				}
				_, err := db.MarkDocumentPackageSendRetentionCompleteV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionCompleteV1Params(packageAttemptMatch235(m)))
				return err
			})
		}
	})
	t.Run("exact frozen tuple and selectors never invent members", func(t *testing.T) {
		root, m := birth(t)
		rows, err := q.f.q.ListDocumentPackageSendRetentionMembersV1(q.f.ctx, packageMemberRetentionList240(m))
		if err != nil || len(rows) != 1 || rows[0].MemberPosition != 0 || rows[0].MemberDocumentID != root.ID || rows[0].PdfKey != root.PdfStorageKey.String || rows[0].PdfVersionID != root.PdfStorageVersionID.String || !bytes.Equal(rows[0].PdfSha256, root.PdfSha256) || rows[0].PdfBytes != m.Capture.PDFBytes || rows[0].PdfPages != m.Capture.PDFPages || rows[0].StartedAt.Valid || rows[0].VerifiedAt.Valid || len(rows[0].ProviderNamespaceSha256) != 0 {
			t.Fatal("historical member tuple differs or fabricated a receipt", err)
		}
		for _, field := range []string{"attempt", "tenant", "root", "package", "revision", "count", "manifest", "legal"} {
			in := packageMemberRetentionList240(m)
			switch field {
			case "attempt":
				in.AttemptID = uuid.New()
			case "tenant":
				in.OrgID = uuid.New()
			case "root":
				in.DocumentID = uuid.New()
			case "package":
				in.PackageID = uuid.New()
			case "revision":
				in.CaptureRevision++
			case "count":
				in.ExpectedMemberCount++
			case "manifest":
				in.ExpectedManifestSha256 = make([]byte, 32)
			case "legal":
				in.ExpectedLegalCommitmentSha256 = make([]byte, 32)
			}
			if got, err := q.f.q.ListDocumentPackageSendRetentionMembersV1(q.f.ctx, in); err != nil || len(got) != 0 {
				t.Fatal("different member binding returned data", field, err)
			}
		}
	})
	t.Run("invalid ordinals and fabricated initial verification refuse", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		packageMemberRetentionRefusal240(t, q, m, "no rows", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 1, namespace))
			return err
		})
		for _, position := range []int16{0, 1} {
			packageMemberRetentionRefusal240(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
				_, err := tx.Exec(q.f.ctx, "INSERT INTO document_package_send_member_retention_v1(attempt_id,org_id,document_id,member_position,provider_namespace_sha256,verified_at,observed_mode,observed_retain_until,verifier_profile) VALUES($1,$2,$3,$4,$5,clock_timestamp(),'COMPLIANCE',$6,'s3-compliance-digest-v1')", m.AttemptID, m.Capture.OrgID, m.Capture.DocumentID, position, namespace, m.RetainUntil)
				return err
			})
		}
	})
	t.Run("started but unconfirmed member is not retained", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		started, err := q.f.q.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace))
		if err != nil || !started.StartedAt.Valid || started.VerifiedAt.Valid || started.ObservedMode.Valid || started.ObservedRetainUntil.Valid || started.VerifierProfile.Valid {
			t.Fatal("member start invented verification", err)
		}
		var retained bool
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT hash_package_send_members_retained_v1($1)", m.AttemptID).Scan(&retained); err != nil || retained {
			t.Fatal("partial receipt satisfied aggregate completion", retained, err)
		}
		packageMemberRetentionRefusal240(t, q, m, "23514", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.MarkDocumentPackageSendRetentionCompleteV1(q.f.ctx, generated.MarkDocumentPackageSendRetentionCompleteV1Params(packageAttemptMatch235(m)))
			return err
		})
	})
	t.Run("namespace and original retention deadline remain exact", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		if _, err := q.f.q.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace)); err != nil {
			t.Fatal(err)
		}
		other := sha256.Sum256([]byte("different-synthetic-SQL-namespace"))
		packageMemberRetentionRefusal240(t, q, m, "23514", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, other[:]))
			return err
		})
		for _, until := range []pgtype.Timestamptz{{Time: m.RetainUntil.Add(-time.Microsecond), Valid: true}, {InfinityModifier: pgtype.Infinity, Valid: true}} {
			packageMemberRetentionRefusal240(t, q, m, "no rows", func(_ pgx.Tx, db *generated.Queries) error {
				_, err := db.ConfirmDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionConfirm240(m, 0, namespace, until))
				return err
			})
		}
		packageMemberRetentionRefusal240(t, q, m, "no rows", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.ConfirmDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionConfirm240(m, 0, other[:], pgtype.Timestamptz{Time: m.RetainUntil, Valid: true}))
			return err
		})
		packageMemberRetentionRefusal240(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
			_, err := tx.Exec(q.f.ctx, "UPDATE document_package_send_member_retention_v1 SET verified_at=clock_timestamp(),observed_mode='GOVERNANCE',observed_retain_until=$2,verifier_profile='s3-compliance-digest-v1' WHERE attempt_id=$1", m.AttemptID, m.RetainUntil)
			return err
		})
	})
	t.Run("SQL acknowledgement is immutable and retries preserve first proof", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if err := packageMemberRetentionSQLReceipts240(q.f.ctx, generated.New(tx), m); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		before := packageMemberRetentionState240(t, q, m)
		requests := q.storagePeer.requests.Load()
		if _, err := q.f.q.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace)); err != nil {
			t.Fatal(err)
		}
		if _, err := q.f.q.ConfirmDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionConfirm240(m, 0, namespace, pgtype.Timestamptz{Time: m.RetainUntil.Add(time.Hour), Valid: true})); err != nil {
			t.Fatal(err)
		}
		if packageMemberRetentionState240(t, q, m) != before || q.storagePeer.requests.Load() != requests {
			t.Fatal("retry changed first SQL acknowledgement or performed provider IO")
		}
		for _, sql := range []string{
			"UPDATE document_package_send_member_retention_v1 SET started_at=started_at+interval '1 second' WHERE attempt_id=$1",
			"UPDATE document_package_send_member_retention_v1 SET provider_namespace_sha256=decode(repeat('01',32),'hex') WHERE attempt_id=$1",
			"UPDATE document_package_send_member_retention_v1 SET verified_at=verified_at+interval '1 second' WHERE attempt_id=$1",
			"UPDATE document_package_send_member_retention_v1 SET observed_retain_until=observed_retain_until+interval '1 day' WHERE attempt_id=$1",
			"UPDATE document_package_send_member_retention_v1 SET verifier_profile='invented' WHERE attempt_id=$1",
			"DELETE FROM document_package_send_member_retention_v1 WHERE attempt_id=$1",
		} {
			packageMemberRetentionRefusal240(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error { _, err := tx.Exec(q.f.ctx, sql, m.AttemptID); return err })
		}
	})
	t.Run("pending privacy after aggregate start refuses member mutations", func(t *testing.T) {
		_, m := birth(t)
		packageMemberRetentionAggregateStart240(t, q, m)
		if _, err := q.f.q.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace)); err != nil {
			t.Fatal(err)
		}
		dsr, err := q.f.q.CreateDataSubjectRequest(q.f.ctx, generated.CreateDataSubjectRequestParams{OrgID: q.f.org, DocumentID: pgtype.UUID{Bytes: m.Capture.DocumentID, Valid: true}, SubjectEmail: "synthetic-sql-retention@hash.example.test", Kind: "access", RequestedVia: "sender", PayloadJson: []byte("{}")})
		if err != nil {
			t.Fatal(err)
		}
		for _, confirm := range []bool{false, true} {
			packageMemberRetentionRefusal240(t, q, m, "23514", func(_ pgx.Tx, db *generated.Queries) error {
				if confirm {
					_, err := db.ConfirmDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionConfirm240(m, 0, namespace, pgtype.Timestamptz{Time: m.RetainUntil, Valid: true}))
					return err
				}
				_, err := db.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace))
				return err
			})
		}
		if _, err := q.f.q.UpdateDataSubjectRequestStatus(q.f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: dsr.ID, OrgID: q.f.org, ExpectedStatus: "open", Status: "withdrawn", FulfilledBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("all SQL receipts preserve terminal history and cannot reopen", func(t *testing.T) {
		_, m := birth(t)
		requests := q.storagePeer.requests.Load()
		if err := packageAttemptTransition235(t, q, m, "completed", false); err != nil {
			t.Fatal(err)
		}
		packageAttemptInspect235(t, q, m, false, "completed")
		var retained bool
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT hash_package_send_members_retained_v1($1)", m.AttemptID).Scan(&retained); err != nil || !retained {
			t.Fatal("complete SQL protocol lost receipts", retained, err)
		}
		packageMemberRetentionRefusal240(t, q, m, "no rows", func(_ pgx.Tx, db *generated.Queries) error {
			_, err := db.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, namespace))
			return err
		})
		packageMemberRetentionRefusal240(t, q, m, "23514", func(tx pgx.Tx, _ *generated.Queries) error {
			_, err := tx.Exec(q.f.ctx, "UPDATE document_package_send_member_retention_v1 SET started_at=started_at WHERE attempt_id=$1", m.AttemptID)
			return err
		})
		if q.storagePeer.requests.Load() != requests {
			t.Fatal("SQL terminal fixture invoked a provider")
		}
	})
}

func TestDocumentPackageMemberRetentionSchemaV1E2E(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		name := "empty ledger"
		if occupied {
			name = "started ledger"
		}
		t.Run(name, func(t *testing.T) {
			q := inspectionFixturePG236(t)
			m := packageLegacyAttempt619(t, q, 105)
			if occupied {
				packageLegacyAggregateStart619(t, q, m)
				if _, err := q.f.q.StartDocumentPackageSendMemberRetentionV1(q.f.ctx, packageMemberRetentionStart240(m, 0, packageMemberRetentionNamespace240())); err != nil {
					t.Fatal(err)
				}
			}
			before, original, requests := packageMemberRetentionState240(t, q, m), packageMeasurementState232(t, q), q.storagePeer.requests.Load()
			cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
			if err != nil {
				t.Fatal(err)
			}
			db := stdlib.OpenDB(*cfg)
			db.SetMaxOpenConns(1)
			db.SetMaxIdleConns(1)
			defer db.Close()
			if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 105 {
				t.Fatal("member schema did not start at M105", version, err)
			}
			err = mdb.RunMigrationsDownToContext(q.f.ctx, db, 104)
			if occupied {
				if err == nil {
					t.Fatal("M105 rollback erased unresolved member progress")
				}
				packageExpectPG218(t, err, "23514")
				if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 105 {
					t.Fatal("occupied M105 rollback changed schema", version, err)
				}
			} else {
				if err != nil {
					t.Fatal("empty M105 rollback refused pending history", err)
				}
				restore := true
				defer func() {
					if restore {
						cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
						defer stop()
						if err := mdb.RunMigrationsUpToContext(cleanup, db, 105); err != nil {
							t.Error("restore M105 after fixture failure", err)
						}
					}
				}()
				if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 104 {
					t.Fatal("empty M105 rollback did not stop at M104", version, err)
				}
				var missingTable, missingMarker bool
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT to_regclass('document_package_send_member_retention_v1') IS NULL,to_regprocedure('hash_package_send_member_retention_version_v1()') IS NULL").Scan(&missingTable, &missingMarker); err != nil || !missingTable || !missingMarker {
					t.Fatal("M105 Down retained protocol schema", missingTable, missingMarker, err)
				}
				if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 105); err != nil {
					t.Fatal(err)
				}
				restore = false
				if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 105 {
					t.Fatal("M105 reapply did not restore current schema", version, err)
				}
			}
			if packageMemberRetentionState240(t, q, m) != before || packageMeasurementState232(t, q) != original || q.storagePeer.requests.Load() != requests {
				t.Fatal("M105 rollback/reapply changed history or invoked a provider")
			}
			rows, err := q.f.q.ListDocumentPackageSendRetentionMembersV1(q.f.ctx, packageMemberRetentionList240(m))
			if err != nil || len(rows) != 1 || rows[0].StartedAt.Valid != occupied || rows[0].VerifiedAt.Valid {
				t.Fatal(fmt.Sprintf("M105 history differs after schema journey occupied=%t", occupied), err)
			}
		})
	}
	t.Run("pre105 completed history receives no fabricated receipts", func(t *testing.T) {
		q := inspectionFixturePG236(t)
		m := packageLegacyAttempt619(t, q, 104)
		cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*cfg)
		db.SetMaxOpenConns(1)
		db.SetMaxIdleConns(1)
		defer db.Close()
		if err := mdb.RunMigrationsDownToContext(q.f.ctx, db, 104); err != nil {
			t.Fatal(err)
		}
		restore := true
		defer func() {
			if restore {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
				defer stop()
				if err := mdb.RunMigrationsUpToContext(cleanup, db, 105); err != nil {
					t.Error("restore M105 historical fixture", err)
				}
			}
		}()
		if version, err := mdb.GetMigrationVersionContext(q.f.ctx, db); err != nil || version != 104 {
			t.Fatal("historical completion fixture is not actually pre105", version, err)
		}

		requests := q.storagePeer.requests.Load()
		// Exercise the actual old SQL protocol at its actual schema version.
		// This is synthetic pre105 completion, not historical provider proof.
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		queries := generated.New(tx)
		match := packageAttemptMatch235(m)
		if err := packageLegacyCompletionStage619(t, q, tx, m, false, false); err != nil {
			t.Fatal(err)
		}
		if _, err := queries.TerminalizeDocumentPackageSendAttemptV1(q.f.ctx, generated.TerminalizeDocumentPackageSendAttemptV1Params{Outcome: "completed", AttemptID: m.AttemptID, OrgID: m.Capture.OrgID, DocumentID: m.Capture.DocumentID, ExpectedManifestSha256: match.ExpectedManifestSha256, ExpectedLegalCommitmentSha256: match.ExpectedLegalCommitmentSha256}); err != nil {
			t.Fatal(err)
		}
		if rows, err := queries.DeleteDocumentPackageSealingIntentV1(q.f.ctx, match); err != nil || rows != 1 {
			t.Fatal("old terminal fixture did not delete its exact intent", rows, err)
		}
		if _, err := tx.Exec(q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		before := packageMeasurementState232(t, q)
		if err := mdb.RunMigrationsUpToContext(q.f.ctx, db, 105); err != nil {
			t.Fatal(err)
		}
		restore = false
		packageAttemptInspect235(t, q, m, false, "completed")
		var receipts int
		var newlyVerified bool
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*) FROM document_package_send_member_retention_v1 WHERE attempt_id=$1),hash_package_send_members_retained_v1($1)", m.AttemptID).Scan(&receipts, &newlyVerified); err != nil || receipts != 0 || newlyVerified {
			t.Fatal("M105 fabricated retention verification for older history", receipts, newlyVerified, err)
		}
		if packageMeasurementState232(t, q) != before || q.storagePeer.requests.Load() != requests {
			t.Fatal("M105 reapply changed historical completion or performed provider IO")
		}
	})
}
