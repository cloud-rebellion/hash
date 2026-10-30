//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// These are actual PostgreSQL persistence/migration controls with synthetic PDF
// pins and reports. Retained report bytes/hash are not PDF/malware eligibility.
func setPackageFixtureReport222(t *testing.T, f lifecycleAuthorizationFixture, d *generated.Document, raw []byte, measure bool) *generated.Document {
	t.Helper()
	//nolint:rawsql -- explicit controlled fresh fixture report; no historical repair
	if tag, err := f.pool.Exec(f.ctx, "UPDATE documents SET metadata_redaction_report=$3::jsonb,updated_at=GREATEST(clock_timestamp(),updated_at+interval '1 microsecond') WHERE id=$1 AND org_id=$2", d.ID, f.org, raw); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	}
	if measure {
		if _, err := f.q.MeasureSignerDocumentReportV1(f.ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: d.ID, OrgID: f.org}); err != nil {
			t.Fatal(err)
		}
	}
	fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: d.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}
func packageReportBytes222(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) []byte {
	t.Helper()
	var raw []byte
	//nolint:rawsql -- independent exact DB serialization oracle for a tiny fixture
	if err := f.pool.QueryRow(f.ctx, "SELECT convert_to(metadata_redaction_report::text,'UTF8') FROM documents WHERE id=$1 AND org_id=$2", id, f.org).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	return raw
}
func packageReportState222(t *testing.T, f lifecycleAuthorizationFixture, p uuid.UUID) string {
	t.Helper()
	var out string
	//nolint:rawsql -- complete bounded synthetic package/capture rollback oracle
	if err := f.pool.QueryRow(f.ctx, "SELECT jsonb_build_object('draft',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY ordinal),'[]'::jsonb) FROM document_attachment_drafts_v1 a WHERE package_id=$1),'header',(SELECT to_jsonb(p) FROM document_packages_v1 p WHERE id=$1),'clock',(SELECT updated_at FROM documents WHERE id=(SELECT document_id FROM document_packages_v1 WHERE id=$1)),'captures',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY revision),'[]'::jsonb) FROM document_package_captures_v1 c WHERE package_id=$1),'members',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY revision,member_position),'[]'::jsonb) FROM document_package_capture_members_v1 m WHERE package_id=$1))::text", p).Scan(&out); err != nil {
		t.Fatal(err)
	}
	return out
}
func selectedReportPackage222(t *testing.T, f lifecycleAuthorizationFixture, label string) (*generated.DocumentPackagesV1, *generated.Document, *generated.Document, *generated.DocumentAttachmentDraftsV1) {
	t.Helper()
	root := packagePDF218(t, f, label+" main")
	annex := packagePDF218(t, f, label+" annex")
	annex = setPackageFixtureReport222(t, f, annex, []byte("{\"fixture\":\"selected original\"}"), true)
	p := packageHeader218(t, f, root)
	selected, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, annex, 3))
	if err != nil {
		t.Fatal(err)
	}
	return packageFresh218(t, f, p.ID), root, annex, selected
}

const insertLegacyPackageDraft222 = "INSERT INTO document_attachment_drafts_v1(package_id,org_id,member_document_id,ordinal,title,category,pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,materialization_id,materialization_sequence) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)"
const insertPackageDraftWithReport222 = "INSERT INTO document_attachment_drafts_v1(package_id,org_id,member_document_id,ordinal,title,category,pdf_key,pdf_version_id,pdf_sha256,pdf_bytes,pdf_pages,source_kind,source_commitment,origin_commitment,materialization_id,materialization_sequence,pdf_intake_report,pdf_intake_report_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"

func packageDraftArgs222(p generated.InsertDocumentAttachmentDraftV1Params) []any {
	return []any{p.PackageID, p.OrgID, p.MemberDocumentID, p.Ordinal, p.Title, p.Category, p.PdfKey, p.PdfVersionID, p.PdfSha256, p.PdfBytes, p.PdfPages, p.SourceKind, p.SourceCommitment, p.OriginCommitment, p.MaterializationID, p.MaterializationSequence}
}

func TestDocumentPackageIntakeReportPersistenceV1E2E(t *testing.T) {
	database := isolateEmptyHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	t.Run("selected and sparse captured reports survive live source changes", func(t *testing.T) {
		p, root, annex, first := selectedReportPackage222(t, f, "Frozen")
		other := setPackageFixtureReport222(t, f, packagePDF218(t, f, "Second sparse annex"), []byte("{\"fixture\":\"second original\"}"), true)
		second, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, other, 9))
		if err != nil {
			t.Fatal(err)
		}
		p = packageFresh218(t, f, p.ID)
		expectedFirst, expectedSecond, expectedMain := packageReportBytes222(t, f, annex.ID), packageReportBytes222(t, f, other.ID), packageReportBytes222(t, f, root.ID)
		for i, selected := range []*generated.DocumentAttachmentDraftsV1{first, second} {
			expected := [][]byte{expectedFirst, expectedSecond}[i]
			sum := sha256.Sum256(expected)
			if !bytes.Equal(selected.PdfIntakeReport, expected) || !bytes.Equal(selected.PdfIntakeReportSha256, sum[:]) {
				t.Fatal("selection did not retain exact database report/hash", i)
			}
		}
		changed, _ := json.Marshal(map[string]string{"fixture": strings.Repeat("later source", 7000)})
		setPackageFixtureReport222(t, f, annex, changed, false)
		//nolint:rawsql -- controlled later source deletion; retained pins have no live FK
		if _, err = f.pool.Exec(f.ctx, "UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", other.ID, f.org); err != nil {
			t.Fatal(err)
		}
		relabeled, err := f.q.UpdateDocumentAttachmentLabelsV1(f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: annex.ID, ExpectedGeneration: p.DraftGeneration, Ordinal: 3, Title: "Relabeled frozen annex", Category: "DPA"})
		if err != nil || !bytes.Equal(relabeled.PdfIntakeReport, expectedFirst) {
			t.Fatal("relabel followed live source", err)
		}
		p = packageFresh218(t, f, p.ID)
		input := captureInput219(t, f, p, 1, 0)
		if _, err = f.q.AppendDocumentPackageCaptureV1(f.ctx, input); err != nil {
			t.Fatal("frozen annex capture followed live source/cache", err)
		}
		capture, members := captureLoad219(t, f, p, 1)
		if len(members) != 3 || !bytes.Equal(capture.Manifest().CanonicalJSON(), input.Manifest) || capture.Header().CanonicalSHA256 != hex.EncodeToString(input.ManifestSha256) {
			t.Fatal("intake evidence changed legal manifest")
		}
		for i, want := range [][]byte{expectedMain, expectedFirst, expectedSecond} {
			sum := sha256.Sum256(want)
			if members[i].MemberPosition != int16(i) || !bytes.Equal(members[i].PdfIntakeReport, want) || !bytes.Equal(members[i].PdfIntakeReportSha256, sum[:]) {
				t.Fatal("sparse capture proof differs", i)
			}
		}
		before := packageReportState222(t, f, p.ID)
		//nolint:rawsql -- captured proof is append-only even when legal pins are unchanged
		_, err = f.pool.Exec(f.ctx, "UPDATE document_package_capture_members_v1 SET pdf_intake_report=NULL,pdf_intake_report_sha256=NULL WHERE package_id=$1 AND member_position=1", p.ID)
		packageExpectPG218(t, err, "23514")
		if packageReportState222(t, f, p.ID) != before {
			t.Fatal("captured proof mutation changed history")
		}
		setPackageFixtureReport222(t, f, root, []byte("{\"fixture\":\"later main\"}"), false)
		_, again := captureLoad219(t, f, p, 1)
		if !bytes.Equal(again[0].PdfIntakeReport, expectedMain) {
			t.Fatal("historical main proof followed current root")
		}
	})
	t.Run("selected proof updates roll back clocks and generations", func(t *testing.T) {
		p, _, annex, selected := selectedReportPackage222(t, f, "Immutable")
		before := packageReportState222(t, f, p.ID)
		different := []byte("{\"different\":true}")
		differentSHA := sha256.Sum256(different)
		cases := map[string]struct{ raw, hash []byte }{"replace both": {different, differentSHA[:]}, "clear both": {nil, nil}, "half body": {selected.PdfIntakeReport, nil}, "half digest": {nil, selected.PdfIntakeReportSha256}, "wrong digest": {selected.PdfIntakeReport, bytes.Repeat([]byte{1}, 32)}}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				//nolint:rawsql -- deliberate forbidden in-place proof mutation
				_, err := f.pool.Exec(f.ctx, "UPDATE document_attachment_drafts_v1 SET pdf_intake_report=$3,pdf_intake_report_sha256=$4 WHERE package_id=$1 AND member_document_id=$2", p.ID, annex.ID, tc.raw, tc.hash)
				packageExpectPG218(t, err, "23514")
				if packageReportState222(t, f, p.ID) != before {
					t.Fatal("failed proof update changed rows, clock or generation")
				}
			})
		}
	})
	t.Run("supplied proof must equal exact actual source serialization", func(t *testing.T) {
		root := packagePDF218(t, f, "Supplied main")
		annex := packagePDF218(t, f, "Supplied annex")
		p := packageHeader218(t, f, root)
		pin := packagePin218(t, p, annex, 1)
		actual := packageReportBytes222(t, f, annex.ID)
		actualSHA := sha256.Sum256(actual)
		different := []byte("{ }")
		differentSHA := sha256.Sum256(different)
		before := packageReportState222(t, f, p.ID)
		cases := map[string]struct{ raw, hash []byte }{"half body": {actual, nil}, "half digest": {nil, actualSHA[:]}, "different JSON spelling": {different, differentSHA[:]}, "wrong digest": {actual, bytes.Repeat([]byte{1}, 32)}}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				args := append(packageDraftArgs222(pin), tc.raw, tc.hash)
				//nolint:rawsql -- supplied report-pair trust-boundary fixture
				_, err := f.pool.Exec(f.ctx, insertPackageDraftWithReport222, args...)
				packageExpectPG218(t, err, "23514")
				if packageReportState222(t, f, p.ID) != before {
					t.Fatal("rejected supplied pair changed package")
				}
			})
		}
		args := append(packageDraftArgs222(pin), actual, actualSHA[:])
		if _, err := f.pool.Exec(f.ctx, insertPackageDraftWithReport222, args...); err != nil {
			t.Fatal("exact source pair rejected", err)
		}
	})
	t.Run("genuine measured object report bound precedes selection", func(t *testing.T) {
		for _, name := range []string{"missing cache", "SQL null", "JSON null", "nonobject", "over64KiB", "exact64KiB"} {
			t.Run(name, func(t *testing.T) {
				root := packagePDF218(t, f, "Bound main "+name)
				annex := packagePDF218(t, f, "Bound annex "+name)
				p := packageHeader218(t, f, root)
				switch name {
				case "missing cache":
					//nolint:rawsql -- actual missing source cache; never fabricate its size
					if tag, err := f.pool.Exec(f.ctx, "DELETE FROM document_read_report_sizes_v1 WHERE document_id=$1 AND org_id=$2", annex.ID, f.org); err != nil || tag.RowsAffected() != 1 {
						t.Fatal(err)
					}
				case "SQL null":
					before := packageReportState222(t, f, p.ID)
					original, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: annex.ID, OrgID: f.org})
					if err != nil {
						t.Fatal(err)
					}
					//nolint:rawsql -- existing NOT NULL must refuse before selection
					_, err = f.pool.Exec(f.ctx, "UPDATE documents SET metadata_redaction_report=NULL,updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2", annex.ID, f.org)
					packageExpectPG218(t, err, "23502")
					after, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: annex.ID, OrgID: f.org})
					if err != nil || !bytes.Equal(after.MetadataRedactionReport, original.MetadataRedactionReport) || after.UpdatedAt != original.UpdatedAt || packageReportState222(t, f, p.ID) != before {
						t.Fatal("NOT NULL refusal changed source or package", err)
					}
					return
				case "JSON null":
					annex = setPackageFixtureReport222(t, f, annex, []byte("null"), true)
				case "nonobject":
					annex = setPackageFixtureReport222(t, f, annex, []byte("[]"), true)
				default:
					var overhead int
					//nolint:rawsql -- independent literal JSONB serialization boundary
					if err := f.pool.QueryRow(f.ctx, "SELECT octet_length(jsonb_build_object('fixture','')::text)").Scan(&overhead); err != nil {
						t.Fatal(err)
					}
					want := 65536
					if name == "over64KiB" {
						want++
					}
					raw, err := json.Marshal(map[string]string{"fixture": strings.Repeat("x", want-overhead)})
					if err != nil {
						t.Fatal(err)
					}
					annex = setPackageFixtureReport222(t, f, annex, raw, true)
					if len(packageReportBytes222(t, f, annex.ID)) != want {
						t.Fatal("controlled exact report bound not established")
					}
				}
				before := packageReportState222(t, f, p.ID)
				selected, err := f.q.InsertDocumentAttachmentDraftV1(f.ctx, packagePin218(t, p, annex, 1))
				if name == "exact64KiB" {
					if err != nil || len(selected.PdfIntakeReport) != 65536 {
						t.Fatal("exact report boundary refused", err)
					}
				} else {
					packageExpectPG218(t, err, "23514")
					if packageReportState222(t, f, p.ID) != before {
						t.Fatal("report refusal changed package")
					}
				}
			})
		}
	})
	t.Run("capture proof failure rolls back header and all members", func(t *testing.T) {
		p, root, _, _ := selectedReportPackage222(t, f, "Atomic proof")
		input := captureInput219(t, f, p, 1, 0)
		//nolint:rawsql -- fresh main report loses its actual cache before capture
		if _, err := f.pool.Exec(f.ctx, "DELETE FROM document_read_report_sizes_v1 WHERE document_id=$1 AND org_id=$2", root.ID, f.org); err != nil {
			t.Fatal(err)
		}
		before := packageReportState222(t, f, p.ID)
		_, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, input)
		packageExpectPG218(t, err, "23514")
		if packageReportState222(t, f, p.ID) != before {
			t.Fatal("failed derivation left a partial header/member")
		}
	})
	t.Run("occupied report rollback refuses without loss", func(t *testing.T) {
		p, _, _, _ := selectedReportPackage222(t, f, "Rollback proof")
		before := packageReportState222(t, f, p.ID)
		cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
		if err != nil {
			t.Fatal(err)
		}
		db := stdlib.OpenDB(*cfg)
		defer db.Close()
		err = mdb.RunMigrationsDownToContext(f.ctx, db, 100)
		if err == nil || !strings.Contains(err.Error(), "retained package intake reports prevent rollback") {
			t.Fatal("occupied101 did not refuse its proof loss", err)
		}
		if packageReportState222(t, f, p.ID) != before {
			t.Fatal("occupied rollback changed retained proof or clocks")
		}
		var version int64
		if version, err = mdb.GetMigrationVersionContext(f.ctx, db); err != nil || version != 101 {
			t.Fatal("failed down changed schema head", version, err)
		}
		if err = mdb.RunMigrationsContext(f.ctx, db); err != nil {
			t.Fatal("restore current schema after occupied101 refusal", err)
		}
	})
}
func legacyPackageCaptureInput222(t *testing.T, f lifecycleAuthorizationFixture, p *generated.DocumentPackagesV1, pin generated.InsertDocumentAttachmentDraftV1Params) generated.AppendDocumentPackageCaptureV1Params {
	t.Helper()
	root, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: p.DocumentID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	main := captureMember219(packagePin218(t, p, root, 1))
	main.Category = "Agreement"
	manifest, err := documentpackage.NewManifestV1(documentpackage.InputV1{Binding: documentpackage.BindingV1{OrgID: f.org, DocumentID: root.ID, PackageID: p.ID, Revision: 1}, Main: main, Annexes: []documentpackage.MemberV1{captureMember219(pin)}})
	if err != nil {
		t.Fatal(err)
	}
	capture, err := documentpackage.NewCaptureV1(manifest, documentpackage.CaptureGuardV1{RootUpdatedAt: root.UpdatedAt.Time, DraftGeneration: p.DraftGeneration, PreviousRevision: 0})
	if err != nil {
		t.Fatal(err)
	}
	header := capture.Header()
	object, _ := hex.DecodeString(header.CanonicalSHA256)
	legal, _ := hex.DecodeString(header.CommitmentSHA256)
	return generated.AppendDocumentPackageCaptureV1Params{PackageID: p.ID, OrgID: f.org, DocumentID: root.ID, Revision: 1, ExpectedPreviousRevision: 0, ExpectedUpdatedAt: root.UpdatedAt, ExpectedGeneration: p.DraftGeneration, Manifest: manifest.CanonicalJSON(), ManifestSha256: object, LegalCommitmentSha256: legal, CreatedBy: f.user.ID}
}
func TestDocumentPackageIntakeReportLegacyMigrationV1E2E(t *testing.T) {
	database := isolateEmptyHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	root := packagePDF218(t, f, "Legacy root")
	annex := packagePDF218(t, f, "Legacy annex")
	p := packageHeader218(t, f, root)
	pin := packagePin218(t, p, annex, 7)
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	if err = mdb.RunMigrationsDownToContext(f.ctx, db, 100); err != nil {
		t.Fatal("empty101 down", err)
	}
	//nolint:rawsql -- exact v100 fixture insert, before proof columns exist
	if _, err = f.pool.Exec(f.ctx, insertLegacyPackageDraft222, packageDraftArgs222(pin)...); err != nil {
		t.Fatal(err)
	}
	p = packageFresh218(t, f, p.ID)
	legacy := legacyPackageCaptureInput222(t, f, p, pin)
	if _, err = f.q.AppendDocumentPackageCaptureV1(f.ctx, legacy); err != nil {
		t.Fatal("genuine v100 populated capture", err)
	}
	if err = mdb.RunMigrationsContext(f.ctx, db); err != nil {
		t.Fatal("up101 over occupied legacy rows", err)
	}
	t.Run("legacy rows remain null through source edit and relabel", func(t *testing.T) {
		setPackageFixtureReport222(t, f, annex, []byte("{\"fixture\":\"later legacy source\"}"), true)
		selected, err := f.q.UpdateDocumentAttachmentLabelsV1(f.ctx, generated.UpdateDocumentAttachmentLabelsV1Params{PackageID: p.ID, OrgID: f.org, MemberDocumentID: annex.ID, ExpectedGeneration: p.DraftGeneration, Ordinal: 7, Title: "Relabeled legacy annex", Category: "Legacy"})
		if err != nil || selected.PdfIntakeReport != nil || selected.PdfIntakeReportSha256 != nil {
			t.Fatal("legacy proof was backfilled", err)
		}
		p = packageFresh218(t, f, p.ID)
		_, members := captureLoad219(t, f, p, 1)
		for _, m := range members {
			if m.PdfIntakeReport != nil || m.PdfIntakeReportSha256 != nil {
				t.Fatal("old capture proof was invented")
			}
		}
		actual := packageReportBytes222(t, f, annex.ID)
		sum := sha256.Sum256(actual)
		before := packageReportState222(t, f, p.ID)
		//nolint:rawsql -- even today's matching report cannot fill legacy proof
		_, err = f.pool.Exec(f.ctx, "UPDATE document_attachment_drafts_v1 SET pdf_intake_report=$3,pdf_intake_report_sha256=$4 WHERE package_id=$1 AND member_document_id=$2", p.ID, annex.ID, actual, sum[:])
		packageExpectPG218(t, err, "23514")
		if packageReportState222(t, f, p.ID) != before {
			t.Fatal("legacy backfill refusal mutated package")
		}
	})
	t.Run("legacy annex requires reselection before a new capture", func(t *testing.T) {
		input := captureInput219(t, f, p, 2, 1)
		before := packageReportState222(t, f, p.ID)
		_, err := f.q.AppendDocumentPackageCaptureV1(f.ctx, input)
		packageExpectPG218(t, err, "23514")
		if packageReportState222(t, f, p.ID) != before {
			t.Fatal("legacy proof refusal left partial new capture")
		}
	})
	t.Run("legacy-only101 down is lossless and occupied100 still refuses", func(t *testing.T) {
		if err = mdb.RunMigrationsDownToContext(f.ctx, db, 100); err != nil {
			t.Fatal("legacy-only101 rollback refused", err)
		}
		var raw []byte
		var captures, members int
		//nolint:rawsql -- legacy schema fields only while101 is absent
		if err = f.pool.QueryRow(f.ctx, "SELECT manifest,(SELECT count(*)::integer FROM document_package_captures_v1 WHERE package_id=$1),(SELECT count(*)::integer FROM document_package_capture_members_v1 WHERE package_id=$1) FROM document_package_captures_v1 WHERE package_id=$1 AND revision=1", p.ID).Scan(&raw, &captures, &members); err != nil || !bytes.Equal(raw, legacy.Manifest) || captures != 1 || members != 2 {
			t.Fatal("legacy-only down lost exact capture", err)
		}
		err = mdb.RunMigrationsDownContext(f.ctx, db)
		if err == nil || !strings.Contains(err.Error(), "package capture history prevents rollback") {
			t.Fatal("occupied100 lost its original refusal", err)
		}
		if err = mdb.RunMigrationsContext(f.ctx, db); err != nil {
			t.Fatal("reapply101", err)
		}
		_, again := captureLoad219(t, f, p, 1)
		for _, m := range again {
			if m.PdfIntakeReport != nil || m.PdfIntakeReportSha256 != nil {
				t.Fatal("reapply invented historical proof")
			}
		}
	})
}
