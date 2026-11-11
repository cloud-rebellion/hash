// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package db

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func email128LifecycleFiles() fstest.MapFS {
	files := brand123LifecycleFiles()
	for _, name := range []string{"00124_draft_in_place_edit.sql", "00125_html_template_revision_insert_guard.sql", "00126_measure_html_document_events.sql", "00127_pending_object_deletions.sql", "00128_workspace_email_and_signing_languages.sql"} {
		files["migrations/"+name] = &fstest.MapFile{Data: []byte("-- named test floor\n")}
	}
	return files
}
func TestSigningLanguages128RequiresWriterTenAndPreservesPriorCohort(t *testing.T) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 || versions[len(versions)-1] != 128 {
		t.Fatal("actual M128 tree unavailable", err)
	}
	version, actual, err := EmbeddedLifecycleIdentityV1()
	if err != nil || version != 10 || LifecycleContractVersionV1 != 10 || actual != digest {
		t.Fatal("semantic Swedish package support requires writer10 and its exact migration identity", version, err)
	}
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128}
	files := email128LifecycleFiles()
	if version, err := reviewedLifecycleContractVersionV1(files, tail); err != nil || version != 10 {
		t.Fatal(err)
	}
	legacyTail := tail[:len(tail)-1]
	legacyFiles := email128LifecycleFiles()
	delete(legacyFiles, "migrations/00128_workspace_email_and_signing_languages.sql")
	if version, err := reviewedLifecycleContractVersionV1(legacyFiles, legacyTail); err != nil || version != 9 {
		t.Fatal("reviewed English M127 cohort lost its original writer9 identity", version, err)
	}
	if version, err := reviewedLifecycleContractVersionV1(legacyFiles, tail); err == nil || version != 0 {
		t.Fatal("old writer9 tree was advertised as M128-capable", version, err)
	}
	delete(files, "migrations/00128_workspace_email_and_signing_languages.sql")
	if requireReviewedLifecycleTreeV1(files, tail) == nil {
		t.Fatal("missing M128 floor accepted")
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		files = email128LifecycleFiles()
		files["migrations/00128_workspace_email_and_signing_languages.sql"].Mode = mode
		if requireReviewedLifecycleTreeV1(files, tail) == nil {
			t.Fatal("nonregular M128 accepted")
		}
	}
	if requireReviewedLifecycleTreeV1(email128LifecycleFiles(), append(tail, 129)) == nil {
		t.Fatal("unreviewed future migration accepted")
	}
}
func TestWorkspaceEmail128DoesNotAddVoidedOrDiscardRetainedConfiguration(t *testing.T) {
	raw, err := fs.ReadFile(embeddedMigrations, "migrations/00128_workspace_email_and_signing_languages.sql")
	if err != nil {
		t.Fatal(err)
	}
	up, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok || strings.Contains(up, "'email.voided'") || !strings.Contains(up, "'email.declined'") || !strings.Contains(up, "'email.quota_warning_80'") {
		t.Fatal("migration expanded unrelated producer scope")
	}
	for _, required := range []string{"locale IN ('en','sv')", "revision > 0", "revision <= 9007199254740991", "REFERENCES orgs(id)"} {
		if !strings.Contains(up, required) {
			t.Fatal("preference constraint missing", required)
		}
	}
	for _, required := range []string{"EXISTS (SELECT 1 FROM org_email_preferences_v1)", "WHERE kind IN ('email.declined','email.quota_warning_80')", "RAISE EXCEPTION"} {
		if !strings.Contains(down, required) {
			t.Fatal("retained data rollback guard missing", required)
		}
	}
}

func TestSigningLanguages128DownRefusesRetainedSwedishBeforeSchemaChanges(t *testing.T) {
	raw, err := fs.ReadFile(embeddedMigrations, "migrations/00128_workspace_email_and_signing_languages.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("M128 Down is missing")
	}
	guard := strings.Index(down, "retained Swedish package consent prevents M128 downgrade")
	firstSchemaChange := strings.Index(down, "CREATE OR REPLACE FUNCTION")
	if guard < 0 || firstSchemaChange < guard {
		t.Fatal("M128 must refuse retained Swedish evidence before restoring old validation")
	}
	for _, required := range []string{
		"document_package_send_attempts_v1,document_package_responses_v1 IN SHARE ROW EXCLUSIVE MODE",
		"FROM document_package_send_attempts_v1 WHERE incorporation_version='hash-package-incorporation-sv-v1'",
		"FROM document_package_responses_v1 WHERE incorporation_version='hash-package-incorporation-sv-v1'",
	} {
		if !strings.Contains(down, required) {
			t.Fatal("retained package rollback boundary missing", required)
		}
	}
	for _, destructive := range []string{"DELETE FROM", "TRUNCATE"} {
		if strings.Contains(strings.ToUpper(down), destructive) {
			t.Fatal("M128 rollback must refuse retained data, never erase it")
		}
	}
}
