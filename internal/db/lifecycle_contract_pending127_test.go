// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestEmbeddedPending127KeepsWriterNineAndRequiresItsNamedFloor(t *testing.T) {
	want, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || versions[len(versions)-1] != 128 {
		t.Fatal("embedded tree does not end at M128", err)
	}
	if version, digest, err := EmbeddedLifecycleIdentityV1(); err != nil || version != LifecycleContractVersionV1 || digest != want {
		t.Fatal("actual tree lost its writer and migration identity", version, digest, err)
	}
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127}
	build := func() fstest.MapFS {
		f := brand123LifecycleFiles()
		for _, name := range []string{"00124_draft_in_place_edit.sql", "00125_html_template_revision_insert_guard.sql", "00126_measure_html_document_events.sql"} {
			f["migrations/"+name] = f["migrations/00123_org_brand_profiles.sql"]
		}
		return f
	}
	f := build()
	if requireReviewedLifecycleTreeV1(f, tail) == nil {
		t.Fatal("M127 accepted without its named migration")
	}
	f["migrations/00127_pending_object_deletions.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if version, err := reviewedLifecycleContractVersionV1(f, tail); err != nil || version != 9 {
		t.Fatal("reviewed M127 tree refused", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		g := build()
		m := *f["migrations/00123_org_brand_profiles.sql"]
		m.Mode = mode
		g["migrations/00127_pending_object_deletions.sql"] = &m
		if requireReviewedLifecycleTreeV1(g, tail) == nil {
			t.Fatal("nonregular M127 floor accepted", mode)
		}
	}
	if requireReviewedLifecycleTreeV1(f, append(append([]int64{}, tail...), 128)) == nil {
		t.Fatal("an unnamed M128 was accepted")
	}
}

// The queue's Down must refuse while obligations remain, and its table must keep
// the org-scoped shape the retention rule asks for. Both are read from the SQL so
// a later edit cannot drop them silently.
func TestPending127MigrationKeepsItsDurabilityShape(t *testing.T) {
	raw, err := fs.ReadFile(embeddedMigrations, "migrations/00127_pending_object_deletions.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	up, down, ok := strings.Cut(sql, "-- +goose Down")
	if !ok {
		t.Fatal("M127 has no Down section")
	}
	for _, want := range []string{
		"org_id UUID NOT NULL REFERENCES orgs(id)",
		"dsr_id UUID REFERENCES data_subject_requests(id)",
		"storage_key TEXT NOT NULL", "version_id TEXT NOT NULL", "sha256 BYTEA NOT NULL",
		"attempts INTEGER NOT NULL", "last_error TEXT NOT NULL",
		"(org_id, next_attempt_at)", "(org_id, document_id)", "UNIQUE (org_id, storage_key, version_id)",
	} {
		if !strings.Contains(up, want) {
			t.Fatalf("M127 Up lost %q", want)
		}
	}
	if !strings.Contains(down, "RAISE EXCEPTION") || !strings.Contains(down, "DROP TABLE pending_object_deletions_v1") {
		t.Fatal("M127 Down must refuse while pending deletions remain, then drop the table")
	}
}
