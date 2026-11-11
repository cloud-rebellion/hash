// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMeasure126KeepsWriterNineAndRequiresItsNamedFloor(t *testing.T) {
	want, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || versions[len(versions)-1] != 127 {
		t.Fatal("embedded tree does not end at M127", err)
	}
	if version, digest, err := EmbeddedLifecycleIdentityV1(); err != nil || version != 9 || digest != want {
		t.Fatal("M126 only backfills derived rows and must keep writer contract 9", version, digest, err)
	}
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126}
	f := brand123LifecycleFiles()
	f["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	f["migrations/00125_html_template_revision_insert_guard.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if requireReviewedLifecycleTreeV1(f, tail) == nil {
		t.Fatal("M126 accepted without its named migration")
	}
	f["migrations/00126_measure_html_document_events.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if err := requireReviewedLifecycleTreeV1(f, tail); err != nil {
		t.Fatal("reviewed M126 tree refused", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		g := brand123LifecycleFiles()
		g["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
		g["migrations/00125_html_template_revision_insert_guard.sql"] = f["migrations/00123_org_brand_profiles.sql"]
		m := *f["migrations/00123_org_brand_profiles.sql"]
		m.Mode = mode
		g["migrations/00126_measure_html_document_events.sql"] = &m
		if requireReviewedLifecycleTreeV1(g, tail) == nil {
			t.Fatal("nonregular M126 floor accepted", mode)
		}
	}
}

func TestMeasure126BackfillIsOrderedAndIdempotent(t *testing.T) {
	raw, err := fs.ReadFile(embeddedMigrations, "migrations/00126_measure_html_document_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	if !strings.Contains(sql, "ORDER BY e.org_id, e.id") {
		t.Fatal("M126 must take the org lock inputs in stable org/id order")
	}
	if !strings.Contains(sql, "ON CONFLICT (event_id) DO NOTHING") {
		t.Fatal("M126 must remain idempotent when a concurrent writer measured an event")
	}
}
