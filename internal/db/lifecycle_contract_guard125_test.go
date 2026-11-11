// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"testing"
)

func TestEmbeddedGuard125KeepsWriterNineAndRequiresItsNamedFloor(t *testing.T) {
	want, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || versions[len(versions)-1] != 127 {
		t.Fatal("embedded tree does not end at M127", err)
	}
	if version, digest, err := EmbeddedLifecycleIdentityV1(); err != nil || version != 9 || digest != want {
		t.Fatal("M125 is trigger-only and must keep writer contract 9", version, digest, err)
	}
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125}
	f := brand123LifecycleFiles()
	f["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if requireReviewedLifecycleTreeV1(f, tail) == nil {
		t.Fatal("M125 accepted without its named migration")
	}
	f["migrations/00125_html_template_revision_insert_guard.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if err := requireReviewedLifecycleTreeV1(f, tail); err != nil {
		t.Fatal("reviewed M125 tree refused", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		g := brand123LifecycleFiles()
		g["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
		m := *f["migrations/00123_org_brand_profiles.sql"]
		m.Mode = mode
		g["migrations/00125_html_template_revision_insert_guard.sql"] = &m
		if requireReviewedLifecycleTreeV1(g, tail) == nil {
			t.Fatal("nonregular M125 floor accepted", mode)
		}
	}
}
