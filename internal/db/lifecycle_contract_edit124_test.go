// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedEdit124BumpsWriterToNineAndRequiresItsNamedFloor(t *testing.T) {
	want, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || versions[len(versions)-1] != 127 {
		t.Fatal("embedded tree does not end at M127", err)
	}
	version, digest, err := EmbeddedLifecycleIdentityV1()
	if err != nil || version != 9 || digest != want {
		t.Fatal("M124 must publish writer contract 9 with the actual migration identity", version, digest, err)
	}
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123, 124}
	f := brand123LifecycleFiles()
	f["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
	if err := requireReviewedLifecycleTreeV1(f, tail); err != nil {
		t.Fatal("reviewed M124 tree refused", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		g := brand123LifecycleFiles()
		g["migrations/00124_draft_in_place_edit.sql"] = f["migrations/00123_org_brand_profiles.sql"]
		g["migrations/00124_draft_in_place_edit.sql"] = &(*f["migrations/00123_org_brand_profiles.sql"])
		g["migrations/00124_draft_in_place_edit.sql"].Mode = mode
		if requireReviewedLifecycleTreeV1(g, tail) == nil {
			t.Fatal("nonregular M124 floor accepted", mode)
		}
	}
	if requireReviewedLifecycleTreeV1(brand123LifecycleFiles(), tail) == nil {
		t.Fatal("M124 accepted without its named migration")
	}
}

func TestEdit124DownPreservesDSRErasureHistory(t *testing.T) {
	raw, err := fs.ReadFile(embeddedMigrations, "migrations/00124_draft_in_place_edit.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("M124 has no Down section")
	}
	if !strings.Contains(down, "EXISTS (SELECT 1 FROM document_pdf_history_erasures_v1)") {
		t.Fatal("M124 Down must refuse while PDF history erasure records remain")
	}
}
