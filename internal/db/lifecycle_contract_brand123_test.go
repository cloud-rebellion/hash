// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func brand123LifecycleFiles() fstest.MapFS {
	f := automationDesignLifecycleFiles121()
	f["migrations/00123_org_brand_profiles.sql"] = &fstest.MapFile{Data: []byte("-- retained brand profile sidecars\n")}
	return f
}

func TestEmbeddedBrand123RetainsWriterEightAndActualMigrationIdentity(t *testing.T) {
	want, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || len(versions) != 127 || versions[len(versions)-1] != 127 {
		t.Fatal("actual embedded brand migration tree differs", versions, err)
	}
	version, digest, err := EmbeddedLifecycleIdentityV1()
	if err != nil || version != 9 || digest != want {
		t.Fatal("named actual brand sidecars changed/refused the existing writer contract", version, digest, err)
	}
}

func TestReviewedBrand123KeepsNamedFloorsAndFutureRefusals(t *testing.T) {
	tail := []int64{115, 116, 117, 118, 119, 120, 121, 122, 123}
	if err := requireReviewedLifecycleTreeV1(brand123LifecycleFiles(), tail); err != nil {
		t.Fatal("reviewed named brand tail refused", err)
	}
	for name, versions := range map[string][]int64{
		"future":        {115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128},
		"missing-floor": {115, 116, 117, 118, 119, 120, 121, 123},
		"duplicate":     {115, 116, 117, 118, 119, 120, 121, 122, 123, 123},
		"unordered":     {115, 116, 117, 118, 119, 120, 121, 123, 122},
		"nonpositive":   {0, 115, 116, 117, 118, 119, 120, 121, 122, 123},
	} {
		t.Run(name, func(t *testing.T) {
			if requireReviewedLifecycleTreeV1(brand123LifecycleFiles(), versions) == nil {
				t.Fatal("unreviewed or malformed version history accepted", versions)
			}
		})
	}
	for _, name := range []string{"00115_later_amendments.sql", "00116_presign_publication_v1.sql", "00117_staff_password_auth.sql", "00118_document_folders.sql", "00119_service_email_templates.sql", "00120_workspace_smtp.sql", "00121_reminder_sender_automation.sql", "00122_service_email_design.sql", "00123_org_brand_profiles.sql"} {
		t.Run(name, func(t *testing.T) {
			for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
				f := brand123LifecycleFiles()
				f["migrations/"+name].Mode = mode
				if requireReviewedLifecycleTreeV1(f, tail) == nil {
					t.Fatal("nonregular named floor accepted", mode)
				}
			}
			f := brand123LifecycleFiles()
			delete(f, "migrations/"+name)
			f["migrations/renamed.sql"] = &fstest.MapFile{Data: []byte("-- renamed")}
			if requireReviewedLifecycleTreeV1(f, tail) == nil {
				t.Fatal("missing/renamed named floor accepted")
			}
		})
	}
	if requireReviewedLifecycleTreeV1(automationDesignLifecycleFiles121(), tail) == nil {
		t.Fatal("old future123-without-named-file refusal was lost")
	}
}
