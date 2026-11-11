// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func smtp730LifecycleFiles() fstest.MapFS {
	f := reviewedLifecycleFiles709()
	f["migrations/00119_service_email_templates.sql"] = &fstest.MapFile{Data: []byte("-- email content")}
	f["migrations/00120_workspace_smtp.sql"] = &fstest.MapFile{Data: []byte("-- scoped SMTP")}
	return f
}
func TestReviewedNamedSMTP120RetainsContractEight730(t *testing.T) {
	for _, versions := range [][]int64{{115, 116, 117}, {115, 116, 117, 118}, {115, 116, 117, 118, 119}, {115, 116, 117, 118, 119, 120}} {
		if e := requireReviewedLifecycleTreeV1(smtp730LifecycleFiles(), versions); e != nil || LifecycleContractVersionV1 != 9 {
			t.Fatal("reviewed prior/current tree refused", versions, e)
		}
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		f := smtp730LifecycleFiles()
		f["migrations/00120_workspace_smtp.sql"].Mode = mode
		if requireReviewedLifecycleTreeV1(f, []int64{115, 116, 117, 118, 119, 120}) == nil {
			t.Fatal("nonregular SMTP migration accepted")
		}
	}
	for _, versions := range [][]int64{{115, 116, 117, 118, 120}, {115, 116, 117, 118, 119, 120, 121}, {115, 116, 117, 118, 119, 120, 120}} {
		if requireReviewedLifecycleTreeV1(smtp730LifecycleFiles(), versions) == nil {
			t.Fatal("unknown or incomplete tail accepted")
		}
	}
	f := smtp730LifecycleFiles()
	delete(f, "migrations/00120_workspace_smtp.sql")
	f["migrations/00120_unreviewed.sql"] = &fstest.MapFile{Data: []byte("-- wrong")}
	if requireReviewedLifecycleTreeV1(f, []int64{115, 116, 117, 118, 119, 120}) == nil {
		t.Fatal("renamed SMTP migration accepted")
	}
}
