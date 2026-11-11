// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func automationDesignLifecycleFiles121() fstest.MapFS {
	f := smtp730LifecycleFiles()
	f["migrations/00121_reminder_sender_automation.sql"] = &fstest.MapFile{Data: []byte("-- finite automation")}
	f["migrations/00122_service_email_design.sql"] = &fstest.MapFile{Data: []byte("-- bounded email design")}
	return f
}
func TestReviewedAutomation121AndDesign122RetainWriterEight(t *testing.T) {
	f := automationDesignLifecycleFiles121()
	for highest := 117; highest <= 122; highest++ {
		versions := []int64{115, 116, 117}
		for n := 118; n <= highest; n++ {
			versions = append(versions, int64(n))
		}
		if version, err := reviewedLifecycleContractVersionV1(f, versions); err != nil || version != 8 {
			t.Fatal("reviewed prior/current named tail refused", highest, err)
		}
	}
	for _, tail := range [][]int64{{115, 116, 117, 118, 119, 120, 121, 122, 123}, {115, 116, 117, 118, 119, 120, 122}, {115, 116, 117, 118, 119, 120, 121, 121, 122}, {115, 116, 117, 118, 119, 120, 122, 121}} {
		if requireReviewedLifecycleTreeV1(f, tail) == nil {
			t.Fatal("future/missing/duplicate/unordered migration accepted", tail)
		}
	}
	for _, name := range []string{"00120_workspace_smtp.sql", "00121_reminder_sender_automation.sql", "00122_service_email_design.sql"} {
		for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
			x := automationDesignLifecycleFiles121()
			x["migrations/"+name].Mode = mode
			if requireReviewedLifecycleTreeV1(x, []int64{115, 116, 117, 118, 119, 120, 121, 122}) == nil {
				t.Fatal("nonregular migration accepted", name, mode)
			}
		}
		x := automationDesignLifecycleFiles121()
		delete(x, "migrations/"+name)
		x["migrations/unreviewed.sql"] = &fstest.MapFile{Data: []byte("-- incorrect")}
		if requireReviewedLifecycleTreeV1(x, []int64{115, 116, 117, 118, 119, 120, 121, 122}) == nil {
			t.Fatal("missing/renamed migration accepted", name)
		}
	}
}
