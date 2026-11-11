// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func TestReviewedLifecycleEmail720Named119RetainsEight(t *testing.T) {
	f := reviewedLifecycleFiles709()
	f["migrations/00119_service_email_templates.sql"] = &fstest.MapFile{Data: []byte("-- revisioned rendered service email\n")}
	if version, err := reviewedLifecycleContractVersionV1(f, []int64{115, 116, 117, 118, 119}); err != nil || version != 8 {
		t.Fatal("named additive mail tree changed/refused original writer contract", err)
	}
	for _, mode := range []fs.FileMode{fs.ModeDir, fs.ModeSymlink} {
		f["migrations/00119_service_email_templates.sql"].Mode = mode
		if requireReviewedLifecycleTreeV1(f, []int64{115, 116, 117, 118, 119}) == nil {
			t.Fatal("nonregular119 accepted")
		}
	}
}
func TestReviewedLifecycleEmail720RefusesUnknownOrBrokenTail(t *testing.T) {
	for _, tc := range []struct {
		name     string
		versions []int64
		remove   string
		wrong    bool
	}{
		{"future120", []int64{115, 116, 117, 118, 119, 120}, "", false},
		{"missing118", []int64{115, 116, 117, 119}, "", false},
		{"missing119file", []int64{115, 116, 117, 118, 119}, "migrations/00119_service_email_templates.sql", false},
		{"wrong119name", []int64{115, 116, 117, 118, 119}, "migrations/00119_service_email_templates.sql", true},
		{"missing117file", []int64{115, 116, 117, 118, 119}, "migrations/00117_staff_password_auth.sql", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := reviewedLifecycleFiles709()
			f["migrations/00119_service_email_templates.sql"] = &fstest.MapFile{Data: []byte("-- reviewed\n")}
			delete(f, tc.remove)
			if tc.wrong {
				f["migrations/00119_unreviewed.sql"] = &fstest.MapFile{Data: []byte("-- unreviewed\n")}
			}
			if requireReviewedLifecycleTreeV1(f, tc.versions) == nil {
				t.Fatal("unknown or incomplete tree accepted")
			}
		})
	}
}
