// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package db

import (
	"io/fs"
	"testing"
	"testing/fstest"
)

func reviewedLifecycleFiles709() fstest.MapFS {
	return fstest.MapFS{
		"migrations/00115_later_amendments.sql":       {Data: []byte("-- later amendments\n")},
		"migrations/00116_presign_publication_v1.sql": {Data: []byte("-- publication\n")},
		"migrations/00117_staff_password_auth.sql":    {Data: []byte("-- staff credentials\n")},
		"migrations/00118_document_folders.sql":       {Data: []byte("-- filing sidecars\n")},
	}
}

func TestReviewedLifecycleTree709Preserves117AndNamed118(t *testing.T) {
	for _, versions := range [][]int64{{115, 116, 117}, {115, 116, 117, 118}} {
		files := reviewedLifecycleFiles709()
		if versions[len(versions)-1] == 117 {
			delete(files, "migrations/00118_document_folders.sql")
		}
		if err := requireReviewedLifecycleTreeV1(files, versions); err != nil {
			t.Fatalf("reviewed tree %v refused: %v", versions, err)
		}
	}
	if LifecycleContractVersionV1 != 9 {
		t.Fatal("filing sidecars changed the retained writer contract")
	}
}

func TestReviewedLifecycleTree709RefusesUnknownOrBrokenBoundary(t *testing.T) {
	cases := map[string][]int64{
		"empty":        nil,
		"old116":       {115, 116},
		"missing115":   {116, 117, 118},
		"missing116":   {115, 117, 118},
		"missing117":   {115, 116, 118},
		"bare118":      {118},
		"future119":    {115, 116, 117, 118, 119},
		"future120":    {115, 116, 117, 120},
		"duplicate":    {115, 116, 117, 118, 118},
		"out-of-order": {115, 117, 116, 118},
	}
	for name, versions := range cases {
		t.Run(name, func(t *testing.T) {
			if err := requireReviewedLifecycleTreeV1(reviewedLifecycleFiles709(), versions); err == nil {
				t.Fatal("unreviewed lifecycle inventory accepted")
			}
		})
	}
	for name, path := range map[string]string{
		"missing-file115": "migrations/00115_later_amendments.sql",
		"missing-file116": "migrations/00116_presign_publication_v1.sql",
		"missing-file117": "migrations/00117_staff_password_auth.sql",
		"wrong-name118":   "migrations/00118_document_folders.sql",
	} {
		t.Run(name, func(t *testing.T) {
			files := reviewedLifecycleFiles709()
			delete(files, path)
			if name == "wrong-name118" {
				files["migrations/00118_unreviewed.sql"] = &fstest.MapFile{Data: []byte("-- not reviewed\n")}
			}
			if err := requireReviewedLifecycleTreeV1(files, []int64{115, 116, 117, 118}); err == nil {
				t.Fatal("missing or renamed reviewed migration accepted")
			}
		})
	}
	for name, mode := range map[string]fs.FileMode{"directory": fs.ModeDir, "symlink": fs.ModeSymlink} {
		t.Run(name, func(t *testing.T) {
			files := reviewedLifecycleFiles709()
			files["migrations/00118_document_folders.sql"].Mode = mode
			if err := requireReviewedLifecycleTreeV1(files, []int64{115, 116, 117, 118}); err == nil {
				t.Fatal("non-regular sidecar accepted")
			}
		})
	}
}

func TestEmbeddedLifecycleIdentity709ReturnsNativeDigest(t *testing.T) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 {
		t.Fatalf("read actual embedded tree: %v", err)
	}
	version, observed, err := EmbeddedLifecycleIdentityV1()
	if err != nil || version != 9 || observed != digest || len(digest) != 64 {
		t.Fatalf("actual tree lost lifecycle/digest binding: version=%d error=%v", version, err)
	}
}
