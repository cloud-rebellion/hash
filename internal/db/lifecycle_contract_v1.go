// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db

import (
	"fmt"
	"io/fs"
)

// LifecycleContractVersionV1 is the complete application/worker contract, not
// the storage encryption or physical database identity contract schema.
// Version7 owns M116 pre-sign archives, publication, recovery and V3 evidence.
// Version8 also owns M117 staff credentials and sealed recovery mail. Older
// workers do not decode that ciphertext and cannot safely consume its queue.
// M118 only adds document filing sidecars and retains this writer contract.
const LifecycleContractVersionV1 = 8

func EmbeddedLifecycleIdentityV1() (version int, migrationsSHA256 string, err error) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil {
		return 0, "", err
	}
	if err := requireReviewedLifecycleTreeV1(embeddedMigrations, versions); err != nil {
		return 0, "", err
	}
	return LifecycleContractVersionV1, digest, nil
}

func requireReviewedLifecycleTreeV1(migrations fs.FS, versions []int64) error {
	unsupported := fmt.Errorf("embedded lifecycle contract requires the reviewed M117 or named M118 migration tree")
	if len(versions) == 0 || len(versions) > 118 {
		return unsupported
	}
	highest := versions[len(versions)-1]
	if highest != 117 && highest != 118 {
		return unsupported
	}
	seen := make(map[int64]bool, len(versions))
	for index, version := range versions {
		if version <= 0 || (index > 0 && versions[index-1] >= version) {
			return unsupported
		}
		seen[version] = true
	}
	names := []string{"00115_later_amendments.sql", "00116_presign_publication_v1.sql", "00117_staff_password_auth.sql"}
	if highest == 118 {
		names = append(names, "00118_document_folders.sql")
	}
	for index, name := range names {
		info, err := fs.Stat(migrations, "migrations/"+name)
		if !seen[int64(115+index)] || err != nil || !info.Mode().IsRegular() {
			return unsupported
		}
	}
	return nil
}
