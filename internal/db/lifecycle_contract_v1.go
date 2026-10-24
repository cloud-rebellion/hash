// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db

import "fmt"

// LifecycleContractVersionV1 is the complete application/worker contract, not
// the storage encryption or physical database identity contract schema.
// Version7 owns M116 pre-sign archives, publication, recovery and V3 evidence.
// M117 adds staff credentials and sealed recovery mail without changing that
// document lifecycle or its retained-artifact compatibility protocol.
const LifecycleContractVersionV1 = 7

func EmbeddedLifecycleIdentityV1() (version int, migrationsSHA256 string, err error) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil {
		return 0, "", err
	}
	// A later migration must receive its own explicit compatibility review.
	if len(versions) == 0 || versions[len(versions)-1] != 117 {
		return 0, "", fmt.Errorf("embedded lifecycle contract requires the reviewed M117 migration tree")
	}
	return LifecycleContractVersionV1, digest, nil
}
