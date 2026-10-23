// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"encoding/json"
	hashdb "github.com/bright-interaction/hash/internal/db"
	"io"
)

const lifecycleContractArgV1 = "--lifecycle-contract"

type compiledLifecycleResultV1 struct {
	SchemaVersion            int    `json:"schema_version"`
	LifecycleContractVersion int    `json:"lifecycle_contract_version"`
	MigrationsSHA256         string `json:"migrations_sha256"`
}

func compiledLifecycleReportV1() (compiledLifecycleResultV1, error) {
	version, digest, err := hashdb.EmbeddedLifecycleIdentityV1()
	if err != nil {
		return compiledLifecycleResultV1{}, err
	}
	return compiledLifecycleResultV1{SchemaVersion: 1, LifecycleContractVersion: version, MigrationsSHA256: digest}, nil
}

func writeCompiledLifecycleReportV1(w io.Writer) error {
	result, err := compiledLifecycleReportV1()
	if err != nil {
		return err
	}
	// This dedicated wire contract stays compact and newline-terminated;
	// existing human-readable rollback modes keep their indented output.
	return json.NewEncoder(w).Encode(result)
}
