// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"encoding/json"
	hashdb "github.com/bright-interaction/hash/internal/db"
	"testing"
)

func TestCompiledLifecycle484BindsActualEmbeddedM117WithoutDatabase(t *testing.T) {
	t.Setenv("HASH_DB_URL", "")
	got, err := compiledLifecycleReportV1()
	if err != nil {
		t.Fatal(err)
	}
	digest, versions, err := hashdb.EmbeddedMigrationsIdentity()
	if err != nil || len(versions) == 0 || versions[len(versions)-1] != 117 || got.SchemaVersion != 1 || got.LifecycleContractVersion != 8 || got.MigrationsSHA256 != digest {
		t.Fatalf("compiled lifecycle not bound to actual embedded tree: %+v %v", got, err)
	}
	raw, err := json.Marshal(got)
	if err != nil || len(raw) > 256 {
		t.Fatal("unbounded or unavailable lifecycle output", err)
	}
	var wire bytes.Buffer
	if err := writeCompiledLifecycleReportV1(&wire); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), append(raw, '\n')) {
		t.Fatal("actual capability writer changed compact canonical wire contract")
	}
}
