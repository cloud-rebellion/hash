//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"fmt"
	"github.com/bright-interaction/hash/internal/testfixture"
	"os"
	"testing"
)

var registryDatabasesE2E *testfixture.OwnedPostgresFactory

func TestMain(m *testing.M) {
	registryDatabasesE2E = testfixture.NewOwnedPostgresFactory(os.Getenv("HASH_E2E_DB_URL"))
	code := m.Run()
	if err := registryDatabasesE2E.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
	os.Exit(code)
}
