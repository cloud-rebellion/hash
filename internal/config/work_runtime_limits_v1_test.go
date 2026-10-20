// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"os"
	"strings"
	"testing"
)

func clearWorkRuntimeEnvironmentTestV1(t *testing.T) {
	t.Helper()
	for _, name := range workRuntimeEnvNamesV1() {
		name := name
		old, present := os.LookupEnv(name)
		if err := os.Unsetenv(name); err != nil {
			t.Fatal("clear test resource allocation")
		}
		t.Cleanup(func() {
			if present {
				_ = os.Setenv(name, old)
			} else {
				_ = os.Unsetenv(name)
			}
		})
	}
}
func setWorkRuntimeEnvironmentTestV1(t *testing.T) {
	t.Helper()
	for _, prefix := range []string{"HASH_WORK_GLOBAL_", "HASH_WORK_ORG_"} {
		for _, suffix := range []string{"PARENT_BYTES", "DB_STAGING_BYTES"} {
			t.Setenv(prefix+suffix, "8388608")
		}
		t.Setenv(prefix+"CHILD_ADDRESS_BYTES", "0")
		t.Setenv(prefix+"PDF_WORKERS", "0")
		t.Setenv(prefix+"SQL_SESSIONS", "2")
		t.Setenv(prefix+"PROVIDER_STREAMS", "0")
		t.Setenv(prefix+"RENDERER_REQUESTS", "0")
	}
	t.Setenv("HASH_WORK_MAX_GRANTS", "8")
	t.Setenv("HASH_WORK_MAX_ORG_GRANTS", "8")
	t.Setenv("HASH_WORK_DB_CONNECTION_ALLOCATION", "5")
}
func TestLoadWorkRuntimeAbsentPreservesBaseStartupV1(t *testing.T) {
	clearWorkRuntimeEnvironmentTestV1(t)
	setAllRequired(t)
	loaded, err := Load()
	if err != nil {
		t.Fatal("base authenticated configuration no longer loads without a resource allocation")
	}
	if loaded.WorkRuntime != nil {
		t.Fatal("missing resource configuration created guessed runtime caps")
	}
}
func TestLoadWorkRuntimeCompleteAllocationRetainsDisabledDimensionsV1(t *testing.T) {
	clearWorkRuntimeEnvironmentTestV1(t)
	setAllRequired(t)
	setWorkRuntimeEnvironmentTestV1(t)
	loaded, err := Load()
	if err != nil || loaded.WorkRuntime == nil {
		t.Fatal("explicit resource configuration did not reach application configuration")
	}
	w := loaded.WorkRuntime
	if w.Limits.Global.ParentBytes != 8<<20 || w.Limits.Organisation.DBStagingBytes != 8<<20 || w.Limits.Global.SQLSessions != 2 || w.Limits.MaxGrants != 8 || w.TotalDBConnections != 5 {
		t.Fatal("explicit resource allocation was defaulted or dropped")
	}
	if w.Limits.Global.PDFWorkers != 0 || w.Limits.Global.ChildAddressBytes != 0 || w.Limits.Organisation.ProviderStreams != 0 || w.Limits.Organisation.RendererRequests != 0 {
		t.Fatal("explicit disabled resource dimension gained guessed capacity")
	}
}
func TestLoadWorkRuntimePartialOrInvalidCannotFallBackV1(t *testing.T) {
	t.Run("single present key", func(t *testing.T) {
		clearWorkRuntimeEnvironmentTestV1(t)
		setAllRequired(t)
		t.Setenv("HASH_WORK_DB_CONNECTION_ALLOCATION", "5")
		if got, err := Load(); got != nil || err == nil {
			t.Fatal("partial allocation silently disabled admission configuration")
		}
	})
	for _, tc := range []struct{ name, key, value string }{
		{"empty present key", "HASH_WORK_GLOBAL_PARENT_BYTES", ""},
		{"negative byte count", "HASH_WORK_GLOBAL_PARENT_BYTES", "-1"},
		{"byte ceiling", "HASH_WORK_GLOBAL_PARENT_BYTES", "1099511627777"},
		{"operation ceiling", "HASH_WORK_GLOBAL_PROVIDER_STREAMS", "65537"},
		{"integer overflow", "HASH_WORK_DB_CONNECTION_ALLOCATION", "9223372036854775808"},
		{"not integer", "HASH_WORK_GLOBAL_PARENT_BYTES", "redacted-private-value"},
		{"zero direct session allocation", "HASH_WORK_GLOBAL_SQL_SESSIONS", "0"},
		{"zero grant allocation", "HASH_WORK_MAX_GRANTS", "0"},
		{"grant ceiling", "HASH_WORK_MAX_GRANTS", "65537"},
		{"organisation bytes exceed global", "HASH_WORK_ORG_PARENT_BYTES", "8388609"},
		{"organisation grants exceed global", "HASH_WORK_MAX_ORG_GRANTS", "9"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearWorkRuntimeEnvironmentTestV1(t)
			setAllRequired(t)
			setWorkRuntimeEnvironmentTestV1(t)
			t.Setenv(tc.key, tc.value)
			got, err := Load()
			if got != nil || err == nil {
				t.Fatal("invalid configured allocation silently became an unconfigured runtime")
			}
			if tc.value == "redacted-private-value" && strings.Contains(err.Error(), tc.value) {
				t.Fatal("configuration error disclosed a raw value")
			}
		})
	}
}
