// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"github.com/bright-interaction/hash/internal/workguard"
)

// WorkRuntimeLimitsV1 is an explicit per-process operator allocation. Absent
// configuration leaves the admission runtime unconfigured; it does not create
// guessed defaults or activate READY. Deployment must separately qualify the
// aggregate allocations against measured process, child and database capacity.
type WorkRuntimeLimitsV1 struct {
	Limits             workguard.LimitsV1
	TotalDBConnections int64
}

var workRuntimeDimensionsV1 = [...]string{"PARENT_BYTES", "DB_STAGING_BYTES", "CHILD_ADDRESS_BYTES", "PDF_WORKERS", "SQL_SESSIONS", "PROVIDER_STREAMS", "RENDERER_REQUESTS"}

func workRuntimeEnvNamesV1() []string {
	out := make([]string, 0, 17)
	for _, prefix := range []string{"HASH_WORK_GLOBAL_", "HASH_WORK_ORG_"} {
		for _, name := range workRuntimeDimensionsV1 {
			out = append(out, prefix+name)
		}
	}
	return append(out, "HASH_WORK_MAX_GRANTS", "HASH_WORK_MAX_ORG_GRANTS", "HASH_WORK_DB_CONNECTION_ALLOCATION")
}
func workRuntimeIntegerEnvV1(name string, minimum, maximum int64) (int64, error) {
	raw, ok := os.LookupEnv(name)
	if !ok || raw == "" {
		return 0, fmt.Errorf("required work resource configuration %s is missing", name)
	}
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("work resource configuration %s is outside its supported integer range", name)
		}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < minimum || value > maximum {
		return 0, fmt.Errorf("work resource configuration %s is outside its supported integer range", name)
	}
	return value, nil
}
func workRuntimeVectorEnvV1(prefix string) (workguard.VectorV1, error) {
	var out workguard.VectorV1
	fields := []*int64{&out.ParentBytes, &out.DBStagingBytes, &out.ChildAddressBytes, &out.PDFWorkers, &out.SQLSessions, &out.ProviderStreams, &out.RendererRequests}
	for i, target := range fields {
		maximum := int64(1 << 40)
		if i >= 3 {
			maximum = 1 << 16
		}
		value, err := workRuntimeIntegerEnvV1(prefix+workRuntimeDimensionsV1[i], 0, maximum)
		if err != nil {
			return out, err
		}
		*target = value
	}
	return out, nil
}
func loadWorkRuntimeLimitsV1() (*WorkRuntimeLimitsV1, error) {
	configured := false
	for _, name := range workRuntimeEnvNamesV1() {
		if _, ok := os.LookupEnv(name); ok {
			configured = true
			break
		}
	}
	if !configured {
		return nil, nil
	}
	out := &WorkRuntimeLimitsV1{}
	var err error
	out.Limits.Global, err = workRuntimeVectorEnvV1("HASH_WORK_GLOBAL_")
	if err != nil {
		return nil, err
	}
	out.Limits.Organisation, err = workRuntimeVectorEnvV1("HASH_WORK_ORG_")
	if err != nil {
		return nil, err
	}
	out.Limits.MaxGrants, err = workRuntimeIntegerEnvV1("HASH_WORK_MAX_GRANTS", 1, 1<<16)
	if err != nil {
		return nil, err
	}
	out.Limits.MaxOrganisationGrants, err = workRuntimeIntegerEnvV1("HASH_WORK_MAX_ORG_GRANTS", 1, 1<<16)
	if err != nil {
		return nil, err
	}
	out.TotalDBConnections, err = workRuntimeIntegerEnvV1("HASH_WORK_DB_CONNECTION_ALLOCATION", 1, 1<<63-1)
	if err != nil {
		return nil, err
	}
	global, org := out.Limits.Global, out.Limits.Organisation
	if org.ParentBytes > global.ParentBytes || org.DBStagingBytes > global.DBStagingBytes || org.ChildAddressBytes > global.ChildAddressBytes || org.PDFWorkers > global.PDFWorkers || org.SQLSessions > global.SQLSessions || org.ProviderStreams > global.ProviderStreams || org.RendererRequests > global.RendererRequests || out.Limits.MaxOrganisationGrants > out.Limits.MaxGrants {
		return nil, errors.New("organisation work limits exceed the explicitly configured process limits")
	}
	if global.SQLSessions < 1 {
		return nil, errors.New("configured work runtime requires a positive HASH_WORK_GLOBAL_SQL_SESSIONS allocation")
	}
	return out, nil
}

// LoadWorkRuntimeLimitsV1 loads only the existing explicit process allocations
// for fixed maintenance commands. Missing configuration remains unconfigured;
// this performs no I/O, migrations or capacity/readiness inference.
func LoadWorkRuntimeLimitsV1() (*WorkRuntimeLimitsV1, error) { return loadWorkRuntimeLimitsV1() }
