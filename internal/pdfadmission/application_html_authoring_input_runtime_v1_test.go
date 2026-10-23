// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"runtime"
	"runtime/debug"
	"strconv"
	"testing"
)

func TestHTMLAuthoringInputRuntimeQualifiedModelsV1(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		bits          int
		info          *debug.BuildInfo
		want          bool
	}{
		{"reviewed-prior", "go1.26.9", 64, &debug.BuildInfo{}, true},
		{"reviewed-security-release", "go1.26.10", 64, &debug.BuildInfo{}, true},
		{"explicit-default-experiments", "go1.26.10", 64, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOEXPERIMENT", Value: ""}}}, true},
		{"ordinary-build-setting", "go1.26.10", 64, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}}}, true},
		{"unreviewed-prior", "go1.26.8", 64, &debug.BuildInfo{}, false},
		{"unreviewed-successor", "go1.26.11", 64, &debug.BuildInfo{}, false},
		{"development-version", "devel go1.26.10", 64, &debug.BuildInfo{}, false},
		{"version-suffix", "go1.26.10-custom", 64, &debug.BuildInfo{}, false},
		{"32-bit-model", "go1.26.10", 32, &debug.BuildInfo{}, false},
		{"missing-build-info", "go1.26.10", 64, nil, false},
		{"green-tea-experiment", "go1.26.10", 64, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "greenteagc"}}}, false},
		{"non-green-tea-experiment", "go1.26.10", 64, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOEXPERIMENT", Value: "nogreenteagc"}}}, false},
		{"experiment-after-other-settings", "go1.26.10", 64, &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}, {Key: "GOEXPERIMENT", Value: "jsonv2"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := htmlAuthoringInputRuntimeSupportedV1(tc.version, tc.bits, tc.info); got != tc.want {
				t.Fatalf("model supported=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestHTMLAuthoringInputEffectiveQualifiedRuntimeCanAdmitResourcesV1(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok || !htmlAuthoringInputRuntimeSupportedV1(runtime.Version(), strconv.IntSize, info) || !htmlAuthoringInputRuntimeOKV1 {
		t.Fatalf("test binary lacks the reviewed default 64-bit Go runtime model: %s", runtime.Version())
	}
	for _, limit := range []int64{1, 8191, 8192, 8193, 1 << 20} {
		n, err := htmlAuthoringInputReadResourcesV1(limit)
		if err != nil || n <= limit {
			t.Fatalf("qualified runtime read limit %d: resources=%d, err=%v", limit, n, err)
		}
	}
}
