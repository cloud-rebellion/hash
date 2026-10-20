// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"testing"
)

func TestPackageSendObservationRejectsAmbiguousClockAndGenerationV1(t *testing.T) {
	valid := packageSendInputV1{ExpectedUpdatedAt: "2026-10-19T12:03:04.123456Z", PackageID: "4e972fb2-ae22-4c84-a52d-93d66507b080", Generation: "9007199254740993"}
	got, err := valid.observationV1()
	if err != nil || !got.ValidV1() || got.Generation != 9007199254740993 {
		t.Fatal("exact decimal selection was rounded", got, err)
	}
	for _, mutate := range []func(*packageSendInputV1){
		func(v *packageSendInputV1) { v.ExpectedUpdatedAt = "2026-10-19T12:03:04.1234567Z" },
		func(v *packageSendInputV1) { v.ExpectedUpdatedAt = "2026-10-19T12:03:04+00:00" },
		func(v *packageSendInputV1) { v.ExpectedUpdatedAt = "2026-02-30T12:03:04Z" },
		func(v *packageSendInputV1) { v.PackageID = "00000000-0000-0000-0000-000000000000" },
		func(v *packageSendInputV1) { v.PackageID = "4E972FB2-AE22-4C84-A52D-93D66507B080" },
		func(v *packageSendInputV1) { v.Generation = "01" }, func(v *packageSendInputV1) { v.Generation = "+1" },
		func(v *packageSendInputV1) { v.Generation = "9223372036854775807" }, func(v *packageSendInputV1) { v.Generation = "0" },
	} {
		v := valid
		mutate(&v)
		if out, err := v.observationV1(); err == nil || out.PresentV1() {
			t.Fatal("ambiguous selection accepted", v, out, err)
		}
	}
	var absent *packageSendInputV1
	if out, err := absent.observationV1(); err != nil || out.PresentV1() {
		t.Fatal("ordinary omission changed", out, err)
	}
}

func TestAutomationSignatureInputRefusesPackageSendV1(t *testing.T) {
	var target automationSignatureRequestInput
	for _, raw := range []string{`{"package_send":{"expected_updated_at":"2026-10-19T12:03:04Z","package_id":"4e972fb2-ae22-4c84-a52d-93d66507b080","generation":"7"}}`, `{"attachments":[]}`} {
		if err := decodeAutomationSignatureRequestRawV1([]byte(raw), &target); err == nil {
			t.Fatal("blocks-only automation silently accepted package input")
		}
	}
}
