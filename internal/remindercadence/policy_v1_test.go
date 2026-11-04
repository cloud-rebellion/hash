// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package remindercadence

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestFinitePolicy121PreservesLegacyAndExplicitIntervalV1(t *testing.T) {
	legacy := LegacyPolicyV1()
	offsets, err := legacy.OffsetsV1()
	if err != nil || !reflect.DeepEqual(offsets, []int{3, 7}) {
		t.Fatalf("legacy schedule changed: %v %v", offsets, err)
	}
	offsets[0] = 99
	again, _ := legacy.OffsetsV1()
	if again[0] != 3 {
		t.Fatal("caller mutated another policy result")
	}
	custom := PolicyV1{Mode: "interval", IntervalDays: 3, MaxFires: 2}
	offsets, err = custom.OffsetsV1()
	if err != nil || !reflect.DeepEqual(offsets, []int{3, 6}) {
		t.Fatalf("explicit interval not honored: %v %v", offsets, err)
	}
	raw, err := custom.ScheduleV1()
	if err != nil || !bytes.Equal(raw, []byte("[{\"days_after_send\":3},{\"days_after_send\":6}]")) {
		t.Fatalf("canonical schedule: %q %v", raw, err)
	}
	sent := time.Date(2026, 3, 28, 18, 0, 0, 0, time.FixedZone("fixture", 3600))
	first, enabled, err := custom.FirstFireV1(sent)
	if err != nil || !enabled || !first.Equal(sent.Add(72*time.Hour)) {
		t.Fatalf("first fire is not send relative: %v %v %v", first, enabled, err)
	}
	delay, err := custom.ManualDelayDaysV1()
	if err != nil || delay != 3 {
		t.Fatal("manual delay drift")
	}
}

func TestFinitePolicy121DisabledAndRefusalsV1(t *testing.T) {
	disabled := PolicyV1{Mode: "disabled"}
	raw, err := disabled.ScheduleV1()
	if err != nil || string(raw) != "[]" {
		t.Fatal("disabled policy constructed reminders")
	}
	if _, enabled, err := disabled.FirstFireV1(time.Now()); err != nil || enabled {
		t.Fatal("disabled policy has a first fire")
	}
	for _, p := range []PolicyV1{
		{}, {Mode: "inherit"}, {Mode: "future"}, {Mode: "legacy"},
		{Mode: "legacy", IntervalDays: 3, MaxFires: 2},
		{Mode: "disabled", MaxFires: 1},
		{Mode: "interval", IntervalDays: 0, MaxFires: 1},
		{Mode: "interval", IntervalDays: -1, MaxFires: 1},
		{Mode: "interval", IntervalDays: 1, MaxFires: 0},
		{Mode: "interval", IntervalDays: 366, MaxFires: 1},
		{Mode: "interval", IntervalDays: 3, MaxFires: 122},
		{Mode: "interval", IntervalDays: int(^uint(0) >> 1), MaxFires: int(^uint(0) >> 1)},
	} {
		if p.ValidateV1() == nil {
			t.Fatalf("malformed policy became legacy/valid: %+v", p)
		}
	}
	max := PolicyV1{Mode: "interval", IntervalDays: 1, MaxFires: 365}
	if offsets, err := max.OffsetsV1(); err != nil || len(offsets) != 365 || offsets[364] != 365 {
		t.Fatal("finite reviewed boundary refused")
	}
}
