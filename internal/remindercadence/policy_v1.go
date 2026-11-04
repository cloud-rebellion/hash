// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package remindercadence

import (
	"bytes"
	"encoding/json"
	"errors"
	"time"
)

// PolicyV1 is a finite saved policy, never SQL/resource authority. Absence is
// resolved explicitly by its locked source owner; malformed input is not legacy.
type PolicyV1 struct {
	Mode         string `json:"mode"`
	IntervalDays int    `json:"interval_days"`
	MaxFires     int    `json:"max_fires"`
}

var ErrPolicyV1 = errors.New("invalid finite reminder policy")

func LegacyPolicyV1() PolicyV1 { return PolicyV1{Mode: "legacy", MaxFires: 2} }

func (p PolicyV1) ValidateV1() error {
	switch p.Mode {
	case "legacy":
		if p.IntervalDays == 0 && p.MaxFires == 2 {
			return nil
		}
	case "disabled":
		if p.IntervalDays == 0 && p.MaxFires == 0 {
			return nil
		}
	case "interval":
		// Divide before multiplying, so hostile machine-sized integers cannot
		// overflow into an apparently short schedule.
		if p.IntervalDays >= 1 && p.IntervalDays <= 365 &&
			p.MaxFires >= 1 && p.MaxFires <= 365/p.IntervalDays {
			return nil
		}
	}
	return ErrPolicyV1
}

func (p PolicyV1) OffsetsV1() ([]int, error) {
	if err := p.ValidateV1(); err != nil {
		return nil, err
	}
	switch p.Mode {
	case "legacy":
		return []int{3, 7}, nil
	case "disabled":
		return []int{}, nil
	default:
		out := make([]int, p.MaxFires)
		for i := range out {
			out[i] = (i + 1) * p.IntervalDays
		}
		return out, nil
	}
}

func (p PolicyV1) ScheduleV1() ([]byte, error) {
	offsets, err := p.OffsetsV1()
	if err != nil {
		return nil, err
	}
	type entry struct {
		Days int `json:"days_after_send"`
	}
	schedule := make([]entry, len(offsets))
	for i, days := range offsets {
		schedule[i].Days = days
	}
	return json.Marshal(schedule)
}

func (p PolicyV1) ManualDelayDaysV1() (int, error) {
	if err := p.ValidateV1(); err != nil {
		return 0, err
	}
	if p.Mode == "legacy" {
		return 3, nil
	}
	return p.IntervalDays, nil
}

func (p PolicyV1) FirstFireV1(sentAt time.Time) (time.Time, bool, error) {
	offsets, err := p.OffsetsV1()
	if err != nil || sentAt.IsZero() {
		return time.Time{}, false, ErrPolicyV1
	}
	if len(offsets) == 0 {
		return time.Time{}, false, nil
	}
	return sentAt.UTC().Add(time.Duration(offsets[0]) * 24 * time.Hour), true, nil
}

// A frozen schedule is the exact finite saved policy, independent of JSONB
// whitespace. A duplicate/extra key or altered offset is not the same schedule.
func (p PolicyV1) ScheduleMatchesV1(raw []byte, remaining int) bool {
	if p.ValidateV1() != nil || p.Mode == "disabled" || remaining <= 0 || remaining > p.MaxFires {
		return false
	}
	want, err := p.ScheduleV1()
	if err != nil {
		return false
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return false
	}
	return bytes.Equal(compact.Bytes(), want)
}
