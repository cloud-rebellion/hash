// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package remindercadence

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type policyRow121 struct {
	v   []any
	err error
}

func (r policyRow121) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != len(r.v) {
		return errors.New("fixture row arity")
	}
	for i, d := range dest {
		reflect.ValueOf(d).Elem().Set(reflect.ValueOf(r.v[i]))
	}
	return nil
}

type policyDB121 struct {
	doc                            *generated.Document
	override, template             *PolicyV1
	replay                         bool
	calls                          []string
	inserted, installed, cancelled int
	schedule                       []byte
	badReturn, conflict            bool
}

func (d *policyDB121) Exec(_ context.Context, s string, _ ...any) (pgconn.CommandTag, error) {
	if !strings.Contains(s, "CancelReminder") {
		return pgconn.CommandTag{}, errors.New("unexpected exec")
	}
	d.cancelled++
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (d *policyDB121) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected rowset")
}
func (d *policyDB121) QueryRow(_ context.Context, s string, args ...any) pgx.Row {
	op := strings.Fields(s)[2]
	d.calls = append(d.calls, op)
	stamp := pgtype.Timestamptz{Time: d.doc.SentAt.Time, Valid: true}
	switch op {
	case "GetReminderPolicySnapshotV1":
		if !d.replay {
			return policyRow121{err: pgx.ErrNoRows}
		}
		return policyRow121{v: []any{d.doc.SenderID, "document", int64(0), int64(7), "interval", int32(5), int32(2), stamp}}
	case "GetDocumentReminderPolicyV1":
		if d.override == nil {
			return policyRow121{err: pgx.ErrNoRows}
		}
		p := d.override
		return policyRow121{v: []any{d.doc.SenderID, int64(7), p.Mode, int32(p.IntervalDays), int32(p.MaxFires), stamp}}
	case "LockTemplateReminderSourceV1":
		return policyRow121{v: []any{uuid.UUID(d.doc.TemplateID.Bytes), d.doc.OrgID}}
	case "GetTemplateReminderPolicyV1":
		if d.template == nil {
			return policyRow121{err: pgx.ErrNoRows}
		}
		p := d.template
		return policyRow121{v: []any{int64(3), p.Mode, int32(p.IntervalDays), int32(p.MaxFires), stamp}}
	case "InsertReminderPolicySnapshotV1":
		d.inserted++
		if d.conflict {
			d.replay = true
			return policyRow121{err: pgx.ErrNoRows}
		}
		return policyRow121{v: []any{d.doc.ID}}
	case "InstallFrozenReminderScheduleV1":
		d.installed++
		d.schedule = append([]byte(nil), args[0].(json.RawMessage)...)
		p := LegacyPolicyV1()
		if d.override != nil && d.override.Mode != "inherit" {
			p = *d.override
		} else if d.template != nil {
			p = *d.template
		}
		first, _, _ := p.FirstFireV1(d.doc.SentAt.Time)
		if d.badReturn {
			first = first.Add(time.Second)
		}
		return policyRow121{v: []any{d.doc.ID, pgtype.Timestamptz{Time: first, Valid: true}, int32(p.MaxFires)}}
	}
	return policyRow121{err: errors.New("unexpected query " + op)}
}
func fixturePolicy121() *policyDB121 {
	return &policyDB121{doc: &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SenderID: uuid.New(), Status: "sent", SentAt: pgtype.Timestamptz{Time: time.Date(2030, 3, 29, 12, 0, 0, 0, time.UTC), Valid: true}}}
}
func TestReminder121FreezeActualQueriesSourceAndFirstFire(t *testing.T) {
	for _, tc := range []struct {
		name          string
		doc, template *PolicyV1
		source        string
		want          PolicyV1
	}{
		{name: "absent-keeps-legacy", source: "legacy", want: LegacyPolicyV1()},
		{name: "template-inherited", doc: &PolicyV1{Mode: "inherit"}, template: &PolicyV1{Mode: "interval", IntervalDays: 4, MaxFires: 3}, source: "template", want: PolicyV1{Mode: "interval", IntervalDays: 4, MaxFires: 3}},
		{name: "document-overrides-template", doc: &PolicyV1{Mode: "interval", IntervalDays: 2, MaxFires: 4}, template: &PolicyV1{Mode: "interval", IntervalDays: 7, MaxFires: 2}, source: "document", want: PolicyV1{Mode: "interval", IntervalDays: 2, MaxFires: 4}},
		{name: "explicit-disabled", doc: &PolicyV1{Mode: "disabled"}, source: "document", want: PolicyV1{Mode: "disabled"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fixturePolicy121()
			d.override = tc.doc
			d.template = tc.template
			if tc.template != nil {
				d.doc.TemplateID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			}
			admitted := false
			frozen, err := FreezeAndInstallV1(context.Background(), generated.New(d), d.doc, func(p PolicyV1) error {
				if d.inserted != 0 || p != tc.want {
					t.Fatal("policy output not admitted before first write", p)
				}
				admitted = true
				return nil
			})
			if err != nil || frozen.Source != tc.source || frozen.Policy != tc.want || !admitted || d.inserted != 1 {
				t.Fatal(frozen, err, d.calls)
			}
			if tc.want.Mode == "disabled" {
				if d.cancelled != 1 || d.installed != 0 {
					t.Fatal("disabled policy installed/replenished schedule")
				}
			} else {
				if d.installed != 1 || !tc.want.ScheduleMatchesV1(d.schedule, tc.want.MaxFires) {
					t.Fatal("schedule/count mismatch", string(d.schedule))
				}
			}
		})
	}
}
func TestReminder121ReplayAndConflictingSnapshotNeverRefill(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		d := fixturePolicy121()
		d.replay = !conflict
		d.conflict = conflict
		calls := 0
		out, err := FreezeAndInstallV1(context.Background(), generated.New(d), d.doc, func(PolicyV1) error { calls++; return nil })
		if err != nil || out.Policy.IntervalDays != 5 || d.installed != 0 || d.cancelled != 0 {
			t.Fatal(out, err)
		}
		if !conflict && calls != 0 {
			t.Fatal("replay selected mutable policy/allocated schedule")
		}
	}
}
func TestReminder121AdmissionAndCorruptReturnsRefuse(t *testing.T) {
	d := fixturePolicy121()
	denied := errors.New("actual owned capacity unavailable")
	_, err := FreezeAndInstallV1(context.Background(), generated.New(d), d.doc, func(PolicyV1) error { return denied })
	if !errors.Is(err, denied) || d.inserted != 0 || d.installed != 0 {
		t.Fatal("admission failure had effects", err)
	}
	d = fixturePolicy121()
	d.badReturn = true
	if _, err = FreezeAndInstallV1(context.Background(), generated.New(d), d.doc, func(PolicyV1) error { return nil }); err == nil {
		t.Fatal("changed physical first fire accepted")
	}
	for _, policy := range []PolicyV1{{Mode: "future"}, {Mode: "interval", IntervalDays: 366, MaxFires: 1}, {Mode: "inherit", IntervalDays: 1}} {
		d = fixturePolicy121()
		d.override = &policy
		if _, err = FreezeAndInstallV1(context.Background(), generated.New(d), d.doc, func(PolicyV1) error { return nil }); err == nil || d.inserted != 0 {
			t.Fatal("invalid stored source wrote snapshot", policy, err)
		}
	}
}
func TestReminder121FrozenScheduleCannotChangeOffsetsCountOrKeys(t *testing.T) {
	p := PolicyV1{Mode: "interval", IntervalDays: 4, MaxFires: 2}
	for _, raw := range []string{`[{"days_after_send":4},{"days_after_send":9}]`, `[{"days_after_send":4},{"days_after_send":8},{"days_after_send":12}]`, `[{"days_after_send":4,"unknown":1},{"days_after_send":8}]`, `[{"days_after_send":0,"days_after_send":4},{"days_after_send":8}]`} {
		if p.ScheduleMatchesV1([]byte(raw), 2) {
			t.Fatal("changed frozen schedule accepted", raw)
		}
	}
	if p.ScheduleMatchesV1([]byte(`[{"days_after_send":4},{"days_after_send":8}]`), 3) {
		t.Fatal("remaining exceeds frozen policy")
	}
	if !p.ScheduleMatchesV1([]byte(`[ { "days_after_send" : 4 }, { "days_after_send" : 8 } ]`), 1) {
		t.Fatal("native JSONB whitespace refused")
	}
}
