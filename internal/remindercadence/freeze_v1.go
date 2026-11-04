// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package remindercadence

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Resolve/Freeze operate on a caller-owned, root-locked same transaction. They
// grant no SQL/body authority. Native producers must admit scalar controls
// before calling, then admit the resolved schedule before its allocation.
type FrozenV1 struct {
	Policy                             PolicyV1
	Source                             string
	TemplateRevision, DocumentRevision int64
}

func finiteStampV1(t pgtype.Timestamptz) bool {
	return t.Valid && t.InfinityModifier == pgtype.Finite && !t.Time.IsZero()
}
func ResolveV1(ctx context.Context, q *generated.Queries, doc *generated.Document) (out FrozenV1, err error) {
	if q == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.SenderID == uuid.Nil {
		return out, ErrPolicyV1
	}
	out = FrozenV1{Policy: LegacyPolicyV1(), Source: "legacy"}
	override, err := q.GetDocumentReminderPolicyV1(ctx, generated.GetDocumentReminderPolicyV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return out, err
	}
	if err == nil {
		if override == nil || override.SenderUserID != doc.SenderID || override.Revision < 1 || !finiteStampV1(override.UpdatedAt) {
			return out, ErrPolicyV1
		}
		out.DocumentRevision = override.Revision
		p := PolicyV1{Mode: override.Mode, IntervalDays: int(override.IntervalDays), MaxFires: int(override.MaxFires)}
		if p.Mode != "inherit" {
			if p.ValidateV1() != nil {
				return out, ErrPolicyV1
			}
			out.Policy = p
			out.Source = "document"
			return out, nil
		}
		if p.IntervalDays != 0 || p.MaxFires != 0 {
			return out, ErrPolicyV1
		}
	}
	if !doc.TemplateID.Valid {
		return out, nil
	}
	tid := uuid.UUID(doc.TemplateID.Bytes)
	source, err := q.LockTemplateReminderSourceV1(ctx, generated.LockTemplateReminderSourceV1Params{TemplateID: tid, OrgID: doc.OrgID})
	if err != nil {
		return out, err
	}
	if source == nil || source.ID != tid || source.OrgID != doc.OrgID {
		return out, ErrPolicyV1
	}
	row, err := q.GetTemplateReminderPolicyV1(ctx, generated.GetTemplateReminderPolicyV1Params{TemplateID: tid, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if row == nil || row.Revision < 1 || !finiteStampV1(row.UpdatedAt) {
		return out, ErrPolicyV1
	}
	out.Policy = PolicyV1{Mode: row.Mode, IntervalDays: int(row.IntervalDays), MaxFires: int(row.MaxFires)}
	if out.Policy.ValidateV1() != nil {
		return out, ErrPolicyV1
	}
	out.Source = "template"
	out.TemplateRevision = row.Revision
	return out, nil
}
func snapshotV1(row *generated.GetReminderPolicySnapshotV1Row, doc *generated.Document) (FrozenV1, error) {
	if row == nil || row.SenderUserID != doc.SenderID || !finiteStampV1(row.CreatedAt) || row.TemplatePolicyRevision < 0 || row.DocumentPolicyRevision < 0 {
		return FrozenV1{}, ErrPolicyV1
	}
	out := FrozenV1{Policy: PolicyV1{Mode: row.Mode, IntervalDays: int(row.IntervalDays), MaxFires: int(row.MaxFires)}, Source: row.Source, TemplateRevision: row.TemplatePolicyRevision, DocumentRevision: row.DocumentPolicyRevision}
	if out.Policy.ValidateV1() != nil {
		return FrozenV1{}, ErrPolicyV1
	}
	switch out.Source {
	case "legacy":
		if out.TemplateRevision != 0 || out.Policy != LegacyPolicyV1() {
			return FrozenV1{}, ErrPolicyV1
		}
	case "template":
		if out.TemplateRevision < 1 {
			return FrozenV1{}, ErrPolicyV1
		}
	case "document":
		if out.DocumentRevision < 1 || out.TemplateRevision != 0 {
			return FrozenV1{}, ErrPolicyV1
		}
	default:
		return FrozenV1{}, ErrPolicyV1
	}
	return out, nil
}

// FreezeAndInstallV1 is called only after genuine fresh completion produces
// sent_at. An existing snapshot is a replay, never permission to refill a
// reminder or rewrite an in-flight schedule from a mutable template/default.
func FreezeAndInstallV1(ctx context.Context, q *generated.Queries, doc *generated.Document, admitSchedule func(PolicyV1) error) (FrozenV1, error) {
	if q == nil || doc == nil || doc.Status != "sent" || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.SenderID == uuid.Nil || !finiteStampV1(doc.SentAt) || admitSchedule == nil {
		return FrozenV1{}, ErrPolicyV1
	}
	args := generated.GetReminderPolicySnapshotV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, SentAt: doc.SentAt}
	existing, err := q.GetReminderPolicySnapshotV1(ctx, args)
	if err == nil {
		return snapshotV1(existing, doc)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return FrozenV1{}, err
	}
	frozen, err := ResolveV1(ctx, q, doc)
	if err != nil {
		return FrozenV1{}, err
	}
	if err = admitSchedule(frozen.Policy); err != nil {
		return FrozenV1{}, err
	}
	id, err := q.InsertReminderPolicySnapshotV1(ctx, generated.InsertReminderPolicySnapshotV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, SenderUserID: doc.SenderID, SentAt: doc.SentAt, Source: frozen.Source, TemplatePolicyRevision: frozen.TemplateRevision, DocumentPolicyRevision: frozen.DocumentRevision, Mode: frozen.Policy.Mode, IntervalDays: int32(frozen.Policy.IntervalDays), MaxFires: int32(frozen.Policy.MaxFires)})
	if errors.Is(err, pgx.ErrNoRows) {
		row, e := q.GetReminderPolicySnapshotV1(ctx, args)
		if e != nil {
			return FrozenV1{}, e
		}
		return snapshotV1(row, doc)
	}
	if err != nil {
		return FrozenV1{}, err
	}
	if id != doc.ID {
		return FrozenV1{}, ErrPolicyV1
	}
	if frozen.Policy.Mode == "disabled" {
		return frozen, q.CancelReminder(ctx, doc.ID)
	}
	schedule, err := frozen.Policy.ScheduleV1()
	if err != nil {
		return FrozenV1{}, err
	}
	row, err := q.InstallFrozenReminderScheduleV1(ctx, generated.InstallFrozenReminderScheduleV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, ScheduleJson: schedule})
	if err != nil {
		return FrozenV1{}, err
	}
	first, ok, err := frozen.Policy.FirstFireV1(doc.SentAt.Time)
	if err != nil || !ok || row == nil || row.DocumentID != doc.ID || int(row.FiresRemaining) != frozen.Policy.MaxFires || !finiteStampV1(row.NextFireAt) || !row.NextFireAt.Time.Equal(first) {
		return FrozenV1{}, ErrPolicyV1
	}
	return frozen, nil
}
