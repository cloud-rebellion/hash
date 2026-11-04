// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package send

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/remindercadence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrAutomationInputV1       = errors.New("invalid automation settings")
	ErrAutomationStaleV1       = errors.New("automation revision changed")
	ErrAutomationObservationV1 = errors.New("document observation changed")
	ErrAutomationNotFoundV1    = errors.New("automation target not found")
	ErrAutomationNotEditableV1 = errors.New("automation target is not editable")
	ErrAutomationUnavailableV1 = errors.New("automation settings unavailable")
)

type AutomationPreferencesV1 struct {
	SchemaVersion int        `json:"schema_version"`
	Revision      int64      `json:"revision"`
	NotifyViewed  bool       `json:"notify_viewed"`
	NotifySigned  bool       `json:"notify_signed"`
	ViewedScope   string     `json:"viewed_scope"`
	UpdatedAt     *time.Time `json:"updated_at"`
}
type AutomationPreferencesInputV1 struct {
	ExpectedRevision           int64
	NotifyViewed, NotifySigned bool
}
type ReminderPolicyViewV1 struct {
	remindercadence.PolicyV1
	OffsetsDays []int `json:"offsets_days"`
}
type ReminderPolicyInputV1 struct {
	ExpectedRevision  int64
	ExpectedUpdatedAt time.Time
	remindercadence.PolicyV1
}
type TemplateReminderPolicyV1 struct {
	SchemaVersion int                  `json:"schema_version"`
	TemplateID    uuid.UUID            `json:"template_id"`
	Revision      int64                `json:"revision"`
	Policy        ReminderPolicyViewV1 `json:"policy"`
	UpdatedAt     *time.Time           `json:"updated_at"`
}
type DocumentReminderPolicyV1 struct {
	SchemaVersion   int                  `json:"schema_version"`
	DocumentID      uuid.UUID            `json:"document_id"`
	Revision        int64                `json:"revision"`
	UpdatedAt       time.Time            `json:"updated_at"`
	Selection       ReminderPolicyViewV1 `json:"selection"`
	EffectivePolicy ReminderPolicyViewV1 `json:"effective_policy"`
	Source          string               `json:"source"`
	Editable        bool                 `json:"editable"`
	Frozen          bool                 `json:"frozen"`
}

func automationPolicyViewV1(p remindercadence.PolicyV1) (ReminderPolicyViewV1, error) {
	if p.Mode == "inherit" && p.IntervalDays == 0 && p.MaxFires == 0 {
		return ReminderPolicyViewV1{p, []int{}}, nil
	}
	offsets, err := p.OffsetsV1()
	return ReminderPolicyViewV1{p, offsets}, err
}
func automationRevisionV1(n int64) bool { return n >= 0 && n < math.MaxInt64 }
func automationTimestampV1(t pgtype.Timestamptz) bool {
	return t.Valid && t.InfinityModifier == pgtype.Finite && !t.Time.IsZero()
}
func automationTimePtrV1(t pgtype.Timestamptz) *time.Time {
	if !automationTimestampV1(t) {
		return nil
	}
	v := t.Time.UTC()
	return &v
}
func automationPolicyRowV1(mode string, days, count int32) (remindercadence.PolicyV1, error) {
	p := remindercadence.PolicyV1{Mode: mode, IntervalDays: int(days), MaxFires: int(count)}
	if p.ValidateV1() != nil {
		return p, ErrAutomationUnavailableV1
	}
	return p, nil
}

// Every operation is one bounded transaction with the original live staff
// credential retained through the final audit wait. Cleanup uncertainty cannot
// become success, a stale response or a not-found result.
func (e *Engine) automationTxV1(ctx context.Context, actor authoring.Actor, fn func(context.Context, pgx.Tx) error) (failure error) {
	if e == nil || e.Pool == nil || e.Audit == nil {
		return ErrAutomationUnavailableV1
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := e.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return errors.Join(ErrAutomationUnavailableV1, err)
	}
	defer func() {
		if err := authoring.Rollback(ctx, tx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			failure = errors.Join(ErrAutomationUnavailableV1, failure, err)
		}
	}()
	if err = fn(ctx, tx); err != nil {
		return err
	}
	if err = tx.Commit(ctx); err != nil {
		return errors.Join(ErrAutomationUnavailableV1, err)
	}
	return nil
}
func (e *Engine) AutomationPreferencesV1(ctx context.Context, actor authoring.Actor, in *AutomationPreferencesInputV1) (out AutomationPreferencesV1, failure error) {
	if in != nil && !automationRevisionV1(in.ExpectedRevision) {
		return out, ErrAutomationInputV1
	}
	var pending audit.PendingEvent
	failure = e.automationTxV1(ctx, actor, func(ctx context.Context, tx pgx.Tx) error {
		guard, err := authoring.LockAuthor(ctx, tx, actor)
		if err != nil {
			return err
		}
		q := generated.New(tx)
		out = AutomationPreferencesV1{SchemaVersion: 1, ViewedScope: "first_view_per_recipient_per_send"}
		if in == nil {
			row, err := q.GetOwnSenderAutomationPreferenceV1(ctx, generated.GetOwnSenderAutomationPreferenceV1Params{OrgID: actor.OrgID, SenderUserID: actor.UserID})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if row == nil || row.Revision < 1 || !automationTimestampV1(row.UpdatedAt) {
					return ErrAutomationUnavailableV1
				}
				out.Revision = row.Revision
				out.NotifyViewed = row.NotifyViewed
				out.NotifySigned = row.NotifySigned
				out.UpdatedAt = automationTimePtrV1(row.UpdatedAt)
			}
		} else {
			// No SHARE->UPDATE upgrade on this optional row: the single closed CAS
			// statement serializes concurrent writers and handles the absent-row race.
			row, err := q.SaveOwnSenderAutomationPreferenceV1(ctx, generated.SaveOwnSenderAutomationPreferenceV1Params{OrgID: actor.OrgID, SenderUserID: actor.UserID, ExpectedRevision: in.ExpectedRevision, NotifyViewed: in.NotifyViewed, NotifySigned: in.NotifySigned})
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAutomationStaleV1
			}
			if err != nil {
				return err
			}
			if row == nil || row.Revision != in.ExpectedRevision+1 || row.NotifyViewed != in.NotifyViewed || row.NotifySigned != in.NotifySigned || !automationTimestampV1(row.UpdatedAt) {
				return ErrAutomationUnavailableV1
			}
			out.Revision = row.Revision
			out.NotifyViewed = row.NotifyViewed
			out.NotifySigned = row.NotifySigned
			out.UpdatedAt = automationTimePtrV1(row.UpdatedAt)
			pending, err = e.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: "sender_automation_preferences.updated", Payload: map[string]any{"revision": row.Revision, "notify_viewed": row.NotifyViewed, "notify_signed": row.NotifySigned}})
			if err != nil {
				return err
			}
		}
		return guard.Recheck(ctx)
	})
	if failure != nil {
		return AutomationPreferencesV1{}, failure
	}
	if in != nil {
		e.Audit.Publish(pending)
	}
	return
}
func (e *Engine) TemplateReminderPolicyV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, in *ReminderPolicyInputV1) (out TemplateReminderPolicyV1, failure error) {
	if id == uuid.Nil || (in != nil && (!automationRevisionV1(in.ExpectedRevision) || in.PolicyV1.ValidateV1() != nil)) {
		return out, ErrAutomationInputV1
	}
	var pending audit.PendingEvent
	failure = e.automationTxV1(ctx, actor, func(ctx context.Context, tx pgx.Tx) error {
		q := generated.New(tx)
		target, err := q.GetTemplateReminderTargetForUpdateV1(ctx, generated.GetTemplateReminderTargetForUpdateV1Params{TemplateID: id, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAutomationNotFoundV1
		}
		if err != nil {
			return err
		}
		if target == nil || target.ID != id || target.OrgID != actor.OrgID {
			return ErrAutomationUnavailableV1
		}
		guard, err := authoring.LockAuthor(ctx, tx, actor)
		if err != nil {
			return err
		}
		out = TemplateReminderPolicyV1{SchemaVersion: 1, TemplateID: id}
		policy := remindercadence.LegacyPolicyV1()
		if in == nil {
			row, err := q.GetTemplateReminderPolicyV1(ctx, generated.GetTemplateReminderPolicyV1Params{TemplateID: id, OrgID: actor.OrgID})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if row == nil || row.Revision < 1 || !automationTimestampV1(row.UpdatedAt) {
					return ErrAutomationUnavailableV1
				}
				policy, err = automationPolicyRowV1(row.Mode, row.IntervalDays, row.MaxFires)
				if err != nil {
					return err
				}
				out.Revision = row.Revision
				out.UpdatedAt = automationTimePtrV1(row.UpdatedAt)
			}
		} else {
			row, err := q.SaveTemplateReminderPolicyV1(ctx, generated.SaveTemplateReminderPolicyV1Params{TemplateID: id, OrgID: actor.OrgID, UpdatedBy: actor.UserID, ExpectedRevision: in.ExpectedRevision, Mode: in.Mode, IntervalDays: int32(in.IntervalDays), MaxFires: int32(in.MaxFires)})
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAutomationStaleV1
			}
			if err != nil {
				return err
			}
			if row == nil || row.Revision != in.ExpectedRevision+1 || row.Mode != in.Mode || int(row.IntervalDays) != in.IntervalDays || int(row.MaxFires) != in.MaxFires || !automationTimestampV1(row.UpdatedAt) {
				return ErrAutomationUnavailableV1
			}
			policy = in.PolicyV1
			out.Revision = row.Revision
			out.UpdatedAt = automationTimePtrV1(row.UpdatedAt)
			pending, err = e.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: "template_reminder_policy.updated", Payload: map[string]any{"template_id": id.String(), "revision": row.Revision, "mode": policy.Mode, "interval_days": policy.IntervalDays, "max_fires": policy.MaxFires}})
			if err != nil {
				return err
			}
		}
		out.Policy, err = automationPolicyViewV1(policy)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if failure != nil {
		return TemplateReminderPolicyV1{}, failure
	}
	if in != nil {
		e.Audit.Publish(pending)
	}
	return
}
func automationDocumentSigningV1(row *generated.GetDocumentReminderTargetForUpdateV1Row) bool {
	if row == nil || !row.MetadataObject {
		return false
	}
	if !row.PurposeSet {
		return true
	}
	if len(row.ReservedPurpose) == 0 || len(row.ReservedPurpose) > 256 {
		return false
	}
	raw := make([]byte, 0, len(row.ReservedPurpose)+40)
	raw = append(raw, []byte(`{"hash:document-purpose:v1":`)...)
	raw = append(raw, row.ReservedPurpose...)
	raw = append(raw, '}')
	purpose, err := documentpurpose.Parse(raw)
	return err == nil && purpose == documentpurpose.Signing
}
func automationDocumentEditableV1(ctx context.Context, q *generated.Queries, row *generated.GetDocumentReminderTargetForUpdateV1Row) (bool, error) {
	if row.Status != "draft" || row.ParentEnvelopeID.Valid || !automationDocumentSigningV1(row) {
		return false, nil
	}
	retained, err := q.HasRetainedDraftSigningEvidence(ctx, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: row.ID, OrgID: row.OrgID})
	if err != nil || retained {
		return false, err
	}
	fence, err := q.TryCollabArchivePrivacyFence(ctx, row.OrgID)
	if err != nil || !fence {
		return false, err
	}
	pending, err := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: row.ID, OrgID: row.OrgID})
	return !pending, err
}
func (e *Engine) DocumentReminderPolicyV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, in *ReminderPolicyInputV1) (out DocumentReminderPolicyV1, failure error) {
	validSelection := func(p remindercadence.PolicyV1) bool {
		return p.ValidateV1() == nil || (p.Mode == "inherit" && p.IntervalDays == 0 && p.MaxFires == 0)
	}
	if id == uuid.Nil || (in != nil && (!automationRevisionV1(in.ExpectedRevision) || in.ExpectedUpdatedAt.IsZero() || !validSelection(in.PolicyV1))) {
		return out, ErrAutomationInputV1
	}
	var pending audit.PendingEvent
	failure = e.automationTxV1(ctx, actor, func(ctx context.Context, tx pgx.Tx) error {
		q := generated.New(tx)
		row, err := q.GetDocumentReminderTargetForUpdateV1(ctx, generated.GetDocumentReminderTargetForUpdateV1Params{DocumentID: id, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAutomationNotFoundV1
		}
		if err != nil {
			return err
		}
		if row == nil || row.ID != id || row.OrgID != actor.OrgID || row.SenderID != actor.UserID || row.ParentEnvelopeID.Valid {
			return ErrAutomationNotFoundV1
		}
		if !automationTimestampV1(row.UpdatedAt) {
			return ErrAutomationUnavailableV1
		}
		guard, err := authoring.LockAuthor(ctx, tx, actor)
		if err != nil {
			return err
		}
		editable, err := automationDocumentEditableV1(ctx, q, row)
		if err != nil {
			return err
		}
		if in != nil {
			if !editable {
				return ErrAutomationNotEditableV1
			}
			if !row.UpdatedAt.Time.Equal(in.ExpectedUpdatedAt) {
				return ErrAutomationObservationV1
			}
			saved, err := q.SaveDocumentReminderPolicyV1(ctx, generated.SaveDocumentReminderPolicyV1Params{DocumentID: id, OrgID: actor.OrgID, SenderUserID: actor.UserID, ExpectedRevision: in.ExpectedRevision, Mode: in.Mode, IntervalDays: int32(in.IntervalDays), MaxFires: int32(in.MaxFires)})
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAutomationStaleV1
			}
			if err != nil {
				return err
			}
			if saved == nil || saved.Revision != in.ExpectedRevision+1 || saved.Mode != in.Mode || int(saved.IntervalDays) != in.IntervalDays || int(saved.MaxFires) != in.MaxFires || !automationTimestampV1(saved.UpdatedAt) {
				return ErrAutomationUnavailableV1
			}
			pending, err = e.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, DocumentID: &id, ActorUserID: &actor.UserID, Kind: "document_reminder_policy.updated", Payload: map[string]any{"revision": saved.Revision, "mode": in.Mode, "interval_days": in.IntervalDays, "max_fires": in.MaxFires}})
			if err != nil {
				return err
			}
		}
		out = DocumentReminderPolicyV1{SchemaVersion: 1, DocumentID: id, UpdatedAt: row.UpdatedAt.Time.UTC(), Editable: editable}
		selection := remindercadence.PolicyV1{Mode: "inherit"}
		p, err := q.GetDocumentReminderPolicyV1(ctx, generated.GetDocumentReminderPolicyV1Params{DocumentID: id, OrgID: actor.OrgID})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if err == nil {
			if p == nil || p.SenderUserID != row.SenderID || p.Revision < 1 || !automationTimestampV1(p.UpdatedAt) {
				return ErrAutomationUnavailableV1
			}
			selection = remindercadence.PolicyV1{Mode: p.Mode, IntervalDays: int(p.IntervalDays), MaxFires: int(p.MaxFires)}
			if !validSelection(selection) {
				return ErrAutomationUnavailableV1
			}
			out.Revision = p.Revision
		}
		out.Selection, err = automationPolicyViewV1(selection)
		if err != nil {
			return err
		}
		effective := remindercadence.LegacyPolicyV1()
		out.Source = "legacy"
		if automationTimestampV1(row.SentAt) {
			out.Frozen = true
			out.Editable = false
			out.Source = "frozen"
			snap, err := q.GetReminderPolicySnapshotV1(ctx, generated.GetReminderPolicySnapshotV1Params{DocumentID: id, OrgID: actor.OrgID, SentAt: row.SentAt})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if snap == nil || snap.SenderUserID != row.SenderID || !automationTimestampV1(snap.CreatedAt) {
					return ErrAutomationUnavailableV1
				}
				effective, err = automationPolicyRowV1(snap.Mode, snap.IntervalDays, snap.MaxFires)
				if err != nil {
					return err
				}
			}
		} else if selection.Mode != "inherit" {
			effective = selection
			out.Source = "document"
		} else if row.TemplateID.Valid {
			tid := uuid.UUID(row.TemplateID.Bytes)
			target, err := q.LockTemplateReminderSourceV1(ctx, generated.LockTemplateReminderSourceV1Params{TemplateID: tid, OrgID: actor.OrgID})
			if err != nil {
				return err
			}
			if target == nil || target.ID != tid || target.OrgID != actor.OrgID {
				return ErrAutomationUnavailableV1
			}
			p, err := q.GetTemplateReminderPolicyV1(ctx, generated.GetTemplateReminderPolicyV1Params{TemplateID: tid, OrgID: actor.OrgID})
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if err == nil {
				if p == nil || p.Revision < 1 || !automationTimestampV1(p.UpdatedAt) {
					return ErrAutomationUnavailableV1
				}
				effective, err = automationPolicyRowV1(p.Mode, p.IntervalDays, p.MaxFires)
				if err != nil {
					return err
				}
				out.Source = "template"
			}
		}
		out.EffectivePolicy, err = automationPolicyViewV1(effective)
		if err != nil {
			return err
		}
		return guard.Recheck(ctx)
	})
	if failure != nil {
		return DocumentReminderPolicyV1{}, failure
	}
	if in != nil {
		e.Audit.Publish(pending)
	}
	return
}
