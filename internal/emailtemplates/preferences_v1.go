// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package emailtemplates

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Exact JSON/JavaScript CAS domain; never emit an unrepresentable revision.
const PreferencesMaxRevisionV1 int64 = 9007199254740991

type PreferencesV1 struct {
	SchemaVersion int        `json:"schema_version"`
	OrgID         uuid.UUID  `json:"org_id"`
	Revision      int64      `json:"revision"`
	Locale        string     `json:"locale"`
	UpdatedAt     *time.Time `json:"updated_at"`
}
type PreferencesInputV1 struct {
	ExpectedRevision int64  `json:"expected_revision"`
	Locale           string `json:"locale"`
}

func validPreferencesInputV1(in PreferencesInputV1) bool {
	return in.ExpectedRevision >= 0 && in.ExpectedRevision < PreferencesMaxRevisionV1 && (in.Locale == "en" || in.Locale == "sv")
}

// This scalar read supplies no actor/SQL authority. Its original caller owns
// the transaction; an existing preference remains SHARE-locked until it ends.
// An absent row selects legacy English at this read's linearization point.
func readPreferencesV1(ctx context.Context, tx pgx.Tx, org uuid.UUID) (PreferencesV1, error) {
	out := PreferencesV1{SchemaVersion: 1, OrgID: org, Locale: "en"}
	if tx == nil || org == uuid.Nil {
		return out, ErrInput
	}
	row, err := generated.New(tx).GetOrgEmailPreferencesV1(ctx, org)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if row == nil || row.OrgID != org || row.Revision <= 0 || row.Revision > PreferencesMaxRevisionV1 || !row.UpdatedAt.Valid || (row.Locale != "en" && row.Locale != "sv") {
		return out, ErrInput
	}
	t := row.UpdatedAt.Time
	out.Revision, out.Locale, out.UpdatedAt = row.Revision, row.Locale, &t
	return out, nil
}

func (s Service) PreferencesV1(ctx context.Context, actor authoring.Actor) (out PreferencesV1, err error) {
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) error {
		out, err = readPreferencesV1(ctx, tx, actor.OrgID)
		return err
	})
	return
}

func (s Service) SavePreferencesV1(ctx context.Context, actor authoring.Actor, in PreferencesInputV1) (out PreferencesV1, err error) {
	if !validPreferencesInputV1(in) {
		return out, ErrInput
	}
	var pending audit.PendingEvent
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, guard *authoring.MemberGuard) error {
		current, e := readPreferencesV1(ctx, tx, actor.OrgID)
		if e != nil {
			return e
		}
		if current.Revision != in.ExpectedRevision {
			return ErrStale
		}
		q := generated.New(tx)
		if in.ExpectedRevision == 0 {
			_, e = q.CreateOrgEmailPreferencesV1(ctx, generated.CreateOrgEmailPreferencesV1Params{OrgID: actor.OrgID, Locale: in.Locale})
		} else {
			_, e = q.UpdateOrgEmailPreferencesV1(ctx, generated.UpdateOrgEmailPreferencesV1Params{OrgID: actor.OrgID, ExpectedRevision: in.ExpectedRevision, Locale: in.Locale})
		}
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrStale
		}
		if e != nil {
			return e
		}
		pending, e = s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: "email_preferences.updated", Payload: map[string]any{"revision": current.Revision + 1, "locale": in.Locale}})
		if e != nil {
			return e
		}
		if e = guard.Recheck(ctx); e != nil {
			return e
		}
		out, e = readPreferencesV1(ctx, tx, actor.OrgID)
		return e
	})
	if err != nil {
		return PreferencesV1{}, err
	}
	s.Audit.Publish(pending)
	return out, nil
}

func syntheticContextV1(ctx context.Context, tx pgx.Tx, org uuid.UUID, kind string) (dispatch.TemplateContext, error) {
	out := SyntheticContext()
	if kind == dispatch.KindQuotaWarning80 {
		prefs, err := readPreferencesV1(ctx, tx, org)
		if err != nil {
			return out, err
		}
		out.Locale = prefs.Locale
	}
	return out, nil
}

// SavedSampleContextForOwnerV1 selects only inert synthetic values in the
// original owner/test transaction. It grants no new recipient or transport
// authority. The caller retains its original guard and admitted source owner.
func SavedSampleContextForOwnerV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, guard *authoring.MemberGuard, kind string) (dispatch.TemplateContext, error) {
	if tx == nil || guard == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || !dispatch.ServiceEmailKindV1(kind) {
		return dispatch.TemplateContext{}, ErrInput
	}
	control := pdfadmission.ServiceEmailControlFromContextV1(ctx)
	if control == nil || !control.MatchesOrgV1(ctx, actor.OrgID) {
		return dispatch.TemplateContext{}, pdfadmission.ErrServiceEmailControlV1
	}
	if err := guard.Recheck(ctx); err != nil {
		return dispatch.TemplateContext{}, err
	}
	out, err := syntheticContextV1(ctx, tx, actor.OrgID, kind)
	if err != nil {
		return dispatch.TemplateContext{}, err
	}
	if err := guard.Recheck(ctx); err != nil {
		return dispatch.TemplateContext{}, err
	}
	return out, nil
}
