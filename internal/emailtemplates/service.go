// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package emailtemplates

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrStale = errors.New("email template revision changed; reload and review")
var ErrInput = dispatch.ErrServiceEmailTemplateV1

type Service struct {
	Pool  *pgxpool.Pool
	Audit *audit.Logger
}
type Input struct {
	ExpectedRevision int64  `json:"expected_revision"`
	SubjectTemplate  string `json:"subject_template"`
	HTMLTemplate     string `json:"html_template"`
	TextTemplate     string `json:"text_template"`
}
type Template struct {
	Kind string `json:"kind"`
	dispatch.ServiceEmailTemplateV1
	UpdatedAt        *time.Time `json:"updated_at"`
	Variables        []string   `json:"variables"`
	MandatoryContent string     `json:"mandatory_content"`
	Editable         bool       `json:"editable"`
}
type Preview struct {
	SchemaVersion             int    `json:"schema_version"`
	Synthetic                 bool   `json:"synthetic"`
	Revision                  int64  `json:"revision"`
	Subject                   string `json:"subject"`
	HTML                      string `json:"html"`
	Text                      string `json:"text"`
	MandatoryContentPreserved bool   `json:"mandatory_content_preserved"`
}

func Default(kind string) Template {
	return Template{Kind: kind, Variables: dispatch.ServiceEmailVariablesV1(), MandatoryContent: "appended_by_hash", Editable: dispatch.ServiceEmailTemplateEditableKindV1(kind)}
}
func read(ctx context.Context, tx pgx.Tx, kind string, actor authoring.Actor) (Template, error) {
	out := Default(kind)
	row, err := generated.New(tx).GetServiceEmailTemplateV1(ctx, generated.GetServiceEmailTemplateV1Params{OrgID: actor.OrgID, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if row.OrgID != actor.OrgID || row.Kind != kind || row.Revision < 1 || !row.UpdatedAt.Valid {
		return out, ErrInput
	}
	tpl := dispatch.ServiceEmailTemplateV1{Revision: row.Revision, SubjectTemplate: row.SubjectTemplate, HTMLTemplate: row.HtmlTemplate, TextTemplate: row.TextTemplate}
	canonical, err := dispatch.ValidateServiceEmailTemplateV1(kind, tpl)
	if err != nil || canonical != tpl {
		return out, ErrInput
	}
	out.ServiceEmailTemplateV1 = tpl
	t := row.UpdatedAt.Time
	out.UpdatedAt = &t
	return out, nil
}
func (s Service) owner(ctx context.Context, actor authoring.Actor, fn func(context.Context, pgx.Tx, *authoring.MemberGuard) error) error {
	if s.Pool == nil || s.Audit == nil {
		return errors.New("email settings dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, err := authoring.LockOwner(ctx, tx, actor)
	if err != nil {
		return err
	}
	if err = fn(ctx, tx, guard); err != nil {
		return err
	}
	if err = guard.Recheck(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s Service) List(ctx context.Context, actor authoring.Actor) (out []Template, err error) {
	out = []Template{}
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) error {
		for _, kind := range dispatch.ServiceEmailKindsV1() {
			tpl, e := read(ctx, tx, kind, actor)
			if e != nil {
				return e
			}
			out = append(out, tpl)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return
}
func validate(kind string, in Input) (dispatch.ServiceEmailTemplateV1, error) {
	if in.ExpectedRevision < 0 || in.ExpectedRevision == math.MaxInt64 {
		return dispatch.ServiceEmailTemplateV1{}, ErrInput
	}
	return dispatch.ValidateServiceEmailTemplateV1(kind, dispatch.ServiceEmailTemplateV1{Revision: in.ExpectedRevision, SubjectTemplate: in.SubjectTemplate, HTMLTemplate: in.HTMLTemplate, TextTemplate: in.TextTemplate})
}
func (s Service) Save(ctx context.Context, actor authoring.Actor, kind string, in Input) (out Template, err error) {
	if !dispatch.ServiceEmailTemplateEditableKindV1(kind) {
		return out, ErrInput
	}
	tpl, err := validate(kind, in)
	if err != nil {
		return out, err
	}
	var pending audit.PendingEvent
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, guard *authoring.MemberGuard) error {
		current, e := read(ctx, tx, kind, actor)
		if e != nil {
			return e
		}
		if current.Revision != in.ExpectedRevision {
			return ErrStale
		}
		tpl.Revision = current.Revision + 1
		q := generated.New(tx)
		e = q.CreateServiceEmailTemplateRevisionV1(ctx, generated.CreateServiceEmailTemplateRevisionV1Params{OrgID: actor.OrgID, Kind: kind, Revision: tpl.Revision, SubjectTemplate: tpl.SubjectTemplate, HtmlTemplate: tpl.HTMLTemplate, TextTemplate: tpl.TextTemplate})
		if e != nil {
			return e
		}
		e = q.SetServiceEmailTemplateHeadV1(ctx, generated.SetServiceEmailTemplateHeadV1Params{OrgID: actor.OrgID, Kind: kind, Revision: tpl.Revision})
		if e != nil {
			return e
		}
		pending, e = s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, Kind: "email_template.updated", Payload: map[string]any{"tool": "update_service_email_template", "kind": kind, "revision": tpl.Revision}})
		if e != nil {
			return e
		}
		if e = guard.Recheck(ctx); e != nil {
			return e
		}
		out, e = read(ctx, tx, kind, actor)
		return e
	})
	if err != nil {
		return Template{}, err
	}
	s.Audit.Publish(pending)
	return
}
func SyntheticContext() dispatch.TemplateContext {
	return dispatch.TemplateContext{DocumentName: "Synthetic service preview", SenderName: "Example sender", SenderEmail: "sender@example.invalid", RecipientName: "Example recipient", OrgName: "Example workspace", Locale: "en", SignURL: "https://example.invalid/sign/preview", DownloadURL: "https://example.invalid/completed/preview", AuditCertURL: "https://example.invalid/audit/preview", PackagePortalURL: "https://example.invalid/package/preview", DownloadExpiresAt: "2030-01-01T12:00:00Z", OpenURL: "https://example.invalid/documents/preview", ApproveURL: "https://example.invalid/approve/preview", DenyURL: "https://example.invalid/decline/preview", DeclineReason: "Synthetic response", ChangeQuote: "Example clause", ChangeContext: "Example context", ChangeProposed: "Example wording", QuotaKind: "documents", QuotaUsed: 8, QuotaLimit: 10, QuotaPct: 80, PeriodResetAt: "2030-01-02", UpgradeURL: "https://example.invalid/settings", PlanName: "Example plan"}
}
func (s Service) Preview(ctx context.Context, actor authoring.Actor, kind string, in Input) (out Preview, err error) {
	if !dispatch.ServiceEmailTemplateEditableKindV1(kind) && (in.SubjectTemplate != "" || in.HTMLTemplate != "" || in.TextTemplate != "") {
		return out, ErrInput
	}
	tpl, err := validate(kind, in)
	if err != nil {
		return out, err
	}
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) error {
		current, e := read(ctx, tx, kind, actor)
		if e != nil {
			return e
		}
		if current.Revision != in.ExpectedRevision {
			return ErrStale
		}
		subject, html, text, e := dispatch.RenderServiceEmailV1(kind, SyntheticContext(), &tpl)
		if e != nil {
			return e
		}
		out = Preview{1, true, current.Revision, subject, html, text, true}
		return nil
	})
	if err != nil {
		return Preview{}, err
	}
	return
}
