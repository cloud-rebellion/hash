// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package emailtemplates

import (
	"bytes"
	"context"
	"errors"
	"math"
	"time"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrStale = errors.New("email template revision changed; reload and review")
var ErrInput = dispatch.ErrServiceEmailTemplateV1

type Service struct {
	Pool    *pgxpool.Pool
	Audit   *audit.Logger
	Work    *pdfadmission.WorkAdmissionV1
	Runtime *ai.Runtime
}
type Input struct {
	ExpectedRevision int64   `json:"expected_revision"`
	DesignJSON       *string `json:"design_json,omitempty"`
	SubjectTemplate  string  `json:"subject_template"`
	HTMLTemplate     string  `json:"html_template"`
	TextTemplate     string  `json:"text_template"`
}
type Template struct {
	Kind  string `json:"kind"`
	owner *pdfadmission.ApplicationServiceEmailControlV1
	dispatch.ServiceEmailTemplateV1
	UpdatedAt        *time.Time `json:"updated_at"`
	Variables        []string   `json:"variables"`
	MandatoryContent string     `json:"mandatory_content"`
	Editable         bool       `json:"editable"`
}
type Preview struct {
	owner                     *pdfadmission.ApplicationServiceEmailControlV1
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
	q := generated.New(tx)
	header, err := q.GetServiceEmailTemplateHeaderV1(ctx, generated.GetServiceEmailTemplateHeaderV1Params{OrgID: actor.OrgID, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	owner := pdfadmission.ServiceEmailControlFromContextV1(ctx)
	if owner != nil {
		if err := owner.AdmitSourceV1(ctx, header); err != nil {
			return out, err
		}
	} else if header.DesignBytes > 0 {
		return out, pdfadmission.ErrServiceEmailControlV1
	}
	row, err := generated.New(tx).GetServiceEmailTemplateV1(ctx, generated.GetServiceEmailTemplateV1Params{OrgID: actor.OrgID, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrInput
	}
	if err != nil {
		return out, err
	}
	if row.OrgID != actor.OrgID || row.Kind != kind || row.Revision < 1 || !row.UpdatedAt.Valid || row.Revision != header.Revision || row.UpdatedAt != header.UpdatedAt || int64(len(row.SubjectTemplate)) != header.SubjectBytes || int64(len(row.HtmlTemplate)) != header.HtmlBytes || int64(len(row.TextTemplate)) != header.TextBytes || int64(len(row.DesignJson)) != header.DesignBytes || !bytes.Equal(row.DesignSha256, header.DesignSha256) || !bytes.Equal(row.DesignSha256, dispatch.ServiceEmailDesignDigestV1(row.DesignJson)) {
		return out, ErrInput
	}
	tpl := dispatch.ServiceEmailTemplateV1{Revision: row.Revision, SubjectTemplate: row.SubjectTemplate, HTMLTemplate: row.HtmlTemplate, TextTemplate: row.TextTemplate, DesignJSON: row.DesignJson}
	var closeWork func()
	if owner != nil {
		closeWork, err = owner.BeginTemplateWorkV1(ctx, tpl)
		if err != nil {
			return out, err
		}
		defer closeWork()
	}
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
	var owner *pdfadmission.ApplicationServiceEmailControlV1
	ctx, owner, err = s.BeginSourceReadV1(ctx, actor)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && owner != nil {
			owner.CloseConsumerV1()
		}
	}()
	err = s.owner(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) error {
		for _, kind := range dispatch.ServiceEmailKindsV1() {
			tpl, e := read(ctx, tx, kind, actor)
			if e != nil {
				return e
			}
			tpl.owner = owner
			out = append(out, tpl)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return
}
func validateWithWork(ctx context.Context, owner *pdfadmission.ApplicationServiceEmailControlV1, kind string, in Input) (dispatch.ServiceEmailTemplateV1, error) {
	if in.ExpectedRevision < 0 || in.ExpectedRevision == math.MaxInt64 {
		return dispatch.ServiceEmailTemplateV1{}, ErrInput
	}
	design := ""
	if in.DesignJSON != nil {
		design = *in.DesignJSON
	}
	tpl := dispatch.ServiceEmailTemplateV1{Revision: in.ExpectedRevision, SubjectTemplate: in.SubjectTemplate, HTMLTemplate: in.HTMLTemplate, TextTemplate: in.TextTemplate, DesignJSON: design}
	if owner == nil {
		return dispatch.ServiceEmailTemplateV1{}, pdfadmission.ErrServiceEmailControlV1
	}
	closeWork, err := owner.BeginTemplateWorkV1(ctx, tpl)
	if err != nil {
		return dispatch.ServiceEmailTemplateV1{}, err
	}
	defer closeWork()
	return dispatch.ValidateServiceEmailTemplateV1(kind, tpl)
}
func validate(kind string, in Input) (dispatch.ServiceEmailTemplateV1, error) {
	if in.ExpectedRevision < 0 || in.ExpectedRevision == math.MaxInt64 {
		return dispatch.ServiceEmailTemplateV1{}, ErrInput
	}
	design := ""
	if in.DesignJSON != nil {
		design = *in.DesignJSON
	}
	return dispatch.ValidateServiceEmailTemplateV1(kind, dispatch.ServiceEmailTemplateV1{Revision: in.ExpectedRevision, SubjectTemplate: in.SubjectTemplate, HTMLTemplate: in.HTMLTemplate, TextTemplate: in.TextTemplate, DesignJSON: design})
}
func (s Service) Save(ctx context.Context, actor authoring.Actor, kind string, in Input) (out Template, err error) {
	if !dispatch.ServiceEmailTemplateEditableKindV1(kind) {
		return out, ErrInput
	}
	var owner *pdfadmission.ApplicationServiceEmailControlV1
	ctx, owner, err = s.BeginSourceReadV1(ctx, actor)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil && owner != nil {
			owner.CloseConsumerV1()
		}
	}()
	if err = admitInput(ctx, owner, in); err != nil {
		return out, err
	}
	tpl, err := validateWithWork(ctx, owner, kind, in)
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
		if in.DesignJSON == nil {
			tpl.DesignJSON = current.DesignJSON
		}
		tpl.Revision = current.Revision + 1
		q := generated.New(tx)
		e = q.CreateServiceEmailTemplateRevisionV1(ctx, generated.CreateServiceEmailTemplateRevisionV1Params{OrgID: actor.OrgID, Kind: kind, Revision: tpl.Revision, SubjectTemplate: tpl.SubjectTemplate, HtmlTemplate: tpl.HTMLTemplate, TextTemplate: tpl.TextTemplate, DesignJson: tpl.DesignJSON, DesignSha256: dispatch.ServiceEmailDesignDigestV1(tpl.DesignJSON)})
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
	out.owner = owner
	return
}
func SyntheticContext() dispatch.TemplateContext {
	return dispatch.TemplateContext{DocumentName: "Synthetic service preview", SenderName: "Example sender", SenderEmail: "sender@example.invalid", RecipientName: "Example recipient", OrgName: "Example workspace", Locale: "en", SignURL: "https://example.invalid/sign/preview", DownloadURL: "https://example.invalid/completed/preview", AuditCertURL: "https://example.invalid/audit/preview", PackagePortalURL: "https://example.invalid/package/preview", DownloadExpiresAt: "2030-01-01T12:00:00Z", OpenURL: "https://example.invalid/documents/preview", ApproveURL: "https://example.invalid/approve/preview", DenyURL: "https://example.invalid/decline/preview", DeclineReason: "Synthetic response", ChangeQuote: "Example clause", ChangeContext: "Example context", ChangeProposed: "Example wording", QuotaKind: "documents", QuotaUsed: 8, QuotaLimit: 10, QuotaPct: 80, PeriodResetAt: "2030-01-02", UpgradeURL: "https://example.invalid/settings", PlanName: "Example plan"}
}
func (s Service) Preview(ctx context.Context, actor authoring.Actor, kind string, in Input) (out Preview, err error) {
	if !dispatch.ServiceEmailTemplateEditableKindV1(kind) && (in.SubjectTemplate != "" || in.HTMLTemplate != "" || in.TextTemplate != "" || (in.DesignJSON != nil && *in.DesignJSON != "")) {
		return out, ErrInput
	}

	var owner *pdfadmission.ApplicationServiceEmailControlV1
	ctx, owner, err = s.BeginSourceReadV1(ctx, actor)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil && owner != nil {
			owner.CloseConsumerV1()
		}
	}()
	if err = admitInput(ctx, owner, in); err != nil {
		return out, err
	}

	tpl, err := validateWithWork(ctx, owner, kind, in)
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
		if in.DesignJSON == nil {
			tpl.DesignJSON = current.DesignJSON
		}
		if owner != nil {
			if e = owner.AdmitSyntheticPreviewV1(ctx); e != nil {
				return e
			}
		}
		closeRender, e := owner.BeginTemplateWorkV1(ctx, tpl)
		if e != nil {
			return e
		}
		defer closeRender()
		subject, html, text, e := dispatch.RenderServiceEmailV1(kind, SyntheticContext(), &tpl)
		if e != nil {
			return e
		}
		out = Preview{SchemaVersion: 1, Synthetic: true, Revision: current.Revision, Subject: subject, HTML: html, Text: text, MandatoryContentPreserved: true, owner: owner}
		return nil
	})
	if err != nil {
		return Preview{}, err
	}
	return
}

// BeginSourceReadV1 binds the original process resource owner to caller context.
// Saved sample callers retain it through their actual render/enqueue/response.
// This supplies no SQL or mutation authority; the original owner guard does.
func (s Service) BeginSourceReadV1(ctx context.Context, actor authoring.Actor) (context.Context, *pdfadmission.ApplicationServiceEmailControlV1, error) {
	if s.Work == nil {
		return ctx, nil, pdfadmission.ErrServiceEmailControlV1
	}
	return s.Work.NewServiceEmailControlV1(ctx, actor.OrgID)
}
func admitInput(ctx context.Context, owner *pdfadmission.ApplicationServiceEmailControlV1, in Input) error {
	design := ""
	if in.DesignJSON != nil {
		design = *in.DesignJSON
	}
	if owner == nil {
		if design != "" {
			return pdfadmission.ErrServiceEmailControlV1
		}
		return nil
	}
	return owner.AdmitInputV1(ctx, in.SubjectTemplate, in.HTMLTemplate, in.TextTemplate, design)
}
func (t Template) CloseConsumerV1() {
	if t.owner != nil {
		t.owner.CloseConsumerV1()
	}
}
func (p Preview) CloseConsumerV1() {
	if p.owner != nil {
		p.owner.CloseConsumerV1()
	}
}
