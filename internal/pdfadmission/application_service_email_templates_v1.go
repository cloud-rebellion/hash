// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const applicationServiceEmailKindsV1 = 9

// This fixed collection belongs to the actual source Work, not a caller's
// renderer/context. Its first allocation is included in that Work's sizeof.
type applicationServiceEmailSlotV1 struct {
	org               uuid.UUID
	attempted, loaded bool
	template          *dispatch.ServiceEmailTemplateV1
}

func applicationServiceEmailKindIndexV1(kind string) (int, error) {
	switch kind {
	case dispatch.KindInvite:
		return 0, nil
	case dispatch.KindReminder:
		return 1, nil
	case dispatch.KindCompletedSigner:
		return 2, nil
	case dispatch.KindCompletedSender:
		return 3, nil
	case dispatch.KindDeclined:
		return 4, nil
	case dispatch.KindChangesRequested:
		return 5, nil
	case dispatch.KindNewComment:
		return 6, nil
	case dispatch.KindVoided:
		return 7, nil
	case dispatch.KindQuotaWarning80:
		return 8, nil
	default:
		return 0, ErrHTMLSendWorkV1
	}
}

func applicationServiceEmailHeaderWorkV1() int64 {
	return 65536 + 8*int64(unsafe.Sizeof(generated.GetServiceEmailTemplateHeaderV1Row{})) + 8*int64(unsafe.Sizeof(applicationServiceEmailSlotV1{}))
}

// The scalar locked header is acquired before any expandable TEXT source is
// read. Individual database/source limits are repeated before their sum.
func applicationServiceEmailSourceWorkV1(h *generated.GetServiceEmailTemplateHeaderV1Row, org uuid.UUID, kind string) (int64, int64, error) {
	if _, err := applicationServiceEmailKindIndexV1(kind); err != nil || h == nil || org == uuid.Nil || h.OrgID != org || h.Kind != kind || h.Revision <= 0 || !applicationStampV1(h.UpdatedAt) ||
		h.SubjectBytes < 0 || h.SubjectBytes > 256 || h.HtmlBytes < 0 || h.HtmlBytes > 16384 || h.TextBytes < 0 || h.TextBytes > 8192 || h.DesignBytes < 0 || h.DesignBytes > dispatch.ServiceEmailDesignSourceBytesV1 || (h.DesignBytes == 0 && len(h.DesignSha256) != 0) || (h.DesignBytes > 0 && len(h.DesignSha256) != 32) {
		return 0, 0, ErrHTMLSendWorkV1
	}
	wire := h.SubjectBytes + h.HtmlBytes + h.TextBytes + h.DesignBytes
	work := 64*wire + 65536 + 8*int64(unsafe.Sizeof(generated.GetServiceEmailTemplateV1Row{})) + 8*int64(unsafe.Sizeof(dispatch.ServiceEmailTemplateV1{}))
	if h.DesignBytes > 0 {
		work += dispatch.ServiceEmailDesignFixedWorkBytesV1
	}
	return work, wire, nil
}

func applicationServiceEmailFromRowsV1(h *generated.GetServiceEmailTemplateHeaderV1Row, r *generated.GetServiceEmailTemplateV1Row, org uuid.UUID, kind string) (*dispatch.ServiceEmailTemplateV1, error) {
	if _, _, err := applicationServiceEmailSourceWorkV1(h, org, kind); err != nil || r == nil || r.OrgID != org || r.Kind != kind || r.Revision != h.Revision || r.UpdatedAt != h.UpdatedAt ||
		int64(len(r.SubjectTemplate)) != h.SubjectBytes || int64(len(r.HtmlTemplate)) != h.HtmlBytes || int64(len(r.TextTemplate)) != h.TextBytes || int64(len(r.DesignJson)) != h.DesignBytes || !bytes.Equal(r.DesignSha256, h.DesignSha256) || !bytes.Equal(r.DesignSha256, dispatch.ServiceEmailDesignDigestV1(r.DesignJson)) {
		return nil, ErrHTMLSendWorkV1
	}
	in := dispatch.ServiceEmailTemplateV1{Revision: r.Revision, SubjectTemplate: r.SubjectTemplate, HTMLTemplate: r.HtmlTemplate, TextTemplate: r.TextTemplate, DesignJSON: r.DesignJson}
	checked, err := dispatch.ValidateServiceEmailTemplateV1(kind, in)
	if err != nil || checked != in {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	return &checked, nil
}

// Caller holds Work.mu after the original actor/member/document/credential
// checks. The SAME retained body owner and transaction fund and read both
// sources; only an absent locked head chooses the unchanged built-in.
func (w *ApplicationHTMLSendWorkV1) serviceEmailTemplateV1(call context.Context, kind string) (*dispatch.ServiceEmailTemplateV1, error) {
	index, err := applicationServiceEmailKindIndexV1(kind)
	if err != nil || w == nil || !w.valid(call) || w.actor == nil || w.queries == nil || w.session == nil || w.session.state == nil || w.sourceDocument == nil || w.sourceDocument.OrgID == uuid.Nil || w.sourceDocument.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	org := w.sourceDocument.OrgID
	s := &w.serviceEmailTemplates[index]
	if s.attempted {
		if !s.loaded || s.org != org {
			return nil, ErrHTMLSendWorkV1
		}
		return s.template, nil
	}
	closeHeader, err := w.actor.acquireOwnedRetainedBodyV1(call, applicationServiceEmailHeaderWorkV1(), 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeHeader)
	s.attempted, s.org = true, org
	h, err := w.queries.GetServiceEmailTemplateHeaderV1(call, generated.GetServiceEmailTemplateHeaderV1Params{OrgID: org, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		s.loaded = true
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	work, wire, err := applicationServiceEmailSourceWorkV1(h, org, kind)
	if err != nil {
		return nil, err
	}
	closeSource, err := w.actor.acquireOwnedRetainedBodyV1(call, work, wire)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeSource)
	row, err := w.queries.GetServiceEmailTemplateV1(call, generated.GetServiceEmailTemplateV1Params{OrgID: org, Kind: kind})
	if err != nil {
		return nil, err
	}
	s.template, err = applicationServiceEmailFromRowsV1(h, row, org, kind)
	if err != nil {
		return nil, err
	}
	s.loaded = true
	return s.template, nil
}

// No SQL, source allocation or fallback may occur after output admission.
func (w *ApplicationHTMLSendWorkV1) cachedServiceEmailTemplateV1(kind string) (*dispatch.ServiceEmailTemplateV1, error) {
	index, err := applicationServiceEmailKindIndexV1(kind)
	if err != nil || w == nil || w.self != w || w.sourceDocument == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s := &w.serviceEmailTemplates[index]
	if !s.attempted || !s.loaded || s.org != w.sourceDocument.OrgID {
		return nil, ErrHTMLSendWorkV1
	}
	return s.template, nil
}

// A change ceremony has one concrete owner notification. Its SAME native
// retention registry and fixed transaction own scalar head, immutable source,
// sanitizer and renderer work through the notification's active borrower.
func (w *ApplicationHTMLCeremonyWorkflowV1) changeServiceEmailTemplateV1(call context.Context) (*dispatch.ServiceEmailTemplateV1, error) {
	if w == nil || !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.closed || w.snapshot == nil || w.snapshot.document == nil || w.sender == nil || w.participant == nil || w.change == nil {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	org := w.snapshot.document.OrgID
	w.mu.Unlock()
	if org == uuid.Nil {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	if err := w.retainV1(call, applicationServiceEmailHeaderWorkV1(), 0); err != nil {
		return nil, err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return nil, err
	}
	h, err := q.GetServiceEmailTemplateHeaderV1(call, generated.GetServiceEmailTemplateHeaderV1Params{OrgID: org, Kind: dispatch.KindChangesRequested})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	work, wire, err := applicationServiceEmailSourceWorkV1(h, org, dispatch.KindChangesRequested)
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, work, wire); err != nil {
		return nil, err
	}
	r, err := q.GetServiceEmailTemplateV1(call, generated.GetServiceEmailTemplateV1Params{OrgID: org, Kind: dispatch.KindChangesRequested})
	if err != nil {
		return nil, err
	}
	return applicationServiceEmailFromRowsV1(h, r, org, dispatch.KindChangesRequested)
}

// Each mandatory original calculator remains authoritative for its own source.
// The already-admitted selected edition only adds its actual expanded costs.
func applicationServiceEmailComponentsV1(kind string, ctx dispatch.TemplateContext, tpl *dispatch.ServiceEmailTemplateV1) (int64, int64, int64, error) {
	var s, h, t int64
	var err error
	switch kind {
	case dispatch.KindInvite:
		s, h, t, err = dispatch.InviteNotificationComponentsV1(ctx)
	case dispatch.KindReminder:
		s, h, t, err = dispatch.ReminderNotificationComponentsV1(ctx)
	case dispatch.KindCompletedSigner, dispatch.KindCompletedSender:
		s, h, t, err = dispatch.CompletedNotificationComponentsV1(kind, ctx)
	case dispatch.KindNewComment:
		s, h, t, err = dispatch.CommentNotificationComponentsV1(ctx)
	case dispatch.KindChangesRequested:
		s, h, t, err = dispatch.ChangeRequestNotificationComponentsV1(ctx)
	default:
		return 0, 0, 0, ErrHTMLSendWorkV1
	}
	if err != nil {
		return 0, 0, 0, err
	}
	return dispatch.ServiceEmailTemplateComponentsV1(ctx, tpl, s, h, t)
}
