// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package emailtemplates

import (
	"context"

	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// NativeRenderedV1 retains only frozen strings and their original process
// resource owner. It neither chooses a destination nor grants SQL/send authority.
type NativeRenderedV1 struct {
	Subject          string
	HTML             string
	Text             string
	Locale           string
	TemplateRevision int64
	owner            *pdfadmission.ApplicationServiceEmailControlV1
}

func (n NativeRenderedV1) CloseConsumerV1() {
	if n.owner != nil {
		n.owner.CloseConsumerV1()
	}
}

// PrepareNativeV1 is restricted to the two already-existing producers added by
// M128. The actual producer supplies its original live transaction and the Work
// of its pool-matched runtime, then retains this result through enqueue/commit.
// No fake owner actor, alternate renderer, SQL callback or new recipient exists.
func PrepareNativeV1(ctx context.Context, work *pdfadmission.WorkAdmissionV1, tx pgx.Tx, org uuid.UUID, kind string, input dispatch.TemplateContext) (out NativeRenderedV1, err error) {
	if ctx == nil || ctx.Err() != nil || work == nil || tx == nil || org == uuid.Nil || (kind != dispatch.KindDeclined && kind != dispatch.KindQuotaWarning80) {
		return out, ErrInput
	}
	call, owner, err := work.NewServiceEmailControlV1(ctx, org)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			owner.CloseConsumerV1()
		}
	}()
	if err = owner.AdmitNativeContextV1(call, input); err != nil {
		return out, err
	}
	if kind == dispatch.KindQuotaWarning80 {
		var prefs PreferencesV1
		prefs, err = readPreferencesV1(call, tx, org)
		if err != nil {
			return out, err
		}
		input.Locale = prefs.Locale
	}
	// Decline keeps the original document locale, including legacy fallback.
	selected, err := readForOrgV1(call, tx, kind, org)
	if err != nil {
		return out, err
	}
	if err = owner.ReserveNativeOutputV1(call); err != nil {
		return out, err
	}
	closeRender, err := owner.BeginTemplateWorkV1(call, selected.ServiceEmailTemplateV1)
	if err != nil {
		return out, err
	}
	defer closeRender()
	var tpl *dispatch.ServiceEmailTemplateV1
	if selected.Revision > 0 {
		tpl = &selected.ServiceEmailTemplateV1
	}
	out.Subject, out.HTML, out.Text, err = dispatch.RenderServiceEmailV1(kind, input, tpl)
	if err != nil {
		return NativeRenderedV1{}, err
	}
	if len(out.Subject) > dispatch.ServiceEmailRenderedSubjectBytesV1 || len(out.HTML) > dispatch.ServiceEmailDesignRenderedBytesV1 || len(out.Text) > dispatch.ServiceEmailDesignRenderedBytesV1 {
		err = ErrInput
		return NativeRenderedV1{}, err
	}
	out.Locale, out.TemplateRevision, out.owner = input.Locale, selected.Revision, owner
	return out, nil
}
