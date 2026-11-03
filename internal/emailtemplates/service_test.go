// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package emailtemplates

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
)

func TestEmailTemplate720SyntheticPreviewAndInput(t *testing.T) {
	for _, kind := range dispatch.ServiceEmailKindsV1() {
		v, err := validate(kind, Input{SubjectTemplate: "{{recipient_name}}", HTMLTemplate: "<p>{{document_name}}</p>"})
		if err != nil {
			t.Fatal(err)
		}
		s, h, p, err := dispatch.RenderServiceEmailV1(kind, SyntheticContext(), &v)
		if err != nil || s == "" || h == "" || p == "" {
			t.Fatal(kind, err)
		}
		if strings.Contains(h, "localhost") || strings.Contains(h, "127.0.0.1") || strings.Contains(h, "/e/o/") {
			t.Fatal("preview reached operational/tracking target")
		}
	}
	for _, in := range []Input{{ExpectedRevision: -1}, {ExpectedRevision: math.MaxInt64}, {HTMLTemplate: "<img src='/asset'>"}, {TextTemplate: "{{undefined}}"}} {
		if _, err := validate(dispatch.KindInvite, in); err == nil {
			t.Fatal("invalid CAS/input accepted")
		}
	}
}
func TestEmailTemplate720UnwiredKindsCannotStoreIgnoredEdits(t *testing.T) {
	for _, kind := range []string{dispatch.KindDeclined, dispatch.KindVoided, dispatch.KindQuotaWarning80} {
		if Default(kind).Editable {
			t.Fatal("unwired kind advertised editable")
		}
		if _, err := (Service{}).Save(context.Background(), authoring.Actor{}, kind, Input{}); !errors.Is(err, ErrInput) {
			t.Fatal("unwired edit did not refuse before any persistence", err)
		}
		if _, err := (Service{}).Preview(context.Background(), authoring.Actor{}, kind, Input{HTMLTemplate: "<p>Ignored</p>"}); !errors.Is(err, ErrInput) {
			t.Fatal("unwired custom preview accepted", err)
		}
	}
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder, dispatch.KindCompletedSigner, dispatch.KindCompletedSender, dispatch.KindChangesRequested, dispatch.KindNewComment} {
		if !Default(kind).Editable {
			t.Fatal("native kind missing editing capability")
		}
	}
}
