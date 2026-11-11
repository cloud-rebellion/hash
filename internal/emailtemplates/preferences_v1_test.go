// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package emailtemplates

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
)

func TestWorkspaceEmail128ClosedPreferenceInput(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		if !validPreferencesInputV1(PreferencesInputV1{Locale: locale}) {
			t.Fatal("supported locale rejected", locale)
		}
	}
	if !validPreferencesInputV1(PreferencesInputV1{Locale: "en", ExpectedRevision: PreferencesMaxRevisionV1 - 1}) {
		t.Fatal("last exact CAS input rejected")
	}
	for _, input := range []PreferencesInputV1{
		{Locale: ""}, {Locale: "sv-SE"}, {Locale: "SV"}, {Locale: " en"}, {Locale: "de"},
		{Locale: "en", ExpectedRevision: -1}, {Locale: "sv", ExpectedRevision: PreferencesMaxRevisionV1}, {Locale: "en", ExpectedRevision: PreferencesMaxRevisionV1 + 1},
	} {
		if validPreferencesInputV1(input) {
			t.Fatal("invalid preference accepted", input)
		}
		if _, err := (Service{}).SavePreferencesV1(context.Background(), authoring.Actor{}, input); !errors.Is(err, ErrInput) {
			t.Fatal("invalid preference reached persistence", err)
		}
	}
}

func TestWorkspaceEmail128OnlyNewNativeKindsBecomeEditable(t *testing.T) {
	for _, kind := range []string{dispatch.KindDeclined, dispatch.KindQuotaWarning80} {
		if !Default(kind).Editable {
			t.Fatal("native producer edition unavailable", kind)
		}
	}
	if Default(dispatch.KindVoided).Editable || len(dispatch.ServiceEmailKindsV1()) != 9 {
		t.Fatal("catalog-only voided became editable or catalog expanded")
	}
}

func TestWorkspaceEmail128NativeCannotInventAuthorityOrFallback(t *testing.T) {
	for _, kind := range []string{dispatch.KindDeclined, dispatch.KindQuotaWarning80, dispatch.KindVoided, dispatch.KindInvite, "unknown"} {
		result, err := PrepareNativeV1(context.Background(), nil, nil, uuid.New(), kind, SyntheticContext())
		if !errors.Is(err, ErrInput) || result.Subject != "" || result.HTML != "" || result.Text != "" {
			t.Fatal("missing actual runtime/transaction produced mail", kind, err)
		}
		result.CloseConsumerV1()
	}
}
