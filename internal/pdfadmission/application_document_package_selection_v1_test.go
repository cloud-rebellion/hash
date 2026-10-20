// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDocumentPackageSelectionRequiresGenuineNativeOwnerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, session := range []*ApplicationSessionV1{nil, {}} {
		if _, err := session.NewDocumentPackageSelectionV1(ctx, uuid.New()); !errors.Is(err, ErrDocumentPackageSelectionV1) {
			t.Fatal("unowned session adopted", err)
		}
	}
	for _, owner := range []*ApplicationDocumentPackageSelectionV1{nil, {}} {
		owner.CloseConsumerV1()
		if err := owner.ValidateSourcesV1(ctx); !errors.Is(err, ErrDocumentPackageSelectionV1) {
			t.Fatal("zero owner validated", err)
		}
	}
	for _, binding := range []*applicationDocumentPackageReadBindingV1{nil, {}, {owner: &applicationDocumentPackageSelectionStateV1{}}} {
		if binding.validV1(ctx, &ApplicationHTMLRevisionReaderV1{}) {
			t.Fatal("forged binding accepted")
		}
	}
}
func TestDocumentPackageSourcePurposeCannotMaterializeRevisionV1(t *testing.T) {
	source := &ApplicationHTMLRevisionSourceV1{state: &applicationHTMLRevisionSourceOwnerV1{purpose: htmlPackageSelectionSourcePurposeV1}}
	if err := source.MaterializeRevisionV1(); !errors.Is(err, ErrHTMLRevisionSourceV1) {
		t.Fatal("read-only source acquired mutation purpose", err)
	}
}
