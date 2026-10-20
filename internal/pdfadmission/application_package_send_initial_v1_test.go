// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPackageSendSelectionDoesNotCreateNativeAuthorityV1(t *testing.T) {
	v := HTMLSendPackageSelectionV1{PackageID: uuid.New(), Generation: 1, ExpectedUpdatedAt: time.Now().UTC().Truncate(time.Microsecond)}
	if !v.ValidV1() {
		t.Fatal("fixture observation invalid")
	}
	for _, w := range []*ApplicationHTMLSendWorkV1{nil, {}, {self: new(ApplicationHTMLSendWorkV1)}} {
		if err := w.CheckPackageSendSelectionV1(context.Background(), v); err == nil {
			t.Fatal("public selection granted initial SQL authority")
		}
		if out, err := w.FindPackageSendSelectionAttemptV1(context.Background(), v); err == nil || out != (HTMLSendPackageAttemptObservationV1{}) {
			t.Fatal("public selection reconstructed history authority", out, err)
		}
	}
}
