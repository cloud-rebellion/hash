// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"testing"
)

func TestPackageInspectionAlwaysRequiresFreshAuthorizationV1(t *testing.T) {
	for _, via := range []string{"rest", "mcp", "automation", "worker", "synthetic-owned-test", ""} {
		t.Run(via, func(t *testing.T) {
			user := uuid.New()
			var e *Engine
			r, err := e.InspectPackageSendAttemptV1(context.Background(), Actor{UserID: &user, OrgID: uuid.New(), Via: via}, uuid.New(), uuid.New())
			if r != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Fatal(r, err)
			}
		})
	}
}

func TestPackageInspectionEmptyOutputCannotBecomeAuthorityV1(t *testing.T) {
	for _, r := range []*PackageSendAttemptInspectionV1{nil, {}, {state: &packageSendAttemptInspectionStateV1{}}} {
		if err := r.WithObservationV1(func(pdfadmission.HTMLSendPackageAttemptObservationV1) error { return nil }); err == nil {
			t.Fatal("unowned result delivered")
		}
		r.CloseConsumerV1()
		r.CloseConsumerV1()
	}
}
