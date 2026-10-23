//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bright-interaction/hash/internal/presignexecute"
)

// This uses the registered route, actual owned schema3 root, genuine native
// imported annex and normal guarded PostgreSQL package selection. It proves
// eligibility distinguishes an empty package header from a selected annex.
// The separate full production journey exercises valid-authority confirmation;
// no placeholder policy reference is used to claim effectful-path coverage here.
func TestPreSign488SelectedAnnexIsIneligibleBeforePreparationE2E(t *testing.T) {
	for _, selected := range []bool{false, true} {
		name := "empty package header"
		if selected {
			name = "selected annex"
		}
		t.Run(name, func(t *testing.T) {
			// A genuine annex import needs the existing physical parser allocation
			// before runtime birth. The auth-only fixture deliberately has no worker.
			q := newOwnedDocumentPackageMeasurementFixtureV1(t)
			if selected {
				ownedCreationPrepareProPlanV1(t, q)
			}
			doc := createBrandedDocumentE2E(t, q.f, q.template, q.cookie)
			q.f.s.PreSignExecutionEnabled = true
			f := preSignAuthFixture488{owned: q, router: q.f.s.Routes(), document: doc}
			f.eligibility(t, q.cookie, "", false)
			if selected {
				annex := packageImported220(t, q, "Controlled pre-sign annex")
				packageCreate223(t, q, packageLatest223(t, q, f.document.ID), annex)
			} else {
				packageCreate223(t, q, packageLatest223(t, q, f.document.ID))
			}
			before := f.snapshot(t)
			packageBefore := packageFullState223(t, q)
			w := f.call(t, http.MethodGet, "/api/v1/presign/executions/documents/"+f.document.ID.String()+"/eligibility", q.cookie, "", nil, http.StatusOK)
			var view presignexecute.EligibilityV1
			d := json.NewDecoder(bytes.NewReader(w.Body.Bytes()))
			d.DisallowUnknownFields()
			if d.Decode(&view) != nil || view.SchemaVersion != 1 || view.OrgID != q.f.org || view.UserID != q.f.user.ID || view.DocumentID != f.document.ID ||
				view.Eligible != (!selected) || (view.Source != nil) != (!selected) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("standalone eligibility did not reflect actual selected annexes")
			}
			f.unchanged(t, before)
			if packageFullState223(t, q) != packageBefore {
				t.Fatal("eligibility changed the ordinary package selection")
			}
		})
	}
}
