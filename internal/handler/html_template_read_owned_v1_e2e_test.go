//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

func ownedHTMLTemplateReadActorE2E(t *testing.T, f lifecycleAuthorizationFixture) (*http.Request, auth.SessionUser, auth.TransactionAuthorization, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal("mint synthetic read credential")
	}
	key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Owned HTML detail reader", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"read"}})
	if err != nil {
		t.Fatal("store synthetic read credential")
	}
	var admitted *http.Request
	h := auth.RequireAPIKey(&auth.PgVerifier{Queries: f.q})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admitted = r
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/automation/v1/templates/synthetic", nil).WithContext(f.ctx)
	req.Header.Set("Authorization", "Bearer "+mint.Plaintext)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent || admitted == nil {
		t.Fatal("original API read credential was not admitted")
	}
	user, ok := auth.FromContext(admitted.Context())
	if !ok {
		t.Fatal("admitted key lost its actor")
	}
	authorize, err := auth.APIKeyTransactionAuthorization(admitted.Context(), uuid.Nil, "read")
	if err != nil {
		t.Fatal("original API read receipt was not retained")
	}
	return admitted, user, authorize, key.ID
}

func TestHTMLTemplateOwnedReadRolesAndRetainedConsumerE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	for _, role := range []string{"owner", "sender", "viewer"} {
		t.Run(role, func(t *testing.T) {
			if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: role}); err != nil {
				t.Fatal("set synthetic read role")
			}
			req, user, authorize, _ := ownedHTMLTemplateReadActorE2E(t, f)
			before := htmlAuthoringNativeSnapshotE2E(t, f.s)
			response, closeConsumer, err := f.s.readHTMLTemplateDetailOwnedV1(req.Context(), user.OrgID, user.UserID, template.ID, authorize)
			if closeConsumer != nil {
				defer closeConsumer()
			}
			if err != nil || closeConsumer == nil || response.ID != template.ID || response.Version != template.Version ||
				response.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) || response.HTMLApproval == nil || len(response.HTMLMasterJSON) == 0 {
				t.Fatal("owned detail lost a valid read role or exact canonical revision")
			}
			held := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if held.Global.ParentBytes <= before.Global.ParentBytes || held.Global.DBStagingBytes <= before.Global.DBStagingBytes || held.GlobalGrants <= before.GlobalGrants {
				t.Fatal("native source/canonical buffers were released before serialization")
			}
			if raw, err := json.Marshal(response); err != nil || len(raw) == 0 {
				t.Fatal("serialize the actual retained native response")
			}
			closeConsumer()
			closeConsumer() // The public consumer closure is deliberately idempotent.
			after := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants || after.Organisation != before.Organisation || after.OrganisationGrants != before.OrganisationGrants {
				t.Fatal("owned HTML detail did not settle to its original observer baseline")
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			browser := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+template.ID.String(), "", cookie)
			var detail templateResponse
			if browser.Code != http.StatusOK || json.Unmarshal(browser.Body.Bytes(), &detail) != nil || detail.ID != response.ID || detail.ContentSHA256 != response.ContentSHA256 {
				t.Fatal("browser read did not preserve the same owned detail for its live read role")
			}
			settled := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if settled.Global != before.Global || settled.GlobalGrants != before.GlobalGrants || settled.Organisation != before.Organisation || settled.OrganisationGrants != before.OrganisationGrants {
				t.Fatal("browser read retained native source work after its response completed")
			}
		})
	}
}

func TestHTMLTemplateOwnedReadRechecksOriginalKeyAfterParentWaitE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	req, user, authorize, keyID := ownedHTMLTemplateReadActorE2E(t, f)
	before := htmlAuthoringNativeSnapshotE2E(t, f.s)
	held, _ := holdHTMLTemplateParentE2E(t, f, template.ID)
	t.Cleanup(func() { _ = held.Rollback(f.ctx) })
	type outcome struct {
		response templateResponse
		close    func()
		err      error
	}
	finished := make(chan outcome, 1)
	go func() {
		response, closeConsumer, err := f.s.readHTMLTemplateDetailOwnedV1(req.Context(), user.OrgID, user.UserID, template.ID, authorize)
		finished <- outcome{response, closeConsumer, err}
	}()
	awaitHTMLAuthoringOperationLockE2E(t, f, "-- name: GetHTMLAuthoringTemplateHeaderV1", "transactionid")
	if _, err := f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID}); err != nil {
		t.Fatal("revoke the actual admitted key during its native parent wait")
	}
	if err := held.Commit(f.ctx); err != nil {
		t.Fatal("release original scoped template parent")
	}
	select {
	case result := <-finished:
		if result.close != nil {
			defer result.close()
		}
		if !errors.Is(result.err, auth.ErrMutationPermissionRevoked) || result.close != nil || result.response.ID != uuid.Nil || len(result.response.HTMLMasterJSON) != 0 {
			t.Fatal("revoked original API key received template data or a usable consumer")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("owned HTML detail did not join after the parent wait")
	}
	after := htmlAuthoringNativeSnapshotE2E(t, f.s)
	if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants {
		t.Fatal("refused owned read leaked native body/work ownership")
	}
}

func TestHTMLTemplateOwnedReadRefusesMissingSizeAdmissionWithoutRepairE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	for _, table := range []string{"html_authoring_template_sizes_v1", "html_authoring_revision_sizes_v1"} {
		t.Run(table, func(t *testing.T) {
			template := createHTMLTemplateE2E(t, f)
			req, user, authorize, _ := ownedHTMLTemplateReadActorE2E(t, f)
			// A negative deletion in this exact disposable DB supplies no new
			// measurement, READY state or caller-declared source length.
			query := "DELETE FROM " + table + " WHERE template_id=$1 AND org_id=$2"
			if _, err := f.pool.Exec(f.ctx, query, template.ID, f.org); err != nil { //nolint:rawsql -- fixed literal table names, fixture-only negative cache deletion
				t.Fatal("remove genuine size admission row for refusal fixture")
			}
			before := htmlAuthoringNativeSnapshotE2E(t, f.s)
			state := htmlTemplateSnapshotE2E(t, f)
			response, closeConsumer, err := f.s.readHTMLTemplateDetailOwnedV1(req.Context(), user.OrgID, user.UserID, template.ID, authorize)
			if closeConsumer != nil {
				defer closeConsumer()
			}
			if !errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) || closeConsumer != nil || response.ID != uuid.Nil || len(response.HTMLMasterJSON) != 0 {
				t.Fatal("missing native size admission exposed unowned template content")
			}
			var count int
			if err := f.pool.QueryRow(f.ctx, strings.Replace(query, "DELETE FROM", "SELECT count(*) FROM", 1), template.ID, f.org).Scan(&count); err != nil || count != 0 { //nolint:rawsql -- prove normal reader did not repair fixture's missing cache
				t.Fatal("owned read manufactured a replacement size measurement")
			}
			after := htmlAuthoringNativeSnapshotE2E(t, f.s)
			if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants || state != htmlTemplateSnapshotE2E(t, f) {
				t.Fatal("failed owned detail changed template/audit state or retained body ownership")
			}
		})
	}
}
