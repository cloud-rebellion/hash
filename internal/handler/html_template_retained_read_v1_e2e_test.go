//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func TestHTMLTemplateRetained783ReadTenantAndLiveKeyRefusalsE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	f := q.f
	template := createHTMLTemplateE2E(t, f)
	selection := htmlTemplateReadSelectionV1{Version: template.Version, ExpectedContentSHA256: hex.EncodeToString(template.HtmlContentSha256)}
	otherOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Example other design organization", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: otherOrg.ID, Email: uuid.NewString() + "@example.test", Name: "Example other owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	foreign := f
	foreign.org, foreign.user = otherOrg.ID, otherUser
	foreignTemplate := createHTMLTemplateE2E(t, foreign)
	if actual, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: foreignTemplate.ID, OrgID: foreign.org}); err != nil || actual.ID != foreignTemplate.ID {
		t.Fatal("foreign-parent refusal fixture is not a genuine measured native template", err)
	}
	req, actor, authorize, keyID := ownedHTMLTemplateReadActorE2E(t, f)
	before := q.snapshotV1(t)
	legacy, selected, closeSelected, err := f.s.readHTMLTemplateSelectionOwnedV1(req.Context(), actor.OrgID, actor.UserID, foreignTemplate.ID, authorize, htmlTemplateReadSelectionV1{Version: foreignTemplate.Version, ExpectedContentSHA256: hex.EncodeToString(foreignTemplate.HtmlContentSha256)})
	if closeSelected != nil {
		defer closeSelected()
	}
	if !errors.Is(err, errTemplateNotFound) || closeSelected != nil || legacy.ID != uuid.Nil || selected.TemplateID != uuid.Nil || len(selected.HTMLMasterJSON) != 0 {
		t.Fatal("real foreign parent exposed retained source or a consumer", err)
	}
	held, holderPID := holdHTMLTemplateParentE2E(t, f, template.ID)
	t.Cleanup(func() { _ = held.Rollback(f.ctx) })
	type outcome struct {
		legacy templateResponse
		source htmlTemplateDesignSourceResponseV1
		close  func()
		err    error
	}
	finished := make(chan outcome, 1)
	go func() {
		legacy, source, closeSource, err := f.s.readHTMLTemplateSelectionOwnedV1(req.Context(), actor.OrgID, actor.UserID, template.ID, authorize, selection)
		finished <- outcome{legacy, source, closeSource, err}
	}()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetHTMLAuthoringTemplateHeaderV1", "transactionid", f.pool.Config().ConnConfig.RuntimeParams["application_name"])
	ownedReadWaitV1(t, q, holderPID, "-- name: GetHTMLAuthoringTemplateHeaderV1")
	if _, err = f.q.DeleteAPIKey(f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: f.user.ID}); err != nil {
		t.Fatal("revoke original admitted key during parent wait", err)
	}
	if err = held.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case result := <-finished:
		if result.close != nil {
			defer result.close()
		}
		if !errors.Is(result.err, auth.ErrMutationPermissionRevoked) || result.close != nil || result.legacy.ID != uuid.Nil || result.source.TemplateID != uuid.Nil || len(result.source.HTMLMasterJSON) != 0 {
			t.Fatal("revoked original credential received retained source or a consumer", result.err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("retained reader failed to join after parent wait")
	}
	after := q.snapshotV1(t)
	if after.Global != before.Global || after.GlobalGrants != before.GlobalGrants || after.Organisation != before.Organisation || after.OrganisationGrants != before.OrganisationGrants {
		t.Fatal("refused retained reads leaked native body ownership")
	}
}
