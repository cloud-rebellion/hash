//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/amendmentauthoring"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestNotice484DirectNativeDiagnosticE2E(t *testing.T) {
	f := newLaterAmendmentFixture483(t, amendments.AgreedNoticeV1)
	var e error
	f.q.f.s.NoticeAccess, e = f.q.runtime.NewLaterAmendmentNoticeAccessV1(f.q.f.s.Storage, f.q.f.s.Cookies, f.q.f.s.PublicURL)
	if e != nil {
		t.Fatal(e)
	}
	candidate := packageLatest223(t, f.q, f.candidate.ID)
	in := amendments.IssueNoticeV1{RequestID: uuid.New(), ExpectedHeadRevision: f.record.Revision, ExpectedDocumentUpdatedAt: candidate.UpdatedAt.Time, Subject: "Synthetic agreed DPA change notice", Text: "Please read the exact later files. Queue acceptance is not a signature.", RecipientEmails: []string{"legal@example.test"}, Reviewed: true}
	credential := auth.SessionPayload{UserID: f.q.f.user.ID, Generation: f.q.f.user.SessionGeneration}
	actor := authoring.Actor{OrgID: f.q.f.org, UserID: f.q.f.user.ID, Authorize: auth.SessionTransactionAuthorization(f.q.f.s.Cookies, f.q.cookie, credential, f.q.f.org)}
	out, e := amendmentauthoring.IssueNoticeV1(f.q.f.ctx, amendmentauthoring.DependenciesV1{Sessions: f.q.f.s.HTMLCreationSessions, Audit: f.q.f.s.Audit, PublicURL: f.q.f.s.PublicURL}, f.q.f.s.NoticeAccess, actor, f.original.ID, f.record.ID, in, "", "")
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		var sqlError *pgconn.PgError
		if errors.As(e, &sqlError) {
			t.Fatalf("native SQL error code=%s constraint=%s routine=%s message=%s", sqlError.Code, sqlError.ConstraintName, sqlError.Routine, sqlError.Message)
		}
		t.Fatalf("native notice failure %T: %v", e, e)
	}
	if out == nil {
		t.Fatal("missing native notice result")
	}
}
