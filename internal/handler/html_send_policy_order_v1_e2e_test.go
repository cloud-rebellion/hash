//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
)

// Real application input ordering, with deliberately absent stored report cache.
// This is a refusal fixture, never a cache repair or substitute success journey.
func TestOwnedHTMLSendExpiryBeforeReportCacheE2E(t *testing.T) {
	for _, expired := range []bool{true, false} {
		t.Run(map[bool]string{true: "expired-original-error", false: "live-reaches-cache-refusal"}[expired], func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			f := q.f
			doc := createHTMLContractDocumentE2E(t, f, q.template, q.cookie)
			until := time.Now().UTC().Add(time.Hour)
			if expired {
				until = time.Now().UTC().Add(-time.Hour)
			}
			if _, err := f.pool.Exec(f.ctx, "UPDATE documents SET expires_at=$1 WHERE id=$2 AND org_id=$3", until, doc.ID, f.org); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- explicit synthetic expired input only
			if _, err := f.pool.Exec(f.ctx, "DELETE FROM document_read_report_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org); err != nil {
				t.Fatal(err)
			} //nolint:rawsql -- deliberately unavailable cache, never repaired
			counts := func() string {
				var got string
				err := f.pool.QueryRow(f.ctx, "SELECT concat_ws(':',(SELECT count(*) FROM events WHERE document_id=$1),(SELECT count(*) FROM email_deliveries),(SELECT count(*) FROM send_sealing_intents WHERE document_id=$1),(SELECT count(*) FROM recipients WHERE document_id=$1 AND magic_token_hash IS NOT NULL))", doc.ID).Scan(&got)
				if err != nil {
					t.Fatal(err)
				}
				return got
			} //nolint:rawsql -- finite synthetic mutation oracle
			before := counts()
			actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, u *generated.User) error {
				if u == nil || u.ID != f.user.ID || u.OrgID != f.org || u.Role != "owner" {
					return auth.ErrMutationPermissionRevoked
				}
				return nil
			}}
			out, err := f.s.Send.Send(f.ctx, actor, doc.ID)
			defer out.CloseConsumerV1()
			if expired {
				if !errors.Is(err, sendengine.ErrExpiryTooSoon) {
					t.Fatalf("original expiry did not precede report cache: %v", err)
				}
			} else {
				if !errors.Is(err, pdfadmission.ErrHTMLSendWorkV1) {
					t.Fatalf("live SES control did not reach actual cache refusal: %v", err)
				}
			}
			if len(out.Links) != 0 || out.Status != "" || counts() != before {
				t.Fatal("refused send changed invitations, events or durable state")
			}
			fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil || fresh.Status != "draft" {
				t.Fatal("refusal changed actual draft", err)
			}
		})
	}
}
