//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5/pgconn"
)

// Exercise the real public lookup, retained credential, native SQL owner and
// locked recipient checks. The missing cache is an explicit negative fixture,
// never a repair. Renderer/S3/retention peers remain synthetic as documented by
// the shared fixture; no provider or capacity claim follows from these cases.
func TestOwnedHTMLNegotiationCredentialAndPartyGuardsE2E(t *testing.T) {
	for _, mode := range []string{"rotated token", "party role change blocked", "unchanged credential"} {
		t.Run(mode, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			document, parties := q.createSentV1(t)
			rc := q.lookupV1(t, parties[0].Token)
			notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(parties[0].Token, ""), rc)
			if err != nil {
				t.Fatal(err)
			}
			evidence, err := signerArticle13NoticeEvidence(rc, notice)
			if err != nil {
				t.Fatal(err)
			}

			type state struct{ changes, events, ownerMail int }
			readState := func() state {
				t.Helper()
				var result state
				if err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*)::integer FROM change_requests WHERE document_id=$1),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2),
 (SELECT count(*)::integer FROM email_deliveries WHERE to_email=$3)`, document.ID, q.f.org, q.f.user.Email).Scan(&result.changes, &result.events, &result.ownerMail); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- exact synthetic side-effect witnesses only
				return result
			}
			before := readState()
			switch mode {
			case "rotated token":
				err = q.f.q.RotateRecipientMagicToken(q.f.ctx, generated.RotateRecipientMagicTokenParams{
					ID: rc.Recipient.ID, DocumentID: document.ID,
					MagicTokenHash:      auth.HashMagicToken("synthetic-revoked-negotiation-replacement"),
					MagicTokenExpiresAt: rc.Recipient.MagicTokenExpiresAt,
				})
			case "party role change blocked":
				_, err = q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET role='observer' WHERE id=$1 AND document_id=$2", rc.Recipient.ID, document.ID) //nolint:rawsql -- attempt to break a synthetic immutable party binding
				var databaseError *pgconn.PgError
				if !errors.As(err, &databaseError) || databaseError.Code != "23514" || databaseError.Message != "Branded signing page requires its exact party and field bindings" {
					t.Fatal("database did not enforce the original exact party binding", err)
				}
				var storedRole string
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT role FROM recipients WHERE id=$1 AND document_id=$2", rc.Recipient.ID, document.ID).Scan(&storedRole); err != nil || storedRole != rc.Recipient.Role {
					t.Fatal("rejected role change altered the bound party", err)
				} //nolint:rawsql -- complete fixed role witness in the owned fixture
				err = nil
			}
			if err != nil {
				t.Fatal(err)
			}
			deleted, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", document.ID, q.f.org) //nolint:rawsql -- deliberate missing-cache refusal, never repair
			if err != nil || deleted.RowsAffected() != 1 {
				t.Fatal("negative fixture did not remove exactly one current cache", err)
			}

			err = q.f.s.Sign.RequestChanges(q.f.ctx, rc, sign.ChangeRequestInput{Message: "Synthetic change request", Notice: evidence})
			want := sign.ErrMagicLinkExpired
			if mode != "rotated token" {
				want = sign.ErrSigningAdmissionUnavailableV1
			}
			if !errors.Is(err, want) {
				t.Fatalf("actual locked credential/cache decision = %v, want %v", err, want)
			}
			if mode == "rotated token" && errors.Is(err, sign.ErrSigningAdmissionUnavailableV1) {
				t.Fatal("missing document cache hid the actual revoked credential")
			}
			if after := readState(); after != before {
				t.Fatalf("refused change request wrote a request, audit event or owner email: before=%+v after=%+v", before, after)
			}
			fresh, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: document.ID, OrgID: q.f.org})
			if err != nil || fresh.Status != document.Status || fresh.UpdatedAt != document.UpdatedAt {
				t.Fatal("refused change request changed the original document", err)
			}
			if err := rc.CloseReadV1(); err != nil {
				t.Fatal(err)
			}
			ownedRevisionConsumedV1(t, q)
		})
	}
}
