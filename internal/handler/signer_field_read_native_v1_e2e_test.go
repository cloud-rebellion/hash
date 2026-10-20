//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	sendengine "github.com/bright-interaction/hash/internal/send"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The M91 row is genuine writer-derived authority for options expansion. A
// missing row must refuse before materializing a visible field; expiry still
// has its original priority. These use actual public creation/review/Send.
func TestOwnedSignerFieldReadMeasurementAndScopeE2E(t *testing.T) {
	for _, scenario := range []string{"visible_baseline", "missing_measurement", "expired_missing_measurement"} {
		t.Run(scenario, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			f.s.Sign.Storage = f.s.Storage
			actor := sendengine.Actor{UserID: &f.user.ID, OrgID: f.org, Via: "test", LawfulBasis: "contract", Authorize: func(_ context.Context, _ pgx.Tx, user *generated.User) error {
				if user == nil || user.ID != f.user.ID || user.OrgID != f.org || user.Role != "owner" {
					return auth.ErrMutationPermissionRevoked
				}
				return nil
			}}
			imported, party, _, _, invitation := ownedRealBrowserManualAutosaveV1(t, q, fieldBrowserPDF("Measured native field response"), 1, actor)
			doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: imported.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			token := strings.TrimPrefix(invitation.Path, "/sign/")
			rows, err := q.f.q.ListFieldsByRecipient(q.f.ctx, generated.ListFieldsByRecipientParams{DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: party.ID, Valid: true}})
			if err != nil || len(rows) == 0 {
				t.Fatal("genuine visible fields absent", err)
			}
			if scenario != "visible_baseline" {
				tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM field_signing_policy_sizes_v1 WHERE field_id=$1 AND document_id=$2 AND org_id=$3", rows[0].ID, doc.ID, q.f.org)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("genuine measurement deletion did not affect exactly one row", err)
				} //nolint:rawsql -- delete genuine derived authority, never forge or refill it
			}
			if scenario == "expired_missing_measurement" {
				tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND document_id=$2", party.ID, doc.ID)
				if err != nil || tag.RowsAffected() != 1 {
					t.Fatal("genuine credential expiry failed", err)
				} //nolint:rawsql -- actual committed credential expiry
			}
			before := nativeCommentWholeState164V1(t, q, doc, q.f.pool)
			measurement := func() string {
				var value string
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(s) ORDER BY field_id),'[]'::jsonb)::text FROM field_signing_policy_sizes_v1 s WHERE document_id=$1 AND org_id=$2", doc.ID, q.f.org).Scan(&value); err != nil {
					t.Fatal("actual field measurement witness failed", err)
				} //nolint:rawsql -- independent read-only whole measurement state
				return value
			}
			beforeMeasurements := measurement()
			response := q.requestV1(token, "/fields")
			q.assertObserversOnlyV1(t)
			if nativeCommentWholeState164V1(t, q, doc, q.f.pool) != before || measurement() != beforeMeasurements {
				t.Fatal("field GET changed business state or manufactured measurement authority")
			}
			want := http.StatusOK
			if scenario == "missing_measurement" {
				want = http.StatusServiceUnavailable
			} else if scenario == "expired_missing_measurement" {
				want = http.StatusGone
			}
			if response.Code != want {
				t.Fatalf("field read status=%d want=%d", response.Code, want)
			}
			if want != http.StatusOK {
				for _, header := range []string{"X-Hash-Document-Id", "X-Hash-Recipient-Id", "X-Hash-PDF-SHA256", "X-Hash-PDF-Pages", "X-Hash-HTML-Source-Commitment", "X-Hash-Materialization-Revision"} {
					if response.Header().Get(header) != "" {
						t.Fatal("refused field read published observation headers")
					}
				}
				var value map[string]json.RawMessage
				if json.Unmarshal(response.Body.Bytes(), &value) == nil && value["fields"] != nil {
					t.Fatal("refused field read published fields")
				}
				return
			}
			var value struct {
				Fields []json.RawMessage `json:"fields"`
				Count  int               `json:"count"`
			}
			if json.Unmarshal(response.Body.Bytes(), &value) != nil || value.Count != len(rows) || len(value.Fields) != len(rows) {
				t.Fatal("genuine visible field set changed count or JSON shape")
			}
			for i, row := range rows {
				want, err := json.Marshal(fieldToDTO(row))
				if err != nil || string(want) != string(value.Fields[i]) {
					t.Fatal("field GET changed current DTO or recipient scope")
				}
			}
		})
	}
}
