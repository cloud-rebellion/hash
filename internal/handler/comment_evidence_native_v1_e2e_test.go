//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestNativeCommentExactEvidenceV1E2E(t *testing.T) {
	for _, side := range []string{"signer", "sender"} {
		t.Run(side+" binds actual persisted message and detects later divergence", func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			notice := nativeCommentNotice163V1(t, q, parties[0].Token)
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie))
			var created commentResponse
			if response.Code != http.StatusCreated || json.Unmarshal(response.Body.Bytes(), &created) != nil {
				t.Fatal("actual native comment was refused", response.Code)
			}
			rows, err := q.f.q.ListComments(q.f.ctx, doc.ID)
			if err != nil || len(rows) != 1 || rows[0].ID.String() != created.ID || rows[0].Body != nativeCommentBody163V1 || rows[0].AuthorSide != side {
				t.Fatal("actual persisted comment differs", err)
			}
			events, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, Limit: 1000})
			if err != nil {
				t.Fatal(err)
			}
			var event *generated.Event
			for _, row := range events {
				if row.Kind == audit.KindCommentPosted {
					if event != nil {
						t.Fatal("duplicate comment event")
					}
					event = row
				}
			}
			if ok, err := sign.CommentAuditEvidenceMatchesV1(event, rows[0]); !ok || err != nil {
				t.Fatal("actual native event does not bind exact persisted comment", err)
			}
			if bytes.Contains(event.PayloadJson, []byte(nativeCommentBody163V1)) {
				t.Fatal("message body leaked into audit payload")
			}
			// The canonical old event-file exporter still accepts the new additive keys.
			if _, _, _, err := evidence.BuildCeremonyEventsJSON(doc.ID, events); err != nil {
				t.Fatal("new comment evidence broke existing ceremony event export", err)
			}
			originalEvent := bytes.Clone(event.PayloadJson)
			baseline := captureNativeCommentState163V1(t, q, doc)
			for _, change := range []string{"body", "id"} {
				func() {
					tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
					defer rollbackHTMLQueryFixtureV1(t, tx)
					statement := "UPDATE document_comments SET body=overlay(body placing 'X' from 1 for 1) WHERE id=$1"
					if change == "id" {
						statement = "UPDATE document_comments SET id=gen_random_uuid() WHERE id=$1"
					}
					if _, err := tx.Exec(q.f.ctx, statement, rows[0].ID); err != nil {
						t.Fatal(err)
					}
					changed, err := generated.New(tx).ListComments(q.f.ctx, doc.ID)
					if err != nil || len(changed) != 1 {
						t.Fatal("actual divergent row unavailable", err)
					}
					if ok, err := sign.CommentAuditEvidenceMatchesV1(event, changed[0]); ok || err == nil {
						t.Fatal("audit commitment accepted divergent persisted " + change)
					}
				}()
				if !bytes.Equal(originalEvent, event.PayloadJson) {
					t.Fatal("evidence check rewrote original event")
				}
				assertNativeCommentUnchanged163V1(t, q, doc, baseline)
			}
			ownedRevisionConsumedV1(t, q)
		})
		t.Run(side+" altered INSERT body rolls back all native effects", func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			doc, parties := q.createSentV1(t)
			notice := nativeCommentNotice163V1(t, q, parties[0].Token)
			tag := "comment242_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			fn, trig, seq := tag+"_fn", tag+"_trg", tag+"_seq"
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				if _, err := q.f.pool.Exec(cleanup, fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON document_comments;DROP FUNCTION IF EXISTS %s();DROP SEQUENCE IF EXISTS %s", trig, fn, seq)); err != nil {
					t.Error(err)
				}
			})
			query := fmt.Sprintf("CREATE SEQUENCE %s;CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.document_id='%s'::uuid THEN PERFORM nextval('%s');NEW.body=overlay(NEW.body placing 'X' from 1 for 1);END IF;RETURN NEW;END $$;CREATE TRIGGER %s BEFORE INSERT ON document_comments FOR EACH ROW EXECUTE FUNCTION %s()", seq, fn, doc.ID.String(), seq, trig, fn)
			if _, err := q.f.pool.Exec(q.f.ctx, query); err != nil {
				t.Fatal(err)
			}
			before := captureNativeCommentState163V1(t, q, doc)
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, nativeCommentRequest163V1(t, q, q.f.ctx, doc, side, parties[0].Token, notice, q.cookie))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("mutated actual INSERT body did not refuse native request", response.Code)
			}
			var calls int64
			var called bool
			if err := q.f.pool.QueryRow(q.f.ctx, "SELECT last_value,is_called FROM "+seq).Scan(&calls, &called); err != nil || !called || calls != 1 {
				t.Fatal("actual before-insert fault was not exercised", err)
			}
			assertNativeCommentUnchanged163V1(t, q, doc, before)
		})
	}
}
