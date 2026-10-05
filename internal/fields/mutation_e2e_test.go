//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fields

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// These fixtures use real PostgreSQL transactions and signed sessions. All
// document, recipient and evidence rows are synthetic; no storage or mail runs.
func TestFieldMutationFinalAuthorizationRollsBackExactStateE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldMutationE2E(t)
			before := f.snapshot(t)
			actor := f.actor(t)
			original := actor.Authorize
			checks := 0
			actor.Authorize = func(ctx context.Context, tx pgx.Tx, user *generated.User) error {
				if err := original(ctx, tx, user); err != nil {
					return err
				}
				checks++
				if user.ID != f.user.ID || user.OrgID != f.orgID || user.Role != "sender" {
					t.Error("callback did not receive the fresh authorized member")
				}
				var isolation string
				if err := tx.QueryRow(ctx, `SELECT current_setting('transaction_isolation')`).Scan(&isolation); err != nil {
					return err
				}
				deadline, bounded := ctx.Deadline()
				if isolation != "read committed" || !bounded || time.Until(deadline) > 10*time.Second {
					t.Error("field mutation lacks its bounded fresh-snapshot transaction")
				}
				if checks == 2 {
					var rows, events int
					if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM document_fields WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&rows, &events); err != nil {
						return err
					}
					wantRows := 2
					if operation == "delete" {
						wantRows = 0
					}
					if rows != wantRows || events != 1 {
						t.Errorf("final callback missed real staged field/audit writes: %d/%d", rows, events)
					}
					return auth.ErrMutationCredentialExpired
				}
				return nil
			}
			row, err := f.mutate(f.ctx, operation, actor)
			if row != nil || !errors.Is(err, auth.ErrMutationCredentialExpired) || checks != 2 {
				t.Fatalf("final authorization result=%t error=%v checks=%d", row != nil, err, checks)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldMutationAuditFailureRollsBackExactStateE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldMutationE2E(t)
			before := f.snapshot(t)
			f.logger.fail = true
			row, err := f.mutate(f.ctx, operation, f.actor(t))
			if row != nil || !errors.Is(err, errFieldFixtureAudit) || f.logger.staged != 1 {
				t.Fatalf("real audit append failure result=%t error=%v staged=%d", row != nil, err, f.logger.staged)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldMutationRequiresOriginalGuardForEverySurfaceE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	before := f.snapshot(t)
	for _, via := range []string{"", "rest", "mcp", "automation", "worker", "test"} {
		actor := f.actor(t)
		actor.Via, actor.Authorize = via, nil
		for _, operation := range []string{"create", "delete"} {
			if row, err := f.mutate(f.ctx, operation, actor); row != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Errorf("missing original guard via=%q operation=%s result=%t error=%v", via, operation, row != nil, err)
			}
		}
	}
	for _, missing := range []string{"user", "organization"} {
		actor := f.actor(t)
		if missing == "user" {
			actor.UserID = uuid.Nil
		} else {
			actor.OrgID = uuid.Nil
		}
		if row, err := f.mutate(f.ctx, "create", actor); row != nil || !errors.Is(err, auth.ErrMutationPermissionRevoked) {
			t.Errorf("missing %s result=%t error=%v", missing, row != nil, err)
		}
	}
	f.assertUnchanged(t, before)
}

func TestFieldMutationChecksLiveSessionAfterParentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout"} {
		for _, operation := range []string{"create", "delete"} {
			t.Run(change+"/"+operation, func(t *testing.T) {
				f := setupFieldMutationE2E(t)
				actor := f.actor(t)
				blocked, pid := f.holdParent(t)
				done := make(chan fieldMutationResult, 1)
				go func() { row, err := f.mutate(f.ctx, operation, actor); done <- fieldMutationResult{row, err} }()
				f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
				query := `UPDATE users SET role='viewer' WHERE id=$1`
				if change == "logout" {
					query = `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`
				}
				if _, err := f.pool.Exec(f.ctx, query, f.user.ID); err != nil {
					t.Fatal(err)
				}
				before := f.snapshotWithDB(t, blocked)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				result := receiveFieldMutation(t, done)
				if result.field != nil || !errors.Is(result.err, auth.ErrMutationPermissionRevoked) {
					t.Fatalf("stale session after parent wait result=%t error=%v", result.field != nil, result.err)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestFieldAuthoringQueriesAndEngineRejectSoftDeletedDraftE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	if err := f.q.DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	before := f.snapshot(t)
	if _, err := f.q.CreateDraftField(f.ctx, f.draftParams()); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct authoring create on soft-deleted draft error=%v", err)
	}
	if _, err := f.q.DeleteFieldByID(f.ctx, generated.DeleteFieldByIDParams{ID: f.field.ID, OrgID: f.orgID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct authoring delete on soft-deleted draft error=%v", err)
	}
	for _, operation := range []string{"create", "delete"} {
		if row, err := f.mutate(f.ctx, operation, f.actor(t)); row != nil || !errors.Is(err, ErrDocumentNotFound) {
			t.Errorf("deleted parent operation=%s result=%t error=%v", operation, row != nil, err)
		}
	}
	f.assertUnchanged(t, before)
}

func TestFieldMutationRejectsSoftDeleteCommittedDuringParentWaitE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldMutationE2E(t)
			blocked, pid := f.holdParent(t)
			actor := f.actor(t)
			done := make(chan fieldMutationResult, 1)
			go func() { row, err := f.mutate(f.ctx, operation, actor); done <- fieldMutationResult{row, err} }()
			f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
			if err := f.q.WithTx(blocked).DeleteDraftDocument(f.ctx, generated.DeleteDraftDocumentParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
				t.Fatal(err)
			}
			before := f.snapshotWithDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			result := receiveFieldMutation(t, done)
			if result.field != nil || !errors.Is(result.err, ErrDocumentNotFound) {
				t.Fatalf("soft-delete after wait result=%t error=%v", result.field != nil, result.err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldSignatureEligibilityUsesFreshParentAfterWaitE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET source_kind='pdf' WHERE id=$1`, f.doc.ID); err != nil {
		t.Fatal(err)
	}
	blocked, pid := f.holdParent(t)
	actor := f.actor(t)
	input := f.input()
	input.Type = "signature"
	done := make(chan fieldMutationResult, 1)
	go func() {
		row, err := f.engine.Create(f.ctx, actor, f.doc.ID, input)
		done <- fieldMutationResult{row, err}
	}()
	f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
	if _, err := blocked.Exec(f.ctx, `UPDATE documents SET source_kind='blocks',updated_at=clock_timestamp() WHERE id=$1`, f.doc.ID); err != nil {
		t.Fatal(err)
	}
	before := f.snapshotWithDB(t, blocked)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	result := receiveFieldMutation(t, done)
	var invalid *ValidationError
	if result.field != nil || !errors.As(result.err, &invalid) {
		t.Fatalf("signature admitted from stale PDF source result=%t error=%v", result.field != nil, result.err)
	}
	f.assertUnchanged(t, before)
}

func TestFieldMutationsPreserveAnomalousDraftEvidenceE2E(t *testing.T) {
	for _, evidence := range []string{"signature", "accepted", "empty_value", "completed_field"} {
		for _, operation := range []string{"create", "delete"} {
			t.Run(evidence+"/"+operation, func(t *testing.T) {
				f := setupFieldMutationE2E(t)
				switch evidence {
				case "signature":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET type='signature' WHERE id=$1`, f.field.ID); err != nil {
						t.Fatal(err)
					}
					if _, err := f.q.InsertSignature(f.ctx, generated.InsertSignatureParams{DocumentID: f.doc.ID, RecipientID: f.recipient.ID, FieldID: f.field.ID, Font: "synthetic", TypedName: "Synthetic captured response", ImageStorageKey: f.orgID.String() + "/fixture/signature.png", ImageSha256: make([]byte, 32), ImageVersionID: pgtype.Text{String: "synthetic-pin", Valid: true}}); err != nil {
						t.Fatal(err)
					}
				case "accepted":
					if _, err := f.pool.Exec(f.ctx, `UPDATE recipients SET status='accepted' WHERE id=$1`, f.recipient.ID); err != nil {
						t.Fatal(err)
					}
				case "empty_value":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET value='' WHERE id=$1`, f.field.ID); err != nil {
						t.Fatal(err)
					}
				case "completed_field":
					if _, err := f.pool.Exec(f.ctx, `UPDATE document_fields SET completed_at=clock_timestamp() WHERE id=$1`, f.field.ID); err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t)
				if operation == "delete" && evidence != "accepted" {
					if _, err := f.q.DeleteFieldByID(f.ctx, generated.DeleteFieldByIDParams{ID: f.field.ID, OrgID: f.orgID}); !errors.Is(err, pgx.ErrNoRows) {
						t.Fatalf("direct SQL deleted captured %s evidence: %v", evidence, err)
					}
					f.assertUnchanged(t, before)
				}
				if row, err := f.mutate(f.ctx, operation, f.actor(t)); row != nil || !errors.Is(err, ErrDocumentHasEvidence) {
					t.Fatalf("captured draft operation=%s result=%t error=%v", operation, row != nil, err)
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestFieldMutationsPreservePendingPrivacyReviewE2E(t *testing.T) {
	for _, linked := range []bool{true, false} {
		for _, status := range []string{"open", "in_progress"} {
			for _, operation := range []string{"create", "delete"} {
				t.Run(fmt.Sprintf("linked_%t/%s/%s", linked, status, operation), func(t *testing.T) {
					f := setupFieldMutationE2E(t)
					f.privacyRequest(t, f.q, linked, status)
					before := f.snapshot(t)
					if row, err := f.mutate(f.ctx, operation, f.actor(t)); row != nil || !errors.Is(err, ErrPendingPrivacyReview) {
						t.Fatalf("pending privacy review result=%t error=%v", row != nil, err)
					}
					f.assertUnchanged(t, before)
				})
			}
		}
	}
}

func TestFieldPrivacyReviewClosedAndUnrelatedScopeAllowAuthoringE2E(t *testing.T) {
	for _, scope := range []string{"linked_fulfilled", "linked_denied", "linked_withdrawn", "global_fulfilled", "global_denied", "global_withdrawn", "other_document", "other_tenant"} {
		for _, operation := range []string{"create", "delete"} {
			t.Run(scope+"/"+operation, func(t *testing.T) {
				f := setupFieldMutationE2E(t)
				switch scope {
				case "other_document":
					other, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.orgID, SenderID: f.user.ID, Name: "Unrelated draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
					if err != nil {
						t.Fatal(err)
					}
					if _, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.orgID, DocumentID: pgtype.UUID{Bytes: other.ID, Valid: true}, SubjectEmail: "unrelated@example.test", SubjectName: "Unrelated subject", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
						t.Fatal(err)
					}
				case "other_tenant":
					foreign := setupFieldMutationE2E(t)
					foreign.privacyRequest(t, foreign.q, false, "in_progress")
				default:
					parts := strings.SplitN(scope, "_", 2)
					f.privacyRequest(t, f.q, parts[0] == "linked", parts[1])
				}
				identityBefore := f.identitySnapshot(t)
				if row, err := f.mutate(f.ctx, operation, f.actor(t)); row == nil || err != nil {
					t.Fatalf("closed/unrelated review operation=%s result=%t error=%v", operation, row != nil, err)
				}
				var fields, events int
				if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_fields WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&fields, &events); err != nil {
					t.Fatal(err)
				}
				wantFields := 2
				if operation == "delete" {
					wantFields = 0
				}
				if fields != wantFields || events != 1 || f.logger.published != 1 || f.identitySnapshot(t) != identityBefore {
					t.Fatalf("allowed field mutation affected other identity/state: fields/events/publications=%d/%d/%d", fields, events, f.logger.published)
				}
			})
		}
	}
}

func TestFieldMutationSeesLinkedPrivacyRequestCommittedDuringParentWaitE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldMutationE2E(t)
			blocked, pid := f.holdParent(t)
			actor := f.actor(t)
			done := make(chan fieldMutationResult, 1)
			go func() { row, err := f.mutate(f.ctx, operation, actor); done <- fieldMutationResult{row, err} }()
			f.awaitBlocked(t, pid, "-- name: GetDocumentForUpdate")
			f.privacyRequest(t, f.q.WithTx(blocked), true, "in_progress")
			before := f.snapshotWithDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			result := receiveFieldMutation(t, done)
			if result.field != nil || !errors.Is(result.err, ErrPendingPrivacyReview) {
				t.Fatalf("fresh linked privacy review result=%t error=%v", result.field != nil, result.err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldPrivacyExclusiveFenceRefusesImmediatelyAndRetriesFreshE2E(t *testing.T) {
	for _, operation := range []string{"create", "delete"} {
		t.Run(operation, func(t *testing.T) {
			f := setupFieldMutationE2E(t)
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = blocked.Rollback(context.Background()) })
			if _, err := blocked.Exec(f.ctx, `SELECT pg_advisory_xact_lock(hash_collab_archive_dsr_lock_key($1::uuid))`, f.orgID); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(f.ctx, time.Second)
			started := time.Now()
			row, err := f.mutate(ctx, operation, f.actor(t))
			elapsed := time.Since(started)
			cancel()
			if row != nil || !errors.Is(err, ErrPrivacyReviewChanging) || elapsed >= 900*time.Millisecond {
				t.Fatalf("exclusive privacy fence result=%t error=%v elapsed=%s", row != nil, err, elapsed)
			}
			f.assertUnchanged(t, before)
			f.privacyRequest(t, f.q.WithTx(blocked), false, "in_progress")
			withPending := f.snapshotWithDB(t, blocked)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if row, err := f.mutate(f.ctx, operation, f.actor(t)); row != nil || !errors.Is(err, ErrPendingPrivacyReview) {
				t.Fatalf("retry missed committed global review result=%t error=%v", row != nil, err)
			}
			f.assertUnchanged(t, withPending)
		})
	}
}

func TestFieldValidationAndScopeFailuresPreserveExactStateE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	foreign := setupFieldMutationE2E(t)
	before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
	cases := map[string]func(*CreateInput){
		"unknown_type":            func(in *CreateInput) { in.Type = "name_auto" },
		"page_limit":              func(in *CreateInput) { in.Page = 1001 },
		"x_negative":              func(in *CreateInput) { in.XPct = -1 },
		"y_limit":                 func(in *CreateInput) { in.YPct = 101 },
		"zero_width":              func(in *CreateInput) { in.WPct = 0 },
		"negative_height":         func(in *CreateInput) { in.HPct = -1 },
		"outside_horizontal_page": func(in *CreateInput) { in.XPct, in.WPct = 90, 20 },
		"outside_vertical_page":   func(in *CreateInput) { in.YPct, in.HPct = 99, 5 },
		"nonfinite_x":             func(in *CreateInput) { in.XPct = math.NaN() },
		"nonfinite_y":             func(in *CreateInput) { in.YPct = math.Inf(1) },
		"nonfinite_width":         func(in *CreateInput) { in.WPct = math.Inf(-1) },
		"nonfinite_height":        func(in *CreateInput) { in.HPct = math.NaN() },
		"label_control":           func(in *CreateInput) { in.Label = "Subject\ncontrol" },
		"label_utf8":              func(in *CreateInput) { in.Label = string([]byte{0xff}) },
		"label_rune_limit":        func(in *CreateInput) { in.Label = strings.Repeat("a", 201) },
		"options_array":           func(in *CreateInput) { in.Options = json.RawMessage(`[]`) },
		"options_malformed":       func(in *CreateInput) { in.Options = json.RawMessage(`{"bad":`) },
		"options_limit": func(in *CreateInput) {
			in.Options = json.RawMessage(`{"oversized":"` + strings.Repeat("x", 128*1024) + `"}`)
		},
		"signature_on_blocks":        func(in *CreateInput) { in.Type = "signature" },
		"dropdown_no_choices":        func(in *CreateInput) { in.Type = "dropdown" },
		"dropdown_duplicate_choices": func(in *CreateInput) { in.Type = "dropdown"; in.Options = json.RawMessage(`{"choices":["A","A"]}`) },
		"dropdown_empty_choice":      func(in *CreateInput) { in.Type = "dropdown"; in.Options = json.RawMessage(`{"choices":[" "]}`) },
		"dropdown_control_choice":    func(in *CreateInput) { in.Type = "dropdown"; in.Options = json.RawMessage(`{"choices":["A\nB"]}`) },
		"dropdown_choice_size": func(in *CreateInput) {
			in.Type = "dropdown"
			in.Options = json.RawMessage(`{"choices":["` + strings.Repeat("x", 513) + `"]}`)
		},
		"quantized_zero_width": func(in *CreateInput) { in.WPct = 0.00001 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := f.input()
			mutate(&input)
			row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input)
			var invalid *ValidationError
			if row != nil || !errors.As(err, &invalid) {
				t.Fatalf("invalid field result=%t error=%v", row != nil, err)
			}
			f.assertUnchanged(t, before)
		})
	}
	input := f.input()
	input.RecipientID = &foreign.recipient.ID
	if row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input); row != nil || !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("foreign recipient field result=%t error=%v", row != nil, err)
	}
	if row, err := f.engine.Delete(f.ctx, f.actor(t), f.doc.ID, foreign.field.ID); row != nil || !errors.Is(err, ErrFieldNotFound) {
		t.Errorf("foreign field delete result=%t error=%v", row != nil, err)
	}
	if row, err := f.engine.Create(f.ctx, f.actor(t), foreign.doc.ID, f.input()); row != nil || !errors.Is(err, ErrDocumentNotFound) {
		t.Errorf("foreign document create result=%t error=%v", row != nil, err)
	}
	params := f.draftParams()
	params.OrgID = foreign.orgID
	if _, err := f.q.CreateDraftField(f.ctx, params); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct authoring SQL ignored tenant scope: %v", err)
	}
	if _, err := f.q.DeleteFieldByID(f.ctx, generated.DeleteFieldByIDParams{ID: f.field.ID, OrgID: foreign.orgID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("direct field delete ignored tenant scope: %v", err)
	}
	f.assertUnchanged(t, before)
	foreign.assertUnchanged(t, foreignBefore)
}

func TestFieldSuccessfulAuthoringPreservesIdentityAndValidAuditChainE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	identityBefore := f.identitySnapshot(t)
	actor := f.actor(t)
	actor.Via, actor.Tool, actor.IP, actor.UserAgent = "mcp", "add_document_field", "192.0.2.45", "synthetic-field-fixture"
	input := f.input()
	input.Type, input.Page, input.Options = "dropdown", -1, json.RawMessage(`{"choices":["Choice A","Choice B"]}`)
	created, err := f.engine.Create(f.ctx, actor, f.doc.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == uuid.Nil || created.DocumentID != f.doc.ID || !created.RecipientID.Valid || uuid.UUID(created.RecipientID.Bytes) != f.recipient.ID || created.Page != 1 || created.Type != "dropdown" || !created.Required || !created.Label.Valid || created.Label.String != input.Label || created.Value.Valid || created.CompletedAt.Valid {
		t.Fatal("field create did not preserve validated authoring scope and values")
	}
	for name, pair := range map[string]struct {
		value pgtype.Numeric
		want  float64
	}{"x": {created.XPct, input.XPct}, "y": {created.YPct, input.YPct}, "width": {created.WPct, input.WPct}, "height": {created.HPct, input.HPct}} {
		value, err := pair.value.Float64Value()
		if err != nil || !value.Valid || value.Float64 != pair.want {
			t.Errorf("%s percentage persisted=%v error=%v, want %v", name, value, err, pair.want)
		}
	}
	var options map[string]any
	if json.Unmarshal(created.OptionsJson, &options) != nil || !reflect.DeepEqual(options["choices"], []any{"Choice A", "Choice B"}) {
		t.Fatal("field options did not retain the validated JSON object")
	}
	actor.Tool = "delete_document_field"
	deleted, err := f.engine.Delete(f.ctx, actor, f.doc.ID, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(deleted, created) {
		t.Fatal("field delete did not return the complete original removed row")
	}
	if f.identitySnapshot(t) != identityBefore {
		t.Fatal("field authoring changed parent state or recipient credential/routing")
	}
	events, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.orgID, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || f.logger.published != 2 {
		t.Fatalf("committed field audit/publication count=%d/%d", len(events), f.logger.published)
	}
	for i, event := range events {
		wantKind, wantTool := "document.field_added", "add_document_field"
		if i == 1 {
			wantKind, wantTool = "document.field_deleted", "delete_document_field"
		}
		var payload map[string]any
		if json.Unmarshal(event.PayloadJson, &payload) != nil || event.Kind != wantKind || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != f.user.ID || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != f.doc.ID || payload["field_id"] != created.ID.String() || payload["type"] != "dropdown" || payload["via"] != "mcp" || payload["tool"] != wantTool || !event.Ua.Valid || event.Ua.String != actor.UserAgent || event.Ip == nil || event.Ip.String() != actor.IP {
			t.Fatalf("field audit %d lost canonical actor, immutable scope or operation provenance", i)
		}
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(events)
	result := verifier.Result()
	if !result.OK || !result.Complete || result.TotalChecked != 2 {
		t.Fatalf("field authoring audit chain failed: %+v", result)
	}
}

func TestFieldOptionsDatabaseUnsafeValuesRejectBeforeMutationE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	before := f.snapshot(t)
	for name, raw := range map[string]string{
		"nested_nul":         `{"metadata":{"value":"\u0000"}}`,
		"nul_key":            `{"metadata":{"\u0000":true}}`,
		"unpaired_surrogate": `{"metadata":"\ud800"}`,
		"numeric_overflow":   `{"metadata":1e131072}`,
		"scale_overflow":     `{"metadata":1e-16384}`,
		"positive_expansion": `{"metadata":1e100000}`,
		"negative_expansion": `{"metadata":1e-16383}`,
		"combined_expansion": `{"a":1e10000,"b":1e10000}`,
		"nesting":            `{"metadata":` + strings.Repeat("[", 32) + `0` + strings.Repeat("]", 32) + `}`,
	} {
		t.Run(name, func(t *testing.T) {
			input := f.input()
			input.Options = json.RawMessage(raw)
			row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input)
			var invalid *ValidationError
			if row != nil || !errors.As(err, &invalid) || invalid.Field != "options" {
				t.Fatalf("database-unsafe options result=%t error=%v", row != nil, err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestFieldPDFSignatureAndInternalSigningPrimitiveRemainSupportedE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET source_kind='pdf' WHERE id=$1`, f.doc.ID); err != nil {
		t.Fatal(err)
	}
	input := f.input()
	input.Type, input.RecipientID = "signature", nil
	before := f.snapshot(t)
	var invalid *ValidationError
	if row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input); row != nil || !errors.As(err, &invalid) {
		t.Fatalf("unassigned PDF signature result=%t error=%v", row != nil, err)
	}
	f.assertUnchanged(t, before)
	input.RecipientID = &f.recipient.ID
	row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input)
	if err != nil || row == nil || row.Type != "signature" {
		t.Fatalf("valid assigned PDF signature result=%t error=%v", row != nil, err)
	}
	f.publishSyntheticSend(t)
	params := f.draftParams()
	params.Type = "signature"
	if _, err := f.q.CreateDraftField(f.ctx, params); !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("draft primitive authored a sent document: %v", err)
	}
	if row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, input); row != nil || !errors.Is(err, ErrDocumentNotDraft) {
		t.Errorf("engine authored a sent document result=%t error=%v", row != nil, err)
	}
	materialized, err := f.q.CreateField(f.ctx, generated.CreateFieldParams{DocumentID: f.doc.ID, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "signature", Page: 1, XPct: fieldNumber(10), YPct: fieldNumber(10), WPct: fieldNumber(20), HPct: fieldNumber(5), Required: true, OptionsJson: json.RawMessage(`{}`)})
	if err != nil || materialized == nil || materialized.DocumentID != f.doc.ID {
		t.Fatalf("internal sent-document signing primitive was broken result=%t error=%v", materialized != nil, err)
	}
}

func TestFieldLimitRefusalRollsBackAndDeletionReopensOneSlotE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	f.seedAdditionalFields(t, MaxFieldsPerDocument-1)
	before := f.snapshot(t)
	if row, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, f.input()); row != nil || !errors.Is(err, ErrFieldLimitReached) {
		t.Fatalf("document field cap result=%t error=%v", row != nil, err)
	}
	f.assertUnchanged(t, before)
	identityBefore := f.identitySnapshot(t)
	if _, err := f.engine.Delete(f.ctx, f.actor(t), f.doc.ID, f.field.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.engine.Create(f.ctx, f.actor(t), f.doc.ID, f.input()); err != nil {
		t.Fatal(err)
	}
	var count, events int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_fields WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&count, &events); err != nil {
		t.Fatal(err)
	}
	if count != MaxFieldsPerDocument || events != 2 || f.logger.published != 2 || f.identitySnapshot(t) != identityBefore {
		t.Fatalf("reopened field slot count/audits/publications=%d/%d/%d or identity changed", count, events, f.logger.published)
	}
}

func TestFieldConcurrentFinalSlotCreatesSerializeOnParentE2E(t *testing.T) {
	f := setupFieldMutationE2E(t)
	f.seedAdditionalFields(t, MaxFieldsPerDocument-2)
	identityBefore := f.identitySnapshot(t)
	blocked, pid := f.holdParent(t)
	actor := f.actor(t)
	done := make(chan fieldMutationResult, 2)
	for _, label := range []string{"Synthetic final slot A", "Synthetic final slot B"} {
		input := f.input()
		input.Label = label
		go func() {
			row, err := f.engine.Create(f.ctx, actor, f.doc.ID, input)
			done <- fieldMutationResult{row, err}
		}()
	}
	f.awaitNBlocked(t, pid, "-- name: GetDocumentForUpdate", 2)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	committed, refused := 0, 0
	for range 2 {
		result := receiveFieldMutation(t, done)
		if result.field != nil && result.err == nil {
			committed++
		} else if result.field == nil && errors.Is(result.err, ErrFieldLimitReached) {
			refused++
		} else {
			t.Fatalf("competing final-slot create result=%t error=%v", result.field != nil, result.err)
		}
	}
	var count, events int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_fields WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)`, f.doc.ID).Scan(&count, &events); err != nil {
		t.Fatal(err)
	}
	if committed != 1 || refused != 1 || count != MaxFieldsPerDocument || events != 1 || f.logger.published != 1 || f.identitySnapshot(t) != identityBefore {
		t.Fatalf("final-slot serialization commits/refusals/fields/events/publications=%d/%d/%d/%d/%d", committed, refused, count, events, f.logger.published)
	}
}

var errFieldFixtureAudit = errors.New("synthetic field audit append failure")

type fieldMutationAudit struct {
	logger            *audit.Logger
	fail              bool
	staged, published int
}

func (a *fieldMutationAudit) LogTx(ctx context.Context, tx pgx.Tx, entry audit.Entry) (audit.PendingEvent, error) {
	pending, err := a.logger.LogTx(ctx, tx, entry)
	if err == nil {
		a.staged++
		if a.fail {
			return audit.PendingEvent{}, errFieldFixtureAudit
		}
	}
	return pending, err
}
func (a *fieldMutationAudit) Publish(pending audit.PendingEvent) {
	a.published++
	a.logger.Publish(pending)
}

type fieldMutationFixture struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	q         *generated.Queries
	engine    *MutationEngine
	logger    *fieldMutationAudit
	orgID     uuid.UUID
	user      *generated.User
	doc       *generated.Document
	recipient *generated.Recipient
	field     *generated.DocumentField
	cookies   *auth.SignedCookie
}

func setupFieldMutationE2E(t *testing.T) *fieldMutationFixture {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	ctx := context.Background()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	migrationDB := stdlib.OpenDB(*config.ConnConfig)
	if err := mdb.RunMigrations(migrationDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = migrationDB.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Field mutation " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := pool.Exec(cleanupCtx, `DELETE FROM orgs WHERE id=$1`, org.ID); err != nil {
			t.Error(err)
		}
	})
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@field-owner.test", Name: "Synthetic field sender", Role: "sender", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "Synthetic field draft", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID, Role: "signer", Email: "synthetic@field-" + org.ID.String() + ".test", Name: "Synthetic recipient", Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	field, err := q.CreateField(ctx, generated.CreateFieldParams{DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Type: "text", Page: 1, XPct: fieldNumber(10), YPct: fieldNumber(10), WPct: fieldNumber(20), HPct: fieldNumber(5), Required: true, Label: pgtype.Text{String: "Existing synthetic field", Valid: true}, OptionsJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := auth.NewSignedCookie(strings.Repeat("5b", 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := &fieldMutationAudit{logger: audit.New(q, pool)}
	return &fieldMutationFixture{ctx: ctx, pool: pool, q: q, engine: &MutationEngine{Pool: pool, Audit: logger}, logger: logger, orgID: org.ID, user: user, doc: doc, recipient: recipient, field: field, cookies: cookies}
}

func fieldNumber(value int64) pgtype.Numeric {
	var out pgtype.Numeric
	_ = out.Scan(fmt.Sprint(value))
	return out
}

func (f *fieldMutationFixture) actor(t *testing.T) Actor {
	t.Helper()
	session := auth.SessionPayload{UserID: f.user.ID, Generation: f.user.SessionGeneration}
	raw, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	cookie := f.cookies.Mint(raw, time.Hour)
	return Actor{OrgID: f.orgID, UserID: f.user.ID, Via: "test", Authorize: auth.SessionTransactionAuthorization(f.cookies, cookie, session, f.orgID)}
}
func (f *fieldMutationFixture) input() CreateInput {
	return CreateInput{RecipientID: &f.recipient.ID, Type: "text", Page: 1, XPct: 10.5, YPct: 15.25, WPct: 20, HPct: 5, Required: true, Label: "New synthetic field", Options: json.RawMessage(`{}`)}
}
func (f *fieldMutationFixture) draftParams() generated.CreateDraftFieldParams {
	return generated.CreateDraftFieldParams{DocumentID: f.doc.ID, OrgID: f.orgID, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "text", Page: 1, XPct: fieldNumber(10), YPct: fieldNumber(10), WPct: fieldNumber(20), HPct: fieldNumber(5), Required: true, OptionsJson: json.RawMessage(`{}`)}
}
func (f *fieldMutationFixture) mutate(ctx context.Context, operation string, actor Actor) (*generated.DocumentField, error) {
	if operation == "create" {
		return f.engine.Create(ctx, actor, f.doc.ID, f.input())
	}
	return f.engine.Delete(ctx, actor, f.doc.ID, f.field.ID)
}

type fieldSnapshotDB interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (f *fieldMutationFixture) snapshot(t *testing.T) string { return f.snapshotWithDB(t, f.pool) }
func (f *fieldMutationFixture) snapshotWithDB(t *testing.T, db fieldSnapshotDB) string {
	t.Helper()
	var state string
	if err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1) SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1)
	)::text`, f.orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}
func (f *fieldMutationFixture) identitySnapshot(t *testing.T) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object('document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id=$1),'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$2))::text`, f.doc.ID, f.orgID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	return state
}
func (f *fieldMutationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before || f.logger.published != 0 {
		t.Fatal("rejected field mutation changed parent, recipient credentials, captured evidence, privacy identity or exact audit state, or published an uncommitted event")
	}
}
func (f *fieldMutationFixture) holdParent(t *testing.T) (pgx.Tx, int32) {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := tx.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return tx, pid
}
func (f *fieldMutationFixture) awaitBlocked(t *testing.T, pid int32, query string) {
	f.awaitNBlocked(t, pid, query, 1)
}
func (f *fieldMutationFixture) awaitNBlocked(t *testing.T, pid int32, query string, want int) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting int
		// Competing row lockers can queue behind the first blocked contender.
		// Follow that chain to the exact fixture holder rather than counting
		// unrelated sessions or assuming every wait is directly on its xid.
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity a WHERE position($2 in a.query)>0 AND EXISTS (
			WITH RECURSIVE blockers(pid) AS (
				SELECT unnest(pg_blocking_pids(a.pid))
				UNION SELECT p.pid FROM blockers b CROSS JOIN LATERAL unnest(pg_blocking_pids(b.pid)) p(pid)
			) SELECT 1 FROM blockers WHERE pid=$1
		)`, pid, query).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting >= want {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("field mutation did not wait on the exact synthetic parent lock holder")
		}
	}
}
func (f *fieldMutationFixture) seedAdditionalFields(t *testing.T, count int) {
	t.Helper()
	if _, err := f.pool.Exec(f.ctx, `INSERT INTO document_fields(document_id,type,page,x_pct,y_pct,w_pct,h_pct,required,options_json) SELECT $1,'text',1,10,10,20,5,true,'{}'::jsonb FROM generate_series(1,$2::integer)`, f.doc.ID, count); err != nil {
		t.Fatal(err)
	}
}

// Reuse the durable ceremony transition exercised by the DSR fixtures. The
// retention receipts here are explicitly synthetic; this test only protects
// the internal signing SQL primitive from draft-authoring restrictions.
func (f *fieldMutationFixture) publishSyntheticSend(t *testing.T) {
	t.Helper()
	sealing, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sealing.Rollback(context.Background()) }()
	seedCompleteFrozenBrandingE2E(t, f.ctx, sealing, f.doc.ID)
	q := f.q.WithTx(sealing)
	if _, err := q.CreateSendSealingIntent(f.ctx, generated.CreateSendSealingIntentParams{DocumentID: f.doc.ID, OrgID: f.orgID, ActorUserID: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ActorEmail: f.user.Email, Via: "e2e", Tool: "synthetic-field-signing-primitive"}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.BeginDocumentSendSealing(f.ctx, generated.BeginDocumentSendSealingParams{ID: f.doc.ID, OrgID: f.orgID}); err != nil {
		t.Fatal(err)
	}
	if err := sealing.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if rows, err := f.q.MarkSendSealingRetentionStarted(f.ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: f.doc.ID, OrgID: f.orgID}); err != nil || rows != 1 {
		t.Fatalf("synthetic retention start rows=%d error=%v", rows, err)
	}
	if rows, err := f.q.MarkSendSealingRetentionComplete(f.ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: f.doc.ID, OrgID: f.orgID}); err != nil || rows != 1 {
		t.Fatalf("synthetic retention completion rows=%d error=%v", rows, err)
	}
	publish, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = publish.Rollback(context.Background()) }()
	q = f.q.WithTx(publish)
	sent, err := q.CompleteDocumentSendSealing(f.ctx, generated.CompleteDocumentSendSealingParams{ID: f.doc.ID, OrgID: f.orgID})
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := q.MarkRecipientSent(f.ctx, generated.MarkRecipientSentParams{ID: f.recipient.ID, DocumentID: f.doc.ID}); err != nil || rows != 1 {
		t.Fatalf("synthetic recipient sent rows=%d error=%v", rows, err)
	}
	epoch, err := article13.CanonicalSentAt(sent.SentAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.logger.logger.LogTx(f.ctx, publish, audit.Entry{OrgID: f.orgID, DocumentID: &f.doc.ID, Kind: audit.KindDocumentSent, Payload: map[string]any{article13.AuditRequiredNoticeSchemaKey: article13.SchemaV1, article13.AuditRequiredNoticeSentAtKey: epoch}}); err != nil {
		t.Fatal(err)
	}
	if rows, err := q.DeleteSendSealingIntent(f.ctx, generated.DeleteSendSealingIntentParams{DocumentID: f.doc.ID, OrgID: f.orgID}); err != nil || rows != 1 {
		t.Fatalf("synthetic sealing intent retirement rows=%d error=%v", rows, err)
	}
	if err := publish.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
}
func (f *fieldMutationFixture) privacyRequest(t *testing.T, q *generated.Queries, linked bool, status string) {
	t.Helper()
	input := generated.CreateDataSubjectRequestParams{OrgID: f.orgID, SubjectEmail: "synthetic-subject@example.test", SubjectName: "Synthetic privacy subject", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}
	if linked {
		input.DocumentID = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
		input.RecipientID = pgtype.UUID{Bytes: f.recipient.ID, Valid: true}
		input.SubjectEmail, input.SubjectName = f.recipient.Email, f.recipient.Name
	}
	request, err := q.CreateDataSubjectRequest(f.ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if status != "open" {
		if _, err := q.UpdateDataSubjectRequestStatus(f.ctx, generated.UpdateDataSubjectRequestStatusParams{ID: request.ID, OrgID: f.orgID, ExpectedStatus: "open", Status: status, ResolutionNote: "Synthetic reviewed fixture state"}); err != nil {
			t.Fatal(err)
		}
	}
}

type fieldMutationResult struct {
	field *generated.DocumentField
	err   error
}

func receiveFieldMutation(t *testing.T, done <-chan fieldMutationResult) fieldMutationResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("field mutation did not finish after releasing its lock")
		return fieldMutationResult{}
	}
}

func seedCompleteFrozenBrandingE2E(t *testing.T, ctx context.Context, db generated.DBTX, documentID uuid.UUID) {
	t.Helper()
	_, err := db.Exec(ctx, `INSERT INTO document_branding_override (
		document_id, primary_hex, accent_hex, surface_hex, text_hex, muted_hex,
		logo_url, logo_alt, font_heading, font_body, signature_color
	) VALUES ($1, '#0F172A', '#3B82F6', '#FFFFFF', '#0F172A', '#64748B',
	          '', '', 'Inter', 'Inter', '#0F172A')
	ON CONFLICT (document_id) DO UPDATE SET
		primary_hex=EXCLUDED.primary_hex, accent_hex=EXCLUDED.accent_hex,
		surface_hex=EXCLUDED.surface_hex, text_hex=EXCLUDED.text_hex,
		muted_hex=EXCLUDED.muted_hex, logo_url=EXCLUDED.logo_url,
		logo_alt=EXCLUDED.logo_alt, font_heading=EXCLUDED.font_heading,
		font_body=EXCLUDED.font_body, signature_color=EXCLUDED.signature_color`, documentID) //nolint:rawsql
	if err != nil {
		t.Fatalf("seed complete canonical frozen branding: %v", err)
	}
}
