//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// The closed one-shot schedule affects only the synthetic HTTP peer. It grants
// no application identity, transaction, size measurement or readiness. Channels
// and the finite independent fixture lifetime exist before serving. Claim and
// shutdown share a mutex, so cleanup cannot miss a late blocked handler.
type ownedRendererGate165V1 struct {
	mu                              sync.Mutex
	arm, entered, release, returned chan struct{}
	armed, closed, claimed          bool
	life                            context.Context
	returnedOnce                    sync.Once
	timedOut                        atomic.Bool
}

func newOwnedRendererGate165V1(life context.Context) *ownedRendererGate165V1 {
	return &ownedRendererGate165V1{arm: make(chan struct{}), entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{}), life: life}
}
func (g *ownedRendererGate165V1) armV1(t *testing.T) {
	t.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.armed || g.claimed {
		t.Fatal("one-shot renderer gate is not fresh")
	}
	g.armed = true
	close(g.arm)
}
func (g *ownedRendererGate165V1) claimV1() (bool, func()) {
	if g == nil {
		return false, func() {}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.claimed {
		return false, func() {}
	}
	select {
	case <-g.arm:
	default:
		return false, func() {}
	}
	g.claimed = true
	return true, func() { g.returnedOnce.Do(func() { close(g.returned) }) }
}
func (g *ownedRendererGate165V1) waitV1() bool {
	close(g.entered)
	select {
	case <-g.release:
		return true
	case <-g.life.Done():
		g.timedOut.Store(true)
		return false
	}
}
func (g *ownedRendererGate165V1) closeV1() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		close(g.release)
	}
	return g.claimed
}

func ownedFamilyWholeState165V1(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, reader nativeCommentStateReader164V1) string {
	t.Helper()
	family := "document_id IN(SELECT id FROM documents WHERE org_id=$2 AND(id=$1 OR parent_envelope_id=$1))"
	parts := []string{}
	for _, item := range []struct{ key, table, predicate string }{
		{"documents", "documents", "org_id=$2 AND(id=$1 OR parent_envelope_id=$1)"},
		{"recipients", "recipients", family}, {"fields", "document_fields", family}, {"signatures", "signatures", family},
		{"requests", "change_requests", family}, {"comments", "document_comments", family},
		{"sealing", "send_sealing_intents", family}, {"finalization", "document_finalization_intents", family},
		{"policy", "document_signing_policy_sizes_v1", family}, {"field_policy", "field_signing_policy_sizes_v1", family},
		{"response", "html_creation_response_sizes_v1", family}, {"report", "document_read_report_sizes_v1", family},
		{"measurements", "html_snapshot_event_payload_sizes_v1", "org_id=$2"},
		{"revision_sizes", "html_revision_snapshot_sizes_v1", family}, {"snapshots", "html_document_materialization_snapshots", family},
		{"events", "events", "org_id=$2"}, {"outbox", "email_deliveries", "TRUE"},
	} {
		parts = append(parts, fmt.Sprintf("'%s',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb) FROM %s x WHERE %s)", item.key, item.table, item.predicate))
	}
	sql := "SELECT jsonb_build_object("
	for i, p := range parts {
		if i > 0 {
			sql += ","
		}
		sql += p
	}
	sql += ")::text"
	var state string
	if err := reader.QueryRow(q.f.ctx, sql, root, q.f.org).Scan(&state); err != nil {
		t.Fatal("complete family state unavailable", err)
	} //nolint:rawsql,gosec -- closed fixture table/predicate list, actual rows only; no mutation or grants
	return state
}
func ownedEnvelopeChildCommentBeforeFreeze165V1(t *testing.T, q *ownedPublicReadFixtureV1, childID uuid.UUID) {
	t.Helper()
	child, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: childID, OrgID: q.f.org})
	if err != nil || child.Status != "sent" {
		t.Fatal("exact genuine child not sent", err)
	}
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, child, "sender", "", "", q.cookie))
	var response commentResponse
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Body != nativeCommentBody163V1 || response.AuthorSide != "sender" {
		t.Fatal("genuine exact-child native comment unavailable", w.Code)
	}
	var rows, events, measured int
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*)::integer FROM document_comments WHERE document_id=$1 AND body=$3 AND author_side='sender' AND user_id=$4),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted' AND actor_user_id=$4 AND recipient_id IS NULL AND payload_json->>'side'='sender'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted')`, childID, q.f.org, nativeCommentBody163V1, q.f.user.ID).Scan(&rows, &events, &measured); err != nil || rows != 1 || events != 1 || measured != 1 {
		t.Fatal("actual child comment lost row/actor/fresh measurement", err)
	} //nolint:rawsql -- positive exact-child native audit witness
	// Current staff events carry the complete five-key content evidence, not
	// the old side-only payload. Bind every actual row/event to that evidence
	// and the exact native staff actor before the family freeze proceeds.
	commentRows, err := q.f.q.ListComments(q.f.ctx, childID)
	if err != nil || len(commentRows) != 1 || commentRows[0].ID.String() != response.ID || commentRows[0].Body != nativeCommentBody163V1 {
		t.Fatal("exact native child comment response/row differs", err)
	}
	commentEvents, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: childID, Valid: true}, Limit: 1000})
	if err != nil {
		t.Fatal("exact native child event history unavailable", err)
	}
	// Public recipients belong to the actual ceremony root. The shared oracle
	// requires a real expected recipient even for this staff-only observation;
	// do not invent one or obtain a new signer credential.
	if !child.ParentEnvelopeID.Valid {
		t.Fatal("genuine envelope child lost its ceremony root")
	}
	rootID := uuid.UUID(child.ParentEnvelopeID.Bytes)
	parties, err := q.f.q.ListRecipientsByDocument(q.f.ctx, rootID)
	if err != nil || len(parties) != 2 || parties[0].DocumentID != rootID {
		t.Fatal("actual ceremony parties unavailable for child audit oracle", err)
	}
	if err = ownedChatCurrentAudit487V1(commentEvents, commentRows, q.f.org, childID, q.f.user.ID, parties[0].ID, 1, 0); err != nil {
		t.Fatal("native child comment lost exact schema/body/hash/actor association", err)
	}
	nativeCommentDrained164V1(t, q)
}

// ONE independent statement observes the committed claim, exact family,
// actual signatures and strictly later completion highwater. No transition
// function or timestamp update is used to manufacture a finalizing fixture.
func ownedEnvelopeClaimProof165V1(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, children []uuid.UUID) {
	t.Helper()
	ids := append([]uuid.UUID{root}, children...)
	var members, recipients, signatures, rawSignatures int
	var frozen, ready, pinned, highwater, unpublished bool
	err := q.f.pool.QueryRow(q.f.ctx, `WITH family AS(SELECT * FROM documents WHERE org_id=$2 AND(id=$1 OR parent_envelope_id=$1)),root AS(SELECT * FROM family WHERE id=$1),parties AS(SELECT * FROM recipients WHERE document_id=$1),signs AS(SELECT * FROM signatures WHERE document_id=$1),highwater AS(
 SELECT sent_at AS at FROM family UNION ALL SELECT signed_at FROM parties UNION ALL SELECT signed_at FROM signs UNION ALL SELECT created_at FROM events WHERE org_id=$2 AND document_id IN(SELECT id FROM family))
 SELECT
 (SELECT count(*)::integer FROM family),
 (SELECT count(*)::integer FROM parties),
 (SELECT count(*)::integer FROM signs s JOIN parties p ON p.id=s.recipient_id JOIN document_fields f ON f.id=s.field_id AND f.document_id IN(SELECT id FROM family)),
 (SELECT count(*)::integer FROM signs),
 (SELECT bool_and(d.id=ANY($3::uuid[]) AND d.status='finalizing' AND d.completion_effective_at_bound AND d.completion_effective_at IS NOT NULL AND isfinite(d.completion_effective_at) AND d.finalization_retain_until IS NOT NULL AND isfinite(d.finalization_retain_until) AND d.completion_effective_at=r.completion_effective_at AND d.finalization_retain_until=r.finalization_retain_until AND d.finalization_retain_until=hash_evidence_retain_until(r.completion_effective_at,$4) AND d.completed_at IS NULL AND ((d.id=$1 AND d.is_envelope AND d.parent_envelope_id IS NULL) OR(d.id<>$1 AND NOT d.is_envelope AND d.parent_envelope_id=$1))) FROM family d CROSS JOIN root r),
 (SELECT count(*)=2 AND count(*) FILTER(WHERE role='buyer')=1 AND count(*) FILTER(WHERE role='seller')=1 AND bool_and(status='signed' AND signed_at IS NOT NULL AND isfinite(signed_at)) FROM parties),
 (SELECT count(*)=2 AND count(DISTINCT recipient_id)=2 AND bool_and(image_storage_key<>'' AND image_version_id IS NOT NULL AND image_version_id<>'' AND octet_length(image_sha256)=32 AND signed_at IS NOT NULL AND isfinite(signed_at)) FROM signs),
 (SELECT r.completion_effective_at>(SELECT max(at) FROM highwater) FROM root r),
 (SELECT bool_and(final_pdf_key IS NULL AND final_pdf_version_id IS NULL AND final_pdf_sha IS NULL AND audit_cert_key IS NULL AND audit_cert_version_id IS NULL AND audit_cert_sha256 IS NULL AND audit_payload_key IS NULL AND audit_payload_version_id IS NULL AND audit_payload_sha256 IS NULL AND audit_signature_key IS NULL AND audit_signature_version_id IS NULL AND audit_signature_sha256 IS NULL) AND NOT EXISTS(SELECT 1 FROM events WHERE org_id=$2 AND document_id IN(SELECT id FROM family) AND kind='document.completed') FROM family)`, root, q.f.org, ids, int32(article13.RetentionYearsV1)).Scan(&members, &recipients, &signatures, &rawSignatures, &frozen, &ready, &pinned, &highwater, &unpublished) //nolint:rawsql -- independent positive committed all-party/family claim evidence only
	if err != nil || members != len(ids) || recipients != 2 || signatures != 2 || rawSignatures != 2 || !frozen || !ready || !pinned || !highwater || !unpublished {
		t.Fatal("renderer boundary is not the genuine committed all-party family freeze", err, members, recipients, signatures, rawSignatures, frozen, ready, pinned, highwater, unpublished)
	}
}

type ownedFinalSignOutcome165V1 struct {
	result *sign.Result
	err    error
}

func ownedEnvelopeCommentFinalizing165V1(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, children []uuid.UUID, rc *sign.RecipientContext, input sign.SignInput, terminal *ownedPlainAuditGateV1, subscribeCompletion func()) (*sign.Result, error) {
	t.Helper()
	gate := q.renderer.gate
	call, cancel := context.WithCancel(q.f.ctx)
	done := make(chan struct{})
	outcome := make(chan ownedFinalSignOutcome165V1, 1)
	joinUntil := time.Now().Add(8 * time.Second)
	var held pgx.Tx
	// Both gates release before any join. Shutdown atomically prevents a late
	// blocked claim; returned spans the whole actual matching ServeHTTP.
	t.Cleanup(func() {
		claimed := gate.closeV1()
		terminal.unblock()
		if held != nil {
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			_ = held.Rollback(ctx)
			stop()
		}
		cancel()
		await := func(ch <-chan struct{}, name string) {
			// A previously joined child remains joined even if later artifact
			// assertions have consumed the original cleanup budget.
			select {
			case <-ch:
				return
			default:
			}
			select {
			case <-ch:
			case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
				t.Error("actual finalization cleanup did not join", name)
			}
		}
		await(done, "final signer")
		if claimed {
			await(gate.returned, "renderer handler")
		}
		q.rendererServer.CloseClientConnections()
		q.rendererServer.Close()
		select {
		case <-terminal.started:
			await(terminal.returned, "terminal hook")
		default:
		}
		_ = rc.CloseReadV1()
	})
	gate.armV1(t)
	go func() {
		defer close(done)
		result, err := q.f.s.Sign.Sign(call, rc, input)
		outcome <- ownedFinalSignOutcome165V1{result: result, err: err}
	}()
	select {
	case <-gate.entered:
	case <-done:
		t.Fatal("last signer returned before actual claimed renderer boundary")
	case <-time.After(5 * time.Second):
		t.Fatal("actual final signer never reached renderer boundary")
	}
	if gate.timedOut.Load() {
		t.Fatal("renderer gate used its failure escape")
	}
	ownedEnvelopeClaimProof165V1(t, q, root, children)
	// This isolated fixture had no subscribers during signed publication.
	// Logger's zero-hook path invokes lastUse synchronously, before claim.
	// Register the terminal observer while the producer is physically paused;
	// closing the renderer release orders it before terminal publication.
	subscribeCompletion()
	child, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: children[0], OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	var pid int32
	held, pid = ownedReadHolderV1(t, q, child.ID, false)
	before := ownedFamilyWholeState165V1(t, q, root, held)
	q.reconcileV1(t)
	pending, vector := q.runtime.SessionsV1().PendingV1(), q.snapshotV1(t)
	job := startNativeCommentJob163V1(t, q, child, "sender", "", "", q.cookie, held)
	ownedReadWaitV1(t, q, pid, "GetHTMLSendDocumentStateHeaderV1")
	if err = held.Commit(q.f.ctx); err != nil {
		t.Fatal(err)
	}
	w := job.joinV1(t)
	if w.Code != http.StatusConflict {
		t.Fatal("native child comment crossed actual finalizing boundary", w.Code)
	}
	if after := ownedFamilyWholeState165V1(t, q, root, q.f.pool); after != before {
		t.Fatal("finalizing comment changed whole family/source/cache/evidence/outbox")
	}
	q.reconcileV1(t)
	if q.runtime.SessionsV1().PendingV1() != pending || q.snapshotV1(t) != vector {
		t.Fatal("refused comment changed independently live finalizer ownership")
	}
	if gate.timedOut.Load() {
		t.Fatal("live freeze proof exhausted the gate's original fixture lifetime")
	}
	gate.closeV1()
	select {
	case got := <-outcome:
		select {
		case <-done:
		case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
			t.Fatal("actual final signer goroutine did not join within original absolute budget")
		}
		select {
		case <-gate.returned:
		case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
			t.Fatal("actual final renderer did not join within original absolute budget")
		}
		return got.result, got.err
	case <-time.After(max(time.Until(joinUntil), time.Nanosecond)):
		t.Fatal("actual last signer did not join after renderer release")
		return nil, context.DeadlineExceeded
	}
}

func ownedEnvelopeChildFrozenRefusal165V1(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, children []uuid.UUID) {
	t.Helper()
	child, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: children[0], OrgID: q.f.org})
	if err != nil || child.Status != "completed" {
		t.Fatal("exact comment child did not genuinely complete", err)
	}
	var ordered bool
	var count int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT (SELECT count(*)::integer FROM document_comments WHERE document_id=$1),d.completion_effective_at>e.created_at FROM documents d JOIN events e ON e.document_id=d.id AND e.org_id=d.org_id AND e.kind='document.comment_posted' WHERE d.id=$1 AND d.org_id=$2", child.ID, q.f.org).Scan(&count, &ordered); err != nil || count != 1 || !ordered {
		t.Fatal("frozen highwater lost its exact original child comment", err)
	} //nolint:rawsql -- exact completed child's genuine historical comment boundary
	before := ownedFamilyWholeState165V1(t, q, root, q.f.pool)
	if err := q.f.s.Sign.FinalizeStranded(q.f.ctx, q.f.org, child.ID); !errors.Is(err, sign.ErrEnvelopeChildFinalization) {
		t.Fatalf("genuine current standalone child retry = %v, want ErrEnvelopeChildFinalization", err)
	}
	var childIntents int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM document_finalization_intents WHERE document_id IN ($1,$2)", children[0], children[1]).Scan(&childIntents); err != nil || childIntents != 0 {
		t.Fatal("standalone child refusal created finalization intents", childIntents, err)
	} //nolint:rawsql -- actual current engine child refusal must create no standalone intent
	if ownedFamilyWholeState165V1(t, q, root, q.f.pool) != before {
		t.Fatal("current standalone child retry rewrote frozen family commitments/history")
	}
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, nativeCommentRequest163V1(t, q, q.f.ctx, child, "sender", "", "", q.cookie))
	if w.Code != http.StatusConflict {
		t.Fatal("same frozen child accepted a late comment", w.Code)
	}
	nativeCommentDrained164V1(t, q)
	if ownedFamilyWholeState165V1(t, q, root, q.f.pool) != before {
		t.Fatal("postcompletion child comment rewrote frozen family commitments/history")
	}
	t.Log("actual exact-child comment201 measured; genuine all-party claim/finalizing parentwait409; full family/caches/events/outbox unchanged; finalization joined and all family artifacts/child highwater preserved; same completed child409 with complete drain")
}
