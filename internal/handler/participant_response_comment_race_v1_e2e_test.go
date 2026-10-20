//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type participantResponseRaceTraceKey253 struct{}
type participantResponseRaceDispatch253 struct {
	pid int32
	err error
}

// Installed on the real original fixture pool before its native factory exists.
// It never replaces SQL, arguments, results, context deadlines or credentials.
// One successfully dispatched matching native event is paused while its actual
// transaction still owns the root. Explicit release and whole-job joins prove
// retirement; context expiry is a test failure escape, not success or credit.
type participantResponseRaceGate253 struct {
	mu                              sync.Mutex
	org, document, recipient, actor uuid.UUID
	kind                            string
	armed, claimed, closed          bool
	entered                         chan participantResponseRaceDispatch253
	release, traceReturned          chan struct{}
	returned                        sync.Once
	expired                         atomic.Bool
}

func newParticipantResponseRaceGate253() *participantResponseRaceGate253 {
	return &participantResponseRaceGate253{entered: make(chan participantResponseRaceDispatch253, 1), release: make(chan struct{}), traceReturned: make(chan struct{})}
}
func (g *participantResponseRaceGate253) arm253(org, document, recipient, actor uuid.UUID, kind string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.org, g.document, g.recipient, g.actor, g.kind, g.armed = org, document, recipient, actor, kind, true
}
func participantResponseRaceUUID253(v any) (uuid.UUID, bool) {
	switch id := v.(type) {
	case uuid.UUID:
		return id, true
	case pgtype.UUID:
		if !id.Valid {
			return uuid.Nil, true
		}
		return uuid.UUID(id.Bytes), true
	default:
		return uuid.Nil, false
	}
}
func (g *participantResponseRaceGate253) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(data.SQL, "-- name: InsertEventIdentityV1 :one\n") || len(data.Args) != 12 {
		return ctx
	}
	org, orgOK := participantResponseRaceUUID253(data.Args[0])
	document, docOK := participantResponseRaceUUID253(data.Args[1])
	recipient, recipientOK := participantResponseRaceUUID253(data.Args[2])
	actor, actorOK := participantResponseRaceUUID253(data.Args[3])
	kind, kindOK := data.Args[4].(string)
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed || g.claimed || g.closed || !orgOK || !docOK || !recipientOK || !actorOK || !kindOK || org != g.org || document != g.document || recipient != g.recipient || actor != g.actor || kind != g.kind {
		return ctx
	}
	g.claimed = true
	return context.WithValue(ctx, participantResponseRaceTraceKey253{}, g)
}
func (g *participantResponseRaceGate253) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if ctx.Value(participantResponseRaceTraceKey253{}) != g {
		return
	}
	defer g.returned.Do(func() { close(g.traceReturned) })
	deadline, bounded := ctx.Deadline()
	if data.Err != nil || !bounded || ctx.Err() != nil || !deadline.After(time.Now()) {
		g.entered <- participantResponseRaceDispatch253{err: fmt.Errorf("matching actual native event did not finish successfully inside its original finite context: %w", data.Err)}
		return
	}
	g.entered <- participantResponseRaceDispatch253{pid: int32(conn.PgConn().PID())}
	// This child bounds only the test barrier; the actual driver's original
	// context/deadline is returned unchanged. A timeout always fails the test.
	hold, stop := context.WithTimeout(ctx, 3*time.Second)
	defer stop()
	select {
	case <-g.release:
	case <-hold.Done():
		g.expired.Store(true)
	}
}
func (g *participantResponseRaceGate253) release253() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		g.closed = true
		close(g.release)
	}
}
func (g *participantResponseRaceGate253) await253(t *testing.T, parent context.Context) int32 {
	t.Helper()
	ctx, stop := context.WithTimeout(parent, 3*time.Second)
	defer stop()
	select {
	case entered := <-g.entered:
		if entered.err != nil || entered.pid <= 0 {
			t.Fatal("actual native event gate did not retain a real successful dispatch", entered.err)
		}
		return entered.pid
	case <-ctx.Done():
		t.Fatal("actual matching native event never reached its dispatch gate", ctx.Err())
		return 0
	}
}

// The predicate, not elapsed time, establishes that the competing real native
// root query is queued behind exactly the winning transaction's backend PID.
// A ticker merely bounds observation traffic; no sleep chooses race ordering.
func participantResponseRaceWait253(t *testing.T, q *ownedPublicReadFixtureV1, blocker int32) {
	t.Helper()
	ctx, stop := context.WithTimeout(q.f.ctx, 2*time.Second)
	defer stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	application := q.f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	for {
		var n int
		err := q.f.pool.QueryRow(ctx, `SELECT count(*)::integer FROM pg_stat_activity a
 WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active'
 AND a.wait_event_type='Lock' AND position('GetHTMLSendDocumentStateHeaderV1' in a.query)>0
 AND a.pid<>$2 AND $2=ANY(pg_blocking_pids(a.pid))`, application, blocker).Scan(&n)
		if err != nil || n > 1 {
			t.Fatal("actual competing root-lock witness unavailable or ambiguous", n, err)
		}
		if n == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal("competitor did not wait behind the actual native winner", ctx.Err())
		}
	} //nolint:rawsql -- actual isolated backend/lock observation, never native authority
}

type participantResponseRaceOutcome253 struct {
	result   *sign.Result
	err      error
	closeErr error
}

func TestParticipantResponseFreezesAgainstConcurrentCommentV1E2E(t *testing.T) {
	for _, mode := range []string{"signature", "acknowledgement"} {
		for _, winner := range []string{"response", "comment"} {
			t.Run(mode+"/"+winner+"-wins", func(t *testing.T) {
				gate := newParticipantResponseRaceGate253()
				var q *ownedPublicReadFixtureV1
				var doc *generated.Document
				var parties []signerBrowserPartyE2E
				if mode == "signature" {
					q = newOwnedPublicReadFixtureProfileV1(t, false, false, gate)
					doc, parties = q.createSentV1(t)
				} else {
					q, doc, parties = participantCapacityAcknowledgement253(t, gate)
				}
				if len(parties) != 2 {
					t.Fatal("atomic response/comment regression requires two real parties")
				}
				first, err := participantCapacityRespond253(t, q, parties[0], mode)
				if err != nil || first == nil || first.Completed {
					t.Fatal("first original response was not committed before the race", err)
				}
				// Prepare the original remaining credential/notice before any gate.
				// The racing response still performs all actual native locked checks.
				rc := q.lookupV1(t, parties[1].Token)
				t.Cleanup(func() {
					if err := rc.CloseReadV1(); err != nil {
						t.Error(err)
					}
				})
				notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(parties[1].Token, ""), rc)
				if err != nil {
					t.Fatal(err)
				}
				noticeEvidence, err := signerArticle13NoticeEvidence(rc, notice)
				if err != nil {
					t.Fatal(err)
				}
				responseCtx, stopResponse := context.WithCancel(q.f.ctx)
				commentCtx, stopComment := context.WithCancel(q.f.ctx)
				responseDone, commentDone := make(chan struct{}), make(chan struct{})
				outcome := make(chan participantResponseRaceOutcome253, 1)
				var responseStarted, commentStarted bool
				comment := httptest.NewRecorder()
				const body = "The complete original agreement includes this independently committed staff comment."
				raw, err := json.Marshal(createCommentInput{Body: body})
				if err != nil {
					t.Fatal(err)
				}
				request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/v1/documents/"+doc.ID.String()+"/comments", bytes.NewReader(raw)).WithContext(commentCtx)
				request.Header.Set("Content-Type", "application/json")
				request.Header.Set("Origin", q.f.s.PublicURL)
				request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
				// Registered after fixture cleanup: release first, cancel original
				// children, and join whole calls before any runtime/provider cleanup.
				t.Cleanup(func() {
					gate.release253()
					stopResponse()
					stopComment()
					join, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					for _, job := range []struct {
						started bool
						done    <-chan struct{}
						name    string
					}{{responseStarted, responseDone, "response"}, {commentStarted, commentDone, "comment"}} {
						if job.started {
							select {
							case <-job.done:
							case <-join.Done():
								t.Error("whole original race operation did not join before cleanup", job.name)
							}
						}
					}
				})
				startResponse := func() {
					responseStarted = true
					go func() {
						defer close(responseDone)
						var result *sign.Result
						var err error
						if mode == "signature" {
							result, err = q.f.s.Sign.Sign(responseCtx, rc, sign.SignInput{TypedName: parties[1].Name, Font: "Caveat", Notice: noticeEvidence, IP: "127.0.0.1", UserAgent: "Synthetic actual response/comment race"})
						} else {
							result, err = q.f.s.Sign.Accept(responseCtx, rc, sign.ParticipantResponseEvidence{Notice: noticeEvidence, IP: "127.0.0.1", UserAgent: "Synthetic actual response/comment race"})
						}
						outcome <- participantResponseRaceOutcome253{result: result, err: err, closeErr: rc.CloseReadV1()}
					}()
				}
				startComment := func() {
					commentStarted = true
					go func() { defer close(commentDone); q.f.s.Routes().ServeHTTP(comment, request) }()
				}
				if winner == "response" {
					kind := audit.KindDocumentSigned
					if mode == "acknowledgement" {
						kind = audit.KindDocumentAccepted
					}
					gate.arm253(q.f.org, doc.ID, parties[1].RecipientID, uuid.Nil, kind)
					startResponse()
					pid := gate.await253(t, q.f.ctx)
					startComment()
					participantResponseRaceWait253(t, q, pid)
				} else {
					gate.arm253(q.f.org, doc.ID, uuid.Nil, q.f.user.ID, audit.KindCommentPosted)
					startComment()
					pid := gate.await253(t, q.f.ctx)
					startResponse()
					participantResponseRaceWait253(t, q, pid)
				}
				gate.release253()
				join, stopJoin := context.WithTimeout(q.f.ctx, 5*time.Second)
				defer stopJoin()
				for _, done := range []<-chan struct{}{responseDone, commentDone, gate.traceReturned} {
					select {
					case <-done:
					case <-join.Done():
						t.Fatal("whole actual competing calls did not join after explicit release", join.Err())
					}
				}
				got := <-outcome
				if gate.expired.Load() || got.err != nil || got.closeErr != nil || got.result == nil || !got.result.Completed {
					current, readErr := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
					if readErr == nil && current != nil {
						t.Logf("actual failed response state=%s result_present=%v unknown_cleanup=%v canceled=%v deadline=%v", current.Status, got.result != nil, errors.Is(got.err, pdfadmission.ErrApplicationSessionUnknownV1), errors.Is(got.err, context.Canceled), errors.Is(got.err, context.DeadlineExceeded))
					} else {
						t.Log("actual failed response state unavailable", readErr)
					}
					t.Fatal("actual final response did not complete after the verified root wait", gate.expired.Load(), got.err, got.closeErr)
				}
				participantResponseRaceProof253(t, q, doc.ID, winner, body, comment)
				q.assertObserversOnlyV1(t)
			})
		}
	}
}

func participantResponseRaceProof253(t *testing.T, q *ownedPublicReadFixtureV1, document uuid.UUID, winner, body string, response *httptest.ResponseRecorder) {
	t.Helper()
	current, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: document, OrgID: q.f.org})
	if err != nil || current.Status != "completed" || !current.CompletionEffectiveAtBound {
		t.Fatal("original raced ceremony did not genuinely complete", err)
	}
	var comments, events, measured, mail, reports int
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*)::integer FROM document_comments WHERE document_id=$1),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id AND m.payload_wire_bytes=octet_length(e.payload_json::text) AND m.measurement_server_version_num=current_setting('server_version_num')::integer WHERE e.document_id=$1 AND e.org_id=$2 AND e.kind='document.comment_posted'),
 (SELECT count(*)::integer FROM email_deliveries WHERE subject=$3),
 (SELECT count(*)::integer FROM document_participant_reports_v1 WHERE document_id=$1 AND org_id=$2)`, document, q.f.org, "New comment on "+current.Name).Scan(&comments, &events, &measured, &mail, &reports); err != nil || reports != 1 {
		t.Fatal("actual race report/comment effects unavailable", err)
	} //nolint:rawsql -- bounded original target effects only, no fabrication or grants
	if winner == "response" {
		if response.Code != http.StatusConflict || comments != 0 || events != 0 || measured != 0 || mail != 0 {
			t.Fatal("queued comment crossed the response's atomic final freeze", response.Code, comments, events, measured, mail)
		}
	} else if response.Code != http.StatusCreated || comments != 1 || events != 1 || measured != 1 || mail < 1 {
		t.Fatal("winning comment did not commit its original row/event/measurement/notification", response.Code, comments, events, measured, mail)
	}
	payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditPayloadKey.String, current.AuditPayloadSha256, current.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, current, current.AuditSignatureKey.String, current.AuditSignatureSha256, current.AuditSignatureVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatal("actual raced certificate/report association is invalid", err)
	}
	assertFreshParticipantReport406(t, q.f, current, payload)
	if winner == "response" {
		if strings.Contains(string(payload), body) {
			t.Fatal("refused queued comment was included as retained evidence")
		}
		return
	}
	var comment commentResponse
	if json.Unmarshal(response.Body.Bytes(), &comment) != nil || comment.Body != body {
		t.Fatal("winning public comment response differs from its original body")
	}
	var eventID uuid.UUID
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT id FROM events WHERE document_id=$1 AND org_id=$2 AND kind='document.comment_posted' AND payload_json->>'comment_id'=$3", document, q.f.org, comment.ID).Scan(&eventID); err != nil {
		t.Fatal("winning exact comment event unavailable", err)
	}
	event, err := q.f.q.GetEventByID(q.f.ctx, eventID)
	cutoff, parseErr := time.Parse(time.RFC3339Nano, claims.ParticipantReportCutoff)
	if err != nil || parseErr != nil || event == nil || !cutoff.After(event.CreatedAt.Time) || !current.CompletionEffectiveAt.Time.After(event.CreatedAt.Time) || !strings.Contains(string(payload), body) || !strings.Contains(string(payload), comment.ID) || !strings.Contains(string(payload), eventID.String()) || !strings.Contains(string(payload), hex.EncodeToString(event.RowHash)) {
		t.Fatal("winning original comment was lost or fell outside the frozen signed report cutoff", err, parseErr)
	}
}
