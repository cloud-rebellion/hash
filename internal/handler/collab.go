// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"nhooyr.io/websocket"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// collabMaxMessageSize caps a single Yjs frame. Routine updates are
// 10-200 bytes; sync_step2 snapshots and the 0x04 compact-snapshot
// message type can grow with document size. The collab Hub already
// compacts above 1 MiB and rejects snapshots > 110% of current state,
// so 2 MiB leaves comfortable headroom while bounding any single
// malicious or malformed frame.
const collabMaxMessageSize = 2 * 1024 * 1024

// collabPingInterval drives an application-level keepalive so a dead
// peer (NAT timeout, hung browser tab) gets reaped instead of holding
// a goroutine indefinitely. Browsers respond to ws ping automatically.
const collabPingInterval = 30 * time.Second
const collabPingTimeout = 10 * time.Second

const maxPendingCollabHandshakes = 32

type collabHandshakeGate struct{ active atomic.Int64 }

func (g *collabHandshakeGate) acquire() (func(), bool) {
	for {
		active := g.active.Load()
		if active >= maxPendingCollabHandshakes {
			return nil, false
		}
		if g.active.CompareAndSwap(active, active+1) {
			var once sync.Once
			return func() { once.Do(func() { g.active.Add(-1) }) }, true
		}
	}
}

// wsPeer wraps a nhooyr websocket as a collab.Peer. Implements
// thread-safe Send + serializes outgoing writes via a mutex inside the
// wsjson layer (nhooyr ws is safe for one writer + one reader).
type wsPeer struct {
	id          string
	conn        *websocket.Conn
	userID      uuid.UUID
	displayName string
	cancel      context.CancelFunc
	done        chan struct{}
}

func (p *wsPeer) ID() string          { return p.id }
func (p *wsPeer) UserID() uuid.UUID   { return p.userID }
func (p *wsPeer) DisplayName() string { return p.displayName }

func (p *wsPeer) Terminate() {
	if p.cancel != nil {
		p.cancel()
	}
	_ = p.conn.CloseNow()
	if p.done != nil {
		<-p.done
	}
}

func (p *wsPeer) Send(ctx context.Context, frame []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return p.conn.Write(ctx, websocket.MessageBinary, frame)
}

// handleCollabSocket upgrades the connection to a WebSocket + joins
// the per-document collab room. The /api/v1 route requires a sender session
// cookie; the socket rechecks that cookie and live permissions per frame.
func (s *Server) handleCollabSocket(w http.ResponseWriter, r *http.Request) {
	if s.Collab == nil {
		writeError(w, http.StatusServiceUnavailable, "collab not enabled on this instance")
		return
	}
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	// RBAC: the collab socket mutates the persisted append-only CRDT log, so it is a
	// write surface. The route lives under RequireRoleForWrites(RoleSender) but that
	// middleware lets GET through unchecked and a WebSocket upgrade IS a GET, so a
	// viewer would otherwise join and write frames. Enforce the role here explicitly.
	if !auth.RoleAtLeast(r.Context(), auth.RoleSender) {
		writeError(w, http.StatusForbidden, "insufficient role for this action")
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := auth.EnforceDocScope(r.Context(), docID); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	releaseHandshake, admitted := s.collabHandshakes.acquire()
	if !admitted {
		w.Header().Set("Retry-After", "2")
		writeError(w, http.StatusTooManyRequests, "collaboration connection capacity busy; retry later")
		return
	}
	defer releaseHandshake()
	doc, err := s.Queries.GetDocument(r.Context(), generated.GetDocumentParams{ID: docID, OrgID: u.OrgID})
	if err != nil {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if doc.Status != "draft" {
		writeError(w, http.StatusConflict, "collaboration requires a draft document")
		return
	}
	query, queryErr := url.ParseQuery(r.URL.RawQuery)
	observations := query["expected_updated_at"]
	var expected time.Time
	if queryErr == nil && len(observations) == 1 {
		expected, queryErr = time.Parse(time.RFC3339Nano, observations[0])
	}
	if queryErr != nil || len(observations) != 1 || expected.IsZero() {
		writeError(w, http.StatusBadRequest, "exact expected_updated_at document observation required")
		return
	}
	if !expected.Equal(doc.UpdatedAt.Time) {
		writeError(w, http.StatusPreconditionFailed, "document changed; preserve your draft and load the current document before connecting")
		return
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "session required")
		return
	}
	// nhooyr.io/websocket OriginPatterns: lock to the configured public
	// host so an attacker on a different origin can't ride a logged-in
	// user's session cookie into a collab room. Local dev gets the
	// loopback variants because the SvelteKit dev server runs on a
	// different port than the Go API. CompressionMode stays disabled
	// to avoid a CRIME-style sidechannel mixing with the auth cookie.
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns:  collabOriginPatterns(s.PublicURL),
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Warn("collab: ws accept", "err", err, "origin", r.Header.Get("Origin"))
		return
	}
	defer conn.CloseNow()

	// Cap any single frame so a hostile peer (or a wedged Y.Doc) can't
	// blow the process memory with one 1 GB binary blob.
	conn.SetReadLimit(collabMaxMessageSize)

	peerID := newPeerID()
	peer := &wsPeer{
		id:          peerID,
		conn:        conn,
		userID:      u.UserID,
		displayName: firstNonEmpty(u.Email, "Anonymous"),
		done:        make(chan struct{}),
	}
	defer close(peer.done)

	// Detach from the request context so a slow client doesn't tear
	// the room down when the request handler returns; the websocket
	// connection has its own lifecycle.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer.cancel = cancel

	join, err := s.Collab.Join(ctx, doc.ID, doc.OrgID, peer)
	if err != nil {
		if errors.Is(err, collab.ErrCapacity) {
			conn.Close(websocket.StatusTryAgainLater, "collaboration capacity busy; retry later")
		} else if errors.Is(err, collab.ErrGeneration) || errors.Is(err, collab.ErrLegacyHistory) {
			conn.Close(websocket.StatusPolicyViolation, "collaboration history needs recovery; preserve draft and reload")
		} else {
			conn.Close(websocket.StatusInternalError, "join failed")
		}
		return
	}
	defer s.Collab.LeaveRoom(ctx, join.Room, peerID)

	stopPing := startCollabKeepalive(ctx, cancel, conn, peerID)
	defer stopPing()

	initialCtx, cancelInitial := context.WithTimeout(ctx, 10*time.Second)
	defer cancelInitial()
	if err := s.withCollabFrameAuthorization(initialCtx, cookie.Value, doc.ID, doc.OrgID, u.UserID, func(frameCtx context.Context) error {
		if !expected.Equal(frameCtx.Value(collabCanonicalUpdatedAtKey{}).(time.Time)) {
			return errors.New("collaboration document observation changed before initialization")
		}
		if err := join.Room.CheckGeneration(frameCtx.Value(collabCanonicalGenerationKey{}).(int64)); err != nil {
			return err
		}
		if err := conn.Write(frameCtx, websocket.MessageBinary, join.Room.GenerationFrame()); err != nil {
			return err
		}
		if err := conn.Write(frameCtx, websocket.MessageBinary, join.Room.BootstrapFrame(peerID)); err != nil {
			return err
		}
		initialFrames, err := collab.SyncFrames(join.InitialState)
		if err != nil {
			return err
		}
		for _, frame := range initialFrames {
			if err := conn.Write(frameCtx, websocket.MessageBinary, frame); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "collaboration generation or authorization changed; preserve draft and reload")
		return
	}
	cancelInitial()
	releaseHandshake()

	_, _ = s.Audit.Log(ctx, audit.Entry{
		OrgID:       doc.OrgID,
		ActorUserID: &u.UserID,
		DocumentID:  &doc.ID,
		Kind:        audit.KindCollabPeerJoined,
		Payload: map[string]any{
			"peer_id":      peerID,
			"display_name": peer.displayName,
		},
	})
	// On the way out, log the peer leaving so the timeline shows the
	// full collaboration window.
	defer func() {
		// Transport/room cleanup must finish even if the audit chain is busy.
		// Recovery waits for this handler before releasing counted capacity.
		auditCtx, auditCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer auditCancel()
		_, _ = s.Audit.Log(auditCtx, audit.Entry{
			OrgID:       doc.OrgID,
			ActorUserID: &u.UserID,
			DocumentID:  &doc.ID,
			Kind:        audit.KindCollabPeerLeft,
			Payload:     map[string]any{"peer_id": peerID},
		})
	}()
	// These execute before the peer-left audit (LIFO) and are idempotent.
	defer s.Collab.LeaveRoom(ctx, join.Room, peerID)
	defer stopPing()
	defer cancel()

	// Read loop: every frame routes to the hub. nhooyr cancels Read on
	// connection close so we exit cleanly.
	for {
		mtype, payload, err := conn.Read(ctx)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				slog.Debug("collab: ws closed", "code", ce.Code, "peer_id", peerID)
			}
			return
		}
		if mtype != websocket.MessageBinary {
			// Yjs is binary-only; reject anything else so a misbehaving
			// client doesn't trigger weird state.
			continue
		}
		// An upgrade does not grant indefinite access. Recheck cookie expiry,
		// membership and draft state for every frame, holding row locks through
		// the mutation so demotion and sealing cannot race the authorization.
		if err := s.withCollabFrameAuthorization(ctx, cookie.Value, doc.ID, doc.OrgID, u.UserID, func(frameCtx context.Context) error {
			if err := join.Room.CheckGeneration(frameCtx.Value(collabCanonicalGenerationKey{}).(int64)); err != nil {
				return err
			}
			return join.Room.HandleFrame(frameCtx, peer, payload)
		}); err != nil {
			slog.Debug("collab: bad frame", "peer_id", peerID, "err", err)
			_ = conn.Close(websocket.StatusPolicyViolation, "collaboration authorization or frame rejected")
			return
		}
	}
}

type collabCanonicalGenerationKey struct{}
type collabCanonicalUpdatedAtKey struct{}

func (s *Server) withCollabFrameAuthorization(ctx context.Context, cookie string, docID, orgID, userID uuid.UUID, apply func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	payload, err := s.Cookies.Verify(cookie)
	if err != nil {
		return errors.New("collaboration session expired")
	}
	var session auth.SessionPayload
	if err := json.Unmarshal(payload, &session); err != nil || session.UserID != userID {
		return errors.New("collaboration session identity invalid")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	doc, err := s.Queries.WithTx(tx).GetDocumentForShare(ctx, generated.GetDocumentForShareParams{ID: docID, OrgID: orgID})
	if err != nil || doc.Status != "draft" {
		return errors.New("collaboration document is no longer an accessible draft")
	}
	var role string
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT role, session_generation FROM users WHERE id = $1 AND org_id = $2 FOR SHARE`, userID, orgID).Scan(&role, &generation); err != nil {
		return errors.New("collaboration membership unavailable")
	}
	if role != string(auth.RoleSender) && role != string(auth.RoleOwner) {
		return errors.New("collaboration write permission revoked")
	}
	if session.Generation != generation {
		return errors.New("collaboration session revoked")
	}
	if _, err := s.Cookies.Verify(cookie); err != nil {
		return errors.New("collaboration session expired while awaiting authorization")
	}
	canonicalGeneration, err := s.Queries.WithTx(tx).GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: docID, OrgID: orgID})
	if err != nil {
		return errors.New("collaboration canonical generation unavailable")
	}
	ctx = context.WithValue(ctx, collabCanonicalGenerationKey{}, canonicalGeneration)
	ctx = context.WithValue(ctx, collabCanonicalUpdatedAtKey{}, doc.UpdatedAt.Time)
	if err := apply(ctx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func newPeerID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// collabOriginPatterns derives the OriginPatterns allow-list from the
// configured public URL. Production gets exactly its own host (the
// nhooyr matcher is hostname-only, ports + paths are ignored). Local
// dev expands to common loopback ports so SvelteKit's vite-dev origin
// (http://localhost:5173) can still join while testing.
func collabOriginPatterns(publicURL string) []string {
	host := collabHost(publicURL)
	if host == "" {
		host = "localhost"
	}
	out := []string{host}
	if config.IsLocalDevelopment(publicURL) {
		out = append(out, "localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*", "[::1]", "[::1]:*")
	}
	return out
}

func collabHost(publicURL string) string {
	u, err := url.Parse(strings.TrimSpace(publicURL))
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// startCollabKeepalive pings every collabPingInterval and tears the
// connection down if the peer fails to pong within collabPingTimeout.
// Returns a stop func the caller must call on disconnect.
func startCollabKeepalive(ctx context.Context, cancel context.CancelFunc, conn *websocket.Conn, peerID string) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(collabPingInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-ticker.C:
				pctx, pcancel := context.WithTimeout(ctx, collabPingTimeout)
				if err := conn.Ping(pctx); err != nil {
					pcancel()
					slog.Debug("collab: ping timeout", "peer_id", peerID, "err", err)
					cancel() // force read loop exit
					return
				}
				pcancel()
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { cancel(); close(done) }); <-stopped }
}
