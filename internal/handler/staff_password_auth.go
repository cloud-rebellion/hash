// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-chi/httprate"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/passwordhash"
)

var errStaffAuthLink = errors.New("authentication link is invalid or expired")

type staffAuthBucket struct {
	until time.Time
	count int
}
type nativeStaffAuthLimits struct {
	mu      sync.Mutex
	buckets map[string]staffAuthBucket
}

// Keep only one-way account identifiers, cap allocation, and expire idle keys.
// The outer global/IP buckets also bound work from rotating account names.
func (l *nativeStaffAuthLimits) allow(kind, email string, now time.Time, limit int) bool {
	digest := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	key := kind + ":" + hex.EncodeToString(digest[:])
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = make(map[string]staffAuthBucket)
	}
	bucket, found := l.buckets[key]
	if !found || !now.Before(bucket.until) {
		if len(l.buckets) >= 4096 {
			for k, b := range l.buckets {
				if !now.Before(b.until) {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= 4096 && !found {
				return false
			}
		}
		bucket = staffAuthBucket{until: now.Add(15 * time.Minute)}
	}
	if bucket.count >= limit {
		return false
	}
	bucket.count++
	l.buckets[key] = bucket
	return true
}

func (s *Server) requireStaffAuthOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if req.Method == http.MethodPost {
			origin := strings.TrimSpace(req.Header.Get("Origin"))
			if origin == "" || !allowedMutationOrigin(origin, req.Host, s.PublicURL) {
				writeError(w, http.StatusForbidden, "same-origin authentication request required")
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

func staffAuthGlobalRateLimit() func(http.Handler) http.Handler {
	return httprate.Limit(120, time.Minute, httprate.WithKeyFuncs(func(*http.Request) (string, error) { return "native-staff-auth", nil }))
}

func (s *Server) handleStaffAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"password_enabled": true, "oidc_enabled": s.OIDC != nil})
}

func decodeStaffAuthJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "application/json required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid authentication request")
		return false
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid authentication request")
		return false
	}
	return true
}

func validStaffPassword(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 &&
		len(password) <= passwordhash.MaxPasswordBytes
}

func validStaffText(value string, required bool) bool {
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 200 || (required && strings.TrimSpace(value) == "") {
		return false
	}
	return !strings.ContainsFunc(value, unicode.IsControl)
}

func (s *Server) staffAuthReady(w http.ResponseWriter) bool {
	if s.Pool == nil || s.Queries == nil || s.Audit == nil || s.Cookies == nil || s.StaffAuthMailBox == nil {
		writeError(w, http.StatusServiceUnavailable, "authentication temporarily unavailable")
		return false
	}
	return true
}

func staffAuthUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "authentication temporarily unavailable")
}

func staffAuthAccepted(w http.ResponseWriter) {
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "If this address can continue, an email with the next step will arrive."})
}

func (s *Server) staffAuthAccountAllowed(w http.ResponseWriter, kind, email string, limit int) bool {
	if !s.staffAuthLimits.allow(kind, email, time.Now(), limit) {
		writeError(w, http.StatusTooManyRequests, "too many authentication attempts; try again later")
		return false
	}
	return true
}

type staffRegistrationInput struct {
	Email       string `json:"email"`
	Name        string `json:"name"`
	CompanyName string `json:"company_name"`
	Password    string `json:"password"`
}

func (s *Server) handleStaffRegister(w http.ResponseWriter, r *http.Request) {
	var in staffRegistrationInput
	if !decodeStaffAuthJSON(w, r, &in) {
		return
	}
	email, name, err := normalizeOIDCIdentity(in.Email, strings.TrimSpace(in.Name))
	company := strings.TrimSpace(in.CompanyName)
	if err != nil || !validStaffText(strings.TrimSpace(in.Name), true) || !validStaffText(name, true) || !validStaffText(company, true) || !validStaffPassword(in.Password) {
		writeError(w, http.StatusBadRequest, "valid email, name, company and a password of at least12 characters and at most1024 UTF-8 bytes are required")
		return
	}
	if !s.staffAuthAccountAllowed(w, "register", email, 5) || !s.staffAuthReady(w) {
		return
	}
	encoded, err := passwordhash.Hash(r.Context(), in.Password)
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	defer rollbackSessionTransaction(ctx, tx)
	q := s.Queries.WithTx(tx)
	if err := q.LockStaffPasswordEmail(ctx, email); err != nil {
		staffAuthUnavailable(w)
		return
	}
	user, err := q.LockStaffPasswordUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		staffAuthUnavailable(w)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		user = nil
	}
	if user != nil {
		if _, err := q.GetStaffPasswordCredentialForUser(ctx, user.ID); err == nil {
			// Registration cannot overwrite a working credential, even with a
			// preselected password. The owner can explicitly use recovery.
			staffAuthAccepted(w)
			return
		} else if !errors.Is(err, pgx.ErrNoRows) {
			staffAuthUnavailable(w)
			return
		}
	}
	purpose := "register"
	if user != nil {
		// The submitter may not control this existing member's mailbox.
		// Its owner chooses their own password through a setup link.
		purpose, encoded, name, company = "setup", "", user.Name, ""
	}
	if err := s.issueStaffAuthEmail(ctx, q, user, email, name, company, purpose, encoded); err != nil {
		staffAuthUnavailable(w)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		staffAuthUnavailable(w)
		return
	}
	staffAuthAccepted(w)
}

func (s *Server) issueStaffAuthEmail(ctx context.Context, q *generated.Queries, user *generated.User, email, name, company, purpose, encoded string) error {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256([]byte(token))
	input := generated.IssueStaffAuthRequestParams{
		ID: uuid.New(), Email: email, Purpose: purpose, Name: name, CompanyName: company,
		TokenHash: digest[:], TtlSeconds: 24 * 60 * 60,
	}
	if user != nil {
		input.UserID = pgtype.UUID{Bytes: user.ID, Valid: true}
		input.SessionGeneration = pgtype.Int8{Int64: user.SessionGeneration, Valid: true}
	}
	path, subject, action := "/reset-password", "Set your Hash password", "Choose your own password"
	if purpose == "register" {
		input.PasswordHash = pgtype.Text{String: encoded, Valid: true}
		path, subject, action = "/verify-email", "Verify your Hash email", "Verify your email"
	} else if purpose == "reset" {
		input.TtlSeconds = 30 * 60
		subject, action = "Reset your Hash password", "Reset your password"
	}
	link := strings.TrimSuffix(s.PublicURL, "/") + path + "#token=" + token
	message := dispatch.Message{
		To: email, Subject: subject,
		HTML: "<p>" + html.EscapeString(action) + " using the link below.</p><p><a href=\"" + html.EscapeString(link) + "\">" + html.EscapeString(action) + "</a></p><p>If you did not request this, ignore this email. The link expires and can be used once.</p>",
		Text: action + ":\n" + link + "\n\nIf you did not request this, ignore this email. The link expires and can be used once.",
	}
	deliveryID := uuid.New()
	sealed, err := dispatch.SealStaffAuthEmail(s.StaffAuthMailBox, deliveryID, message)
	if err != nil {
		return err
	}
	if err := q.DeleteExpiredStaffAuthRequests(ctx); err != nil {
		return err
	}
	if err := q.DeleteStaffAuthRequestsByEmail(ctx, email); err != nil {
		return err
	}
	if err := q.IssueStaffAuthRequest(ctx, input); err != nil {
		return err
	}
	return q.EnqueueStaffAuthEmail(ctx, generated.EnqueueStaffAuthEmailParams{ID: deliveryID, ToEmail: email, Subject: subject, StaffAuthCiphertext: sealed})
}

func parseStaffAuthToken(token string) ([]byte, error) {
	if len(token) != 43 {
		return nil, errStaffAuthLink
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != token {
		return nil, errStaffAuthLink
	}
	sum := sha256.Sum256([]byte(token))
	return sum[:], nil
}

func (s *Server) redeemStaffAuth(ctx context.Context, token, encoded string, registration bool) (*generated.User, error) {
	digest, err := parseStaffAuthToken(token)
	if err != nil {
		return nil, err
	}
	observed, err := s.Queries.GetStaffAuthRequest(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errStaffAuthLink
	}
	if err != nil {
		return nil, err
	}
	var verifiedRegistrationHash string
	if registration {
		if observed.Purpose != "register" || !observed.PasswordHash.Valid || encoded == "" || len(encoded) > passwordhash.MaxPasswordBytes {
			return nil, errStaffAuthLink
		}
		matches, err := passwordhash.Verify(ctx, encoded, observed.PasswordHash.String)
		if err != nil {
			return nil, err
		}
		if !matches {
			return nil, errStaffAuthLink
		}
		verifiedRegistrationHash = observed.PasswordHash.String
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer rollbackSessionTransaction(ctx, tx)
	q := s.Queries.WithTx(tx)
	if err := q.LockStaffPasswordEmail(ctx, observed.Email); err != nil {
		return nil, err
	}
	request, err := q.GetStaffAuthRequestForUpdate(ctx, digest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errStaffAuthLink
	}
	if err != nil {
		return nil, err
	}
	if request.Email != observed.Email || (registration && request.Purpose != "register") ||
		(!registration && request.Purpose != "setup" && request.Purpose != "reset") {
		return nil, errStaffAuthLink
	}
	user, err := q.LockStaffPasswordUserByEmail(ctx, request.Email)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		user = nil
	}
	var created bool
	if user == nil {
		if !registration || request.UserID.Valid {
			return nil, errStaffAuthLink
		}
		org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: request.CompanyName, Plan: "starter"})
		if err != nil {
			return nil, err
		}
		user, err = q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: request.Email, Name: request.Name, Role: "owner"})
		if err != nil {
			return nil, err
		}
		created = true
	} else {
		// An identity created after registration cannot inherit a submitter's
		// previously selected password, even after a mail link is opened.
		if registration {
			return nil, errStaffAuthLink
		}
		if request.UserID.Valid &&
			(uuid.UUID(request.UserID.Bytes) != user.ID || !request.SessionGeneration.Valid || request.SessionGeneration.Int64 != user.SessionGeneration) {
			return nil, errStaffAuthLink
		}
	}
	if registration {
		if !request.PasswordHash.Valid || request.PasswordHash.String != verifiedRegistrationHash {
			return nil, errStaffAuthLink
		}
		affected, err := q.CreateStaffPasswordCredential(ctx, generated.CreateStaffPasswordCredentialParams{UserID: user.ID, PasswordHash: request.PasswordHash.String})
		if err != nil {
			return nil, err
		}
		if affected != 1 {
			return nil, errStaffAuthLink
		}
	} else {
		if !request.UserID.Valid || uuid.UUID(request.UserID.Bytes) != user.ID {
			return nil, errStaffAuthLink
		}
		if err := q.SetStaffPasswordCredential(ctx, generated.SetStaffPasswordCredentialParams{UserID: user.ID, PasswordHash: encoded}); err != nil {
			return nil, err
		}
	}
	user, err = q.RotateStaffPasswordSession(ctx, generated.RotateStaffPasswordSessionParams{ID: user.ID, SessionGeneration: user.SessionGeneration})
	if err != nil {
		return nil, err
	}
	affected, err := q.ConsumeStaffAuthRequest(ctx, request.ID)
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, errStaffAuthLink
	}
	if err := q.InvalidateStaffAuthRequestsByEmail(ctx, request.Email); err != nil {
		return nil, err
	}
	kind := "member.password_reset"
	if registration {
		kind = "member.password_verified"
	}
	if created {
		kind = audit.KindMemberCreated
	}
	pending, err := s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: user.OrgID, ActorUserID: &user.ID, Kind: kind,
		Payload: map[string]any{"member_id": user.ID.String(), "provider": "password", "bootstrap": created}})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.Audit.Publish(pending)
	return user, nil
}

func (s *Server) handleStaffVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeStaffAuthJSON(w, r, &in) || !s.staffAuthReady(w) {
		return
	}
	if _, err := parseStaffAuthToken(in.Token); err != nil {
		writeError(w, http.StatusBadRequest, errStaffAuthLink.Error())
		return
	}
	if in.Password == "" || len(in.Password) > passwordhash.MaxPasswordBytes {
		writeError(w, http.StatusBadRequest, "verification link or password is incorrect or expired")
		return
	}
	if !s.staffAuthRedemptionAllowed(w, r, in.Token) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	user, err := s.redeemStaffAuth(ctx, in.Token, in.Password, true)
	if err != nil {
		if errors.Is(err, errStaffAuthLink) {
			writeError(w, http.StatusBadRequest, "verification link or password is incorrect or expired")
		} else {
			staffAuthUnavailable(w)
		}
		return
	}
	if err := auth.MintSession(w, s.Cookies, SessionCookieName, auth.SessionPayload{UserID: user.ID, Generation: user.SessionGeneration}, 24*time.Hour); err != nil {
		staffAuthUnavailable(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStaffPasswordLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeStaffAuthJSON(w, r, &in) {
		return
	}
	email, _, err := normalizeOIDCIdentity(in.Email, "")
	if err != nil || in.Password == "" || len(in.Password) > passwordhash.MaxPasswordBytes {
		writeError(w, http.StatusUnauthorized, "email or password is incorrect")
		return
	}
	if !s.staffAuthAccountAllowed(w, "login", email, 20) || !s.staffAuthReady(w) {
		return
	}
	credential, lookupErr := s.Queries.GetStaffPasswordCredential(r.Context(), email)
	if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
		staffAuthUnavailable(w)
		return
	}
	encoded := passwordhash.DummyHash
	if lookupErr == nil {
		encoded = credential.PasswordHash
	}
	matches, err := passwordhash.Verify(r.Context(), in.Password, encoded)
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	if lookupErr != nil || !matches {
		writeError(w, http.StatusUnauthorized, "email or password is incorrect")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	defer rollbackSessionTransaction(ctx, tx)
	user, err := s.Queries.WithTx(tx).RefreshStaffPasswordLogin(ctx, generated.RefreshStaffPasswordLoginParams{UserID: credential.ID, SessionGeneration: credential.SessionGeneration, PasswordHash: encoded})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusUnauthorized, "email or password is incorrect")
		return
	}
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		staffAuthUnavailable(w)
		return
	}
	if err := auth.MintSession(w, s.Cookies, SessionCookieName, auth.SessionPayload{UserID: user.ID, Generation: user.SessionGeneration}, 24*time.Hour); err != nil {
		staffAuthUnavailable(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleStaffForgotPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !decodeStaffAuthJSON(w, r, &in) {
		return
	}
	email, _, err := normalizeOIDCIdentity(in.Email, "")
	if err != nil {
		staffAuthAccepted(w)
		return
	}
	if !s.staffAuthAccountAllowed(w, "recovery", email, 5) || !s.staffAuthReady(w) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	defer rollbackSessionTransaction(ctx, tx)
	q := s.Queries.WithTx(tx)
	if err := q.LockStaffPasswordEmail(ctx, email); err != nil {
		staffAuthUnavailable(w)
		return
	}
	user, err := q.LockStaffPasswordUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		staffAuthAccepted(w)
		return
	}
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	purpose := "reset"
	if _, err := q.GetStaffPasswordCredentialForUser(ctx, user.ID); errors.Is(err, pgx.ErrNoRows) {
		purpose = "setup"
	} else if err != nil {
		staffAuthUnavailable(w)
		return
	}
	if err := s.issueStaffAuthEmail(ctx, q, user, email, user.Name, "", purpose, ""); err != nil {
		staffAuthUnavailable(w)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		staffAuthUnavailable(w)
		return
	}
	staffAuthAccepted(w)
}

func (s *Server) handleStaffResetPassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeStaffAuthJSON(w, r, &in) {
		return
	}
	if _, err := parseStaffAuthToken(in.Token); err != nil {
		writeError(w, http.StatusBadRequest, errStaffAuthLink.Error())
		return
	}
	if !validStaffPassword(in.Password) {
		writeError(w, http.StatusBadRequest, "password requires at least12 characters and at most1024 UTF-8 bytes")
		return
	}
	if !s.staffAuthReady(w) {
		return
	}
	if !s.staffAuthRedemptionAllowed(w, r, in.Token) {
		return
	}
	encoded, err := passwordhash.Hash(r.Context(), in.Password)
	if err != nil {
		staffAuthUnavailable(w)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	_, err = s.redeemStaffAuth(ctx, in.Token, encoded, false)
	if err != nil {
		if errors.Is(err, errStaffAuthLink) {
			writeError(w, http.StatusBadRequest, errStaffAuthLink.Error())
		} else {
			staffAuthUnavailable(w)
		}
		return
	}
	auth.ClearSession(w, SessionCookieName)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) staffAuthRedemptionAllowed(w http.ResponseWriter, r *http.Request, token string) bool {
	digest, err := parseStaffAuthToken(token)
	if err != nil {
		writeError(w, http.StatusBadRequest, errStaffAuthLink.Error())
		return false
	}
	pending, err := s.Queries.GetStaffAuthRequest(r.Context(), digest)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusBadRequest, errStaffAuthLink.Error())
		return false
	}
	if err != nil {
		staffAuthUnavailable(w)
		return false
	}
	return s.staffAuthAccountAllowed(w, "redemption", pending.Email, 10)
}
