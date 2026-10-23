// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package noticeaccess

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/google/uuid"
)

const cookiePurposeV1 = "amendment-notice-read-v1"

func cookieNameV1(notice uuid.UUID) string { return "__Secure-hash_notice_" + notice.String() }
func apiPathV1(notice uuid.UUID) string    { return "/api/v1/notices/" + notice.String() }

// Mount even when unavailable, so a missing process allocation cannot fall
// through to a successful SPA shell. No staff/session/signer route is mounted.
func MountV1(r chi.Router, e *EngineV1) {
	r.Group(func(r chi.Router) {
		r.Use(httprate.LimitByIP(240, time.Minute))
		r.Post("/api/v1/notices/{notice_id}/access", func(w http.ResponseWriter, r *http.Request) {
			if e == nil {
				accessErrorV1(w, ErrUnavailableV1)
				return
			}
			e.exchangeV1(w, r)
		})
		r.With(noticeCredentialLimitV1(e, 240)).Get("/api/v1/notices/{notice_id}", func(w http.ResponseWriter, r *http.Request) {
			if e == nil {
				accessErrorV1(w, ErrUnavailableV1)
				return
			}
			e.presentationV1(w, r)
		})
		r.With(httprate.LimitByIP(60, time.Minute), noticeCredentialLimitV1(e, 30)).Get("/api/v1/notices/{notice_id}/files/{position}", func(w http.ResponseWriter, r *http.Request) {
			if e == nil {
				accessErrorV1(w, ErrUnavailableV1)
				return
			}
			e.fileV1(w, r)
		})
	})
}
func accessErrorV1(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "application/json")
	status := http.StatusServiceUnavailable
	body := `{"error":"notice files temporarily unavailable"}`
	if errors.Is(err, ErrDeniedV1) {
		status = http.StatusNotFound
		body = `{"error":"notice access invalid, revoked or expired"}`
	}
	if errors.Is(err, ErrPreconditionV1) {
		status = http.StatusPreconditionFailed
		body = `{"error":"exact notice file commitment required"}`
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}
func requestNoticeV1(r *http.Request) (uuid.UUID, error) {
	raw := chi.URLParam(r, "notice_id")
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, ErrDeniedV1
	}
	return id, nil
}
func (e *EngineV1) exchangeV1(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	notice, err := requestNoticeV1(r)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	// Fragment possession may obtain only this bounded read cookie. It never
	// creates a sender session or a response/receipt. Cross-origin POST refuses.
	media, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != e.publicURL || mediaErr != nil || media != "application/json" || strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	control, err := e.work.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: 16 << 10})
	if err != nil {
		accessErrorV1(w, ErrUnavailableV1)
		return
	}
	defer control.Close()
	deadline, ok := ctx.Deadline()
	if !ok || http.NewResponseController(w).SetReadDeadline(deadline) != nil {
		accessErrorV1(w, ErrUnavailableV1)
		return
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, 129))
	if err != nil || len(raw) > 128 {
		clear(raw)
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	defer clear(raw)
	var input struct {
		Token string `json:"token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF {
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	canonical, _ := json.Marshal(input)
	defer clear(canonical)
	if !bytes.Equal(canonical, raw) {
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	digest, err := TokenDigestV1(input.Token)
	input.Token = ""
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	snapshot, err := e.lookupV1(ctx, notice, digest, nil)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	defer snapshot.closeV1()
	writing := false
	err = e.withReadGuardV1(ctx, snapshot, func(use context.Context) error {
		ttl := 10 * time.Minute
		if remaining := time.Until(snapshot.expires); remaining < ttl {
			ttl = remaining
		}
		if ttl <= time.Second {
			return ErrDeniedV1
		}
		payload := make([]byte, 64)
		copy(payload[:16], snapshot.access[:])
		copy(payload[16:32], snapshot.notice[:])
		copy(payload[32:], snapshot.tokenSHA[:])
		defer clear(payload)
		token, err := e.cookies.MintPurpose(cookiePurposeV1, payload, ttl)
		if err != nil {
			return ErrUnavailableV1
		}
		if err := setWriteDeadlineV1(w, use); err != nil {
			return err
		}
		http.SetCookie(w, &http.Cookie{Name: cookieNameV1(notice), Value: token, Path: apiPathV1(notice), MaxAge: int(ttl / time.Second), Expires: time.Now().Add(ttl).UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		writing = true
		return writeJSONV1(w, use, struct {
			Schema    string    `json:"schema"`
			ExpiresAt time.Time `json:"expires_at"`
		}{SchemaV1, snapshot.expires.UTC()})
	})
	if err != nil && !writing {
		accessErrorV1(w, err)
	}
}
func (e *EngineV1) cookieSnapshotV1(ctx context.Context, r *http.Request, notice uuid.UUID) (*snapshotV1, error) {
	cookie, err := r.Cookie(cookieNameV1(notice))
	if err != nil {
		return nil, ErrDeniedV1
	}
	payload, err := e.cookies.VerifyPurpose(cookiePurposeV1, cookie.Value)
	if err != nil || len(payload) != 64 {
		return nil, ErrDeniedV1
	}
	defer clear(payload)
	var id, boundNotice uuid.UUID
	var digest [32]byte
	copy(id[:], payload[:16])
	copy(boundNotice[:], payload[16:32])
	copy(digest[:], payload[32:])
	if id == uuid.Nil || boundNotice != notice {
		return nil, ErrDeniedV1
	}
	return e.lookupV1(ctx, notice, digest, &id)
}
func setWriteDeadlineV1(w http.ResponseWriter, ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok || ctx.Err() != nil {
		return ErrUnavailableV1
	}
	if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
		return ErrUnavailableV1
	}
	return nil
}
func writeJSONV1(w http.ResponseWriter, ctx context.Context, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > 256<<10 {
		return ErrUnavailableV1
	}
	defer clear(raw)
	if ctx.Err() != nil {
		return ErrDeniedV1
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(http.StatusOK)
	n, err := w.Write(raw)
	if err == nil && n != len(raw) {
		return io.ErrShortWrite
	}
	return err
}
func (e *EngineV1) presentationV1(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	notice, err := requestNoticeV1(r)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	snapshot, err := e.cookieSnapshotV1(ctx, r, notice)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	defer snapshot.closeV1()
	writing := false
	err = e.withReadGuardV1(ctx, snapshot, func(use context.Context) error {
		if err := setWriteDeadlineV1(w, use); err != nil {
			return err
		}
		writing = true
		return writeJSONV1(w, use, snapshot.public)
	})
	if err != nil && !writing {
		accessErrorV1(w, err)
	}
}
func (e *EngineV1) fileV1(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	notice, err := requestNoticeV1(r)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	position, err := strconv.Atoi(chi.URLParam(r, "position"))
	if err != nil || position < 0 || position >= MaxFilesV1 || strconv.Itoa(position) != chi.URLParam(r, "position") {
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	snapshot, err := e.cookieSnapshotV1(ctx, r, notice)
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	defer snapshot.closeV1()
	if position >= len(snapshot.files.Files) {
		accessErrorV1(w, ErrDeniedV1)
		return
	}
	file := snapshot.files.Files[position]
	values := r.Header.Values("If-Match")
	commit := hex.EncodeToString(snapshot.fileSHA[:])
	etag := ExpectedFileETagV1(commit, file.SHA256)
	if len(values) != 1 || values[0] != etag || r.Header.Get("Range") != "" {
		accessErrorV1(w, ErrPreconditionV1)
		return
	}
	digest, _ := hex.DecodeString(file.SHA256)
	slot, err := e.physicalSlotV1()
	if err != nil {
		accessErrorV1(w, err)
		return
	}
	defer e.closePhysicalV1(slot)
	handle, _, err := e.store.ReadPackagePDFLocalOwnedV1(ctx, file.Key, file.VersionID, digest, file.Bytes, e.work, snapshot.org)
	slot.read = handle
	if err != nil {
		accessErrorV1(w, ErrUnavailableV1)
		return
	}
	writing := false
	err = handle.WithPDFV1(func(body []byte) error {
		if int64(len(body)) != file.Bytes {
			return ErrUnavailableV1
		}
		return e.withReadGuardV1(ctx, snapshot, func(use context.Context) error {
			if err := setWriteDeadlineV1(w, use); err != nil {
				return err
			}
			if use.Err() != nil {
				return ErrDeniedV1
			}
			h := w.Header()
			h.Set("Cache-Control", "no-store")
			h.Set("Pragma", "no-cache")
			h.Set("Referrer-Policy", "no-referrer")
			h.Set("Content-Type", "application/pdf")
			h.Set("Content-Length", strconv.FormatInt(file.Bytes, 10))
			h.Set("Content-Disposition", "attachment; filename=\"notice-file-"+strconv.Itoa(position)+".pdf\"")
			h.Set("ETag", etag)
			h.Set("X-Hash-Notice-Id", notice.String())
			h.Set("X-Hash-Notice-File-Commitment-SHA256", commit)
			h.Set("X-Hash-PDF-SHA256", file.SHA256)
			h.Set("X-Hash-PDF-Bytes", strconv.FormatInt(file.Bytes, 10))
			h.Set("X-Hash-PDF-Pages", strconv.Itoa(int(file.Pages)))
			h.Set("X-Hash-Notice-File-Position", strconv.Itoa(position))
			h.Set("X-Hash-Notice-File-Version-SHA256", FileVersionSHA256V1(file))
			writing = true
			w.WriteHeader(http.StatusOK)
			n, err := w.Write(body)
			if err == nil && n != len(body) {
				return io.ErrShortWrite
			}
			return err
		})
	})
	if err != nil && !writing {
		accessErrorV1(w, err)
	}
}

func noticeCredentialLimitV1(e *EngineV1, requests int) func(http.Handler) http.Handler {
	return httprate.Limit(requests, time.Minute, httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
		notice, err := requestNoticeV1(r)
		if err != nil || e == nil || e.cookies == nil {
			return "invalid-notice-access", nil
		}
		cookie, err := r.Cookie(cookieNameV1(notice))
		if err != nil {
			return "invalid-notice-access", nil
		}
		payload, err := e.cookies.VerifyPurpose(cookiePurposeV1, cookie.Value)
		if err != nil || len(payload) != 64 {
			return "invalid-notice-access", nil
		}
		defer clear(payload)
		digest := domainHashV1("hash:notice-read-rate:v1", payload[:32])
		return hex.EncodeToString(digest[:]), nil
	}))
}
