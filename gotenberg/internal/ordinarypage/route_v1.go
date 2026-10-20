// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ordinarypage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/gotenberg/internal/hashapi"
	"github.com/labstack/echo/v4"
)

type PrepareFuncV1 func(context.Context, *slog.Logger, PlanV1, []byte) (*PackageV1, error)

var ErrRouteConfigV1 = errors.New("ordinarypage: private route configuration invalid")

const routeCleanupReserveV1 = 10 * time.Second
const routeWriteLimitV1 = 5 * time.Second

func ValidTokenV1(token string) bool {
	if len(token) < 32 || len(token) > 128 {
		return false
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

// The production callback must use the shared Chromium supervisor and owned
// network/source/target cleanup, then return its genuine native-print package.
// This route exposes no arbitrary HTML, font, URL or public conversion options.
func RouteV1(token string, apiTimeout time.Duration, prepare PrepareFuncV1) (api.Route, error) {
	if !ValidTokenV1(token) || apiTimeout < 15*time.Second || apiTimeout > time.Duration(1<<63-1)-5*time.Second || prepare == nil {
		return api.Route{}, ErrRouteConfigV1
	}
	tokenSHA := sha256.Sum256([]byte(token))
	// One registered route owns one complete ordinary-request working set,
	// from before body decoding through the final response write. This bounds
	// only this route; it is not a retained-disk or other-route quota.
	operationPermit := make(chan struct{}, 1)
	return api.Route{Method: http.MethodPost, Path: RoutePathV1, DisableTelemetry: true, Handler: func(c echo.Context) error {
		// Echo's independent hard timeout can reuse its pooled Context. Retain only
		// the raw request/writer; never touch c after entering the owned callback.
		r, w := c.Request(), c.Response().Writer
		parent := r.Context()
		started := time.Now()
		responseDeadline := started.Add(apiTimeout)
		if deadline, ok := parent.Deadline(); ok && deadline.Before(responseDeadline) {
			responseDeadline = deadline
		}
		refuse := func(status int) error {
			return writeResponseV1(parent, w, responseDeadline, status, "text/plain; charset=utf-8", []byte("hash ordinary page request refused\n"))
		}
		auth := r.Header.Values("Authorization")
		if len(auth) != 1 || len(auth[0]) < 7 || auth[0][:7] != "Bearer " || !ValidTokenV1(auth[0][7:]) {
			return refuse(http.StatusUnauthorized)
		}
		supplied := sha256.Sum256([]byte(auth[0][7:]))
		if subtle.ConstantTimeCompare(tokenSHA[:], supplied[:]) != 1 {
			return refuse(http.StatusUnauthorized)
		}
		if parent.Err() != nil {
			return nil
		}
		if r.Method != http.MethodPost {
			return refuse(http.StatusMethodNotAllowed)
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Encoding")) != 0 {
			return refuse(http.StatusBadRequest)
		}
		types := r.Header.Values("Content-Type")
		if len(types) != 1 || types[0] != "application/json" {
			return refuse(http.StatusUnsupportedMediaType)
		}
		if r.ContentLength > MaxRequestBytesV1 {
			return refuse(http.StatusRequestEntityTooLarge)
		}
		remaining := time.Until(responseDeadline) - routeCleanupReserveV1
		if remaining <= 0 {
			return refuse(http.StatusServiceUnavailable)
		}
		workLimit := min(60*time.Second, apiTimeout-routeCleanupReserveV1, remaining)
		ctx, cancel := context.WithTimeout(parent, workLimit)
		defer cancel()
		workDeadline, _ := ctx.Deadline()
		controller := http.NewResponseController(w)
		if controller.SetReadDeadline(workDeadline) != nil || controller.SetWriteDeadline(responseDeadline) != nil {
			return refuse(http.StatusServiceUnavailable)
		}
		if r.Body == nil {
			return refuse(http.StatusBadRequest)
		}
		// All request/context/deadline snapshots are complete before the wait.
		// A queued request expires without reading its body or entering Chromium.
		select {
		case operationPermit <- struct{}{}:
			defer func() { <-operationPermit }()
		case <-ctx.Done():
			return refuse(http.StatusServiceUnavailable)
		}
		// The select may choose an available permit concurrently with cancellation.
		if ctx.Err() != nil {
			return refuse(http.StatusServiceUnavailable)
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, MaxRequestBytesV1+1))
		if err != nil {
			return refuse(http.StatusBadRequest)
		}
		if len(raw) > MaxRequestBytesV1 {
			return refuse(http.StatusRequestEntityTooLarge)
		}
		if ctx.Err() != nil {
			return refuse(http.StatusServiceUnavailable)
		}
		request, err := DecodeRequestV1(ctx, raw)
		if err != nil {
			return refuse(http.StatusBadRequest)
		}
		candidate, err := prepare(ctx, slog.New(slog.DiscardHandler), request.Plan, request.FontBytes)
		if err != nil || ctx.Err() != nil || candidate == nil {
			return refuse(http.StatusServiceUnavailable)
		}
		body := candidate.Bytes()
		if _, err := DecodeWithContextV1(ctx, body, request.Plan); err != nil || ctx.Err() != nil {
			return refuse(http.StatusServiceUnavailable)
		}
		return writeResponseV1(parent, w, minTimeV1(responseDeadline, workDeadline), http.StatusOK, MediaTypeV1, body)
	}}, nil
}
func writeResponseV1(ctx context.Context, w http.ResponseWriter, deadline time.Time, status int, mime string, body []byte) error {
	if ctx.Err() != nil || !time.Now().Before(deadline) {
		return nil
	}
	writeDeadline := minTimeV1(deadline, time.Now().Add(routeWriteLimitV1))
	if http.NewResponseController(w).SetWriteDeadline(writeDeadline) != nil {
		return errors.New("ordinarypage: response unavailable")
	}
	if ctx.Err() != nil || !time.Now().Before(writeDeadline) {
		return nil
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	n, err := w.Write(body)
	if err != nil || n != len(body) {
		return errors.New("ordinarypage: response unavailable")
	}
	return nil
}

func minTimeV1(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
