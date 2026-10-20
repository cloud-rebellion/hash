// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/go-chi/chi/v5/middleware"
)

// panicMiddleware retains code-stack diagnostics without the recovered value.
// The outer Hash recovery preserves the existing HTTP500/abort behavior.
func panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler {
					// chi's Recoverer treats ErrAbortHandler as a
					// deliberate disconnect; propagate so it can do
					// the same.
					panic(rec)
				}
				slog.Error("http handler panicked",
					"category", "panic",
					"path", safeAccessPath(r.URL.Path),
					"method", r.Method,
					"request_id", middleware.GetReqID(r.Context()),
					"stack", string(debug.Stack()),
				)
				// Re-panic so the outer Hash recovery writes the standard500.
				panic(rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Keep chi's500/abort/upgrade behavior without its raw panic printer. Inner
// observers retain fixed diagnostics and code stacks; no panic value is logged.
func hashRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if value := recover(); value != nil {
				if value == http.ErrAbortHandler {
					panic(value)
				}
				if r.Header.Get("Connection") != "Upgrade" {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()
		next.ServeHTTP(w, r)
	})
}
