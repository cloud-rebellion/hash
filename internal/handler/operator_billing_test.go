// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
)

func TestOperatorPaymentHTTPHandlersCannotUseDatabase(t *testing.T) {
	s := &Server{Billing: billing.NewOperator(nil, nil)}
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	for name, handler := range map[string]http.HandlerFunc{"checkout": s.handleStartBillingCheckout, "cancel": s.handleCancelBillingSubscription, "webhook": s.handleBillingWebhook} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
			handler(rr, r)
			if rr.Code >= 200 && rr.Code < 300 {
				t.Fatalf("payment falsely succeeded: %s", rr.Body.String())
			}
		})
	}
	rr := httptest.NewRecorder()
	s.handleListBillingInvoices(rr, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	if rr.Code != 200 || rr.Body.String() != "{\"invoices\":[]}\n" {
		t.Fatalf("fake invoice state: %s", rr.Body.String())
	}
}

func TestOperatorRetiredPaymentCallbackCannotReturnSPA(t *testing.T) {
	s := &Server{PublicURL: "http://localhost", Billing: billing.NewOperator(nil, nil), Frontend: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SPA"))
	})}
	routes := s.Routes()
	for _, path := range []string{"/webhooks/billing", "/webhooks/billing/old-provider-secret"} {
		rr := httptest.NewRecorder()
		routes.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, path, nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("retired callback %s got %d body=%s", path, rr.Code, rr.Body.String())
		}
	}
}
