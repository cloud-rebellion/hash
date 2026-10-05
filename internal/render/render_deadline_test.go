// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type deadlineTransport func(*http.Request) (*http.Response, error)

func (f deadlineTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRenderHasOverallDeadlineWithoutCallerDeadline(t *testing.T) {
	calls := 0
	var firstDeadline time.Time
	g := NewGotenberg("http://renderer.invalid")
	g.HTTP = &http.Client{Transport: deadlineTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("render has no deadline")
		}
		if calls == 1 {
			firstDeadline = deadline
		} else if !deadline.Equal(firstDeadline) {
			t.Fatal("retry reset overall deadline")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 || remaining > 60*time.Second {
			t.Fatalf("deadline remaining %v", remaining)
		}
		return nil, errors.New("synthetic transport failure")
	})}
	if _, err := g.HTMLToPDF(context.Background(), "<p>test</p>", PDFOptions{}); err == nil {
		t.Fatal("expected transport error")
	}
	if calls != 3 {
		t.Fatalf("attempts=%d", calls)
	}
}

func TestRenderAdmissionHonorsShorterCallerDeadline(t *testing.T) {
	g := NewGotenberg("http://renderer.invalid")
	g.sem = make(chan struct{}, 1)
	g.sem <- struct{}{}
	g.HTTP = &http.Client{Transport: deadlineTransport(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport called while admission full")
		return nil, nil
	})}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := g.HTMLToPDF(ctx, "<p>test</p>", PDFOptions{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v", err)
	}
}
