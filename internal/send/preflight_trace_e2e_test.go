//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package send_test

import (
	"context"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This diagnostic tracer only schedules the actual second native state query
// after preparation commits. It supplies no row, authorization, measurement or
// transaction capability; the original query and all its guards still run.
type sendAdmissionTrace struct {
	mu               sync.Mutex
	document         uuid.UUID
	calls            int
	reached, release chan struct{}
	once             sync.Once
}

func (s *sendAdmissionTrace) arm(document uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.document = document
	s.reached, s.release = make(chan struct{}), make(chan struct{})
}

func (s *sendAdmissionTrace) unblock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.release != nil {
		s.once.Do(func() { close(s.release) })
	}
}

func (s *sendAdmissionTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.HasPrefix(data.SQL, "-- name: GetHTMLSendDocumentStateHeaderV1") || len(data.Args) == 0 {
		return ctx
	}
	id, ok := data.Args[0].(uuid.UUID)
	s.mu.Lock()
	if !ok || s.document == uuid.Nil || id != s.document {
		s.mu.Unlock()
		return ctx
	}
	s.calls++
	if s.calls != 2 {
		s.mu.Unlock()
		return ctx
	}
	close(s.reached)
	release := s.release
	s.mu.Unlock()
	select {
	case <-release:
	case <-ctx.Done():
	}
	return ctx
}

func (*sendAdmissionTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
