// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var ErrAutomationMaterializationV1 = errors.New("pdfadmission: native automation materialization unavailable")
var ErrAutomationRequestHashConflictV1 = errors.New("pdfadmission: automation request hash conflict")

// Migration63 fixes hashes at32 bytes and state to claimed/ready/sent. Its
// genuine claim/replay/bind rows have no cold JSON or arbitrary text bodies.
type ApplicationAutomationRequestWriterV1 struct {
	state *applicationAutomationRequestStateV1
}
type applicationAutomationRequestStateV1 struct {
	mu                               sync.Mutex
	session                          *ApplicationSessionV1
	reader                           *ApplicationHTMLAuthoringReaderV1
	queries                          *generated.Queries
	close                            func()
	request                          *generated.AutomationSignatureRequest
	rows                             [3]*generated.AutomationSignatureRequest
	count                            int
	claimed, replayed, bound, closed bool
}

func (h *ApplicationSessionV1) NewAutomationRequestWriterV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationAutomationRequestWriterV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrAutomationMaterializationV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationAutomationRequestStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationAutomationRequestWriterV1{})) + 8*int64(unsafe.Sizeof(generated.AutomationSignatureRequest{})) + 2*int64(unsafe.Sizeof(generated.ClaimAutomationSignatureRequestParams{})) + 2*int64(unsafe.Sizeof(generated.GetAutomationSignatureRequestForUpdateParams{})) + 2*int64(unsafe.Sizeof(generated.BindAutomationSignatureRequestDocumentParams{})) + 8*(64+7)
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	return &ApplicationAutomationRequestWriterV1{state: &applicationAutomationRequestStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), close: close}}, nil
}
func (s *applicationAutomationRequestStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.closed && s.session != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}
func automationRequestCloneV1(row *generated.AutomationSignatureRequest) *generated.AutomationSignatureRequest {
	if row == nil {
		return nil
	}
	copy := *row
	copy.IdempotencyKeyHash = bytes.Clone(row.IdempotencyKeyHash)
	copy.RequestHash = bytes.Clone(row.RequestHash)
	copy.State = strings.Clone(row.State)
	return &copy
}
func (s *applicationAutomationRequestStateV1) acceptV1(row *generated.AutomationSignatureRequest, key, hash [32]byte) error {
	if row == nil || row.ID == uuid.Nil || row.OrgID != s.session.state.org || len(row.IdempotencyKeyHash) != 32 || len(row.RequestHash) != 32 || subtle.ConstantTimeCompare(row.IdempotencyKeyHash, key[:]) != 1 || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || (row.State != "claimed" && row.State != "ready" && row.State != "sent") {
		return ErrAutomationMaterializationV1
	}
	if subtle.ConstantTimeCompare(row.RequestHash, hash[:]) != 1 {
		return ErrAutomationRequestHashConflictV1
	}
	return nil
}
func (w *ApplicationAutomationRequestWriterV1) ClaimV1(ctx context.Context, key, hash [32]byte) (*generated.AutomationSignatureRequest, bool, error) {
	if w == nil || w.state == nil {
		return nil, false, ErrAutomationMaterializationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.claimed {
		return nil, false, ErrAutomationMaterializationV1
	}
	s.claimed = true
	row, err := s.queries.ClaimAutomationSignatureRequest(ctx, generated.ClaimAutomationSignatureRequestParams{OrgID: s.session.state.org, IdempotencyKeyHash: key[:], RequestHash: hash[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		s.replayed = true
		row, err = s.queries.GetAutomationSignatureRequestForUpdate(ctx, generated.GetAutomationSignatureRequestForUpdateParams{OrgID: s.session.state.org, IdempotencyKeyHash: key[:]})
	}
	if err != nil {
		return nil, false, err
	}
	if err = s.acceptV1(row, key, hash); err != nil {
		return nil, false, err
	}
	if !s.replayed && (row.State != "claimed" || row.DocumentID.Valid) {
		return nil, false, ErrAutomationMaterializationV1
	}
	s.rows[s.count] = row
	s.count++
	s.request = automationRequestCloneV1(row)
	return row, s.replayed, nil
}
func (w *ApplicationAutomationRequestWriterV1) BindFreshDocumentV1(ctx context.Context, source *ApplicationBlocksCreationWriterV1) (*generated.AutomationSignatureRequest, error) {
	if w == nil || w.state == nil || source == nil || source.state == nil {
		return nil, ErrAutomationMaterializationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.claimed || s.replayed || s.bound || s.request == nil || s.count >= len(s.rows) {
		return nil, ErrAutomationMaterializationV1
	}
	doc, release, err := source.state.borrowFreshV1(ctx, s.session, s.reader)
	if err != nil {
		return nil, err
	}
	defer release()
	row, err := s.queries.BindAutomationSignatureRequestDocument(ctx, generated.BindAutomationSignatureRequestDocumentParams{ID: s.request.ID, OrgID: s.request.OrgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.request.ID || row.OrgID != s.request.OrgID || row.DocumentID != (pgtype.UUID{Bytes: doc.ID, Valid: true}) || row.State != "ready" || row.CreatedAt != s.request.CreatedAt || !applicationStampV1(row.UpdatedAt) || !bytes.Equal(row.IdempotencyKeyHash, s.request.IdempotencyKeyHash) || !bytes.Equal(row.RequestHash, s.request.RequestHash) {
		return nil, ErrAutomationMaterializationV1
	}
	s.rows[s.count] = row
	s.count++
	s.request = automationRequestCloneV1(row)
	s.bound = true
	return row, nil
}
func (w *ApplicationAutomationRequestWriterV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.request = nil
	s.rows = [3]*generated.AutomationSignatureRequest{}
	if s.close != nil {
		s.close()
		s.close = nil
	}
}

type ApplicationAutomationRecipientsV1 struct {
	state *applicationAutomationRecipientsStateV1
}
type applicationAutomationRecipientsStateV1 struct {
	mu                sync.Mutex
	session           *ApplicationSessionV1
	reader            *ApplicationHTMLAuthoringReaderV1
	queries           *generated.Queries
	close, releaseDoc func()
	doc               *generated.Document
	values            []recipients.Values
	rows              []*generated.Recipient
	audits            *applicationAutomationAuditBatchV1
	next              int
	now               time.Time
	closed            bool
}

func (h *ApplicationSessionV1) NewAutomationRecipientsV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1, source *ApplicationBlocksCreationWriterV1, values []recipients.Values) (*ApplicationAutomationRecipientsV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) || source == nil || source.state == nil || len(values) < 1 || len(values) > 50 {
		return nil, ErrAutomationMaterializationV1
	}
	doc, release, err := source.state.borrowFreshV1(ctx, h, reader)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	raw := 2*int64(unsafe.Sizeof(applicationAutomationAuditBatchV1{})) + 2*int64(unsafe.Sizeof(ApplicationAutomationAuditsV1{})) + 2*int64(unsafe.Sizeof(applicationAutomationRecipientsStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationAutomationRecipientsV1{}))
	for _, value := range values {
		if !htmlInputAddV1(&raw, int64(len(value.Role)+len(value.Email)+len(value.Name)+len(value.Locale)), 2) || !htmlInputAddV1(&raw, 1, 4*int64(unsafe.Sizeof(recipients.Values{}))+4*int64(unsafe.Sizeof(generated.Recipient{}))+2*int64(unsafe.Sizeof(generated.CreateRecipientParams{}))+2*int64(unsafe.Sizeof((*generated.Recipient)(nil)))+2*32+43+7) {
			return nil, ErrAutomationMaterializationV1
		}
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, err
	}
	copied := make([]recipients.Values, len(values))
	for i, v := range values {
		copied[i] = v
		copied[i].Role = strings.Clone(v.Role)
		copied[i].Email = strings.Clone(v.Email)
		copied[i].Name = strings.Clone(v.Name)
		copied[i].Locale = strings.Clone(v.Locale)
	}
	success = true
	return &ApplicationAutomationRecipientsV1{state: &applicationAutomationRecipientsStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), close: close, releaseDoc: release, doc: doc, values: copied, rows: make([]*generated.Recipient, 0, 2*len(values)), now: time.Now()}}, nil
}

// The original materializer interleaves each fresh recipient with its audit.
// One aggregate source-derived grant holds this finite original <=50 batch.
func (w *ApplicationAutomationRecipientsV1) CreateNextV1(ctx context.Context) (*generated.Recipient, error) {
	if w == nil || w.state == nil {
		return nil, ErrAutomationMaterializationV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.next >= len(s.values) || s.doc == nil || s.session == nil || s.reader == nil || !s.reader.valid(ctx) {
		return nil, ErrAutomationMaterializationV1
	}
	value := s.values[s.next]
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		return nil, err
	}
	expiry := magictoken.Expiry(s.doc.ExpiresAt, s.now)
	row, err := s.queries.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: s.doc.ID, Role: value.Role, Email: value.Email, Name: value.Name, OrderIndex: value.OrderIndex, Locale: value.Locale, MagicTokenHash: hash, MagicTokenExpiresAt: expiry})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != s.doc.ID || row.Role != value.Role || row.Email != value.Email || row.Name != value.Name || row.OrderIndex != value.OrderIndex || row.Locale != value.Locale || row.Status != "pending" || !bytes.Equal(row.MagicTokenHash, hash) || !applicationStampV1(row.CreatedAt) || row.SentAt.Valid || row.FirstViewedAt.Valid || row.SignedAt.Valid || row.DeclinedReason.Valid || row.MagicTokenExpiresAt.Valid != expiry.Valid || (expiry.Valid && (!applicationStampV1(row.MagicTokenExpiresAt) || !row.MagicTokenExpiresAt.Time.Equal(expiry.Time.UTC().Truncate(time.Microsecond)))) {
		return nil, ErrAutomationMaterializationV1
	}
	for _, prior := range s.rows {
		if prior.ID == row.ID {
			return nil, ErrAutomationMaterializationV1
		}
	}
	copy := *row
	copy.Role = strings.Clone(row.Role)
	copy.Email = strings.Clone(row.Email)
	copy.Name = strings.Clone(row.Name)
	copy.Locale = strings.Clone(row.Locale)
	copy.Status = strings.Clone(row.Status)
	copy.MagicTokenHash = bytes.Clone(row.MagicTokenHash)
	s.rows = append(s.rows, row, &copy)
	s.next++
	return row, nil
}
func (w *ApplicationAutomationRecipientsV1) CloseConsumerV1() {
	if w == nil || w.state == nil {
		return
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.doc = nil
	s.values = nil
	s.rows = nil
	if s.close != nil {
		s.close()
		s.close = nil
	}
	if s.releaseDoc != nil {
		s.releaseDoc()
		s.releaseDoc = nil
	}
}
