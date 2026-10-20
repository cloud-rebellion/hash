// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/remindercadence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrReminderV1 = errors.New("pdfadmission: native reminder unavailable")
var ErrReminderDeadlineV1 = errors.New("pdfadmission: reminder document deadline has passed")

type ApplicationReminderV1 struct{ state *applicationReminderStateV1 }
type applicationReminderRecipientV1 struct {
	recipient                   *generated.Recipient
	token                       string
	message                     dispatch.Message
	outbox                      uuid.UUID
	rotated, rendered, enqueued bool
}
type applicationReminderStateV1 struct {
	mu                                                         sync.Mutex
	self                                                       *applicationReminderStateV1
	work                                                       *ApplicationHTMLSendWorkV1
	document                                                   *generated.Document
	schedule                                                   *generated.Reminder
	closes                                                     []func()
	recipients                                                 []applicationReminderRecipientV1
	audits                                                     *applicationReminderAuditBatchV1
	auditHeld, auditOpening                                    bool
	actor                                                      pgtype.UUID
	senderEmail, publicURL, orgName, ip, via, tool             string
	expiry                                                     pgtype.Timestamptz
	automatic, due, prepared, reset, queue, delivery, finished bool
	auditNext                                                  int
	consumerClosed, released                                   bool
}

func reminderEligibleV1(r *generated.Recipient) bool {
	return r != nil && (r.Status == "pending" || r.Status == "sent" || r.Status == "viewed")
}
func (s *applicationReminderStateV1) validLockedV1(call context.Context) bool {
	w := s.work
	return s.self == s && !s.consumerClosed && !s.released && w != nil && w.valid(call) && s.document != nil && w.stage != nil && w.stage.operation != nil && w.reminder == s && w.sourceDocument == s.document && w.stage.operation.reminderSubject == s.document.ID && ((s.automatic && w.stage.purpose == HTMLReminderScheduledV1) || (!s.automatic && w.stage.purpose == HTMLReminderManualV1))
}

// policyTime is the original Engine.Now policy value, not caller due/next/count
// authority. Due/cadence derive only from this actual locked private schedule.
func (w *ApplicationHTMLSendWorkV1) StartReminderV1(call context.Context, policyTime time.Time) (*ApplicationReminderV1, bool, error) {
	if w == nil || w.self != w {
		return nil, false, ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.reminder != nil || w.sourceDocument == nil || w.stage == nil || (w.stage.purpose != HTMLReminderManualV1 && w.stage.purpose != HTMLReminderScheduledV1) || w.stage.operation.reminderSubject != w.sourceDocument.ID || (w.sourceDocument.Status != "sent" && w.sourceDocument.Status != "in_progress") || policyTime.IsZero() {
		return nil, false, ErrReminderV1
	}
	if w.sourceDocument.ExpiresAt.Valid && !w.sourceDocument.ExpiresAt.Time.After(policyTime) {
		return nil, false, ErrReminderDeadlineV1
	}
	close, err := w.actor.acquireOwnedRetainedBodyV1(call, 65536+8*int64(unsafe.Sizeof(applicationReminderStateV1{})), 0)
	if err != nil {
		return nil, false, err
	}
	s := &applicationReminderStateV1{work: w, document: w.sourceDocument, automatic: w.stage.purpose == HTMLReminderScheduledV1, due: true, closes: []func(){close}}
	s.self = s
	w.reminder = s
	w.sourceBorrowers++
	result := &ApplicationReminderV1{state: s}
	if !s.automatic {
		return result, true, nil
	}
	h, err := w.queries.GetReminderScheduleHeaderV1(call, generated.GetReminderScheduleHeaderV1Params{DocumentID: s.document.ID, OrgID: s.document.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		s.due = false
		return result, false, nil
	}
	if err != nil {
		return result, false, err
	}
	if h == nil || h.DocumentID != s.document.ID || h.ScheduleWireBytes < 0 {
		return result, false, ErrReminderV1
	}
	if h.FiresRemaining <= 0 || !h.NextFireAt.Valid || h.NextFireAt.Time.After(policyTime) {
		s.due = false
		return result, false, nil
	}
	if !applicationStampV1(s.document.SentAt) {
		return result, false, errors.New("automatic reminder requires send timestamp")
	}
	// One actual original JSON wire is priced before expansion. The conservative
	// wire-derived parser/typed-array scratch also funds malformed ignored keys;
	// no fixed schedule-entry ceiling replaces the original cadence policy.
	raw := int64(8192)
	if !htmlInputAddV1(&raw, h.ScheduleWireBytes, 96) {
		return result, false, ErrReminderV1
	}
	closeSchedule, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, h.ScheduleWireBytes)
	if err != nil {
		return result, false, err
	}
	s.closes = append(s.closes, closeSchedule)
	row, err := w.queries.ReadReminderScheduleV1(call, generated.ReadReminderScheduleV1Params{DocumentID: s.document.ID, OrgID: s.document.OrgID, ExpectedWireBytes: h.ScheduleWireBytes})
	if err != nil {
		return result, false, err
	}
	if row == nil || row.DocumentID != h.DocumentID || row.NextFireAt != h.NextFireAt || row.LastFiredAt != h.LastFiredAt || row.FiresRemaining != h.FiresRemaining || int64(len(row.ScheduleJson)) != h.ScheduleWireBytes {
		return result, false, ErrReminderV1
	}
	next, err := remindercadence.NextV1(row.ScheduleJson, int(row.FiresRemaining), s.document.SentAt.Time)
	if err != nil {
		return result, false, err
	}
	s.schedule = row
	next = next.UTC().Truncate(time.Microsecond)
	advanced, err := w.queries.AdvanceNativeReminderV1(call, generated.AdvanceNativeReminderV1Params{DocumentID: s.document.ID, NextFireAt: pgtype.Timestamptz{Time: next, Valid: true}, ExpectedFiresRemaining: row.FiresRemaining})
	if err != nil {
		return result, false, fmt.Errorf("advance automatic reminder: %w", err)
	}
	if advanced == nil || advanced.DocumentID != row.DocumentID || !bytes.Equal(advanced.ScheduleJson, row.ScheduleJson) || !applicationStampV1(advanced.LastFiredAt) || !applicationStampV1(advanced.NextFireAt) || !advanced.NextFireAt.Time.Equal(next) || advanced.FiresRemaining != row.FiresRemaining-1 {
		return result, false, ErrReminderV1
	}
	return result, true, nil
}

// Original concrete instance configuration and actor metadata are measured
// before cloning. No public body/count/cost/token/message can mint these slots.
func (r *ApplicationReminderV1) PrepareV1(call context.Context, publicURL, orgName, ip, via, tool string, queue, delivery bool, policyTime time.Time) error {
	if r == nil || r.state == nil {
		return ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.due || s.prepared || !w.recipientsRead || w.sourceActor == nil || w.sourceActor.OrgID != s.document.OrgID || (s.automatic && w.sourceActor.ID != s.document.SenderID) || queue && !delivery || policyTime.IsZero() {
		return ErrReminderV1
	}
	count := int64(0)
	for _, row := range w.sourceRecipients {
		if row == nil || row.DocumentID != s.document.ID {
			return ErrReminderV1
		}
		if reminderEligibleV1(row) {
			count++
		}
	}
	raw := int64(65536)
	if !htmlInputAddV1(&raw, count, 8192+8*int64(unsafe.Sizeof(applicationReminderRecipientV1{}))+8*int64(unsafe.Sizeof(applicationReminderAuditSlotV1{}))) {
		return ErrReminderV1
	}
	for _, v := range []string{publicURL, orgName, ip, via, tool, w.sourceActor.Email} {
		if !htmlInputAddV1(&raw, int64(len(v)), 16) {
			return ErrReminderV1
		}
	}
	for _, row := range w.sourceRecipients {
		if reminderEligibleV1(row) {
			for _, v := range []string{row.Email, row.Name, row.Role, row.Locale} {
				if !htmlInputAddV1(&raw, int64(len(v)), 16) {
					return ErrReminderV1
				}
			}
			if !htmlInputAddV1(&raw, int64(len(publicURL)), 8) {
				return ErrReminderV1
			}
		}
	}
	closeInputs, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, closeInputs)
	s.publicURL, s.orgName, s.ip, s.via, s.tool, s.senderEmail = strings.Clone(publicURL), strings.Clone(orgName), strings.Clone(ip), strings.Clone(via), strings.Clone(tool), strings.Clone(w.sourceActor.Email)
	s.queue, s.delivery = queue, delivery
	s.expiry = magictoken.Expiry(s.document.ExpiresAt, policyTime)
	s.expiry.Time = s.expiry.Time.UTC().Truncate(time.Microsecond)
	if !s.automatic {
		s.actor = pgtype.UUID{Bytes: w.sourceActor.ID, Valid: true}
	}
	s.recipients = make([]applicationReminderRecipientV1, 0, count)
	for _, row := range w.sourceRecipients {
		if reminderEligibleV1(row) {
			s.recipients = append(s.recipients, applicationReminderRecipientV1{recipient: row})
		}
	}
	output := int64(0)
	if delivery {
		probe := s.publicURL + "/sign/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		for _, item := range s.recipients {
			ctx := dispatch.TemplateContext{DocumentName: s.document.Name, SenderName: s.senderEmail, SenderEmail: s.senderEmail, RecipientName: item.recipient.Name, OrgName: s.orgName, Locale: item.recipient.Locale, SignURL: probe, Acknowledgement: !s.document.RequiresSignature}
			a, b, c, err := dispatch.ReminderNotificationComponentsV1(ctx)
			if err != nil {
				return err
			}
			for _, n := range []int64{a, b, c} {
				if !htmlInputAddV1(&output, n, 4) {
					return ErrReminderV1
				}
			}
		}
	}
	outputWire := int64(0)
	if queue {
		outputWire = output
	}
	closeOutputs, err := w.actor.acquireOwnedRetainedBodyV1(call, output, outputWire)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, closeOutputs)
	if err = s.prepareAuditBatchLockedV1(call); err != nil {
		return err
	}
	s.prepared = true
	return nil
}
func (r *ApplicationReminderV1) CountV1(call context.Context) (int, error) {
	if r == nil || r.state == nil {
		return 0, ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return 0, ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared {
		return 0, ErrReminderV1
	}
	return len(s.recipients), nil
}
func (r *ApplicationReminderV1) RotateV1(call context.Context, index int) error {
	if r == nil || r.state == nil {
		return ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared || index < 0 || index >= len(s.recipients) || s.recipients[index].rotated {
		return ErrReminderV1
	}
	item := &s.recipients[index]
	old := item.recipient
	token, hash, err := auth.MintMagicToken()
	if err != nil {
		return err
	}
	if len(token) != 43 || len(hash) != 32 {
		return ErrReminderV1
	}
	row, err := w.queries.RotateReminderRecipientV1(call, generated.RotateReminderRecipientV1Params{OrgID: s.document.OrgID, DocumentID: s.document.ID, RecipientID: old.ID, ExpectedTokenHash: old.MagicTokenHash, TokenHash: hash, TokenExpiresAt: s.expiry})
	if err != nil {
		return err
	}
	want := *old
	want.MagicTokenHash = hash
	want.MagicTokenExpiresAt = s.expiry
	if row == nil {
		return fmt.Errorf("%w: rotated recipient result is absent", ErrReminderV1)
	}
	// PostgreSQL timestamptz is a finite instant. pgx may decode it with a
	// different Location pointer from the normalized UTC policy value. Bind
	// that instant/validity first, then compare every other returned field.
	if !applicationStampV1(row.MagicTokenExpiresAt) || !applicationStampEqualV1(row.MagicTokenExpiresAt, s.expiry) {
		return fmt.Errorf("%w: rotated recipient expiry differs", ErrReminderV1)
	}
	want.MagicTokenExpiresAt = row.MagicTokenExpiresAt
	if !htmlSendRecipientsEqualV1([]*generated.Recipient{&want}, []*generated.Recipient{row}) || !bytes.Equal(row.MagicTokenHash, hash) {
		return fmt.Errorf("%w: rotated recipient tuple differs", ErrReminderV1)
	}
	item.token = token
	item.rotated = true
	return nil
}
func (r *ApplicationReminderV1) ResetManualScheduleV1(call context.Context) error {
	if r == nil || r.state == nil {
		return ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared || s.automatic || s.reset {
		return ErrReminderV1
	}
	for _, i := range s.recipients {
		if !i.rotated {
			return ErrReminderV1
		}
	}
	if err := w.queries.ResetReminderAfterManualRemind(call, s.document.ID); err != nil {
		return err
	}
	s.reset = true
	return nil
}
func (r *ApplicationReminderV1) RenderV1(call context.Context, index int) (dispatch.Message, error) {
	if r == nil || r.state == nil {
		return dispatch.Message{}, ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return dispatch.Message{}, ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared || !s.delivery || index < 0 || index >= len(s.recipients) {
		return dispatch.Message{}, ErrReminderV1
	}
	item := &s.recipients[index]
	if !item.rotated || item.rendered {
		return dispatch.Message{}, ErrReminderV1
	}
	rec := item.recipient
	subject, html, text, err := dispatch.Render(dispatch.KindReminder, dispatch.TemplateContext{DocumentName: s.document.Name, SenderName: s.senderEmail, SenderEmail: s.senderEmail, RecipientName: rec.Name, OrgName: s.orgName, Locale: rec.Locale, SignURL: s.publicURL + "/sign/" + item.token, BeaconURL: s.publicURL + "/e/o/" + item.token, Acknowledgement: !s.document.RequiresSignature})
	if err != nil {
		return dispatch.Message{}, err
	}
	msg := dispatch.Message{To: rec.Email, Subject: subject, HTML: html, Text: text, ReplyTo: s.senderEmail, FromName: s.orgName}
	item.message = dispatch.Message{To: strings.Clone(msg.To), Subject: strings.Clone(msg.Subject), HTML: strings.Clone(msg.HTML), Text: strings.Clone(msg.Text), ReplyTo: strings.Clone(msg.ReplyTo), FromName: strings.Clone(msg.FromName)}
	item.rendered = true
	return msg, nil
}
func (r *ApplicationReminderV1) EnqueueV1(call context.Context, index int) error {
	if r == nil || r.state == nil {
		return ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared || !s.queue || index < 0 || index >= len(s.recipients) {
		return ErrReminderV1
	}
	// Preserve render-all before the first enqueue, including late render refusal.
	for _, i := range s.recipients {
		if !i.rendered {
			return ErrReminderV1
		}
	}
	item := &s.recipients[index]
	if item.enqueued {
		return ErrReminderV1
	}
	msg := item.message
	row, err := w.queries.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text, ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: []byte("{}")})
	if err != nil {
		return err
	}
	if row == nil || row.ID == uuid.Nil || row.ToEmail != msg.To || row.Subject != msg.Subject || row.HtmlBody != msg.HTML || row.TextBody != msg.Text || row.ReplyTo != msg.ReplyTo || row.FromName != msg.FromName || row.Status != "pending" || row.LastError != "" || string(row.HeadersJson) != "{}" {
		return ErrReminderV1
	}
	item.outbox = row.ID
	item.enqueued = true
	return nil
}
func (r *ApplicationReminderV1) FinishV1(call context.Context, policyTime time.Time) error {
	if r == nil || r.state == nil {
		return ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.work
	if w == nil {
		return ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !s.validLockedV1(call) || !s.prepared || s.finished || (!s.automatic && !s.reset) || s.auditNext != len(s.recipients) || policyTime.IsZero() {
		return ErrReminderV1
	}
	for i, item := range s.recipients {
		if !item.rotated || (s.delivery && !item.rendered) || (s.queue && (!item.enqueued || item.outbox == uuid.Nil)) {
			return ErrReminderV1
		}
		if s.audits == nil {
			return ErrReminderV1
		}
		s.audits.mu.Lock()
		owner := s.audits.slots[i].owner
		s.audits.mu.Unlock()
		if owner == nil {
			return ErrReminderV1
		}
		owner.mu.Lock()
		valid := !owner.closed && owner.used && owner.attempted && owner.eventID != uuid.Nil
		owner.mu.Unlock()
		if !valid {
			return ErrReminderV1
		}
	}
	if s.document.ExpiresAt.Valid && !s.document.ExpiresAt.Time.After(policyTime) {
		return ErrReminderDeadlineV1
	}
	if len(s.recipients) > 0 && (!applicationStampV1(s.expiry) || !s.expiry.Time.After(policyTime)) {
		return ErrReminderDeadlineV1
	}
	s.finished = true
	return nil
}

func (s *applicationReminderStateV1) retireLockedV1() ([]func(), *ApplicationHTMLSendWorkV1) {
	if !s.consumerClosed || s.released || s.auditHeld {
		return nil, nil
	}
	s.released = true
	closes, w := s.closes, s.work
	s.closes = nil
	s.recipients = nil
	s.audits = nil
	s.schedule = nil
	s.document = nil
	s.work = nil
	s.senderEmail = ""
	s.publicURL = ""
	s.orgName = ""
	s.ip = ""
	s.via = ""
	s.tool = ""
	return closes, w
}
func retireReminderV1(closes []func(), w *ApplicationHTMLSendWorkV1) {
	for i := len(closes) - 1; i >= 0; i-- {
		closes[i]()
	}
	if w != nil {
		w.mu.Lock()
		w.sourceBorrowers--
		c, a := w.retireSourcesLockedV1()
		w.mu.Unlock()
		htmlSendCloseSourceResourcesV1(c, a)
		w.releaseFamilyRootIfRetiredV1()
	}
}
func (s *applicationReminderStateV1) closeConsumerV1() {
	s.mu.Lock()
	if s.consumerClosed {
		s.mu.Unlock()
		return
	}
	s.consumerClosed = true
	batch := s.audits
	s.mu.Unlock()
	if batch != nil {
		batch.closeConsumerV1()
	}
	s.mu.Lock()
	closes, w := s.retireLockedV1()
	s.mu.Unlock()
	retireReminderV1(closes, w)
}
func (s *applicationReminderStateV1) releaseAuditV1() {
	s.mu.Lock()
	s.auditHeld = false
	closes, w := s.retireLockedV1()
	s.mu.Unlock()
	retireReminderV1(closes, w)
}

func (r *ApplicationReminderV1) CloseConsumerV1() {
	if r != nil && r.state != nil {
		r.state.closeConsumerV1()
	}
}
