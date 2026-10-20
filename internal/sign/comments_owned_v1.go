// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type CommentResultV1 struct {
	*generated.DocumentComment
	self    *CommentResultV1
	once    *sync.Once
	release func()
}

func (r *CommentResultV1) CloseConsumerV1() {
	if r != nil && r.self == r && r.once != nil {
		r.once.Do(func() {
			r.DocumentComment = nil
			if r.release != nil {
				r.release()
				r.release = nil
			}
		})
	}
}

func (e *Engine) NewSignerCommentHTTPInputV1(ctx context.Context, rc *RecipientContext) (*pdfadmission.ApplicationCommentInputV1, error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || rc == nil || rc.readLease == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	defer finish()
	return e.WorkRuntime.SessionsV1().NewSignerCommentHTTPInputV1(ctx, original.Document.OrgID)
}
func (e *Engine) SignerCommentOwnedV1(rc *RecipientContext, input *pdfadmission.ApplicationCommentInputV1, evidence ParticipantResponseEvidence) (*CommentResultV1, error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || rc == nil || rc.readLease == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	request, err := e.WorkRuntime.SessionsV1().NewSignerCommentRequestV1(rc.readLease.reader, input, evidence.IP, evidence.UserAgent, evidence.Notice)
	if err != nil {
		finish()
		return nil, commentAdmissionFailureV1(err)
	}
	return e.mutateCommentOwnedV1(request, original, uuid.Nil, nil, finish)
}
func (e *Engine) SenderCommentOwnedV1(input *pdfadmission.ApplicationCommentInputV1, org, document, user uuid.UUID, authorize func(context.Context, *generated.User) error) (*CommentResultV1, error) {
	if authorize == nil {
		return nil, ErrSenderCommentNotAuthorized
	}
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	request, err := e.WorkRuntime.SessionsV1().NewStaffCommentRequestV1(input, org, document, user)
	if err != nil {
		return nil, commentAdmissionFailureV1(err)
	}
	return e.mutateCommentOwnedV1(request, nil, user, authorize, nil)
}
func commentAdmissionFailureV1(err error) error {
	if errors.Is(err, pdfadmission.ErrCommentInputV1) || errors.Is(err, pdfadmission.ErrCommentRequestV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return blockSignatureFailureV1(err)
}

// No ordinary pool/Audit.LogTx fallback exists. Both PDF/block and HTML-backed
// documents use the same actual native parent, locks and intrinsically measured
// audit append. The original application policy remains at its locked points.
func (e *Engine) mutateCommentOwnedV1(request *pdfadmission.ApplicationCommentRequestV1, original *RecipientContext, user uuid.UUID, authorize func(context.Context, *generated.User) error, finishOriginal func()) (result *CommentResultV1, failure error) {
	var finishMutation func()
	transferred := false
	defer func() {
		request.CloseConsumerV1()
		if !transferred {
			if finishMutation != nil {
				finishMutation()
			}
			if finishOriginal != nil {
				finishOriginal()
			}
		}
		failure = commentAdmissionFailureV1(failure)
		if failure != nil && result != nil {
			result.CloseConsumerV1()
			result = nil
		}
	}()
	body, ip, ua, notice, err := request.MetadataV1()
	if err != nil {
		return nil, err
	}
	if original != nil {
		if err = validateNoticeEvidence(original, notice); err != nil {
			return nil, err
		}
	}
	if err = validateCommentBody(body); err != nil {
		return nil, err
	}
	native, err := request.NewOperationV1()
	if err != nil {
		return nil, err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, native.CloseV1(cleanup))
	}()
	purpose := pdfadmission.HTMLStaffCommentMutationV1
	if original != nil {
		purpose = pdfadmission.HTMLSignerCommentMutationV1
	}
	stage, err := native.OpenSQLV1(purpose)
	if err != nil {
		return nil, err
	}
	stageClosed := false
	defer func() {
		if !stageClosed {
			failure = errors.Join(failure, stage.CloseSQLV1())
		}
	}()
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		return nil, err
	}
	var pending audit.PendingEvent
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	defer func() {
		if event != nil {
			event.CloseConsumerV1()
		}
	}()
	var row *generated.DocumentComment
	var messages []dispatch.Message
	var finishMessages func()
	defer func() {
		if finishMessages != nil {
			finishMessages()
		}
	}()
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		state, err := w.StateV1(actual)
		if errors.Is(err, pgx.ErrNoRows) {
			if original != nil {
				return ErrMagicLinkExpired
			}
			return ErrCommentDocumentNotFound
		} else if err != nil {
			return err
		}
		// Scalar identity/epoch and commentable status refusals precede expanded
		// models. Full notice policy still repeats after the genuine measured read.
		if original != nil && (state.ID != original.Document.ID || state.OrgID != original.Document.OrgID || state.SentAt != original.Document.SentAt || state.Article13NoticeEpochAt != original.Document.Article13NoticeEpochAt || state.Article13NoticeEpochV61Committed != original.Document.Article13NoticeEpochV61Committed || !state.HasSupportedArticle13NoticeSchema) {
			return ErrInvalidNoticeEvidence
		}
		if err = checkCommentStatusV1(state.BoundedStatus); err != nil {
			return err
		}
		models, err := w.ReadModelsV1(actual)
		if err != nil {
			return err
		}
		doc := models.Document
		if original != nil {
			if err = ValidateLockedNoticeEvidence(original, doc, notice); err != nil {
				return err
			}
		}
		if err = checkDocumentCommentable(doc); err != nil {
			return err
		}
		finishMutation, err = w.BeginCommentMutationV1(actual, request)
		if err != nil {
			return err
		}
		var actor *generated.User
		if original != nil {
			fresh, err := w.ReadSignerCommentRecipientV1(actual)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMagicLinkExpired
			}
			if err != nil {
				return err
			}
			if err = ValidateLockedRecipientCredential(original, fresh, doc, e.now()); err != nil {
				return err
			}
		} else {
			actor, err = w.ReadActorV1(actual, user)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSenderCommentNotAuthorized
			}
			if err != nil {
				return err
			}
			if actor.Role != string(auth.RoleSender) && actor.Role != string(auth.RoleOwner) {
				return ErrSenderCommentNotAuthorized
			}
			if err = authorize(actual, actor); err != nil {
				return err
			}
		}
		row, err = w.CreateCommentV1(actual)
		if err != nil {
			return err
		}
		commentEvidence, err := w.CommentAuditEvidenceV1(actual)
		if err != nil {
			return err
		}
		if e.Mailer != nil {
			if original != nil {
				if _, err = w.ReadActorV1(actual, doc.SenderID); err != nil {
					return fmt.Errorf("load signer-comment sender: %w", err)
				}
			} else {
				if _, err = w.ReadStaffCommentRecipientsV1(actual); err != nil {
					return err
				}
			}
			if err = w.RenderCommentNotificationsV1(actual, e.OrgName, e.BaseURL); err != nil {
				return err
			}
			if usesDurableEmailQueue(e.Mailer) {
				if err = w.EnqueueCommentNotificationsV1(actual); err != nil {
					return err
				}
			}
			messages, finishMessages, err = w.BorrowCommentMessagesV1(actual)
			if err != nil {
				return err
			}
		}
		entry := audit.Entry{OrgID: doc.OrgID, DocumentID: &doc.ID, Kind: audit.KindCommentPosted, ActorUserID: &user, Payload: commentAuditPayloadV1(commentEvidence)}
		auditPurpose := pdfadmission.HTMLAuditStaffCommentV1
		if original != nil {
			entry.ActorUserID = nil
			entry.RecipientID = &original.Recipient.ID
			entry.IP, entry.UserAgent = ip, ua
			entry.Payload, err = responseAuditPayload(commentAuditPayloadV1(commentEvidence), notice)
			if err != nil {
				return err
			}
			auditPurpose = pdfadmission.HTMLAuditSignerCommentV1
		}
		pending, event, err = ownedaudit.LogV1(e.Audit, actual, session, auditPurpose, entry)
		if err != nil {
			return fmt.Errorf("audit comment: %w", err)
		}
		if original != nil {
			fresh, err := w.ReadSignerCommentRecipientV1(actual)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrMagicLinkExpired
			}
			if err != nil {
				return err
			}
			if err = ValidateLockedRecipientCredential(original, fresh, doc, e.now()); err != nil {
				return err
			}
			return ValidateLockedNoticeEvidence(original, doc, notice)
		}
		return authorize(actual, actor)
	})
	if err != nil {
		return nil, err
	}
	if err = session.CommitV1(call); err != nil {
		_ = session.CommitDispatchObservationV1()
		return nil, fmt.Errorf("commit comment: %w", err)
	}
	if err = stage.CloseSQLV1(); err != nil {
		return nil, err
	}
	stageClosed = true
	if event != nil {
		if err = ownedaudit.PublishV1(e.Audit, pending, event); err != nil {
			return nil, err
		}
		event = nil
	}
	e.deliverPostCommitEmails(messages)
	r := &CommentResultV1{DocumentComment: row, once: &sync.Once{}, release: func() {
		if finishMutation != nil {
			finishMutation()
		}
		if finishOriginal != nil {
			finishOriginal()
		}
	}}
	r.self = r
	transferred = true
	return r, nil
}

func commentAuditPayloadV1(e pdfadmission.CommentAuditEvidenceV1) map[string]any {
	return map[string]any{"side": e.Side, "comment_evidence_schema": pdfadmission.CommentAuditEvidenceSchemaV1, "comment_id": e.CommentID.String(), "comment_body_sha256": hex.EncodeToString(e.BodySHA256[:]), "comment_created_at": e.CreatedAt.Time.UTC().Format(time.RFC3339Nano)}
}

var ErrCommentAuditEvidenceV1 = errors.New("sign: comment evidence differs")

// CommentAuditEvidenceMatchesV1 checks content association, not authorization or
// organization-chain continuity. A separately verified signed report/chain must
// supply the trusted event. Old side-only events return false,nil: their text is
// not retrospectively proved, and this function never rewrites stored history.
func CommentAuditEvidenceMatchesV1(event *generated.Event, row *generated.DocumentComment) (bool, error) {
	if event == nil {
		return false, ErrCommentAuditEvidenceV1
	}
	payload, err := commentEvidenceObjectV1(event.PayloadJson)
	if err != nil {
		return false, ErrCommentAuditEvidenceV1
	}
	if _, present := payload["comment_evidence_schema"]; !present {
		for _, key := range []string{"comment_id", "comment_body_sha256", "comment_created_at"} {
			if _, present := payload[key]; present {
				return false, ErrCommentAuditEvidenceV1
			}
		}
		return false, nil
	}
	for key := range payload {
		switch key {
		case "side", "comment_evidence_schema", "comment_id", "comment_body_sha256", "comment_created_at", "notice_schema", "notice_digest", "notice_snapshot":
		default:
			return false, ErrCommentAuditEvidenceV1
		}
	}
	value := func(key string) string {
		var v string
		if json.Unmarshal(payload[key], &v) != nil {
			return ""
		}
		return v
	}
	schema, id, digest, stamp, side := value("comment_evidence_schema"), value("comment_id"), value("comment_body_sha256"), value("comment_created_at"), value("side")
	if schema != pdfadmission.CommentAuditEvidenceSchemaV1 || row == nil || row.ID == uuid.Nil || row.DocumentID == uuid.Nil || event.Kind != audit.KindCommentPosted || !event.DocumentID.Valid || event.DocumentID.Bytes != row.DocumentID || id != row.ID.String() || side != row.AuthorSide || !row.CreatedAt.Valid || row.CreatedAt.InfinityModifier != pgtype.Finite || row.CreatedAt.Time.IsZero() || row.CreatedAt.Time.Nanosecond()%1000 != 0 || stamp != row.CreatedAt.Time.UTC().Format(time.RFC3339Nano) {
		return false, ErrCommentAuditEvidenceV1
	}
	switch side {
	case "sender":
		if !row.UserID.Valid || row.UserID.Bytes == uuid.Nil || row.RecipientID.Valid || event.ActorUserID != row.UserID || event.RecipientID.Valid {
			return false, ErrCommentAuditEvidenceV1
		}
	case "signer":
		if !row.RecipientID.Valid || row.RecipientID.Bytes == uuid.Nil || row.UserID.Valid || event.RecipientID != row.RecipientID || event.ActorUserID.Valid {
			return false, ErrCommentAuditEvidenceV1
		}
	default:
		return false, ErrCommentAuditEvidenceV1
	}
	expected := sha256.Sum256([]byte(row.Body))
	if digest != hex.EncodeToString(expected[:]) || !commentEvidencePayloadsEqualV1(payload, event.PayloadHashed) {
		return false, ErrCommentAuditEvidenceV1
	}
	recomputed, err := audit.RecomputeEventRowHash(event)
	if err != nil || len(event.RowHash) != sha256.Size || subtle.ConstantTimeCompare(recomputed, event.RowHash) != 1 {
		return false, ErrCommentAuditEvidenceV1
	}
	return true, nil
}

// PostgreSQL JSONB changes whitespace/key order. Compare complete semantic
// values while the row hash separately checks the original exact preimage.
// Duplicate root evidence keys and trailing values never have a second reading.
func commentEvidenceObjectV1(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, ErrCommentAuditEvidenceV1
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, ErrCommentAuditEvidenceV1
		}
		key, ok := token.(string)
		if !ok {
			return nil, ErrCommentAuditEvidenceV1
		}
		if _, seen := fields[key]; seen {
			return nil, ErrCommentAuditEvidenceV1
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrCommentAuditEvidenceV1
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrCommentAuditEvidenceV1
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, ErrCommentAuditEvidenceV1
	}
	return fields, nil
}
func commentEvidencePayloadsEqualV1(left map[string]json.RawMessage, right []byte) bool {
	fields, err := commentEvidenceObjectV1(right)
	if err != nil || len(fields) != len(left) {
		return false
	}
	for key, lraw := range left {
		rraw, ok := fields[key]
		if !ok {
			return false
		}
		var l, r any
		ld := json.NewDecoder(bytes.NewReader(lraw))
		ld.UseNumber()
		rd := json.NewDecoder(bytes.NewReader(rraw))
		rd.UseNumber()
		if ld.Decode(&l) != nil || rd.Decode(&r) != nil || !reflect.DeepEqual(l, r) {
			return false
		}
	}
	return true
}
