// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This result contains only the exact durable evidence needed by the original
// publication audits. Neither the customer token nor a storage locator escapes.
type PreSignPublicationResultV1 struct {
	Expired             bool
	ExecutionID         uuid.UUID
	ExecutionSHA256     string
	AssetsSHA256        string
	VisiblePDFSHA256    string
	CustomerRecipientID uuid.UUID
	RetainUntil         time.Time
}

// One fixed publication is registered on its SAME work before its first read.
// Output loans and this private comparison state live through the last audit
// and UPDATE consumer; caller-provided result fields cannot publish anything.
type preSignPublicationV1 struct {
	result                                   PreSignPublicationResultV1
	executor                                 uuid.UUID
	retentionStarted, retentionCompleted     time.Time
	customer, provider                       *generated.Recipient
	document, sentDocument                   *generated.Document
	outboxID                                 uuid.UUID
	message                                  dispatch.Message
	ready, sentViewed, markAttempted, marked bool
}

func preSignPublicationRecipientBytesV1(r *generated.Recipient) int64 {
	if r == nil {
		return 0
	}
	return int64(len(r.Role) + len(r.Email) + len(r.Name) + len(r.MagicTokenHash) + len(r.DeclinedReason.String) + len(r.Locale))
}

func preSignPublicationRecipientEqualV1(a, b *generated.Recipient) bool {
	return a != nil && b != nil && a.ID == b.ID && a.DocumentID == b.DocumentID && a.Role == b.Role &&
		a.Email == b.Email && a.Name == b.Name && a.OrderIndex == b.OrderIndex && a.Status == b.Status &&
		bytes.Equal(a.MagicTokenHash, b.MagicTokenHash) && a.SentAt == b.SentAt && a.FirstViewedAt == b.FirstViewedAt &&
		a.SignedAt == b.SignedAt && a.DeclinedReason == b.DeclinedReason && a.CreatedAt == b.CreatedAt &&
		a.MagicTokenExpiresAt == b.MagicTokenExpiresAt && a.Locale == b.Locale
}

func preSignPublicationCloneRecipientV1(r *generated.Recipient) *generated.Recipient {
	if r == nil {
		return nil
	}
	out := *r
	out.Role = strings.Clone(r.Role)
	out.Email = strings.Clone(r.Email)
	out.Name = strings.Clone(r.Name)
	out.MagicTokenHash = bytes.Clone(r.MagicTokenHash)
	out.DeclinedReason.String = strings.Clone(r.DeclinedReason.String)
	out.Locale = strings.Clone(r.Locale)
	return &out
}

func preSignPublicationDocumentEqualV1(a, b *generated.Document) bool {
	return a != nil && b != nil && htmlSendDocumentExactTupleEqualV1(a, b) && a.ParticipantReportSchema == b.ParticipantReportSchema
}

func preSignPublicationNumericV1(n pgtype.Numeric, want int64) bool {
	if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite || n.Int == nil || n.Int.BitLen() > 256 || n.Exp < -32 || n.Exp > 32 {
		return false
	}
	v, err := n.Value()
	text, ok := v.(string)
	if err != nil || !ok || len(text) > 128 {
		return false
	}
	rat, ok := new(big.Rat).SetString(text)
	return ok && new(big.Rat).Mul(rat, big.NewRat(10000, 1)).Cmp(big.NewRat(want, 1)) == 0
}

// The retained execution identifies BOTH actual parties and both protected
// fields. A role/status prefix is never sufficient to select a customer or to
// excuse a different provider signature. No caller model enters this check.
func (w *ApplicationHTMLSendWorkV1) preSignPublicationSourceV1(r presignexecute.RetainedAssetsV1) (customerResult, providerResult *generated.Recipient, failure error) {
	stage := "publication_source_scope"
	defer func() { failure = htmlPreSignPublicationFailureV1(stage, failure) }()
	e := r.Execution().Snapshot()
	p := r.Publication()
	d := w.sourceDocument
	i := w.sourceIntent
	if d == nil || i == nil || w.models == nil || d.ID != w.logicalDocumentV1() || d.ID != e.Document.ID || d.OrgID != e.OrgID ||
		d.OrgID != w.session.state.org || d.SenderID != e.Document.SenderID || d.Status != "sealing" || d.DeletedAt.Valid ||
		d.ParentEnvelopeID.Valid || d.IsEnvelope || d.SourceKind != "pdf" || !d.RequiresSignature || d.RoutingMode != "parallel" ||
		d.SigningAdmissionPolicy != "historical" || !d.EvidenceVersionPinsRequired || d.LawfulBasis != "contract" ||
		!d.PdfStorageKey.Valid || d.PdfStorageKey.String != e.Document.BasePDF.Artifact.StorageKey ||
		!d.PdfStorageVersionID.Valid || d.PdfStorageVersionID.String != e.Document.BasePDF.Artifact.VersionID ||
		hex.EncodeToString(d.PdfSha256) != e.Document.BasePDF.Artifact.SHA256 ||
		!d.HtmlCurrentMaterializationID.Valid || uuid.UUID(d.HtmlCurrentMaterializationID.Bytes) != e.Document.Materialization.ID ||
		!d.HtmlCurrentMaterializationSequence.Valid || int64(d.HtmlCurrentMaterializationSequence.Int32) != e.Document.Materialization.Revision ||
		!d.HtmlCurrentPageCount.Valid || int(d.HtmlCurrentPageCount.Int32) != e.Document.BasePDF.Pages ||
		i.DocumentID != d.ID || i.OrgID != d.OrgID || !i.PresignExecutionID.Valid || uuid.UUID(i.PresignExecutionID.Bytes) != e.ID ||
		i.PackageSendAttemptID.Valid || !i.ActorUserID.Valid || uuid.UUID(i.ActorUserID.Bytes) != e.Executor.UserID || i.ActorEmail == "" ||
		!i.Article13NoticeEpochAt.Valid || !i.Article13NoticeEpochAt.Time.Equal(e.CeremonyEpoch) ||
		!i.RetainUntil.Valid || !i.RetainUntil.Time.Equal(p.RetainUntil) || p.State != "retaining" ||
		!i.RetentionStartedAt.Valid || !i.RetentionCompletedAt.Valid ||
		!i.RetentionStartedAt.Time.Equal(p.RetentionStartedAt) || !i.RetentionCompletedAt.Time.Equal(p.RetentionCompletedAt) ||
		p.RetentionStartedAt.IsZero() || p.RetentionCompletedAt.Before(p.RetentionStartedAt) ||
		p.CustomerRecipientID != e.Document.Parties[0].ID || len(w.sourceRecipients) != 2 || len(w.sourceFields) != 2 {
		return nil, nil, ErrHTMLSendWorkV1
	}
	stage = "publication_source_validate"
	commitment, err := htmlsource.Commitment(d)
	if err != nil || commitment != e.Document.Materialization.SourceCommitment || htmlsource.Validate(d, false) != nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	stage = "publication_source_party_validation"
	if htmlsource.ValidateContractParties(d, w.sourceRecipients) != nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	stage = "publication_source_field_validation"
	if htmlsource.ValidateSigningFields(d, w.sourceFields, e.Document.BasePDF.Pages) != nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	stage = "publication_source_parties"
	var selected [2]*generated.Recipient
	for index, want := range e.Document.Parties {
		for _, row := range w.sourceRecipients {
			if row != nil && row.ID == want.ID {
				if selected[index] != nil || row.DocumentID != d.ID || row.Role != want.Role || row.Name != want.Name || row.Email != want.Email || row.DeclinedReason.Valid {
					return nil, nil, ErrHTMLSendWorkV1
				}
				selected[index] = row
			}
		}
		if selected[index] == nil {
			return nil, nil, ErrHTMLSendWorkV1
		}
	}
	customer, provider := selected[0], selected[1]
	if customer.ID == provider.ID || customer.Role != "customer" || customer.Status != "pending" || customer.SentAt.Valid ||
		customer.FirstViewedAt.Valid || customer.SignedAt.Valid || provider.Role != "provider" || provider.Status != "signed" ||
		provider.SentAt.Valid || provider.FirstViewedAt.Valid || !provider.SignedAt.Valid || !provider.SignedAt.Time.Equal(e.ExecutedAt) ||
		len(provider.MagicTokenHash) != 0 || !provider.MagicTokenExpiresAt.Valid || !provider.MagicTokenExpiresAt.Time.Equal(time.Unix(0, 0).UTC()) {
		return nil, nil, ErrHTMLSendWorkV1
	}
	stage = "publication_source_fields"
	for _, want := range e.Document.Fields {
		// The actual stored pair was validated above. Retained commitments use
		// the original typed encoding, independently of JSONB wire spelling.
		options, err := htmlsource.SigningFieldOptions(d, want.Slot)
		if err != nil {
			return nil, nil, ErrHTMLSendWorkV1
		}
		sha := sha256.Sum256(options)
		found := false
		for _, f := range w.sourceFields {
			if f != nil && f.ID == want.ID {
				if found || f.DocumentID != d.ID || !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) != want.RecipientID ||
					f.Type != want.Type || f.Required != want.Required || int(f.Page) != want.Page || f.Value.Valid || f.CompletedAt.Valid ||
					!preSignPublicationNumericV1(f.XPct, want.X) || !preSignPublicationNumericV1(f.YPct, want.Y) ||
					!preSignPublicationNumericV1(f.WPct, want.W) || !preSignPublicationNumericV1(f.HPct, want.H) ||
					hex.EncodeToString(sha[:]) != want.OptionsSHA256 {
					return nil, nil, ErrHTMLSendWorkV1
				}
				found = true
			}
		}
		if !found {
			return nil, nil, ErrHTMLSendWorkV1
		}
	}
	return customer, provider, nil
}

// PublishPreSignCustomerV1 is the fixed one-customer analogue of the ordinary
// completion producer. It does not widen that producer's purpose or loop over
// a caller's recipients. ReadModels/Recipients/Fields/Intent and the measured
// retained evidence loan must already belong to this exact publication work.
func (w *ApplicationHTMLSendWorkV1) PublishPreSignCustomerV1(call context.Context, publicURL, orgName string) (result PreSignPublicationResultV1, failure error) {
	stage := "publication_scope"
	defer func() { failure = htmlPreSignPublicationFailureV1(stage, failure) }()
	var zero PreSignPublicationResultV1
	if w == nil || w.self != w {
		return zero, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage.purpose != HTMLPreSignPublicationV1 || !w.presignEvidenceAttempted ||
		w.sourceDocument == nil || w.sourceIntent == nil || !w.recipientsRead || !w.fieldsRead || w.presignPublication != nil || w.completedAttempted {
		w.mu.Unlock()
		return zero, ErrHTMLSendWorkV1
	}
	stage = "publication_state_loan"
	closeState, err := w.actor.acquireOwnedRetainedBodyV1(call, 8*int64(unsafe.Sizeof(preSignPublicationV1{})), 0)
	if err != nil {
		w.mu.Unlock()
		return zero, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeState)
	s := &preSignPublicationV1{}
	w.presignPublication = s
	w.mu.Unlock()
	stage = "publication_retained_read"
	retained, err := w.ReadRetainedPreSignV1(call)
	if err != nil {
		return zero, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.presignPublication != s || w.stage.purpose != HTMLPreSignPublicationV1 {
		return zero, ErrHTMLSendWorkV1
	}
	stage = "publication_source"
	customer, provider, err := w.preSignPublicationSourceV1(retained)
	if err != nil {
		return zero, err
	}
	e := retained.Execution().Snapshot()
	p := retained.Publication()
	s.result = PreSignPublicationResultV1{ExecutionID: e.ID, ExecutionSHA256: retained.Execution().Commitment(), AssetsSHA256: retained.Assets().Commitment(),
		VisiblePDFSHA256: e.VisiblePDF.Artifact.SHA256, CustomerRecipientID: customer.ID, RetainUntil: p.RetainUntil.UTC()}
	s.executor = e.Executor.UserID
	s.retentionStarted = p.RetentionStartedAt
	s.retentionCompleted = p.RetentionCompletedAt
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var databaseNow time.Time
	var deadlineExact, signatureExact bool
	stage = "publication_proof_shape"
	imageSHA, err := hex.DecodeString(e.Signature.Image.SHA256)
	if err != nil || len(imageSHA) != 32 {
		return zero, ErrHTMLSendWorkV1
	}
	stage = "publication_proof_sql"
	err = db.QueryRow(call, `SELECT clock_timestamp(),$1::timestamptz=hash_evidence_retain_until($2::timestamptz,7),
	 (SELECT count(*)=1 AND COALESCE(bool_and(id=$4 AND recipient_id=$5 AND field_id=$6 AND signature_kind=$7
	  AND presign_execution_id=$8 AND font=$9 AND typed_name=$10 AND image_storage_key=$11 AND image_sha256=$12
	  AND image_version_id=$13 AND image_version_pin_required AND signed_at=$14 AND signer_ip IS NULL AND signer_ua IS NULL),FALSE)
	  FROM signatures WHERE document_id=$3)`, p.RetainUntil, e.CeremonyEpoch, e.Document.ID, e.Signature.ID, e.Signature.RecipientID, e.Signature.FieldID,
		presignexecute.SignatureKind, e.ID, e.Signature.Style.Font, e.Signature.TypedName, e.Signature.Image.StorageKey, imageSHA, e.Signature.Image.VersionID, e.ExecutedAt).
		Scan(&databaseNow, &deadlineExact, &signatureExact)
	if err != nil || databaseNow.IsZero() || !deadlineExact || !signatureExact {
		return zero, errors.Join(ErrHTMLSendWorkV1, err)
	}
	s.result.Expired = !databaseNow.Before(p.RetainUntil) || (w.sourceDocument.ExpiresAt.Valid && !databaseNow.Before(w.sourceDocument.ExpiresAt.Time))
	// The existing declared-policy completion guard remains mandatory. Its
	// fixed retained-source producer owns its own native source/CPU loans and
	// must run outside this mutex, before any customer credential mutation.
	w.mu.Unlock()
	stage = "publication_policy_freeze"
	err = w.freezePreSignAmendmentPolicyV1(call, retained)
	w.mu.Lock()
	if err != nil {
		return zero, err
	}
	if !w.valid(call) || w.presignPublication != s || w.stage.purpose != HTMLPreSignPublicationV1 {
		return zero, ErrHTMLSendWorkV1
	}
	stage = "publication_source_repeat"
	if _, _, err = w.preSignPublicationSourceV1(retained); err != nil {
		return zero, err
	}
	// Full actual input, row copies, token/URL containers and fixed reminder SQL
	// are paid before cloning, minting, rendering or a full RETURNING row.
	stage = "publication_input_size"
	raw, err := htmlAuthoringSumV1(4*int64(len(publicURL)), int64(len(orgName)), 2*int64(len(w.sourceIntent.ActorEmail)),
		4*preSignPublicationRecipientBytesV1(customer), 4*preSignPublicationRecipientBytesV1(provider),
		8*int64(unsafe.Sizeof(generated.Recipient{})), int64(len(w.sourceIntent.ActorIp)+len(w.sourceIntent.Via)+len(w.sourceIntent.Tool)+len(w.sourceIntent.LastError.String)),
		8*int64(unsafe.Sizeof(dispatch.Message{}))+2*(43+32)+512)
	if err != nil {
		return zero, err
	}
	stage = "publication_input_loan"
	closeInputs, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return zero, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeInputs)
	s.customer = preSignPublicationCloneRecipientV1(customer)
	s.provider = preSignPublicationCloneRecipientV1(provider)
	var msg dispatch.Message
	if !s.result.Expired {
		probeURL := publicURL + "/sign/" + strings.Repeat("A", 43)
		probeBeacon := publicURL + "/e/o/" + strings.Repeat("A", 43)
		context := dispatch.TemplateContext{DocumentName: w.sourceDocument.Name, SenderName: w.sourceIntent.ActorEmail, SenderEmail: w.sourceIntent.ActorEmail,
			RecipientName: customer.Name, OrgName: orgName, Locale: customer.Locale, SignURL: probeURL, BeaconURL: probeBeacon, Acknowledgement: false}
		stage = "publication_output_size"
		subjectBytes, htmlBytes, textBytes, err := dispatch.InviteNotificationComponentsV1(context)
		if err != nil {
			return zero, err
		}
		output, err := htmlAuthoringSumV1(subjectBytes, htmlBytes, textBytes, int64(len(customer.Email)+len(w.sourceIntent.ActorEmail)+len(orgName)+len("pending")))
		if err != nil {
			return zero, err
		}
		outputCopies, err := htmlAuthoringSumV1(output, output, output)
		if err != nil {
			return zero, err
		}
		stage = "publication_output_loan"
		closeOutput, err := w.actor.acquireOwnedRetainedBodyV1(call, outputCopies, 2)
		if err != nil {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		w.closes = append(w.closes, closeOutput)
		stage = "publication_token"
		token, hash, err := auth.MintMagicToken()
		if err != nil || len(token) != 43 || len(hash) != 32 {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		expiry := magictoken.Expiry(w.sourceDocument.ExpiresAt, databaseNow)
		if p.RetainUntil.Before(expiry.Time) {
			expiry.Time = p.RetainUntil
		}
		stage = "publication_token_sql"
		if err = w.queries.RotateRecipientMagicToken(call, generated.RotateRecipientMagicTokenParams{ID: customer.ID, DocumentID: e.Document.ID, MagicTokenHash: hash, MagicTokenExpiresAt: expiry}); err != nil {
			return zero, err
		}
		stage = "publication_recipient_sent"
		count, err := w.queries.MarkRecipientSent(call, generated.MarkRecipientSentParams{ID: customer.ID, DocumentID: e.Document.ID})
		if err != nil || count != 1 {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		context.SignURL = publicURL + "/sign/" + token
		context.BeaconURL = publicURL + "/e/o/" + token
		stage = "publication_invite_render"
		subject, html, text, err := dispatch.Render(dispatch.KindInvite, context)
		if err != nil || int64(len(subject)) > subjectBytes || int64(len(html)) > htmlBytes || int64(len(text)) > textBytes {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		msg = dispatch.Message{To: customer.Email, Subject: subject, HTML: html, Text: text, ReplyTo: w.sourceIntent.ActorEmail, FromName: orgName}
		s.customer.MagicTokenHash = bytes.Clone(hash)
		s.customer.MagicTokenExpiresAt = expiry
		s.customer.Status = "sent"
		stage = "publication_recipient_read"
		fresh, err := w.queries.GetRecipient(call, generated.GetRecipientParams{ID: customer.ID, OrgID: e.OrgID})
		if err != nil || fresh == nil || !fresh.SentAt.Valid {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		s.customer.SentAt = fresh.SentAt
		if !preSignPublicationRecipientEqualV1(s.customer, fresh) {
			return zero, ErrHTMLSendWorkV1
		}
	} else {
		// Clear any preallocated draft credential without minting one. The
		// already signed provider is deliberately never passed to token SQL.
		stage = "publication_expired_token"
		err = w.queries.RotateRecipientMagicToken(call, generated.RotateRecipientMagicTokenParams{ID: customer.ID, DocumentID: e.Document.ID,
			MagicTokenHash: []byte{}, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Unix(0, 0).UTC(), Valid: true}})
		if err != nil {
			return zero, err
		}
		s.customer.MagicTokenHash = []byte{}
		s.customer.MagicTokenExpiresAt = pgtype.Timestamptz{Time: time.Unix(0, 0).UTC(), Valid: true}
	}
	w.completedAttempted = true
	stage = "publication_document_loan"
	documentRaw, _, err := w.admitDocumentReturnV1(call, int64(len("sent")+len("hash-a13-2026-08-31")))
	if err != nil {
		return zero, err
	}
	stage = "publication_document_sent"
	row, err := w.queries.CompleteDocumentSendSealing(call, generated.CompleteDocumentSendSealingParams{ID: e.Document.ID, OrgID: e.OrgID})
	if err != nil || !w.verifyDocumentReturnV1(row, documentRaw) || row.Status != "sent" {
		return zero, errors.Join(ErrHTMLSendWorkV1, err)
	}
	stage = "publication_document_exact"
	before, after := *w.sourceDocument, *row
	before.Status = after.Status
	before.SentAt = after.SentAt
	before.Article13NoticeEpochAt = after.Article13NoticeEpochAt
	before.Article13NoticeSchema = after.Article13NoticeSchema
	before.Article13NoticeEpochV61Committed = after.Article13NoticeEpochV61Committed
	before.UpdatedAt = after.UpdatedAt
	if !preSignPublicationDocumentEqualV1(&before, &after) || row.SentAt != w.sourceIntent.Article13NoticeEpochAt ||
		row.Article13NoticeEpochAt != w.sourceIntent.Article13NoticeEpochAt || row.Article13NoticeSchema != "hash-a13-2026-08-31" || !row.Article13NoticeEpochV61Committed {
		return zero, ErrHTMLSendWorkV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	w.models.Document = row
	w.completedDocument = row
	s.sentDocument = htmlSendCloneDocumentV1(row)
	if s.result.Expired {
		w.expiredAttempted = true
		stage = "publication_expired_loan"
		documentRaw, _, err = w.admitDocumentReturnV1(call, int64(len("expired")))
		if err != nil {
			return zero, err
		}
		// Ordinary ExpireDocumentIfActive intentionally requires expires_at.
		// This fixed producer also closes the exact retained-deadline case;
		// neither a caller timestamp nor a generic status mutation is accepted.
		stage = "publication_expired_sql"
		tag, err := db.Exec(call, `UPDATE documents d SET status='expired',updated_at=now()
		 WHERE d.org_id=$1 AND d.id=$2 AND d.status='sent' AND d.updated_at=$3 AND d.deleted_at IS NULL
		 AND ((d.expires_at IS NOT NULL AND d.expires_at<=clock_timestamp()) OR EXISTS(
		  SELECT 1 FROM presign_execution_publications_v1 p JOIN send_sealing_intents i ON i.org_id=p.org_id AND i.document_id=p.document_id
		  WHERE p.org_id=d.org_id AND p.document_id=d.id AND p.execution_id=$4 AND p.customer_recipient_id=$5
		  AND p.state='retaining' AND p.retain_until=$6 AND p.retain_until<=clock_timestamp()
		  AND i.presign_execution_id=p.execution_id AND i.retain_until=p.retain_until
		  AND p.retention_started_at=i.retention_started_at AND p.retention_completed_at=i.retention_completed_at
		  AND i.retention_completed_at IS NOT NULL))`, e.OrgID, e.Document.ID, w.sourceDocument.UpdatedAt, e.ID, customer.ID, p.RetainUntil)
		if err != nil || tag.RowsAffected() != 1 {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		stage = "publication_expired_read"
		row, err = w.queries.GetDocument(call, generated.GetDocumentParams{ID: e.Document.ID, OrgID: e.OrgID})
		if err != nil || !w.verifyDocumentReturnV1(row, documentRaw) || row.Status != "expired" {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		before, after = *w.sourceDocument, *row
		before.Status = after.Status
		before.UpdatedAt = after.UpdatedAt
		if !preSignPublicationDocumentEqualV1(&before, &after) {
			return zero, ErrHTMLSendWorkV1
		}
		w.sourceDocument = htmlSendCloneDocumentV1(row)
		w.models.Document = row
		w.completedDocument = row
		stage = "publication_reminder_cancel"
		if err = w.queries.CancelReminder(call, e.Document.ID); err != nil {
			return zero, err
		}
	} else {
		stage = "publication_reminder_upsert"
		if err = w.queries.UpsertReminderSchedule(call, generated.UpsertReminderScheduleParams{DocumentID: e.Document.ID,
			Column2: []byte(`[{"days_after_send":3},{"days_after_send":7}]`), FiresRemaining: 2}); err != nil {
			return zero, err
		}
		stage = "publication_outbox"
		outbox, err := w.queries.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text, ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: []byte("{}")})
		if err != nil || outbox == nil || outbox.ID == uuid.Nil || outbox.ToEmail != msg.To || outbox.Subject != msg.Subject || outbox.HtmlBody != msg.HTML ||
			outbox.TextBody != msg.Text || outbox.ReplyTo != msg.ReplyTo || outbox.FromName != msg.FromName || string(outbox.HeadersJson) != "{}" || outbox.Status != "pending" || outbox.LastError != "" {
			return zero, errors.Join(ErrHTMLSendWorkV1, err)
		}
		s.outboxID = outbox.ID
		s.message = dispatch.Message{To: strings.Clone(msg.To), Subject: strings.Clone(msg.Subject), HTML: strings.Clone(msg.HTML), Text: strings.Clone(msg.Text), ReplyTo: strings.Clone(msg.ReplyTo), FromName: strings.Clone(msg.FromName)}
	}
	s.document = htmlSendCloneDocumentV1(w.sourceDocument)
	stage = "publication_current"
	if err = w.preSignPublicationCurrentV1(call, s); err != nil {
		return zero, err
	}
	s.ready = true
	return s.result, nil
}

// This is the actual guarded sent row from CompleteDocumentSendSealing, kept
// before any same-transaction expiry. The sent audit never receives a made-up
// status rewrite of an expired row or a mutable alias to private comparison.
func (w *ApplicationHTMLSendWorkV1) PreSignSentDocumentV1(call context.Context) (*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.presignPublication
	if !w.valid(call) || w.stage.purpose != HTMLPreSignPublicationV1 || s == nil || !s.ready || s.sentViewed || s.sentDocument == nil || s.sentDocument.Status != "sent" {
		return nil, ErrHTMLSendWorkV1
	}
	s.sentViewed = true
	return htmlSendCloneDocumentV1(s.sentDocument), nil
}

// Re-read the exact rows after the fixed mutation and again immediately before
// publishing. This does not trust mutable models returned to the policy layer.
func (w *ApplicationHTMLSendWorkV1) preSignPublicationCurrentV1(call context.Context, s *preSignPublicationV1) (failure error) {
	stage := "publication_current_scope"
	defer func() { failure = htmlPreSignPublicationFailureV1(stage, failure) }()
	if s == nil || s.customer == nil || s.provider == nil || s.document == nil {
		return ErrHTMLSendWorkV1
	}
	stage = "publication_current_recipients"
	for _, want := range []*generated.Recipient{s.customer, s.provider} {
		got, err := w.queries.GetRecipient(call, generated.GetRecipientParams{ID: want.ID, OrgID: w.session.state.org})
		if err != nil {
			return err
		}
		if !preSignPublicationRecipientEqualV1(want, got) {
			return ErrHTMLSendWorkV1
		}
	}
	// The already paid original document loan is extended before a fresh full
	// row read. JSON/source bodies must still equal the original actual tuple.
	stage = "publication_current_document_loan"
	if _, _, err := w.admitDocumentReturnV1(call, 0); err != nil {
		return err
	}
	stage = "publication_current_document"
	doc, err := w.queries.GetDocument(call, generated.GetDocumentParams{ID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil {
		return err
	}
	if !preSignPublicationDocumentEqualV1(doc, s.document) {
		return ErrHTMLSendWorkV1
	}
	stage = "publication_current_intent"
	intent, err := w.queries.GetSendSealingIntent(call, generated.GetSendSealingIntentParams{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil {
		return err
	}
	if intent == nil || *intent != *w.sourceIntent {
		return ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var exact bool
	stage = "publication_current_outbox"
	if s.result.Expired {
		err = db.QueryRow(call, `SELECT NOT EXISTS(SELECT 1 FROM reminders WHERE document_id=$1)`, w.logicalDocumentV1()).Scan(&exact)
	} else {
		err = db.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM email_deliveries WHERE id=$1 AND to_email=$2 AND subject=$3 AND html_body=$4
		 AND text_body=$5 AND reply_to=$6 AND from_name=$7 AND headers_json='{}'::jsonb AND status='pending' AND last_error='')
		 AND EXISTS(SELECT 1 FROM reminders WHERE document_id=$8 AND schedule_json='[{"days_after_send":3},{"days_after_send":7}]'::jsonb
		 AND fires_remaining=2 AND last_fired_at IS NULL AND next_fire_at IS NOT NULL)
		 AND EXISTS(SELECT 1 FROM documents WHERE org_id=$9 AND id=$8 AND (expires_at IS NULL OR expires_at>clock_timestamp()))
		 AND $10::timestamptz>clock_timestamp()`, s.outboxID, s.message.To, s.message.Subject, s.message.HTML, s.message.Text, s.message.ReplyTo, s.message.FromName, w.logicalDocumentV1(), w.session.state.org, s.result.RetainUntil).Scan(&exact)
	}
	if err != nil {
		return err
	}
	if !exact {
		return ErrHTMLSendWorkV1
	}
	return nil
}

// MarkPreSignPublicationV1 consumes the original native audit, not a caller's
// assertion that an invite happened. Every six-key value and the actual row
// hash are rechecked inside this SAME still-open publication transaction.
func (w *ApplicationHTMLSendWorkV1) MarkPreSignPublicationV1(call context.Context, eventID uuid.UUID) (failure error) {
	stage := "publication_mark_scope"
	defer func() { failure = htmlPreSignPublicationFailureV1(stage, failure) }()
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s := w.presignPublication
	if !w.valid(call) || w.stage.purpose != HTMLPreSignPublicationV1 || s == nil || !s.ready || s.markAttempted || s.marked ||
		(s.result.Expired != (eventID == uuid.Nil)) {
		return ErrHTMLSendWorkV1
	}
	s.markAttempted = true
	stage = "publication_mark_current"
	if err := w.preSignPublicationCurrentV1(call, s); err != nil {
		return err
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	state := "expired"
	var published pgtype.Timestamptz
	var event pgtype.UUID
	if !s.result.Expired {
		expected := map[string]string{"execution_id": s.result.ExecutionID.String(), "execution_sha256": s.result.ExecutionSHA256,
			"visible_pdf_sha256": s.result.VisiblePDFSHA256, "assets_sha256": s.result.AssetsSHA256,
			"customer_recipient_id": s.result.CustomerRecipientID.String(), "retain_until": s.result.RetainUntil.UTC().Format(time.RFC3339Nano)}
		stage = "publication_mark_canonical"
		canonical, err := json.Marshal(expected)
		if err != nil {
			return err
		}
		var jsonBytes, hashedBytes, uaBytes, prevBytes int64
		stage = "publication_mark_measure"
		err = db.QueryRow(call, `SELECT octet_length(payload_json::text)::bigint,octet_length(payload_hashed)::bigint,
		 COALESCE(octet_length(ua),0)::bigint,COALESCE(octet_length(prev_hash),0)::bigint FROM events
		 WHERE id=$1 AND org_id=$2 AND document_id=$3 AND recipient_id=$4 AND actor_user_id=$5 AND kind='presign.execution.published'
		 AND octet_length(row_hash)=32`, eventID, w.session.state.org, w.logicalDocumentV1(), s.result.CustomerRecipientID, s.executor).
			Scan(&jsonBytes, &hashedBytes, &uaBytes, &prevBytes)
		if err != nil {
			return err
		}
		stage = "publication_mark_shape"
		if jsonBytes < 1 || hashedBytes != int64(len(canonical)) || uaBytes < 0 || (prevBytes != 0 && prevBytes != 32) {
			return ErrHTMLSendWorkV1
		}
		stage = "publication_mark_size"
		raw, err := htmlAuthoringSumV1(jsonBytes, hashedBytes, uaBytes, prevBytes, 32, int64(len("presign.execution.published")), int64(unsafe.Sizeof(generated.Event{})))
		if err != nil {
			return err
		}
		stage = "publication_mark_loan"
		closeEvent, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, jsonBytes)
		if err != nil {
			return errors.Join(ErrHTMLSendWorkV1, err)
		}
		w.closes = append(w.closes, closeEvent)
		stage = "publication_mark_read"
		row, err := w.queries.GetEventByID(call, eventID)
		if err != nil {
			return err
		}
		stage = "publication_mark_row"
		if row == nil || row.ID != eventID || row.OrgID != w.session.state.org || !row.DocumentID.Valid || uuid.UUID(row.DocumentID.Bytes) != w.logicalDocumentV1() ||
			!row.RecipientID.Valid || uuid.UUID(row.RecipientID.Bytes) != s.result.CustomerRecipientID || !row.ActorUserID.Valid || uuid.UUID(row.ActorUserID.Bytes) != s.executor ||
			row.Kind != "presign.execution.published" || !row.CreatedAt.Valid || row.CreatedAt.Time.Before(s.retentionCompleted) ||
			!bytes.Equal(row.PayloadHashed, canonical) || int64(len(row.PayloadJson)) != jsonBytes || int64(len(row.Ua.String)) != uaBytes ||
			int64(len(row.PrevHash)) != prevBytes || len(row.RowHash) != 32 {
			return ErrHTMLSendWorkV1
		}
		stage = "publication_mark_payload"
		var payload map[string]string
		if json.Unmarshal(row.PayloadJson, &payload) != nil || len(payload) != len(expected) {
			return ErrHTMLSendWorkV1
		}
		for key, value := range expected {
			if payload[key] != value {
				return ErrHTMLSendWorkV1
			}
		}
		stage = "publication_mark_hash"
		computed, err := audit.RecomputeEventRowHash(row)
		if err != nil || !bytes.Equal(computed, row.RowHash) {
			return errors.Join(ErrHTMLSendWorkV1, err)
		}
		state = "published"
		published = row.CreatedAt
		event = pgtype.UUID{Bytes: eventID, Valid: true}
	}
	stage = "publication_mark_update"
	tag, err := db.Exec(call, `UPDATE presign_execution_publications_v1 SET state=$4,published_at=$5,publication_event_id=$6
	 WHERE org_id=$1 AND document_id=$2 AND execution_id=$3 AND state='retaining' AND customer_recipient_id=$7
	 AND retain_until=$8 AND retention_started_at=$9 AND retention_completed_at=$10
	 AND published_at IS NULL AND publication_event_id IS NULL AND ($4='expired' OR $8>clock_timestamp())`, w.session.state.org, w.logicalDocumentV1(), s.result.ExecutionID, state, published, event,
		s.result.CustomerRecipientID, s.result.RetainUntil, s.retentionStarted, s.retentionCompleted)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrHTMLSendWorkV1
	}
	s.marked = true
	return nil
}
