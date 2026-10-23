// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"math"
	"time"
)

var ErrHTMLAuditEventV1 = errors.New("pdfadmission: owned HTML audit event unavailable")

// Only fixed existing event schemas are supported. This does not authorize a
// mutation or make an Entry trusted: original application policy still runs.
type HTMLAuditPurposeV1 uint8

const (
	HTMLAuditDocumentCreatedV1 HTMLAuditPurposeV1 = iota + 1
	HTMLAuditHTMLReviewV1
	HTMLAuditHTMLRevisionV1
	HTMLAuditRecipientInvitedV1
	HTMLAuditDocumentSentV1
	HTMLAuditDocumentExpiredV1
	HTMLAuditCRMObservedV1
	HTMLAuditChangesRequestedV1
	HTMLAuditChangeDecisionV1
	HTMLAuditCeremonyRetiredV1
	HTMLAuditPlainPDFCreatedV1
	HTMLAuditPlainFieldAddedV1
	HTMLAuditPlainLayoutRecipientCreatedV1
	HTMLAuditBlocksCreatedV1
	HTMLAuditBlocksUpdatedV1
	HTMLAuditEnvelopeUpdatedV1
	HTMLAuditPlainRecipientCreatedV1
	HTMLAuditPlainRecipientUpdatedV1
	HTMLAuditPlainRecipientDeletedV1
	HTMLAuditBlockSignedV1
	HTMLAuditPlainDraftUpdatedV1
	HTMLAuditAutomationDocumentCreatedV1
	HTMLAuditAutomationRecipientCreatedV1
	HTMLAuditPDFLayoutTemplateCreatedV1
	HTMLAuditHistoricalCompletedV1
	HTMLAuditAcknowledgedV1
	HTMLAuditSignerViewedV1
	HTMLAuditSignerFieldFilledV1
	HTMLAuditSignerCommentV1
	HTMLAuditStaffCommentV1
	HTMLAuditDocumentAttachmentAddedV1
	HTMLAuditDocumentAttachmentLayoutV1
	HTMLAuditPackageRecipientInvitedV1
	HTMLAuditPackageDocumentSentV1
	HTMLAuditPackageDocumentExpiredV1
	HTMLAuditPackageSendAbortedV1
	HTMLAuditPackageSignedV1
	HTMLAuditPackageAcknowledgedV1
	HTMLAuditReminderManualV1
	HTMLAuditReminderAutomaticV1
	HTMLAuditVariableBindingV1
	HTMLAuditManualProposalCreatedV1
	HTMLAuditManualProposalStatusV1
	HTMLAuditManualNegotiationSettingV1
	HTMLAuditManualBilingualTargetV1
	HTMLAuditAIRequestedV1
	HTMLAuditAICompletedV1
	HTMLAuditAIResultReadyV1
	HTMLAuditAIBilingualCheckedV1
	HTMLAuditAIRiskAnalyzedV1
	HTMLAuditSignerClarifierRequestedV1
	HTMLAuditSignerAIRequestedV1
	HTMLAuditSignerAICompletedV1
	HTMLAuditSignerClarifierAnsweredV1
	HTMLAuditLaterAmendmentV1
	HTMLAuditLaterAmendmentNoticeV1
	HTMLAuditLaterAmendmentAccessRevokedV1
	HTMLAuditPreSignCommittedV1
	HTMLAuditPreSignPublishedV1
	HTMLAuditPreSignSupersededV1
)

func (p HTMLAuditPurposeV1) KindV1() string {
	switch p {
	case HTMLAuditPreSignCommittedV1:
		return "presign.execution.committed"
	case HTMLAuditPreSignPublishedV1:
		return "presign.execution.published"
	case HTMLAuditPreSignSupersededV1:
		return "presign.execution.superseded"
	case HTMLAuditLaterAmendmentAccessRevokedV1:
		return "document.amendment_notice_access_revoked"
	case HTMLAuditLaterAmendmentV1:
		return "document.amendment_linked"
	case HTMLAuditLaterAmendmentNoticeV1:
		return "document.amendment_notice_queued"
	case HTMLAuditSignerClarifierRequestedV1:
		return "clarifier.requested"
	case HTMLAuditSignerAIRequestedV1:
		return "ai.requested"
	case HTMLAuditSignerAICompletedV1:
		return "ai.completed"
	case HTMLAuditSignerClarifierAnsweredV1:
		return "clarifier.answered"
	case HTMLAuditAIRequestedV1:
		return "ai.requested"
	case HTMLAuditAICompletedV1:
		return "ai.completed"
	case HTMLAuditAIResultReadyV1:
		return "ai.result_ready"
	case HTMLAuditAIBilingualCheckedV1:
		return "bilingual.checked"
	case HTMLAuditAIRiskAnalyzedV1:
		return "risk.analyzed"
	case HTMLAuditManualProposalCreatedV1:
		return "negotiation.proposed"
	case HTMLAuditManualProposalStatusV1:
		return "negotiation.status_changed"
	case HTMLAuditManualNegotiationSettingV1:
		return "negotiation.setting_changed"
	case HTMLAuditManualBilingualTargetV1:
		return "bilingual.target_changed"
	case HTMLAuditVariableBindingV1:
		return "document.updated"
	case HTMLAuditReminderManualV1, HTMLAuditReminderAutomaticV1:
		return "reminder.sent"
	case HTMLAuditDocumentAttachmentLayoutV1:
		return "document.attachments_updated"
	case HTMLAuditDocumentAttachmentAddedV1:
		return "document.attachment_added"
	case HTMLAuditSignerCommentV1, HTMLAuditStaffCommentV1:
		return "document.comment_posted"
	case HTMLAuditSignerFieldFilledV1:
		return "document.field_filled"
	case HTMLAuditSignerViewedV1:
		return "document.viewed"
	case HTMLAuditAcknowledgedV1, HTMLAuditPackageAcknowledgedV1:
		return "document.accepted"
	case HTMLAuditHistoricalCompletedV1:
		return "document.completed"
	case HTMLAuditPDFLayoutTemplateCreatedV1:
		return "template.created"
	case HTMLAuditAutomationDocumentCreatedV1:
		return "document.created"
	case HTMLAuditAutomationRecipientCreatedV1:
		return "recipient.created"
	case HTMLAuditPlainDraftUpdatedV1:
		return "document.updated"
	case HTMLAuditBlockSignedV1, HTMLAuditPackageSignedV1:
		return "document.signed"
	case HTMLAuditPlainRecipientCreatedV1:
		return "recipient.created"
	case HTMLAuditPlainRecipientUpdatedV1:
		return "recipient.updated"
	case HTMLAuditPlainRecipientDeletedV1:
		return "recipient.deleted"
	case HTMLAuditDocumentCreatedV1, HTMLAuditPlainPDFCreatedV1, HTMLAuditBlocksCreatedV1:
		return "document.created"
	case HTMLAuditPlainFieldAddedV1:
		return "document.field_added"
	case HTMLAuditPlainLayoutRecipientCreatedV1:
		return "recipient.created"
	case HTMLAuditHTMLReviewV1, HTMLAuditHTMLRevisionV1, HTMLAuditBlocksUpdatedV1, HTMLAuditEnvelopeUpdatedV1:
		return "document.updated"
	case HTMLAuditRecipientInvitedV1, HTMLAuditPackageRecipientInvitedV1:
		return "recipient.invited"
	case HTMLAuditDocumentSentV1, HTMLAuditPackageDocumentSentV1:
		return "document.sent"
	case HTMLAuditDocumentExpiredV1, HTMLAuditPackageDocumentExpiredV1:
		return "document.expired"
	case HTMLAuditPackageSendAbortedV1:
		return "document.send_aborted"
	case HTMLAuditCRMObservedV1:
		return "crm.variables.observed"
	case HTMLAuditChangesRequestedV1, HTMLAuditChangeDecisionV1:
		return "document.changes_requested"
	case HTMLAuditCeremonyRetiredV1:
		return "document.revised"
	}
	return ""
}
func htmlAuditRootKeyV1(p HTMLAuditPurposeV1, k string) bool {
	if len(k) == 0 {
		return false
	}
	var fields string
	switch p {
	case HTMLAuditPreSignCommittedV1:
		fields = "|execution_id|execution_sha256|grant_id|grant_revision|use_number|request_id|command_sha256|executor_kind|executor_user_id|executor_credential_id|"
	case HTMLAuditPreSignPublishedV1:
		fields = "|execution_id|execution_sha256|visible_pdf_sha256|assets_sha256|customer_recipient_id|retain_until|"
	case HTMLAuditPreSignSupersededV1:
		fields = "|prior_execution_id|prior_execution_sha256|prior_document_id|document_id|request_id|source_commitment|"
	case HTMLAuditLaterAmendmentAccessRevokedV1:
		fields = "|schema|amendment_id|notice_id|access_id|revoked_at|"
	case HTMLAuditLaterAmendmentV1:
		fields = "|schema|amendment_id|amendment_document_id|mode|revision|basis_sha256|file_commitment_sha256|original_pins_sha256|original_document_id|request_id|owner_alert|"
	case HTMLAuditLaterAmendmentNoticeV1:
		fields = "|schema|amendment_id|notice_id|notice_sha256|file_commitment_sha256|request_id|recipient_count|owner_alert|"
	case HTMLAuditSignerClarifierRequestedV1, HTMLAuditSignerAIRequestedV1:
		fields = "|via|tool|block_id|locale|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditSignerAICompletedV1:
		fields = "|via|tool|request_event_id|usage_id|provider|model|shield_active|input_tokens|output_tokens|success|transfer_jurisdiction|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditSignerClarifierAnsweredV1:
		fields = "|via|tool|request_event_id|block_id|locale|shield_active|latency_ms|input_tokens|output_tokens|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditAIRequestedV1:
		fields = "|via|tool|"
	case HTMLAuditAICompletedV1:
		fields = "|via|tool|request_event_id|usage_id|provider|model|shield_active|input_tokens|output_tokens|success|transfer_jurisdiction|"
	case HTMLAuditAIResultReadyV1:
		fields = "|via|tool|request_event_id|provider_called|"
	case HTMLAuditAIBilingualCheckedV1:
		fields = "|via|tool|request_event_id|equivalent|confidence|shield_active|"
	case HTMLAuditAIRiskAnalyzedV1:
		fields = "|via|tool|request_event_id|findings_count|high|medium|low|shield_active|latency_ms|"
	case HTMLAuditManualProposalCreatedV1:
		fields = "|via|tool|proposal_id|block_id|kind|ai_assisted|"
	case HTMLAuditManualProposalStatusV1:
		fields = "|via|proposal_id|status|"
	case HTMLAuditManualNegotiationSettingV1:
		fields = "|via|enabled|"
	case HTMLAuditManualBilingualTargetV1:
		fields = "|via|lang|"
	case HTMLAuditVariableBindingV1:
		fields = "|via|tool|variable|source_kind|"
	case HTMLAuditReminderManualV1:
		fields = "|manual|via|tool|"
	case HTMLAuditReminderAutomaticV1:
		fields = "|automatic|via|tool|"
	case HTMLAuditPackageSignedV1:
		fields = "|font|typed_name|image_sha256|signature_id|notice_schema|notice_digest|notice_snapshot|package_response_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|incorporation_version|incorporation_sha256|package_consent|response_kind|"
	case HTMLAuditPackageAcknowledgedV1:
		fields = "|recipient_email|notice_schema|notice_digest|notice_snapshot|package_response_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|incorporation_version|incorporation_sha256|package_consent|response_kind|"
	case HTMLAuditPackageRecipientInvitedV1:
		fields = "|email|role|package_send_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|"
	case HTMLAuditPackageDocumentSentV1:
		fields = "|recipient_count|evidence_retained|lawful_basis|lawful_basis_confirmed|retain_until|expired_before_invite|required_notice_schema|required_notice_sent_at|package_send_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|"
	case HTMLAuditPackageDocumentExpiredV1:
		fields = "|before_invite|irreversible_sealing_recovery|package_send_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|"
	case HTMLAuditPackageSendAbortedV1:
		fields = "|reason|package_send_schema|package_send_attempt_id|package_id|capture_revision|manifest_sha256|legal_commitment_sha256|"
	case HTMLAuditDocumentAttachmentLayoutV1:
		fields = "|schema|package_id|draft_generation|before|after|"
	case HTMLAuditDocumentAttachmentAddedV1:
		fields = "|schema|package_id|member_document_id|ordinal|title|category|draft_generation|pdf_sha256|pdf_bytes|pdf_pages|pdf_intake_report_sha256|source_kind|source_commitment|origin_commitment|materialization_id|materialization_sequence|"
	case HTMLAuditSignerCommentV1:
		fields = "|side|comment_evidence_schema|comment_id|comment_body_sha256|comment_created_at|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditStaffCommentV1:
		fields = "|side|comment_evidence_schema|comment_id|comment_body_sha256|comment_created_at|"
	case HTMLAuditSignerFieldFilledV1:
		fields = "|field_id|type|label|value_len|value_hash|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditSignerViewedV1:
		fields = "|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditAcknowledgedV1:
		fields = "|recipient_email|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditHistoricalCompletedV1:
		fields = "|mode|completion_effective_at_bound|completion_effective_at|retain_until|final_pdf_key|final_pdf_sha256|final_pdf_version_id|audit_cert_key|audit_cert_sha256|audit_cert_version_id|audit_payload_key|audit_payload_sha256|audit_payload_version_id|audit_signature_key|audit_signature_sha256|audit_signature_version_id|envelope_id|propagated|"
	case HTMLAuditPDFLayoutTemplateCreatedV1:
		fields = "|template_id|source_kind|name|layout_version|party_count|field_count|"
	case HTMLAuditAutomationDocumentCreatedV1:
		fields = "|name|source_kind|via|automation_request_id|template_id|template_version|template_content_sha256|"
	case HTMLAuditAutomationRecipientCreatedV1:
		fields = "|email|name|role|via|automation_request_id|"
	case HTMLAuditPlainDraftUpdatedV1:
		fields = "|via|tool|"
	case HTMLAuditBlockSignedV1:
		fields = "|font|typed_name|image_sha256|signature_id|notice_schema|notice_digest|notice_snapshot|"
	case HTMLAuditPlainRecipientCreatedV1, HTMLAuditPlainRecipientUpdatedV1, HTMLAuditPlainRecipientDeletedV1:
		fields = "|email|name|role|via|tool|"
	case HTMLAuditEnvelopeUpdatedV1:
		fields = "|via|tool|child_id|child_count|count|"
	case HTMLAuditBlocksCreatedV1:
		fields = "|name|source_kind|via|tool|"
	case HTMLAuditBlocksUpdatedV1:
		fields = "|via|tool|blocks|"
	case HTMLAuditPlainPDFCreatedV1:
		fields = "|name|source_kind|intake|via|tool|template_id|template_version|layout_version|party_count|"
	case HTMLAuditPlainFieldAddedV1:
		fields = "|field_id|recipient_id|party_role|type|page|required|via|tool|"
	case HTMLAuditPlainLayoutRecipientCreatedV1:
		fields = "|role|name|email|via|template_layout_version|"
	case HTMLAuditDocumentCreatedV1:
		fields = "|source_kind|authoring_kind|template_id|template_version|template_content_sha256|html_source_commitment|pdf_sha256|review_required|changed_sections|contract_party_bindings|contract_profile_digest|creation_request_id|creation_input_digest|"
	case HTMLAuditHTMLReviewV1:
		fields = "|html_pdf_reviewed|pdf_sha256|html_source_commitment|"
	case HTMLAuditHTMLRevisionV1:
		fields = "|html_materialization_revision|html_source_commitment|review_required|placement_reset|changed_sections|contract_party_identities_updated|"
	case HTMLAuditRecipientInvitedV1:
		fields = "|email|role|via|tool|"
	case HTMLAuditDocumentSentV1:
		fields = "|recipient_count|evidence_retained|lawful_basis|lawful_basis_confirmed|retain_until|expired_before_invite|required_notice_schema|required_notice_sent_at|envelope_id|propagated|via|tool|"
	case HTMLAuditDocumentExpiredV1:
		fields = "|before_invite|irreversible_sealing_recovery|envelope_id|propagated|via|tool|"
	case HTMLAuditCRMObservedV1:
		fields = "|observations|assurance|via|tool|"
	case HTMLAuditChangesRequestedV1:
		fields = "|message|block_id|quote|notice_schema|notice_digest|notice_snapshot|change_request|context|proposed|"
	case HTMLAuditChangeDecisionV1:
		fields = "|change_request|resolution|"
	case HTMLAuditCeremonyRetiredV1:
		return false
	default:
		return false
	}
	// No concatenation or allocation before admission, including hostile names.
	for i := 0; i < len(fields); i++ {
		if fields[i] != '|' {
			continue
		}
		j := i + 1
		for j < len(fields) && fields[j] != '|' {
			j++
		}
		if j-i-1 == len(k) && fields[i+1:j] == k {
			return true
		}
		i = j - 1
	}
	return false
}

type htmlAuditShapeV1 struct{ raw, wire, nodes int64 }

func (s *htmlAuditShapeV1) add(raw, wire, nodes int64) error {
	if raw < 0 || wire < 0 || nodes < 0 || raw > math.MaxInt64-s.raw || wire > math.MaxInt64-s.wire || nodes > math.MaxInt64-s.nodes {
		return ErrHTMLAuditEventV1
	}
	s.raw += raw
	s.wire += wire
	s.nodes += nodes
	return nil
}
func (s *htmlAuditShapeV1) text(v string, key bool) error {
	n := int64(len(v))
	extra := int64(2)
	if key {
		extra = 4
	}
	if n > (math.MaxInt64-extra)/6 {
		return ErrHTMLAuditEventV1
	}
	return s.add(n, 6*n+extra, 1)
}
func htmlAuditPayloadShapeV1(ctx context.Context, p HTMLAuditPurposeV1, m map[string]any) (htmlAuditShapeV1, error) {
	var s htmlAuditShapeV1
	if !applicationContextV1(ctx) || p.KindV1() == "" {
		return s, ErrHTMLAuditEventV1
	}
	for k := range m {
		if !htmlAuditRootKeyV1(p, k) {
			return s, ErrHTMLAuditEventV1
		}
	}
	// Nil root payload has the original audit prepareEntry semantics: {}.
	if m == nil {
		err := s.add(0, 2, 1)
		return s, err
	}
	if p == HTMLAuditAIBilingualCheckedV1 {
		if err := s.add(0, 2, 1); err != nil {
			return s, err
		}
		for key, value := range m {
			if err := s.text(key, true); err != nil {
				return s, err
			}
			if err := s.add(0, 2, 1); err != nil {
				return s, err
			}
			if key == "confidence" {
				confidence, ok := value.(float64)
				if !ok || math.IsNaN(confidence) || math.IsInf(confidence, 0) {
					return s, ErrHTMLAuditEventV1
				}
				if err := s.add(0, 32, 1); err != nil {
					return s, err
				}
			} else if err := s.value(ctx, value, 1); err != nil {
				return s, err
			}
		}
		return s, nil
	}
	err := s.value(ctx, m, 0)
	return s, err
}

// Walk concrete supported application values without Marshal, reflection,
// generic interface-map decoding, copies or scalable scratch before the loan.
// Arbitrary RawMessage, []byte, floats/JSON exponents, custom Marshalers and
// pointers are refused. Actual old audit schemas use the listed finite types.
func (s *htmlAuditShapeV1) value(ctx context.Context, v any, depth int) error {
	if depth > 8 || ctx.Err() != nil {
		return ErrHTMLAuditEventV1
	}
	switch x := v.(type) {
	case nil:
		return s.add(0, 4, 1)
	case string:
		return s.text(x, false)
	case bool:
		return s.add(0, 5, 1)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return s.add(0, 21, 1)
	case uuid.UUID:
		return s.add(16, 38, 1)
	case time.Time:
		return s.add(0, 66, 1)
	case article13.Snapshot:
		// Fixed original Snapshot+Copy keys, UUIDs, retention integer and punctuation
		// occupy <4096bytes. Every real variable string is counted individually.
		if err := s.add(48, 4096, 64); err != nil {
			return err
		}
		for _, text := range [...]string{x.Schema, x.SentAt, x.Controller, x.ControllerContact, x.Processor, x.ProcessorContact, x.PurposeSummary, x.LegalBasisDisclosure, x.SupervisoryAuthority, x.PolicyURL, string(x.DSRCapability), x.Copy.Title, x.Copy.Intro, x.Copy.ControllerLabel, x.Copy.ControllerContactLabel, x.Copy.ProcessorLabel, x.Copy.PurposeLabel, x.Copy.LegalBasisLabel, x.Copy.RetentionLabel, x.Copy.RetentionValue, x.Copy.AuthorityLabel, x.Copy.RightsSummary, x.Copy.RightsBody, x.Copy.SubmitRequestLabel, x.Copy.KindLabel, x.Copy.DSRAccessLabel, x.Copy.DSRRectificationLabel, x.Copy.DSRErasureLabel, x.Copy.DSRRestrictionLabel, x.Copy.DSRPortabilityLabel, x.Copy.DSRObjectionLabel, x.Copy.NoteLabel, x.Copy.NotePlaceholder, x.Copy.SendRequestLabel, x.Copy.RequestReceived, x.Copy.ReadPolicyLabel, x.Copy.AcknowledgementLabel, x.Copy.FinePrint} {
			if err := s.text(text, false); err != nil {
				return err
			}
		}
		return nil
	case htmlsource.PartyBinding:
		if err := s.add(16, 128, 3); err != nil {
			return err
		}
		return s.text(x.Slot, false)
	case map[string]any:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for k, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.text(k, true); err != nil {
				return err
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.value(ctx, value, depth+1); err != nil {
				return err
			}
		}
		return nil
	case map[string]string:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for k, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.text(k, true); err != nil {
				return err
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.text(value, false); err != nil {
				return err
			}
		}
		return ctx.Err()
	case []string:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for _, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.text(value, false); err != nil {
				return err
			}
		}
		return ctx.Err()
	case []map[string]any:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for _, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.value(ctx, value, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []map[string]string:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for _, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.value(ctx, value, depth+1); err != nil {
				return err
			}
		}
		return nil
	case []htmlsource.PartyBinding:
		if x == nil {
			return s.add(0, 4, 1)
		}
		if err := s.add(0, 2, 1); err != nil {
			return err
		}
		for _, value := range x {
			if ctx.Err() != nil {
				return ErrHTMLAuditEventV1
			}
			if err := s.add(0, 2, 1); err != nil {
				return err
			}
			if err := s.value(ctx, value, depth+1); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrHTMLAuditEventV1
	}
}
