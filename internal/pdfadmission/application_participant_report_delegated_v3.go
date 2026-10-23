// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
)

// Caller holds the original work mutex and native parent/history locks. The
// canonical execution and all eight exact descriptors own a separate fixed
// body loan. This closed projection never reads mutable PayloadJson or accepts
// a caller's public delegation object as producer evidence.
func (w *ApplicationHTMLSendWorkV1) participantDelegationLockedV3(call context.Context, events []*generated.Event, document *generated.Document) (render.ParticipantDelegatedExecutionV1, error) {
	var out render.ParticipantDelegatedExecutionV1
	if !w.valid(call) || w.state == nil {
		return out, ErrHistoricalFinalizationSourceV1
	}
	var status string
	if document != nil {
		// Response sizing owns the exact validated native freeze return row.
		if document.ID != w.logicalDocumentV1() || document.OrgID != w.session.state.org {
			return out, ErrHistoricalFinalizationSourceV1
		}
		status = document.Status
	} else {
		// CertificateData deliberately owns scalar header/history only. This
		// exact current native header was locked and reference-authorized;
		// no other absent-document caller can substitute a cached status.
		state := w.certificateRead
		if w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationCertificateDataV1 || w.familyRoot != nil ||
			w.state.ParentEnvelopeID.Valid || w.state.BoundedStatus != "finalizing" ||
			w.state.ID != w.logicalDocumentV1() || w.state.OrgID != w.session.state.org || !applicationStampV1(w.state.UpdatedAt) ||
			state == nil || !state.authorized || !state.headAttempted || state.head == nil ||
			!state.eventsAttempted || state.events == nil || !state.reportAttempted {
			return out, ErrHistoricalFinalizationSourceV1
		}
		status = w.state.BoundedStatus
	}
	r, err := w.loadDelegatedFinalizationLockedV1(call)
	if err != nil || r == nil {
		return out, ErrHistoricalFinalizationSourceV1
	}
	e, g, p := r.Execution().Snapshot(), r.Grant().Snapshot(), r.Publication()
	copy := presignregistry.Disclosure()
	if p.State != "published" || p.CustomerRecipientID != e.Document.Parties[0].ID || p.PublishedAt.IsZero() ||
		p.RetentionStartedAt.IsZero() || p.RetentionCompletedAt.IsZero() || p.RetentionCompletedAt.Before(p.RetentionStartedAt) ||
		p.PublishedAt.Before(p.RetentionCompletedAt) || g.Disclosure.Version != copy.Version || g.Disclosure.SHA256 != copy.SHA256 {
		return out, ErrHistoricalFinalizationSourceV1
	}
	var exact bool
	err = (&applicationOwnedDBTXV1{session: w.session.state}).QueryRow(call, `SELECT COALESCE(d.source_kind='pdf' AND d.requires_signature AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND d.signing_admission_policy='historical' AND d.pdf_storage_key=$3 AND d.pdf_storage_version_id=$4 AND d.pdf_sha256=$5
 AND d.html_current_materialization_id=$6 AND d.html_current_materialization_sequence=$7 AND d.article13_notice_epoch_at=$8
 AND d.status=$9 AND d.deleted_at IS NULL,FALSE) FROM documents d WHERE d.org_id=$1 AND d.id=$2`,
		e.OrgID, e.Document.ID, e.Document.BasePDF.Artifact.StorageKey, e.Document.BasePDF.Artifact.VersionID, mustDecodeDelegatedSHA256V3(e.Document.BasePDF.Artifact.SHA256),
		e.Document.Materialization.ID, e.Document.Materialization.Revision, e.CeremonyEpoch, status).Scan(&exact)
	if err != nil || !exact {
		return out, ErrHistoricalFinalizationSourceV1
	}
	payload, err := presignexecute.AuditPayload(r.Execution(), r.Command())
	if err != nil {
		return out, err
	}
	expected, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	var event *generated.Event
	for _, v := range events {
		if v != nil && v.ID == r.AuditEventID() {
			if event != nil || v.Kind != presignexecute.AuditKindCommitted || v.OrgID != e.OrgID || !v.DocumentID.Valid || uuid.UUID(v.DocumentID.Bytes) != e.Document.ID ||
				!v.ActorUserID.Valid || uuid.UUID(v.ActorUserID.Bytes) != e.Executor.UserID || !v.CreatedAt.Valid || !bytes.Equal(v.PayloadHashed, expected) || len(v.RowHash) != 32 {
				return out, ErrHistoricalFinalizationSourceV1
			}
			event = v
		}
	}
	if event == nil {
		return out, ErrHistoricalFinalizationSourceV1
	}
	return render.ParticipantDelegatedExecutionV1{SchemaVersion: 1, EventID: event.ID.String(), EventRowSHA256: hex.EncodeToString(event.RowHash), EventAt: event.CreatedAt.Time.UTC().Format(time.RFC3339Nano),
		ExecutionID: e.ID.String(), ExecutionSHA256: r.Execution().Commitment(), PolicyID: e.Policy.ID.String(), PolicyRevision: e.Policy.Revision, PolicySHA256: e.Policy.SHA256,
		GrantID: e.Grant.ID.String(), GrantRevision: e.Grant.Revision, GrantSHA256: e.Grant.SHA256, UseNumber: e.UseNumber,
		ProviderRecipientID: e.Signature.RecipientID.String(), ProviderSignatureID: e.Signature.ID.String(), ProviderName: g.Grantor.Name, ExecutedAt: e.ExecutedAt.UTC().Format(time.RFC3339Nano),
		BasePDFSHA256: e.Document.BasePDF.Artifact.SHA256, VisiblePDFSHA256: e.VisiblePDF.Artifact.SHA256, AssetsSHA256: r.Assets().Commitment(), OverlayProofSHA256: e.VisibleStampProofSHA256,
		DisclosureVersion: copy.Version, DisclosureSHA256: copy.SHA256, DisclosureText: copy.Text}, nil
}

func mustDecodeDelegatedSHA256V3(value string) []byte { raw, _ := hex.DecodeString(value); return raw }
