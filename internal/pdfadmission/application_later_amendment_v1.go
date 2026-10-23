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
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strconv"
	"time"
)

// All SQL here runs through the genuine same-session native DBTX. It accepts
// neither a pool/transaction nor caller-supplied documents, pins or costs.
const laterAmendmentRecordSQLV1 = `SELECT jsonb_build_object(
 'id',a.id,'request_id',a.request_id,'revision',a.revision::text,'predecessor_id',a.predecessor_id,
 'document_id',a.document_id,'document_name',d.name,'document_status',d.status,'mode',a.mode,
 'basis',(convert_from(a.basis,'UTF8')::jsonb)||jsonb_build_object('sha256',encode(a.basis_sha256,'hex'),
 'reviewed_by',a.created_by,'reviewed_at',a.created_at,'attribution',CASE WHEN convert_from(a.basis,'UTF8')::jsonb->>'kind'='reviewed_legacy_clause'
 THEN 'Owner review of an existing agreement clause; not signatory consent or legal validation.' ELSE 'Policy frozen with the presented agreement.' END),
 'file_commitment_sha256',encode(a.file_commitment_sha256,'hex'),'created_at',a.created_at,'created_by',a.created_by)
 FROM document_amendments_v1 a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id
 WHERE a.id=$1 AND a.org_id=$2 AND d.deleted_at IS NULL`

func laterAmendmentRecordV1(ctx context.Context, db generated.DBTX, id, org uuid.UUID) (amendments.RecordV1, error) {
	var out amendments.RecordV1
	var raw []byte
	if e := db.QueryRow(ctx, laterAmendmentRecordSQLV1, id, org).Scan(&raw); e != nil {
		return out, e
	}
	if len(raw) > 32768 || json.Unmarshal(raw, &out) != nil || out.ID != id || !amendments.ValidModeV1(out.Mode) || out.DocumentID == uuid.Nil || out.CreatedBy == uuid.Nil || !amendments.ValidTimestampV1(out.CreatedAt) {
		return amendments.RecordV1{}, amendments.ErrUnavailableV1
	}
	var noticeID uuid.UUID
	e := db.QueryRow(ctx, `SELECT id FROM document_amendment_notices_v1 WHERE amendment_id=$1 AND org_id=$2`, id, org).Scan(&noticeID)
	if e == nil {
		notice, e := laterAmendmentNoticeRecordV1(ctx, db, noticeID, org)
		if e != nil {
			return amendments.RecordV1{}, e
		}
		out.Notice = &notice
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return amendments.RecordV1{}, e
	}
	return out, nil
}

// LinkLaterAmendmentV1 consumes BOTH actual paired read snapshots. The fixed
// application policy already checked their statuses, live owner credential and
// privacy before bodies; it rechecks the same credential after audit and before
// COMMIT. Exact response-loss retries read the original immutable request even
// after its separate document has advanced through normal signing.
func (w *ApplicationDocumentPackageSelectionV1) LinkLaterAmendmentV1(call context.Context, in amendments.CreateV1, actor uuid.UUID, ip, ua, publicURL string, appendAudit func(context.Context, *ApplicationHTMLAuditEventConsumerV1) error) (out amendments.OutcomeV1, failure error) {
	if w == nil || w.state == nil || actor == uuid.Nil || appendAudit == nil {
		return out, amendments.ErrUnavailableV1
	}
	s := w.state
	if e := s.beginV1(call); e != nil {
		return out, e
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attempted || s.readActor != actor || s.closed.Load() || s.readers[0] == nil || s.readers[1] == nil || s.readers[0].snapshot == nil || s.readers[1].snapshot == nil {
		return out, amendments.ErrUnavailableV1
	}
	original, candidate := s.readers[0].snapshot.document, s.readers[1].snapshot.document
	if original == nil || candidate == nil || original.ID != s.ids[0] || candidate.ID != s.ids[1] || original.OrgID != s.session.state.org || candidate.OrgID != original.OrgID || in.AmendmentDocumentID != candidate.ID {
		return out, amendments.ErrUnavailableV1
	}
	if e := in.ValidateV1(original.ID); e != nil {
		return out, e
	}
	// Schema bounds limit the complete relation plus four independent original
	// artifact pins. Fund before SQL JSON, marshal/hash scratch and result copies.
	close, e := s.actor.acquireOwnedRetainedBodyV1(call, 8<<20, 2<<20)
	if e != nil {
		return out, e
	}
	s.closes = append(s.closes, close)
	db := &applicationOwnedDBTXV1{session: s.session.state}
	digest, e := amendments.RequestDigestV1(in)
	if e != nil {
		return out, e
	}
	var oldID uuid.UUID
	var oldDigest []byte
	e = db.QueryRow(call, `SELECT id,request_sha256 FROM document_amendments_v1 WHERE org_id=$1 AND original_document_id=$2 AND request_id=$3`, original.OrgID, original.ID, in.RequestID).Scan(&oldID, &oldDigest)
	if e == nil {
		if hex.EncodeToString(oldDigest) != digest {
			return out, amendments.ErrChangedV1
		}
		record, e := laterAmendmentRecordV1(call, db, oldID, original.OrgID)
		if e != nil {
			return out, e
		}
		return amendments.OutcomeV1{State: "unchanged", RequestID: in.RequestID, Amendment: &record}, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	if original.Status != "completed" || candidate.Status != "draft" || !candidate.UpdatedAt.Valid || !candidate.UpdatedAt.Time.Equal(in.ExpectedDocumentUpdatedAt) || candidate.SentAt.Valid || candidate.DeletedAt.Valid || candidate.IsEnvelope || candidate.ParentEnvelopeID.Valid || candidate.SourceKind != "pdf" || (in.Mode == amendments.SignatureV1) != candidate.RequiresSignature {
		return out, amendments.ErrChangedV1
	}
	if len(ip) > 64 || len(ua) > 1024 {
		return out, amendments.ErrInputV1
	}
	var headID pgtype.UUID
	var headRevision int64
	e = db.QueryRow(call, `SELECT id,revision FROM document_amendments_v1 WHERE org_id=$1 AND original_document_id=$2 ORDER BY revision DESC LIMIT 1`, original.OrgID, original.ID).Scan(&headID, &headRevision)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	expected, _ := amendments.RevisionV1(in.ExpectedHeadRevision)
	if headRevision != expected || (in.ExpectedHeadID == nil) != (!headID.Valid) || (in.ExpectedHeadID != nil && uuid.UUID(headID.Bytes) != *in.ExpectedHeadID) {
		return out, amendments.ErrChangedV1
	}
	var originalPins, files []byte
	if e = db.QueryRow(call, `SELECT convert_to(hash_amendment_original_pins_v1($1,$2)::text,'UTF8'),convert_to(hash_amendment_file_set_v1($3,$2)::text,'UTF8')`, original.ID, original.OrgID, candidate.ID).Scan(&originalPins, &files); e != nil {
		return out, e
	}
	if len(originalPins) < 2 || len(originalPins) > 32768 || len(files) < 2 || len(files) > 65536 {
		return out, amendments.ErrUnavailableV1
	}
	var measured amendments.FileSetV1
	if json.Unmarshal(files, &measured) != nil || len(measured.Files) < 1 || len(measured.Files) > 17 || measured.Files[0].DocumentID != candidate.ID {
		return out, amendments.ErrUnavailableV1
	}
	main := measured.Files[0]
	if sanitize.ValidateStoredPDFProvenanceV1(candidate.MetadataRedactionReport, main.SHA256, main.Bytes, int(main.Pages)) != nil {
		return out, amendments.ErrChangedV1
	}
	basis := in.Basis
	if basis.Kind == "frozen_agreement_policy" {
		// Independently resolve the frozen body. An ID alone never supplies policy.
		var raw []byte
		if e = db.QueryRow(call, `SELECT basis FROM document_amendment_policies_v1 WHERE id=$1 AND org_id=$2 AND document_id=$3`, basis.FrozenPolicyID, original.OrgID, original.ID).Scan(&raw); e != nil {
			return out, e
		}
		var resolved amendments.BasisV1
		if len(raw) > 16384 || json.Unmarshal(raw, &resolved) != nil {
			return out, amendments.ErrChangedV1
		}
		resolved.Kind = "reviewed_legacy_clause"
		resolved.FrozenPolicyID = nil
		if resolved.ValidateV1(in.Mode) != nil {
			return out, amendments.ErrChangedV1
		}
		// Keep only the resolved policy's permission body in the relation, retaining
		// its original ID/kind. SQL independently rechecks the frozen row at insert.
		basis = resolved
		basis.Kind = "frozen_agreement_policy"
		basis.FrozenPolicyID = in.Basis.FrozenPolicyID
	}
	rawBasis, e := json.Marshal(basis)
	if e != nil {
		return out, e
	}
	if len(rawBasis) > 16384 {
		return out, amendments.ErrInputV1
	}
	basisDigest, e := amendments.DigestV1("hash:later-amendment-basis:v1", basis)
	if e != nil {
		return out, e
	}
	fileHash := sha256.New()
	fileHash.Write([]byte("hash:later-amendment-files:v1\x00"))
	fileHash.Write(files)
	fileDigest := fileHash.Sum(nil)
	originalDigest := sha256.Sum256(originalPins)
	alert, e := laterAmendmentOwnerAlertForV1(call, s, HTMLAuditLaterAmendmentV1.KindV1(), publicURL)
	if e != nil {
		return out, e
	}
	id := uuid.New()
	payload := map[string]any{"schema": amendments.SchemaV1, "amendment_id": id.String(), "amendment_document_id": candidate.ID.String(), "mode": string(in.Mode), "revision": strconv.FormatInt(expected+1, 10), "basis_sha256": basisDigest, "file_commitment_sha256": hex.EncodeToString(fileDigest), "original_pins_sha256": hex.EncodeToString(originalDigest[:]), "original_document_id": original.ID.String(), "request_id": in.RequestID.String()}
	payload["owner_alert"] = alert.payloadV1()
	scope := &applicationLaterAmendmentAuditScopeV1{source: s, call: call, actor: actor}
	eventCall := context.WithValue(call, laterAmendmentAuditKeyV1{}, scope)
	event, e := s.session.NewHTMLAuditEventV1(eventCall, HTMLAuditLaterAmendmentV1, original.OrgID, candidate.ID, pgtype.UUID{}, pgtype.UUID{Bytes: actor, Valid: true}, HTMLAuditLaterAmendmentV1.KindV1(), ip, ua, payload)
	if e != nil {
		return out, e
	}
	if e = appendAudit(call, event); e != nil {
		event.CloseConsumerV1()
		return out, e
	}
	event.mu.Lock()
	eventID := event.eventID
	valid := event.used && event.attempted && !event.closed && eventID != uuid.Nil
	event.mu.Unlock()
	if !valid {
		return out, amendments.ErrUnavailableV1
	}
	requestHash, _ := hex.DecodeString(digest)
	basisHash, _ := hex.DecodeString(basisDigest)
	var created time.Time
	e = db.QueryRow(call, `INSERT INTO document_amendments_v1(id,org_id,original_document_id,document_id,revision,previous_revision,predecessor_id,request_id,request_sha256,mode,basis,basis_sha256,original_pins,original_pins_sha256,file_set,file_commitment_sha256,created_by,event_id,owner_alert_user_id,owner_alert_email_delivery_id,owner_alert_message_sha256)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING created_at`, id, original.OrgID, original.ID, candidate.ID, expected+1, expected, in.ExpectedHeadID, in.RequestID, requestHash, in.Mode, rawBasis, basisHash, originalPins, originalDigest[:], files, fileDigest, actor, eventID, alert.user, alert.email, alert.messageSHA[:]).Scan(&created)
	if e != nil {
		return out, e
	}
	record, e := laterAmendmentRecordV1(call, db, id, original.OrgID)
	if e != nil || !record.CreatedAt.Equal(created) {
		return out, errors.Join(amendments.ErrUnavailableV1, e)
	}
	out = amendments.OutcomeV1{State: "committed", RequestID: in.RequestID, Amendment: &record}
	return out, call.Err()
}

// Fixed source snapshots only. A later notice preparation cannot mint an
// alternate file inventory or trust current mutable annex source documents.
func (r *ApplicationHTMLRevisionReaderV1) ReadLaterAmendmentInventoryV1(call context.Context) (out amendments.InventoryV1, failure error) {
	if r == nil || r.self != r {
		return out, amendments.ErrUnavailableV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil {
		return out, amendments.ErrUnavailableV1
	}
	d := r.snapshot.document
	if d.Status != "completed" || d.DeletedAt.Valid || d.IsEnvelope || d.ParentEnvelopeID.Valid {
		return out, amendments.ErrChangedV1
	}
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var count, rawBytes int64
	e := db.QueryRow(call, `SELECT count(*),COALESCE(sum(octet_length(a.basis)*6+131072),0)::bigint FROM document_amendments_v1 a WHERE a.org_id=$1 AND a.original_document_id=$2`, d.OrgID, d.ID).Scan(&count, &rawBytes)
	if e != nil {
		return out, e
	}
	if count < 0 || count > amendments.MaxHistoryV1 || rawBytes < 0 || rawBytes > 16<<20 {
		return out, amendments.ErrUnavailableV1
	}
	close, e := r.authoring.acquireOwnedRetainedBodyV1(call, 1<<20+32*rawBytes, 1<<20+8*rawBytes)
	if e != nil {
		return out, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	var pins []byte
	if e = db.QueryRow(call, `SELECT convert_to(hash_amendment_original_pins_v1($1,$2)::text,'UTF8')`, d.ID, d.OrgID).Scan(&pins); e != nil {
		return out, e
	}
	var original struct {
		FinalPDF struct {
			SHA256 string `json:"sha256"`
		} `json:"final_pdf"`
		ReportSHA256 string `json:"report_sha256"`
		Package      *struct {
			Commitment string `json:"legal_commitment_sha256"`
		} `json:"package"`
	}
	if len(pins) > 32768 || json.Unmarshal(pins, &original) != nil {
		return out, amendments.ErrUnavailableV1
	}
	out = amendments.InventoryV1{Schema: amendments.SchemaV1, OriginalDocumentID: d.ID, HeadRevision: "0", Original: amendments.OriginalV1{DocumentID: d.ID, Name: d.Name, CompletedAt: d.CompletedAt.Time, FinalPDFSHA256: original.FinalPDF.SHA256, ReportSHA256: original.ReportSHA256}, FrozenPolicies: []amendments.BasisRecordV1{}, Amendments: []amendments.RecordV1{}}
	if original.Package != nil {
		out.Original.PackageCommitmentSHA256 = original.Package.Commitment
	}
	var frozenID, by uuid.UUID
	var policyRaw, policySHA []byte
	var frozenAt time.Time
	e = db.QueryRow(call, `SELECT id,basis,basis_sha256,frozen_by,frozen_at FROM document_amendment_policies_v1 WHERE org_id=$1 AND document_id=$2 AND presented_pdf_sha256=$3 AND presented_pdf_version_id=$4`, d.OrgID, d.ID, d.PdfSha256, d.PdfStorageVersionID).Scan(&frozenID, &policyRaw, &policySHA, &by, &frozenAt)
	if e == nil {
		var policy amendments.BasisV1
		if len(policyRaw) > 16384 || len(policySHA) != 32 || json.Unmarshal(policyRaw, &policy) != nil || policy.Kind != "frozen_agreement_policy" || policy.FrozenPolicyID == nil || *policy.FrozenPolicyID != frozenID {
			return amendments.InventoryV1{}, amendments.ErrUnavailableV1
		}
		out.FrozenPolicies = append(out.FrozenPolicies, amendments.BasisRecordV1{BasisV1: policy, SHA256: hex.EncodeToString(policySHA), ReviewedBy: by, ReviewedAt: frozenAt, Attribution: "Policy frozen with the presented agreement."})
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return amendments.InventoryV1{}, e
	}
	rows, e := db.Query(call, `SELECT id FROM document_amendments_v1 WHERE org_id=$1 AND original_document_id=$2 ORDER BY revision LIMIT 65`, d.OrgID, d.ID)
	if e != nil {
		return out, e
	}
	var ids [amendments.MaxHistoryV1]uuid.UUID
	n := 0
	for rows.Next() {
		if n >= len(ids) {
			rows.Close()
			return out, amendments.ErrUnavailableV1
		}
		if e = rows.Scan(&ids[n]); e != nil {
			rows.Close()
			return out, e
		}
		n++
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return out, e
	}
	if int64(n) != count {
		return out, amendments.ErrChangedV1
	}
	for i := 0; i < n; i++ {
		record, e := laterAmendmentRecordV1(call, db, ids[i], d.OrgID)
		if e != nil {
			return amendments.InventoryV1{}, e
		}
		if record.Revision != strconv.Itoa(i+1) || (i == 0) != (record.PredecessorID == nil) || (i > 0 && (record.PredecessorID == nil || *record.PredecessorID != ids[i-1])) {
			return amendments.InventoryV1{}, amendments.ErrUnavailableV1
		}
		out.Amendments = append(out.Amendments, record)
	}
	if n > 0 {
		id := ids[n-1]
		out.HeadID = &id
		out.HeadRevision = strconv.Itoa(n)
	}
	return out, call.Err()
}

// Native pin equality is exact original bytes, not JSON reserialization.
func laterAmendmentPinsEqualV1(a, b []byte) bool { return len(a) > 0 && bytes.Equal(a, b) }

func (r *ApplicationHTMLRevisionReaderV1) ReadLaterAmendmentRelationV1(call context.Context) (out amendments.CandidateRelationV1, failure error) {
	if r == nil || r.self != r {
		return out, amendments.ErrUnavailableV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil {
		return out, amendments.ErrUnavailableV1
	}
	d := r.snapshot.document
	close, e := r.authoring.acquireOwnedRetainedBodyV1(call, 2<<20, 1<<20)
	if e != nil {
		return out, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	db := &applicationOwnedDBTXV1{session: r.session.state}
	var id, original uuid.UUID
	if e = db.QueryRow(call, `SELECT id,original_document_id FROM document_amendments_v1 WHERE document_id=$1 AND org_id=$2`, d.ID, d.OrgID).Scan(&id, &original); e != nil {
		return out, e
	}
	record, e := laterAmendmentRecordV1(call, db, id, d.OrgID)
	if e != nil {
		return out, e
	}
	return amendments.CandidateRelationV1{Schema: amendments.SchemaV1, OriginalDocumentID: original, Amendment: record}, call.Err()
}

func laterAmendmentNoticeRecordV1(ctx context.Context, db generated.DBTX, id, org uuid.UUID) (out amendments.NoticeV1, failure error) {
	var raw []byte
	e := db.QueryRow(ctx, `SELECT jsonb_build_object('id',n.id,'request_id',n.request_id,'subject',n.subject,'text',n.text_body,
 'sha256',encode(n.notice_sha256,'hex'),'file_commitment_sha256',encode(n.file_commitment_sha256,'hex'),
 'issued_at',n.issued_at,'issued_by',n.issued_by,'verified_receipts','[]'::jsonb,'deliveries',COALESCE((SELECT jsonb_agg(jsonb_build_object(
 'access_id',c.id,'revoked_at',c.revoked_at,'email_delivery_id',x.email_delivery_id,'recipient_email',x.recipient_email,'state',CASE e.status WHEN 'pending' THEN 'queued' WHEN 'retrying' THEN 'retrying' WHEN 'sent' THEN 'provider_accepted' WHEN 'failed' THEN 'failed' ELSE 'unavailable' END,
 'attempts',e.attempts,'provider_accepted_at',e.sent_at) ORDER BY x.position) FROM document_amendment_notice_deliveries_v1 x JOIN email_deliveries e ON e.id=x.email_delivery_id JOIN document_amendment_notice_access_v1 c ON c.email_delivery_id=x.email_delivery_id AND c.org_id=x.org_id AND c.notice_id=x.notice_id WHERE x.notice_id=n.id AND x.org_id=n.org_id),'[]'::jsonb))
 FROM document_amendment_notices_v1 n WHERE n.id=$1 AND n.org_id=$2`, id, org).Scan(&raw)
	if e != nil {
		return out, e
	}
	if len(raw) > 131072 || json.Unmarshal(raw, &out) != nil || out.ID != id || out.Deliveries == nil || len(out.Deliveries) < 1 || len(out.Deliveries) > 32 || out.VerifiedReceipts == nil {
		return amendments.NoticeV1{}, amendments.ErrUnavailableV1
	}
	for _, d := range out.Deliveries {
		if d.EmailDeliveryID == uuid.Nil || (d.State != "queued" && d.State != "retrying" && d.State != "provider_accepted" && d.State != "failed") {
			return amendments.NoticeV1{}, amendments.ErrUnavailableV1
		}
	}
	return out, ctx.Err()
}
