// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This projection is reachable only after the real frozen-root stage reference
// and original chain/event reads. Header measurement, funding, fresh header and
// exact row counts precede the native private body projection and formatter.
func (w *ApplicationHTMLSendWorkV1) readParticipantReportLockedV1(call context.Context, state *applicationHistoricalCertificateReadV1) error {
	if state == nil || !state.authorized || state.head == nil || state.events == nil || state.reportAttempted || w.state == nil || !applicationStampV1(w.state.UpdatedAt) {
		return ErrHTMLSendWorkV1
	}
	return w.projectParticipantReportLockedV1(call, w.state.UpdatedAt, state)
}

// Shared private projection, not a certificate/reference authorization seam.
// The historical caller retains its original reference gate; the response
// caller must own its original bound mutation, audit and all family row locks.
func (w *ApplicationHTMLSendWorkV1) projectParticipantReportLockedV1(call context.Context, cutoff pgtype.Timestamptz, state *applicationHistoricalCertificateReadV1) error {
	return w.projectParticipantReportForSizingLockedV1(call, cutoff, state, false, w.sourceDocument)
}

// reserveClock is private formatter sizing only. SQL selection/verification
// always uses the actual locked-history cutoff; no reserved timestamp is ever
// persisted, signed, returned as report evidence or used to select history.
func (w *ApplicationHTMLSendWorkV1) projectParticipantReportForSizingLockedV1(call context.Context, cutoff pgtype.Timestamptz, state *applicationHistoricalCertificateReadV1, reserveClock bool, document *generated.Document) error {
	if !w.valid(call) || state == nil || state.reportAttempted || !applicationStampV1(cutoff) {
		return ErrHTMLSendWorkV1
	}
	state.reportAttempted = true
	control := int64(16384) + 8*int64(unsafe.Sizeof(generated.GetParticipantReportHeaderV1Params{})) + 8*int64(unsafe.Sizeof(generated.GetParticipantReportHeaderV1Row{}))
	closeControl, err := w.actor.acquireOwnedRetainedBodyV1(call, control, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeControl)
	p := generated.GetParticipantReportHeaderV1Params{OrgID: w.session.state.org, DocumentID: w.logicalDocumentV1(), Cutoff: cutoff}
	h, err := w.queries.GetParticipantReportHeaderV1(call, p)
	if err != nil {
		return err
	}
	if h == nil {
		return fmt.Errorf("%w: header unavailable", render.ErrParticipantReportV1)
	}
	if h.RowCount < 0 {
		return fmt.Errorf("%w: header row count %d", render.ErrParticipantReportV1, h.RowCount)
	}
	if h.RowCount > render.MaxParticipantReportRowsV1 {
		return ErrParticipantReportCapacityV1
	}
	if h.RawBytes < 0 {
		return fmt.Errorf("%w: header raw bytes %d", render.ErrParticipantReportV1, h.RawBytes)
	}
	if h.RawBytes > render.MaxParticipantReportRawBytesV1 {
		return ErrParticipantReportCapacityV1
	}
	if h.BindingCount < 0 || h.BindingCount > 1 {
		return fmt.Errorf("%w: header package binding count %d", render.ErrParticipantReportV1, h.BindingCount)
	}
	if h.FutureMutationCount != 0 {
		return fmt.Errorf("%w: header post-cutoff proposal mutations %d", render.ErrParticipantReportV1, h.FutureMutationCount)
	}
	if h.UnmeasuredEventCount != 0 {
		return fmt.Errorf("%w: header unmeasured events %d", render.ErrParticipantReportV1, h.UnmeasuredEventCount)
	}
	if h.ScopeCount < 1 || h.ScopeCount > render.MaxParticipantReportRowsV1 || !participantReportSchemaKnownV1(h.ReportSchema) {
		return fmt.Errorf("%w: report scope or schema", render.ErrParticipantReportV1)
	}
	schema := h.ReportSchema
	if reserveClock {
		// Fresh finalization always selects V2 in its genuine DB transition.
		// This value is formatter sizing only and never persists evidence.
		schema = render.ParticipantReportSchemaV2
		var delegated bool
		if err := (&applicationOwnedDBTXV1{session: w.session.state}).QueryRow(call, `SELECT EXISTS(SELECT 1 FROM presign_executions WHERE org_id=$1 AND document_id=$2)`, p.OrgID, p.DocumentID).Scan(&delegated); err != nil {
			return err
		}
		if delegated {
			schema = render.ParticipantReportSchemaV3
		}
	}
	// V2's fixed labels/framing are funded before loading any rows. Reserve at
	// least half of each existing fixed quote for native scalar/canonical work;
	// the formatter's independent bounds cover the other half. Measured source
	// bytes separately cover variable values, escaping and retained copies.
	const framingBytes, rowBytes int64 = 65536, 8192
	if render.ParticipantReportHTMLV2FixedMarkupBytes > framingBytes/2 || render.ParticipantReportHTMLV2RecordMarkupBytes > rowBytes/2 {
		return ErrHTMLSendWorkV1
	}
	raw := framingBytes + 8*int64(unsafe.Sizeof(render.ParticipantReportV1{}))
	if !htmlInputAddV1(&raw, h.RawBytes, 96) || !htmlInputAddV1(&raw, h.RowCount, rowBytes) || !htmlInputAddV1(&raw, h.ScopeCount, 512) {
		return ErrHTMLSendWorkV1
	}
	wire := h.RawBytes
	if !htmlInputAddV1(&wire, h.ScopeCount, 64) {
		return ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeBody)
	fresh, err := w.queries.GetParticipantReportHeaderV1(call, p)
	if err != nil {
		return err
	}
	if fresh == nil || *fresh != *h {
		return fmt.Errorf("%w: header changed before projection", render.ErrParticipantReportV1)
	}
	scopeParams := generated.ListParticipantReportHistoryScopeV2Params{OrgID: p.OrgID, DocumentID: p.DocumentID}
	documents, err := w.queries.ListParticipantReportHistoryScopeV2(call, scopeParams)
	if err != nil {
		return err
	}
	if int64(len(documents)) != h.ScopeCount || !slices.Contains(documents, p.DocumentID) {
		return render.ErrParticipantReportV1
	}
	events, err := w.queries.ListParticipantReportEventRowsV1(call, generated.ListParticipantReportEventRowsV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID, Cutoff: p.Cutoff})
	if err != nil {
		return err
	}
	comments, err := w.queries.ListParticipantReportCommentsV1(call, generated.ListParticipantReportCommentsV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID, Cutoff: p.Cutoff})
	if err != nil {
		return err
	}
	versions, err := w.queries.ListParticipantReportRevisionsV1(call, generated.ListParticipantReportRevisionsV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID, Cutoff: p.Cutoff})
	if err != nil {
		return err
	}
	proposals, err := w.queries.ListParticipantReportProposalsV1(call, generated.ListParticipantReportProposalsV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID, Cutoff: p.Cutoff})
	if err != nil {
		return err
	}
	members, err := w.queries.ListParticipantReportMembersV1(call, generated.ListParticipantReportMembersV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID})
	if err != nil {
		return err
	}
	responses, err := w.queries.ListParticipantReportResponsesV1(call, generated.ListParticipantReportResponsesV1Params{OrgID: p.OrgID, DocumentID: p.DocumentID})
	if err != nil {
		return err
	}
	if int64(len(events)+len(comments)+len(versions)+len(proposals)+len(members)+len(responses)) != h.RowCount || len(members) > 17 || (h.BindingCount == 0 && (len(members) != 0 || len(responses) != 0)) || (h.BindingCount == 1 && (len(members) == 0 || len(responses) == 0)) {
		return fmt.Errorf("%w: projected row or package cardinality", render.ErrParticipantReportV1)
	}
	r := render.ParticipantReportV1{Schema: render.ParticipantReportSchemaV1, DocumentID: p.DocumentID.String(), Cutoff: p.Cutoff.Time.UTC().Format(time.RFC3339Nano)}
	if reserveClock {
		r.Cutoff = responseCertificateSizingTimestampV1
	}
	r.Events, err = render.ParticipantReportEventsV1(events, p.Cutoff.Time)
	if err != nil {
		return fmt.Errorf("participant report event projection: %w", err)
	}
	for _, c := range comments {
		v, err := render.ParticipantReportCommentV1FromRow(c, events)
		if err != nil {
			return fmt.Errorf("participant report shared comment association: %w", err)
		}
		r.Comments = append(r.Comments, v)
	}
	// A new body/actor evidence row must resolve to exactly one retained shared
	// comment. Missing or mutated comment history is refused, never relabeled
	// as an unverified legacy body.
	for _, event := range events {
		if event == nil || event.Kind != "document.comment_posted" {
			continue
		}
		var evidence struct {
			Schema string `json:"comment_evidence_schema"`
		}
		if json.Unmarshal(event.PayloadHashed, &evidence) != nil {
			return fmt.Errorf("%w: shared comment event payload", render.ErrParticipantReportV1)
		}
		if evidence.Schema == "" {
			continue
		}
		if evidence.Schema != CommentAuditEvidenceSchemaV1 {
			return fmt.Errorf("%w: shared comment evidence schema", render.ErrParticipantReportV1)
		}
		found := 0
		for _, comment := range r.Comments {
			if comment.EventID == event.ID.String() {
				found++
			}
		}
		if found != 1 {
			return fmt.Errorf("%w: shared comment event coverage", render.ErrParticipantReportV1)
		}
	}
	for _, v := range versions {
		if v == nil || !applicationStampV1(v.CreatedAt) {
			return render.ErrParticipantReportV1
		}
		r.Revisions = append(r.Revisions, render.ParticipantReportRevisionV1{ID: v.ID.String(), DocumentID: v.DocumentID.String(), Number: v.VersionNo, Name: v.Name, SourceKind: v.SourceKind, At: v.CreatedAt.Time.UTC().Format(time.RFC3339Nano)})
	}
	for _, v := range proposals {
		if v == nil || !applicationStampV1(v.CreatedAt) || !applicationStampV1(v.UpdatedAt) {
			return render.ErrParticipantReportV1
		}
		r.Proposals = append(r.Proposals, render.ParticipantReportProposalV1{ID: v.ID.String(), DocumentID: v.DocumentID.String(), Kind: v.ProposalKind, BlockID: v.BlockID, Text: v.ProposedText, Rationale: v.Rationale, Status: v.Status, At: v.CreatedAt.Time.UTC().Format(time.RFC3339Nano), UpdatedAt: v.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)})
	}
	for i, v := range members {
		if v == nil || int(v.MemberPosition) != i || len(v.PdfSha256) != 32 || strings.TrimSpace(v.PdfVersionID) == "" || v.PdfBytes <= 0 || v.PdfPages <= 0 {
			return render.ErrParticipantReportV1
		}
		r.Members = append(r.Members, render.ParticipantReportMemberV1{Position: int32(v.MemberPosition), DocumentID: v.MemberDocumentID.String(), Title: v.Title, Category: v.Category, PDFSHA256: hex.EncodeToString(v.PdfSha256), PDFVersionID: v.PdfVersionID, PDFBytes: v.PdfBytes, PDFPages: v.PdfPages})
	}
	for _, v := range responses {
		if v == nil || !applicationStampV1(v.ResponseEventCreatedAt) || len(v.ManifestSha256) != 32 || len(v.LegalCommitmentSha256) != 32 || len(v.ResponseEventRowSha256) != 32 || len(v.IncorporationSha256) != 32 {
			return render.ErrParticipantReportV1
		}
		signature := ""
		if v.SignatureID.Valid {
			signature = uuid.UUID(v.SignatureID.Bytes).String()
		}
		r.Responses = append(r.Responses, render.ParticipantReportResponseV1{RecipientID: v.RecipientID.String(), AttemptID: v.AttemptID.String(), ManifestSHA256: hex.EncodeToString(v.ManifestSha256), LegalCommitmentSHA256: hex.EncodeToString(v.LegalCommitmentSha256), Kind: v.ResponseKind, SignatureID: signature, EventID: v.ResponseEventID.String(), EventRowSHA256: hex.EncodeToString(v.ResponseEventRowSha256), At: v.ResponseEventCreatedAt.Time.UTC().Format(time.RFC3339Nano), IncorporationVersion: v.IncorporationVersion, IncorporationSHA256: hex.EncodeToString(v.IncorporationSha256)})
	}
	actualRaw := int64(0)
	for _, event := range events {
		n, e := historicalCertificateEventRawV1(event)
		if e != nil || !htmlInputAddV1(&actualRaw, n, 1) || !htmlInputAddV1(&actualRaw, int64(len(event.PayloadJson)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, v := range comments {
		if !htmlInputAddV1(&actualRaw, int64(len(v.AuthorName)+len(v.AuthorSide)+len(v.Body)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, v := range versions {
		if !htmlInputAddV1(&actualRaw, int64(len(v.Name)+len(v.SourceKind)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, v := range proposals {
		if !htmlInputAddV1(&actualRaw, int64(len(v.ProposalKind)+len(v.BlockID)+len(v.ProposedText)+len(v.Rationale)+len(v.Status)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, v := range members {
		if !htmlInputAddV1(&actualRaw, int64(len(v.Title)+len(v.Category)+len(v.PdfVersionID)+len(v.PdfSha256)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, v := range responses {
		if !htmlInputAddV1(&actualRaw, int64(len(v.ManifestSha256)+len(v.LegalCommitmentSha256)+len(v.ResponseKind)+len(v.ResponseEventRowSha256)+len(v.IncorporationVersion)+len(v.IncorporationSha256)), 1) {
			return ErrHTMLSendWorkV1
		}
	}
	if actualRaw != h.RawBytes {
		return fmt.Errorf("%w: projected raw byte measurement differs", render.ErrParticipantReportV1)
	}
	fresh, err = w.queries.GetParticipantReportHeaderV1(call, p)
	if err != nil {
		return err
	}
	if fresh == nil || *fresh != *h {
		return fmt.Errorf("%w: header changed after projection", render.ErrParticipantReportV1)
	}
	documentsAfter, err := w.queries.ListParticipantReportHistoryScopeV2(call, scopeParams)
	if err != nil {
		return err
	}
	if !slices.Equal(documents, documentsAfter) {
		return render.ErrParticipantReportV1
	}
	state.reportSchema = schema
	if schema == render.ParticipantReportSchemaV2 || schema == render.ParticipantReportSchemaV3 {
		// Reconstruct from the complete original hashed rows, never caller facts.
		// Actual cutoff selects history; the reserved sizing timestamp is display only.
		actualCutoff := r.Cutoff
		r.Cutoff = p.Cutoff.Time.UTC().Format(time.RFC3339Nano)
		scope := render.ParticipantNarrativeScopeDraft402{Org: p.OrgID, Root: p.DocumentID, Documents: documents}
		var v2 render.ParticipantReportV2
		var e error
		if schema == render.ParticipantReportSchemaV3 {
			delegated, captureErr := w.participantDelegationLockedV3(call, events, document)
			if captureErr != nil {
				return captureErr
			}
			v2, e = render.NewParticipantReportV3(scope, events, r, delegated)
		} else {
			v2, e = render.NewParticipantReportV2(scope, events, r)
		}
		r.Cutoff = actualCutoff
		if e != nil {
			if errors.Is(e, render.ErrCertificatePayloadCapacityV1) {
				return ErrParticipantReportCapacityV1
			}
			return fmt.Errorf("participant report original narrative: %w", e)
		}
		if reserveClock {
			v2.Cutoff = responseCertificateSizingTimestampV1
		}
		state.reportHTML, state.reportSHA256, err = v2.HTMLV3()
		if err != nil {
			if errors.Is(err, render.ErrCertificatePayloadCapacityV1) {
				return ErrParticipantReportCapacityV1
			}
			return fmt.Errorf("participant report V2 canonical projection: %w", err)
		}
		state.reportRows = v2.SourceRowsV2()
		state.reportCutoff = p.Cutoff
		state.reportEvents = events
		return nil
	}
	// CanonicalV1 intentionally preserves its historical error contract. Here
	// the measured native producer distinguishes actual canonical length from
	// malformed history before invoking the same current HTML formatter.
	canonical, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if int64(len(canonical)) > render.MaxParticipantReportRawBytesV1 {
		return ErrParticipantReportCapacityV1
	}
	state.reportHTML, state.reportSHA256, err = r.HTMLV2()
	if err != nil {
		return fmt.Errorf("participant report canonical projection: %w", err)
	}
	state.reportCutoff = p.Cutoff
	state.reportRows = int64(len(r.Events) + len(r.Comments) + len(r.Revisions) + len(r.Proposals) + len(r.Members) + len(r.Responses))
	state.reportEvents = events
	return nil
}

// No external row/JSON/digest can create this fact. It is copied only from the
// funded snapshot that produced the exact signed certificate payload.
type participantReportCommitmentV1 struct {
	schema string
	cutoff pgtype.Timestamptz
	rows   int64
	sha    [32]byte
}

func participantReportCommitmentFromV1(schema string, cutoff pgtype.Timestamptz, rows int64, digest string) (participantReportCommitmentV1, error) {
	var c participantReportCommitmentV1
	b, err := hex.DecodeString(digest)
	if err != nil || !participantReportSchemaKnownV1(schema) || len(b) != 32 || !applicationStampV1(cutoff) || rows < 0 || rows > render.MaxParticipantReportRowsV1 {
		return c, errors.New("participant report commitment unavailable")
	}
	c.schema = schema
	copy(c.sha[:], b)
	c.cutoff = cutoff
	c.cutoff.Time = c.cutoff.Time.UTC()
	c.rows = rows
	return c, nil
}

// Closed private dispatch; unknown native variants fail before formatting/storage.
func participantReportSchemaKnownV1(schema string) bool {
	return schema == render.ParticipantReportSchemaV1 || schema == render.ParticipantReportSchemaV2 || schema == render.ParticipantReportSchemaV3
}
