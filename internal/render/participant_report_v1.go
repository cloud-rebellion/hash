// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

const ParticipantReportSchemaV1 = "hash-participant-report-v1"
const MaxParticipantReportRowsV1 = 10000
const MaxParticipantReportRawBytesV1 int64 = 8 << 20

// This is a presentation of the complete bounded participant history at one
// frozen cutoff, not a reconstruction of the interleaved organization ledger.
// The native certificate owner supplies and funds these rows before allocation.
type ParticipantReportV1 struct {
	Schema     string                        `json:"schema"`
	DocumentID string                        `json:"document_id"`
	Cutoff     string                        `json:"cutoff"`
	Events     []ParticipantReportEventV1    `json:"events"`
	Comments   []ParticipantReportCommentV1  `json:"comments"`
	Revisions  []ParticipantReportRevisionV1 `json:"revisions"`
	Proposals  []ParticipantReportProposalV1 `json:"proposals"`
	Members    []ParticipantReportMemberV1   `json:"members"`
	Responses  []ParticipantReportResponseV1 `json:"responses"`
}
type ParticipantReportEventV1 struct{ ID, DocumentID, Kind, At, ActorID, RecipientID, RowSHA256 string }
type ParticipantReportCommentV1 struct{ ID, DocumentID, AuthorName, Side, ActorID, At, Body, Evidence, EventID, EventRowSHA256 string }
type ParticipantReportRevisionV1 struct {
	ID, DocumentID, Name, SourceKind, At string
	Number                               int32
}
type ParticipantReportProposalV1 struct{ ID, DocumentID, Kind, BlockID, Text, Rationale, Status, At, UpdatedAt string }
type ParticipantReportMemberV1 struct {
	Position                                             int32
	DocumentID, Title, Category, PDFSHA256, PDFVersionID string
	PDFBytes                                             int64
	PDFPages                                             int32
}
type ParticipantReportResponseV1 struct{ RecipientID, AttemptID, ManifestSHA256, LegalCommitmentSHA256, Kind, SignatureID, EventID, EventRowSHA256, At, IncorporationVersion, IncorporationSHA256 string }

var ErrParticipantReportV1 = errors.New("audit certificate: participant history is unsupported or inconsistent")

func ParticipantReportVisibleEventV1(kind string) bool {
	switch kind {
	case audit.KindDocumentCreated, audit.KindDocumentUpdated, audit.KindDocumentSent, audit.KindDocumentViewed, audit.KindDocumentFieldFill, audit.KindDocumentSigned, audit.KindDocumentAccepted, audit.KindDocumentDeclined, audit.KindChangesRequested, audit.KindDocumentRevised, audit.KindCommentPosted, audit.KindDocumentVoided, audit.KindDocumentExpired, audit.KindRecipientCreated, audit.KindRecipientInvited, audit.KindRecipientUpdated, audit.KindRecipientDeleted, audit.KindReminderSent:
		return true
	}
	return false
}

// The original forensic row is checked BEFORE choosing public fields. We do
// not redact/re-hash rows and never claim this document subset proves chain
// continuity. Unknown/private event kinds disclose no payload or narrative.
func ParticipantReportEventsV1(events []*generated.Event, cutoff time.Time) ([]ParticipantReportEventV1, error) {
	ordered := append([]*generated.Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i] == nil || ordered[j] == nil {
			return ordered[i] != nil
		}
		if !ordered[i].CreatedAt.Time.Equal(ordered[j].CreatedAt.Time) {
			return ordered[i].CreatedAt.Time.Before(ordered[j].CreatedAt.Time)
		}
		return bytes.Compare(ordered[i].ID[:], ordered[j].ID[:]) < 0
	})
	result := make([]ParticipantReportEventV1, 0, len(events))
	seen := make(map[uuid.UUID]struct{}, len(events))
	for _, event := range ordered {
		if event == nil || event.ID == uuid.Nil || !event.DocumentID.Valid || !event.CreatedAt.Valid || event.CreatedAt.Time.IsZero() || event.CreatedAt.Time.After(cutoff) || len(event.RowHash) != 32 {
			return nil, fmt.Errorf("%w: event row metadata or cutoff", ErrParticipantReportV1)
		}
		if _, ok := seen[event.ID]; ok {
			return nil, fmt.Errorf("%w: duplicate event row", ErrParticipantReportV1)
		}
		seen[event.ID] = struct{}{}
		sum, err := audit.RecomputeEventRowHash(event)
		if err != nil || subtle.ConstantTimeCompare(sum, event.RowHash) != 1 {
			return nil, fmt.Errorf("%w: original event row commitment", ErrParticipantReportV1)
		}
		if !ParticipantReportVisibleEventV1(event.Kind) {
			continue
		}
		actor := ""
		if event.ActorUserID.Valid {
			actor = uuid.UUID(event.ActorUserID.Bytes).String()
		}
		// These are separate original ledger fields, not competing actor
		// assertions. Staff recipient lifecycle operations legitimately record
		// both the staff actor and the recipient subject; recipient responses
		// carry the participant in RecipientID without a staff ActorUserID.
		recipient := ""
		if event.RecipientID.Valid {
			recipient = uuid.UUID(event.RecipientID.Bytes).String()
		}
		result = append(result, ParticipantReportEventV1{ID: event.ID.String(), DocumentID: uuid.UUID(event.DocumentID.Bytes).String(), Kind: event.Kind, At: event.CreatedAt.Time.UTC().Format(time.RFC3339Nano), ActorID: actor, RecipientID: recipient, RowSHA256: hex.EncodeToString(event.RowHash)})
	}
	return result, nil
}

// A legacy side-only row is shown explicitly as unverified historical text.
// New evidence requires the exact body, actor, side, document and timestamp
// association in the ORIGINAL hashed event preimage. Display JSON is irrelevant.
func ParticipantReportCommentV1FromRow(row *generated.DocumentComment, events []*generated.Event) (ParticipantReportCommentV1, error) {
	if row == nil || row.ID == uuid.Nil || row.DocumentID == uuid.Nil || !row.CreatedAt.Valid || row.CreatedAt.Time.IsZero() {
		return ParticipantReportCommentV1{}, ErrParticipantReportV1
	}
	actor := ""
	switch row.AuthorSide {
	case "sender":
		if !row.UserID.Valid || row.RecipientID.Valid {
			return ParticipantReportCommentV1{}, ErrParticipantReportV1
		}
		actor = uuid.UUID(row.UserID.Bytes).String()
	case "signer":
		if !row.RecipientID.Valid || row.UserID.Valid {
			return ParticipantReportCommentV1{}, ErrParticipantReportV1
		}
		actor = uuid.UUID(row.RecipientID.Bytes).String()
	default:
		return ParticipantReportCommentV1{}, ErrParticipantReportV1
	}
	result := ParticipantReportCommentV1{ID: row.ID.String(), DocumentID: row.DocumentID.String(), AuthorName: row.AuthorName, Side: row.AuthorSide, ActorID: actor, At: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano), Body: row.Body, Evidence: "legacy-text-not-verified"}
	for _, event := range events {
		if event == nil || event.Kind != audit.KindCommentPosted {
			continue
		}
		var payload struct {
			Schema  string `json:"comment_evidence_schema"`
			ID      string `json:"comment_id"`
			BodySHA string `json:"comment_body_sha256"`
			At      string `json:"comment_created_at"`
			Side    string `json:"side"`
		}
		if json.Unmarshal(event.PayloadHashed, &payload) != nil {
			return ParticipantReportCommentV1{}, ErrParticipantReportV1
		}
		if payload.ID != row.ID.String() {
			continue
		}
		sum := sha256.Sum256([]byte(row.Body))
		recomputed, err := audit.RecomputeEventRowHash(event)
		if result.EventID != "" || payload.Schema != "hash-comment-evidence-v1" || payload.BodySHA != hex.EncodeToString(sum[:]) || payload.At != result.At || payload.Side != row.AuthorSide || !event.DocumentID.Valid || uuid.UUID(event.DocumentID.Bytes) != row.DocumentID || event.ActorUserID != row.UserID || event.RecipientID != row.RecipientID || err != nil || len(event.RowHash) != 32 || subtle.ConstantTimeCompare(recomputed, event.RowHash) != 1 {
			return ParticipantReportCommentV1{}, ErrParticipantReportV1
		}
		result.Evidence = "body-and-actor-associated"
		result.EventID = event.ID.String()
		result.EventRowSHA256 = hex.EncodeToString(event.RowHash)
	}
	return result, nil
}

func (r ParticipantReportV1) CanonicalV1() ([]byte, [32]byte, error) {
	var empty [32]byte
	if r.Schema != ParticipantReportSchemaV1 || r.DocumentID == "" || r.Cutoff == "" || len(r.Events)+len(r.Comments)+len(r.Revisions)+len(r.Proposals)+len(r.Responses)+len(r.Members) > MaxParticipantReportRowsV1 || len(r.Members) > 17 {
		return nil, empty, ErrParticipantReportV1
	}
	cutoff, err := time.Parse(time.RFC3339Nano, r.Cutoff)
	if err != nil || cutoff.IsZero() || r.Cutoff != cutoff.UTC().Format(time.RFC3339Nano) {
		return nil, empty, ErrParticipantReportV1
	}
	raw, err := json.Marshal(r)
	if err != nil || int64(len(raw)) > MaxParticipantReportRawBytesV1 {
		return nil, empty, ErrParticipantReportV1
	}
	return raw, sha256.Sum256(raw), nil
}

func (r ParticipantReportV1) HTMLV1() (string, string, error) {
	raw, sum, err := r.CanonicalV1()
	if err != nil {
		return "", "", err
	}
	_ = raw
	var b strings.Builder
	fmt.Fprintf(&b, `<section class="hash-participant-report"><h3>Participant negotiation and signature report</h3><p>Complete retained participant history through %s. Later completion publication is outside this cutoff. Private event kinds and internal notes are excluded; this is not proof of organization-chain continuity. Historical text marked unverified has no retrospective body or actor attestation. Revision metadata and proposal states are retained database observations; no content attestation is inferred.</p>`, certificateEscapeV1(r.Cutoff))
	section := func(title string) { fmt.Fprintf(&b, "<h4>%s</h4><table><tbody>", title) }
	row := func(values ...string) {
		b.WriteString("<tr>")
		for _, v := range values {
			fmt.Fprintf(&b, "<td style=\"white-space:pre-wrap;overflow-wrap:anywhere\">%s</td>", certificateEscapeV1(v))
		}
		b.WriteString("</tr>")
	}
	end := func() { b.WriteString("</tbody></table>") }
	section("Events (original row commitments)")
	for _, e := range r.Events {
		row(e.At, e.DocumentID, e.Kind, e.ActorID, e.RecipientID, e.ID, e.RowSHA256)
	}
	end()
	section("Shared negotiation comments")
	for _, c := range r.Comments {
		row(c.At, c.DocumentID, c.AuthorName, c.Side, c.ActorID, c.Body, c.Evidence, c.EventID, c.EventRowSHA256)
	}
	end()
	section("Retained revision metadata")
	for _, v := range r.Revisions {
		row(v.At, v.DocumentID, fmt.Sprint(v.Number), v.Name, v.SourceKind, v.ID)
	}
	end()
	section("Shared negotiation proposals (retained state at cutoff)")
	for _, p := range r.Proposals {
		row(p.At, p.UpdatedAt, p.DocumentID, p.Kind, p.BlockID, p.Text, p.Rationale, p.Status, p.ID)
	}
	end()
	section("Frozen legal package originals")
	for _, m := range r.Members {
		row(fmt.Sprint(m.Position), m.DocumentID, m.Title, m.Category, m.PDFSHA256, m.PDFVersionID, fmt.Sprint(m.PDFBytes), fmt.Sprint(m.PDFPages))
	}
	end()
	section("Whole-package consent and response receipts")
	for _, p := range r.Responses {
		row(p.RecipientID, p.AttemptID, p.ManifestSHA256, p.LegalCommitmentSHA256, p.Kind, p.SignatureID, p.EventID, p.EventRowSHA256, p.At, p.IncorporationVersion, p.IncorporationSHA256)
	}
	end()
	// The exact canonical projection is embedded, escaped, inside the detached
	// signed payload, so independent verifiers need not infer table semantics.
	fmt.Fprintf(&b, `<pre class="hash-participant-report-canonical" style="white-space:pre-wrap;font-size:7px">%s</pre></section>`, certificateEscapeV1(string(raw)))
	return b.String(), hex.EncodeToString(sum[:]), nil
}
