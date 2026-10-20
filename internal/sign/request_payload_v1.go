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
	"io"
	"math"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	requestOriginSchemaV1  = "hash-presented-request-origin-v1"
	requestOriginIssuerV1  = "hash-presented-magic-link-v1"
	acceptedIntentSchemaV1 = "hash-accepted-fitted-intent-v1"
	// These ceilings are derived below from the complete supported wire schema,
	// not operational shortcuts. The admission uses each body's EXACT byte size.
	requestOriginMaxBytesV1       = pdfadmission.MaxApplicationRequestOriginBytesV1
	acceptedIntentMaxBytesV1      = pdfadmission.MaxApplicationAcceptedIntentBytesV1
	requestDocumentNameMaxBytesV1 = 65536 // M86/M88 octet_length contract.
	requestPayloadChunkV1         = 4096
)

// Private persistence types carry no bearer token and grant no authority. Raw
// controller/org/basis strings are committed byte-for-byte (including whitespace)
// because their database TEXT columns have no finite compatible plaintext cap.
// Complete disclosed Article13 material remains in the accepted intent body.
type requestStringCommitmentV1 struct {
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type requestTimeV1 struct {
	Valid bool   `json:"valid"`
	Value string `json:"value"`
}
type requestUUIDV1 struct {
	Valid bool   `json:"valid"`
	Value string `json:"value"`
}
type requestOriginWireV1 struct {
	Schema            string                    `json:"schema"`
	Issuer            string                    `json:"issuer"`
	OrgID             string                    `json:"org_id"`
	DocumentID        string                    `json:"document_id"`
	RecipientID       string                    `json:"recipient_id"`
	TokenSHA256       string                    `json:"token_sha256"`
	RecipientExpiry   requestTimeV1             `json:"recipient_expiry"`
	DocumentExpiry    requestTimeV1             `json:"document_expiry"`
	SentAt            requestTimeV1             `json:"sent_at"`
	NoticeEpoch       requestTimeV1             `json:"notice_epoch"`
	NoticeSchema      string                    `json:"notice_schema"`
	NoticeCommitted   bool                      `json:"notice_committed"`
	DocumentName      string                    `json:"document_name"`
	LawfulBasis       requestStringCommitmentV1 `json:"lawful_basis"`
	Role              string                    `json:"role"`
	RecipientStatus   string                    `json:"recipient_status"`
	DocumentStatus    string                    `json:"document_status"`
	SigningPolicy     string                    `json:"signing_policy"`
	SourceKind        string                    `json:"source_kind"`
	RoutingTier       string                    `json:"routing_tier"`
	RequiresSignature bool                      `json:"requires_signature"`
	IsEnvelope        bool                      `json:"is_envelope"`
	ParentEnvelopeID  requestUUIDV1             `json:"parent_envelope_id"`
	DocumentDeletedAt requestTimeV1             `json:"document_deleted_at"`
	ConfirmationBy    requestUUIDV1             `json:"confirmation_by"`
	ConfirmationAt    requestTimeV1             `json:"confirmation_at"`
	ConfirmationVia   string                    `json:"confirmation_via"`
	ControllerName    requestStringCommitmentV1 `json:"controller_name"`
	ControllerContact requestStringCommitmentV1 `json:"controller_contact"`
	ConfirmationBasis requestStringCommitmentV1 `json:"confirmation_basis"`
	ControllerOrgName requestStringCommitmentV1 `json:"controller_org_name"`
}

// These private V1 structs pin the notice field set and order independently
// of future additions to the public Article13 structs.
type requestNoticeCopyV1 struct {
	Title                  string `json:"title"`
	Intro                  string `json:"intro"`
	ControllerLabel        string `json:"controller_label"`
	ControllerContactLabel string `json:"controller_contact_label"`
	ProcessorLabel         string `json:"processor_label"`
	PurposeLabel           string `json:"purpose_label"`
	LegalBasisLabel        string `json:"legal_basis_label"`
	RetentionLabel         string `json:"retention_label"`
	RetentionValue         string `json:"retention_value"`
	AuthorityLabel         string `json:"authority_label"`
	RightsSummary          string `json:"rights_summary"`
	RightsBody             string `json:"rights_body"`
	SubmitRequestLabel     string `json:"submit_request_label"`
	KindLabel              string `json:"kind_label"`
	DSRAccessLabel         string `json:"dsr_access_label"`
	DSRRectificationLabel  string `json:"dsr_rectification_label"`
	DSRErasureLabel        string `json:"dsr_erasure_label"`
	DSRRestrictionLabel    string `json:"dsr_restriction_label"`
	DSRPortabilityLabel    string `json:"dsr_portability_label"`
	DSRObjectionLabel      string `json:"dsr_objection_label"`
	NoteLabel              string `json:"note_label"`
	NotePlaceholder        string `json:"note_placeholder"`
	SendRequestLabel       string `json:"send_request_label"`
	RequestReceived        string `json:"request_received"`
	ReadPolicyLabel        string `json:"read_policy_label"`
	AcknowledgementLabel   string `json:"acknowledgement_label"`
	FinePrint              string `json:"fine_print"`
}
type requestNoticeSnapshotV1 struct {
	Schema               string                  `json:"schema"`
	DocumentID           uuid.UUID               `json:"document_id"`
	OrgID                uuid.UUID               `json:"org_id"`
	RecipientID          uuid.UUID               `json:"recipient_id"`
	SentAt               string                  `json:"sent_at"`
	Controller           string                  `json:"controller"`
	ControllerContact    string                  `json:"controller_contact"`
	Processor            string                  `json:"processor"`
	ProcessorContact     string                  `json:"processor_contact"`
	PurposeSummary       string                  `json:"purpose_summary"`
	LegalBasisDisclosure string                  `json:"legal_basis_disclosure"`
	RetentionYears       int                     `json:"retention_years"`
	SupervisoryAuthority string                  `json:"supervisory_authority"`
	PolicyURL            string                  `json:"policy_url"`
	DSRCapability        article13.DSRCapability `json:"dsr_capability"`
	Copy                 requestNoticeCopyV1     `json:"copy"`
}
type requestNoticeWireV1 struct {
	Schema   string                  `json:"schema"`
	Digest   string                  `json:"digest"`
	Snapshot requestNoticeSnapshotV1 `json:"snapshot"`
}

func requestNoticeFromArticle13V1(e article13.Evidence) requestNoticeWireV1 {
	s := e.Snapshot
	c := s.Copy
	return requestNoticeWireV1{Schema: e.Schema, Digest: e.Digest, Snapshot: requestNoticeSnapshotV1{Schema: s.Schema, DocumentID: s.DocumentID, OrgID: s.OrgID, RecipientID: s.RecipientID, SentAt: s.SentAt, Controller: s.Controller, ControllerContact: s.ControllerContact, Processor: s.Processor, ProcessorContact: s.ProcessorContact, PurposeSummary: s.PurposeSummary, LegalBasisDisclosure: s.LegalBasisDisclosure, RetentionYears: s.RetentionYears, SupervisoryAuthority: s.SupervisoryAuthority, PolicyURL: s.PolicyURL, DSRCapability: s.DSRCapability, Copy: requestNoticeCopyV1{Title: c.Title, Intro: c.Intro, ControllerLabel: c.ControllerLabel, ControllerContactLabel: c.ControllerContactLabel, ProcessorLabel: c.ProcessorLabel, PurposeLabel: c.PurposeLabel, LegalBasisLabel: c.LegalBasisLabel, RetentionLabel: c.RetentionLabel, RetentionValue: c.RetentionValue, AuthorityLabel: c.AuthorityLabel, RightsSummary: c.RightsSummary, RightsBody: c.RightsBody, SubmitRequestLabel: c.SubmitRequestLabel, KindLabel: c.KindLabel, DSRAccessLabel: c.DSRAccessLabel, DSRRectificationLabel: c.DSRRectificationLabel, DSRErasureLabel: c.DSRErasureLabel, DSRRestrictionLabel: c.DSRRestrictionLabel, DSRPortabilityLabel: c.DSRPortabilityLabel, DSRObjectionLabel: c.DSRObjectionLabel, NoteLabel: c.NoteLabel, NotePlaceholder: c.NotePlaceholder, SendRequestLabel: c.SendRequestLabel, RequestReceived: c.RequestReceived, ReadPolicyLabel: c.ReadPolicyLabel, AcknowledgementLabel: c.AcknowledgementLabel, FinePrint: c.FinePrint}}}
}
func (w requestNoticeWireV1) evidenceV1() article13.Evidence {
	s := w.Snapshot
	c := s.Copy
	return article13.Evidence{Schema: w.Schema, Digest: w.Digest, Snapshot: article13.Snapshot{Schema: s.Schema, DocumentID: s.DocumentID, OrgID: s.OrgID, RecipientID: s.RecipientID, SentAt: s.SentAt, Controller: s.Controller, ControllerContact: s.ControllerContact, Processor: s.Processor, ProcessorContact: s.ProcessorContact, PurposeSummary: s.PurposeSummary, LegalBasisDisclosure: s.LegalBasisDisclosure, RetentionYears: s.RetentionYears, SupervisoryAuthority: s.SupervisoryAuthority, PolicyURL: s.PolicyURL, DSRCapability: s.DSRCapability, Copy: article13.Copy{Title: c.Title, Intro: c.Intro, ControllerLabel: c.ControllerLabel, ControllerContactLabel: c.ControllerContactLabel, ProcessorLabel: c.ProcessorLabel, PurposeLabel: c.PurposeLabel, LegalBasisLabel: c.LegalBasisLabel, RetentionLabel: c.RetentionLabel, RetentionValue: c.RetentionValue, AuthorityLabel: c.AuthorityLabel, RightsSummary: c.RightsSummary, RightsBody: c.RightsBody, SubmitRequestLabel: c.SubmitRequestLabel, KindLabel: c.KindLabel, DSRAccessLabel: c.DSRAccessLabel, DSRRectificationLabel: c.DSRRectificationLabel, DSRErasureLabel: c.DSRErasureLabel, DSRRestrictionLabel: c.DSRRestrictionLabel, DSRPortabilityLabel: c.DSRPortabilityLabel, DSRObjectionLabel: c.DSRObjectionLabel, NoteLabel: c.NoteLabel, NotePlaceholder: c.NotePlaceholder, SendRequestLabel: c.SendRequestLabel, RequestReceived: c.RequestReceived, ReadPolicyLabel: c.ReadPolicyLabel, AcknowledgementLabel: c.AcknowledgementLabel, FinePrint: c.FinePrint}}}
}

type acceptedIntentWireV1 struct {
	Schema        string              `json:"schema"`
	OrgID         string              `json:"org_id"`
	DocumentID    string              `json:"document_id"`
	RecipientID   string              `json:"recipient_id"`
	CeremonyEpoch string              `json:"ceremony_epoch"`
	TypedName     string              `json:"typed_name"`
	Font          string              `json:"font"`
	Notice        requestNoticeWireV1 `json:"notice"`
}

// The future owned sidecar session must acquire an actual shared metadata/body/
// work lease BEFORE this codec hashes raw context, copies or serializes bodies.
// This interface supplies resource admission only: authentication always comes
// from this Engine's private LookupByToken receipt and private accepted intent.
// There is intentionally no allow-all default, public constructor or READY bit.
type requestPayloadBudgetV1 struct {
	OrgID, DocumentID, RecipientID                          uuid.UUID
	OriginBytes, IntentBytes, RawContextBytes, WorkingBytes int64
}
type requestPayloadAdmissionV1 interface {
	AcquireRequestPayloadV1(context.Context, requestPayloadBudgetV1) (func(), error)
}
type requestPayloadHeaderV1 struct {
	OrgID, DocumentID, RecipientID                   uuid.UUID
	CeremonyEpoch                                    string
	OriginBytes, IntentBytes                         int64
	OriginSHA256, IntentSHA256, SemanticIntentSHA256 [sha256.Size]byte
}
type durableRequestPayloadV1 struct {
	header         requestPayloadHeaderV1
	origin, intent []byte
	releaseOnce    sync.Once
	release        func()
}

// Release only after consumers, SQL capture and physical transaction retirement
// have finished. Unknown commit must retain the same owned payload/lease; it may
// not create another operation, silently rebind, or release live resource debt.
func (p *durableRequestPayloadV1) releaseV1() {
	if p != nil {
		p.releaseOnce.Do(func() {
			if p.release != nil {
				p.release()
			}
		})
	}
}

type reboundRequestPayloadV1 struct {
	context *RecipientContext
	intent  *fittedSigningIntentV1
	payload *durableRequestPayloadV1
}

func requestPayloadErrorV1(ctx context.Context, prior error) error {
	if ctx != nil && ctx.Err() != nil {
		return fittedRequestCancellationV1(ctx, prior)
	}
	if prior != nil {
		return prior
	}
	return ErrSigningAdmissionUnavailableV1
}
func requestPayloadCheckContextV1(ctx context.Context) error {
	if ctx == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	if ctx.Err() != nil {
		return fittedRequestCancellationV1(ctx)
	}
	return nil
}
func requestPayloadAddV1(a, b int64) (int64, error) {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return 0, ErrSigningAdmissionUnavailableV1
	}
	return a + b, nil
}
func requestTimeFromPGV1(p pgtype.Timestamptz) (requestTimeV1, error) {
	if !p.Valid {
		return requestTimeV1{}, nil
	}
	if !finiteFittedTimeV1(p) {
		return requestTimeV1{}, ErrSigningAdmissionUnavailableV1
	}
	value, err := article13.CanonicalSentAt(p.Time)
	if err != nil {
		return requestTimeV1{}, ErrSigningAdmissionUnavailableV1
	}
	return requestTimeV1{Valid: true, Value: value}, nil
}
func (w requestTimeV1) pgV1(required bool) (pgtype.Timestamptz, error) {
	if !w.Valid {
		if required || w.Value != "" {
			return pgtype.Timestamptz{}, ErrSigningAdmissionUnavailableV1
		}
		return pgtype.Timestamptz{}, nil
	}
	if len(w.Value) > 30 || article13.ValidateCanonicalSentAt(w.Value) != nil {
		return pgtype.Timestamptz{}, ErrSigningAdmissionUnavailableV1
	}
	parsed, err := time.Parse(time.RFC3339Nano, w.Value)
	if err != nil {
		return pgtype.Timestamptz{}, ErrSigningAdmissionUnavailableV1
	}
	return pgtype.Timestamptz{Valid: true, Time: parsed}, nil
}
func requestUUIDFromPGV1(p pgtype.UUID) requestUUIDV1 {
	if !p.Valid {
		return requestUUIDV1{}
	}
	return requestUUIDV1{Valid: true, Value: uuid.UUID(p.Bytes).String()}
}
func (w requestUUIDV1) pgV1() (pgtype.UUID, error) {
	if !w.Valid {
		if w.Value != "" {
			return pgtype.UUID{}, ErrSigningAdmissionUnavailableV1
		}
		return pgtype.UUID{}, nil
	}
	id, err := uuid.Parse(w.Value)
	if err != nil || id == uuid.Nil || id.String() != w.Value {
		return pgtype.UUID{}, ErrSigningAdmissionUnavailableV1
	}
	return pgtype.UUID{Valid: true, Bytes: id}, nil
}
func requestHexV1(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for _, b := range []byte(s) {
		if !((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')) {
			return false
		}
	}
	return true
}
func requestOneOfV1(s string, permitted ...string) bool {
	for _, p := range permitted {
		if s == p {
			return true
		}
	}
	return false
}
func (w requestOriginWireV1) validateV1() error {
	if w.Schema != requestOriginSchemaV1 || w.Issuer != requestOriginIssuerV1 || !requestHexV1(w.TokenSHA256) ||
		len(w.DocumentName) == 0 || len(w.DocumentName) > requestDocumentNameMaxBytesV1 || !utf8.ValidString(w.DocumentName) ||
		w.NoticeSchema != article13.SchemaV1 || !w.NoticeCommitted || w.SigningPolicy != "pdf-static-v1" || w.SourceKind != "pdf" || w.RoutingTier != "SES" || !w.RequiresSignature || w.IsEnvelope ||
		!recipients.CanRespond(w.Role) || !requestOneOfV1(w.RecipientStatus, "pending", "sent", "viewed") || !requestOneOfV1(w.DocumentStatus, "sent", "in_progress") ||
		!requestOneOfV1(w.ConfirmationVia, "rest", "mcp", "worker", "test", "demo", "automation") {
		return ErrSigningAdmissionUnavailableV1
	}
	for _, s := range []string{w.OrgID, w.DocumentID, w.RecipientID} {
		id, err := uuid.Parse(s)
		if err != nil || id == uuid.Nil || id.String() != s {
			return ErrSigningAdmissionUnavailableV1
		}
	}
	for _, p := range []requestStringCommitmentV1{w.LawfulBasis, w.ControllerName, w.ControllerContact, w.ConfirmationBasis, w.ControllerOrgName} {
		if p.Bytes <= 0 || !requestHexV1(p.SHA256) {
			return ErrSigningAdmissionUnavailableV1
		}
	}
	for _, t := range []requestTimeV1{w.RecipientExpiry, w.SentAt, w.NoticeEpoch, w.ConfirmationAt} {
		if _, err := t.pgV1(true); err != nil {
			return err
		}
	}
	for _, t := range []requestTimeV1{w.DocumentExpiry, w.DocumentDeletedAt} {
		if _, err := t.pgV1(false); err != nil {
			return err
		}
	}
	if w.SentAt != w.NoticeEpoch || w.ParentEnvelopeID.Valid || w.DocumentDeletedAt.Valid {
		return ErrSigningAdmissionUnavailableV1
	}
	if _, err := w.ParentEnvelopeID.pgV1(); err != nil {
		return err
	}
	if _, err := w.ConfirmationBy.pgV1(); err != nil {
		return err
	}
	return nil
}
func (w acceptedIntentWireV1) validateShapeV1() error {
	if len(w.TypedName) > render.MaxSignatureNameBytes || len(w.Font) > 14 || w.Schema != acceptedIntentSchemaV1 || w.Notice.Schema != article13.SchemaV1 || !requestHexV1(w.Notice.Digest) ||
		!requestOneOfV1(w.Font, "Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple") || render.ValidateSignatureName(w.TypedName) != nil || article13.ValidateCanonicalSentAt(w.CeremonyEpoch) != nil || w.Notice.evidenceV1().Snapshot.Validate() != nil {
		return ErrInvalidNoticeEvidence
	}
	for _, s := range []string{w.OrgID, w.DocumentID, w.RecipientID} {
		id, err := uuid.Parse(s)
		if err != nil || id == uuid.Nil || id.String() != s {
			return ErrInvalidNoticeEvidence
		}
	}
	n := w.Notice.Snapshot
	if n.OrgID.String() != w.OrgID || n.DocumentID.String() != w.DocumentID || n.RecipientID.String() != w.RecipientID || n.SentAt != w.CeremonyEpoch {
		return ErrInvalidNoticeEvidence
	}
	return nil
}

// Only known fixed structs, scalars and uuid.UUID occur in these wire types.
// This exact counter follows encoding/json's compact default HTML escaping; it
// never calls Marshal, copies a body, or constructs a maximum-size test string.
type requestJSONCounterV1 struct {
	ctx         context.Context
	n, progress int64
}

func (c *requestJSONCounterV1) addV1(n int64) error {
	value, err := requestPayloadAddV1(c.n, n)
	if err != nil {
		return err
	}
	c.n = value
	return nil
}
func (c *requestJSONCounterV1) stringV1(s string) error {
	if err := c.addV1(2); err != nil {
		return err
	}
	for i := 0; i < len(s); {
		if c.progress >= requestPayloadChunkV1 {
			if err := requestPayloadCheckContextV1(c.ctx); err != nil {
				return err
			}
			c.progress = 0
		}
		b := s[i]
		step, n := 1, int64(1)
		switch {
		case b == '"' || b == '\\':
			n = 2
		case b == '\b' || b == '\f' || b == '\n' || b == '\r' || b == '\t':
			n = 2
		case b < 0x20 || b == '<' || b == '>' || b == '&':
			n = 6
		case b >= utf8.RuneSelf:
			r, size := utf8.DecodeRuneInString(s[i:])
			if r == utf8.RuneError && size == 1 {
				return ErrSigningAdmissionUnavailableV1
			}
			step = size
			n = int64(size)
			if r == '\u2028' || r == '\u2029' {
				n = 6
			}
		}
		if err := c.addV1(n); err != nil {
			return err
		}
		i += step
		c.progress += int64(step)
	}
	return requestPayloadCheckContextV1(c.ctx)
}

var requestUUIDTypeV1 = reflect.TypeOf(uuid.UUID{})

func (c *requestJSONCounterV1) valueV1(v reflect.Value) error {
	if err := requestPayloadCheckContextV1(c.ctx); err != nil {
		return err
	}
	if !v.IsValid() {
		return ErrSigningAdmissionUnavailableV1
	}
	if v.Type() == requestUUIDTypeV1 {
		return c.addV1(38)
	}
	switch v.Kind() {
	case reflect.String:
		return c.stringV1(v.String())
	case reflect.Bool:
		if v.Bool() {
			return c.addV1(4)
		}
		return c.addV1(5)
	case reflect.Int, reflect.Int64:
		return c.addV1(int64(len(strconv.FormatInt(v.Int(), 10))))
	case reflect.Struct:
		if err := c.addV1(2); err != nil {
			return err
		}
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("json")
			if tag == "" || strings.Contains(tag, ",") {
				return ErrSigningAdmissionUnavailableV1
			}
			if i > 0 {
				if err := c.addV1(1); err != nil {
					return err
				}
			}
			if err := c.stringV1(tag); err != nil {
				return err
			}
			if err := c.addV1(1); err != nil {
				return err
			}
			if err := c.valueV1(v.Field(i)); err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrSigningAdmissionUnavailableV1
	}
}
func requestExactJSONBytesV1(ctx context.Context, value any) (int64, error) {
	c := requestJSONCounterV1{ctx: ctx}
	if err := c.valueV1(reflect.ValueOf(value)); err != nil {
		return 0, err
	}
	return c.n, nil
}
func requestPayloadBudgetForV1(p *presentedCredentialV1, originBytes, intentBytes int64) (requestPayloadBudgetV1, error) {
	if p == nil {
		return requestPayloadBudgetV1{}, ErrSigningAdmissionUnavailableV1
	}
	raw := int64(0)
	for _, s := range []string{p.lawfulBasis, p.controllerName, p.controllerContact, p.confirmationBasis, p.controllerOrgName} {
		var err error
		raw, err = requestPayloadAddV1(raw, int64(len(s)))
		if err != nil {
			return requestPayloadBudgetV1{}, err
		}
	}
	resources, err := pdfadmission.ApplicationRequestPayloadResourcesForV1(pdfadmission.ApplicationRequestPayloadCostV1{OriginBytes: originBytes, IntentBytes: intentBytes, RawContextBytes: raw})
	if err != nil {
		return requestPayloadBudgetV1{}, ErrSigningAdmissionUnavailableV1
	}
	return requestPayloadBudgetV1{OrgID: p.orgID, DocumentID: p.documentID, RecipientID: p.recipientID, OriginBytes: originBytes, IntentBytes: intentBytes, RawContextBytes: raw, WorkingBytes: resources.WorkingBytes}, nil
}
func requestRawCommitmentV1(ctx context.Context, s string) (requestStringCommitmentV1, error) {
	h := sha256.New()
	var scratch [requestPayloadChunkV1]byte
	for start := 0; start < len(s); {
		if err := requestPayloadCheckContextV1(ctx); err != nil {
			return requestStringCommitmentV1{}, err
		}
		end := start + requestPayloadChunkV1
		if end > len(s) {
			end = len(s)
		}
		n := copy(scratch[:], s[start:end])
		_, _ = h.Write(scratch[:n])
		start = end
	}
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return requestStringCommitmentV1{}, err
	}
	return requestStringCommitmentV1{SHA256: hex.EncodeToString(h.Sum(nil)), Bytes: int64(len(s))}, nil
}
func requestPlaceholderCommitmentV1(s string) requestStringCommitmentV1 {
	return requestStringCommitmentV1{SHA256: strings.Repeat("0", sha256.Size*2), Bytes: int64(len(s))}
}
func requestOriginFromCredentialV1(p *presentedCredentialV1) (requestOriginWireV1, error) {
	if p == nil {
		return requestOriginWireV1{}, ErrSigningAdmissionUnavailableV1
	}
	recipient, err := requestTimeFromPGV1(p.recipientExpiry)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	document, err := requestTimeFromPGV1(p.documentExpiry)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	sent, err := requestTimeFromPGV1(p.sentAt)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	epoch, err := requestTimeFromPGV1(p.noticeEpoch)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	deleted, err := requestTimeFromPGV1(p.documentDeletedAt)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	confirmation, err := requestTimeFromPGV1(p.confirmationAt)
	if err != nil {
		return requestOriginWireV1{}, err
	}
	w := requestOriginWireV1{Schema: requestOriginSchemaV1, Issuer: requestOriginIssuerV1, OrgID: p.orgID.String(), DocumentID: p.documentID.String(), RecipientID: p.recipientID.String(), TokenSHA256: hex.EncodeToString(p.tokenHash[:]), RecipientExpiry: recipient, DocumentExpiry: document, SentAt: sent, NoticeEpoch: epoch, NoticeSchema: p.noticeSchema, NoticeCommitted: p.noticeCommitted, DocumentName: p.documentName, LawfulBasis: requestPlaceholderCommitmentV1(p.lawfulBasis), Role: p.role, RecipientStatus: p.recipientStatus, DocumentStatus: p.documentStatus, SigningPolicy: p.signingPolicy, SourceKind: p.sourceKind, RoutingTier: p.routingTier, RequiresSignature: p.requiresSignature, IsEnvelope: p.isEnvelope, ParentEnvelopeID: requestUUIDFromPGV1(p.parentEnvelopeID), DocumentDeletedAt: deleted, ConfirmationBy: requestUUIDFromPGV1(p.confirmationBy), ConfirmationAt: confirmation, ConfirmationVia: p.confirmationVia, ControllerName: requestPlaceholderCommitmentV1(p.controllerName), ControllerContact: requestPlaceholderCommitmentV1(p.controllerContact), ConfirmationBasis: requestPlaceholderCommitmentV1(p.confirmationBasis), ControllerOrgName: requestPlaceholderCommitmentV1(p.controllerOrgName)}
	return w, w.validateV1()
}
func requestOriginHashContextV1(ctx context.Context, p *presentedCredentialV1, w *requestOriginWireV1) error {
	for _, item := range []struct {
		raw    string
		target *requestStringCommitmentV1
	}{{p.lawfulBasis, &w.LawfulBasis}, {p.controllerName, &w.ControllerName}, {p.controllerContact, &w.ControllerContact}, {p.confirmationBasis, &w.ConfirmationBasis}, {p.controllerOrgName, &w.ControllerOrgName}} {
		commitment, err := requestRawCommitmentV1(ctx, item.raw)
		if err != nil {
			return err
		}
		*item.target = commitment
	}
	return nil
}
func acceptedIntentFromPrivateV1(i *fittedSigningIntentV1) acceptedIntentWireV1 {
	p := i.credential
	return acceptedIntentWireV1{Schema: acceptedIntentSchemaV1, OrgID: p.orgID.String(), DocumentID: p.documentID.String(), RecipientID: p.recipientID.String(), CeremonyEpoch: i.notice.Snapshot.SentAt, TypedName: i.typedName, Font: i.font, Notice: requestNoticeFromArticle13V1(i.notice)}
}
func (e *Engine) requestPayloadPrivateAdmissionV1(ctx context.Context, rc *RecipientContext, i *fittedSigningIntentV1, underLease bool) (*presentedCredentialV1, error) {
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	if e == nil || rc == nil || i == nil || i.credential == nil || rc.presentedCredential != i.credential || i.credential.issuer != e || rc.Recipient == nil || rc.Document == nil || rc.ControllerOrg == nil || rc.LawfulBasisConfirmation == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	p := i.credential
	if underLease && !p.matchesContextV1(rc) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if !finiteFittedTimeV1(p.recipientExpiry) || (p.documentExpiry.Valid && !finiteFittedTimeV1(p.documentExpiry)) || !finiteFittedTimeV1(p.confirmationAt) || !p.fittedDocumentMatchesV1(rc.Document) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err := p.originalLiveV1(e.now()); err != nil {
		return nil, err
	}
	// The genuine issuer already validated the complete acknowledgement digest.
	// Shape validation here avoids calling Evidence.Validate/Marshal before the
	// resource lease. The immutable private value is re-verified under that lease.
	if err := acceptedIntentFromPrivateV1(i).validateShapeV1(); err != nil {
		return nil, err
	}
	return p, requestPayloadCheckContextV1(ctx)
}
func (e *Engine) captureDurableRequestPayloadV1(ctx context.Context, rc *RecipientContext, i *fittedSigningIntentV1, admission requestPayloadAdmissionV1) (out *durableRequestPayloadV1, err error) {
	p, err := e.requestPayloadPrivateAdmissionV1(ctx, rc, i, false)
	if err != nil {
		return nil, err
	}
	origin, err := requestOriginFromCredentialV1(p)
	if err != nil {
		return nil, err
	}
	intent := acceptedIntentFromPrivateV1(i)
	ob, err := requestExactJSONBytesV1(ctx, origin)
	if err != nil {
		return nil, err
	}
	ib, err := requestExactJSONBytesV1(ctx, intent)
	if err != nil {
		return nil, err
	}
	budget, err := requestPayloadBudgetForV1(p, ob, ib)
	if err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	release, err := admission.AcquireRequestPayloadV1(ctx, budget)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, requestPayloadErrorV1(ctx, err)
	}
	if release == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	success := false
	defer func() {
		if ctx.Err() != nil {
			err = requestPayloadErrorV1(ctx, err)
			out = nil
			success = false
		}
		if !success {
			release()
		}
		if err != nil {
			err = requestPayloadErrorV1(ctx, err)
		}
	}()
	if _, err = e.requestPayloadPrivateAdmissionV1(ctx, rc, i, true); err != nil {
		return nil, err
	}
	if err = requestOriginHashContextV1(ctx, p, &origin); err != nil {
		return nil, err
	}
	if err = i.notice.Validate(); err != nil {
		return nil, ErrInvalidNoticeEvidence
	}
	originBody, err := json.Marshal(origin)
	if err != nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	intentBody, err := json.Marshal(intent)
	if err != nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if int64(len(originBody)) != ob || int64(len(intentBody)) != ib {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = e.requestPayloadPrivateAdmissionV1(ctx, rc, i, true); err != nil {
		return nil, err
	}
	oh, err := requestBodySHA256V1(ctx, originBody)
	if err != nil {
		return nil, err
	}
	ih, err := requestBodySHA256V1(ctx, intentBody)
	if err != nil {
		return nil, err
	}
	result := &durableRequestPayloadV1{header: requestPayloadHeaderV1{OrgID: p.orgID, DocumentID: p.documentID, RecipientID: p.recipientID, CeremonyEpoch: intent.CeremonyEpoch, OriginBytes: ob, IntentBytes: ib, OriginSHA256: oh, IntentSHA256: ih, SemanticIntentSHA256: ih}, origin: originBody, intent: intentBody, release: release}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	success = true
	return result, nil
}

type requestPayloadReaderV1 struct {
	ctx    context.Context
	reader *bytes.Reader
}

func (r requestPayloadReaderV1) Read(dst []byte) (int, error) {
	if err := requestPayloadCheckContextV1(r.ctx); err != nil {
		return 0, err
	}
	if len(dst) > requestPayloadChunkV1 {
		dst = dst[:requestPayloadChunkV1]
	}
	return r.reader.Read(dst)
}
func requestDecodeCanonicalV1(ctx context.Context, body []byte, target any) error {
	dec := json.NewDecoder(requestPayloadReaderV1{ctx: ctx, reader: bytes.NewReader(body)})
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		return requestPayloadErrorV1(ctx, ErrSigningAdmissionUnavailableV1)
	}
	var trailing struct{}
	if err := dec.Decode(&trailing); err != io.EOF {
		return requestPayloadErrorV1(ctx, ErrSigningAdmissionUnavailableV1)
	}
	if err := requestPayloadCheckContextV1(ctx); err != nil {
		return err
	}
	n, err := requestExactJSONBytesV1(ctx, reflect.ValueOf(target).Elem().Interface())
	if err != nil || n != int64(len(body)) {
		return requestPayloadErrorV1(ctx, ErrSigningAdmissionUnavailableV1)
	}
	encoded, err := json.Marshal(target)
	if err != nil || !bytes.Equal(encoded, body) {
		return ErrSigningAdmissionUnavailableV1
	}
	return requestPayloadCheckContextV1(ctx)
}
func requestBodySHA256V1(ctx context.Context, body []byte) ([sha256.Size]byte, error) {
	h := sha256.New()
	for start := 0; start < len(body); {
		if err := requestPayloadCheckContextV1(ctx); err != nil {
			return [sha256.Size]byte{}, err
		}
		end := start + requestPayloadChunkV1
		if end > len(body) {
			end = len(body)
		}
		_, _ = h.Write(body[start:end])
		start = end
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, requestPayloadCheckContextV1(ctx)
}

// Rebind is private and requires a new genuine token lookup AND a newly issued
// private intent from this Engine. Untrusted JSON cannot construct credentials.
// The future sidecar adapter must obtain these bodies from the exact immutable
// locked row and compare full bodies; these hashes alone do not prove capture,
// authorization, an operation ID, admission89, publication or READY.
func (e *Engine) rebindDurableRequestPayloadV1(ctx context.Context, current *RecipientContext, currentIntent *fittedSigningIntentV1, header requestPayloadHeaderV1, originBody, intentBody []byte, admission requestPayloadAdmissionV1) (out *reboundRequestPayloadV1, err error) {
	p, err := e.requestPayloadPrivateAdmissionV1(ctx, current, currentIntent, false)
	if err != nil {
		return nil, err
	}
	if header.OrgID != p.orgID || header.DocumentID != p.documentID || header.RecipientID != p.recipientID || header.CeremonyEpoch != currentIntent.notice.Snapshot.SentAt || header.OriginBytes != int64(len(originBody)) || header.IntentBytes != int64(len(intentBody)) || header.IntentSHA256 != header.SemanticIntentSHA256 {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	budget, err := requestPayloadBudgetForV1(p, header.OriginBytes, header.IntentBytes)
	if err != nil {
		return nil, err
	}
	if admission == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	release, err := admission.AcquireRequestPayloadV1(ctx, budget)
	if err != nil {
		if release != nil {
			release()
		}
		return nil, requestPayloadErrorV1(ctx, err)
	}
	if release == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	success := false
	defer func() {
		if ctx.Err() != nil {
			err = requestPayloadErrorV1(ctx, err)
			out = nil
			success = false
		}
		if !success {
			release()
		}
		if err != nil {
			err = requestPayloadErrorV1(ctx, err)
		}
	}()
	if _, err = e.requestPayloadPrivateAdmissionV1(ctx, current, currentIntent, true); err != nil {
		return nil, err
	}
	oh, err := requestBodySHA256V1(ctx, originBody)
	if err != nil {
		return nil, err
	}
	ih, err := requestBodySHA256V1(ctx, intentBody)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(oh[:], header.OriginSHA256[:]) != 1 || subtle.ConstantTimeCompare(ih[:], header.IntentSHA256[:]) != 1 {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	var origin requestOriginWireV1
	var intent acceptedIntentWireV1
	if err = requestDecodeCanonicalV1(ctx, originBody, &origin); err != nil {
		return nil, err
	}
	if err = origin.validateV1(); err != nil {
		return nil, err
	}
	if err = requestDecodeCanonicalV1(ctx, intentBody, &intent); err != nil {
		return nil, err
	}
	if err = intent.validateShapeV1(); err != nil {
		return nil, err
	}
	if err = intent.Notice.evidenceV1().Validate(); err != nil {
		return nil, ErrInvalidNoticeEvidence
	}
	// Fresh expiry renewals and normal sent/viewed/in_progress transitions may
	// change current rows. Reconstruct the stored ORIGINAL values only after all
	// other immutable scope, verifier, raw-context and intent material matches.
	original := *p
	original.recipientExpiry, err = origin.RecipientExpiry.pgV1(true)
	if err != nil {
		return nil, err
	}
	original.documentExpiry, err = origin.DocumentExpiry.pgV1(false)
	if err != nil {
		return nil, err
	}
	original.recipientStatus = origin.RecipientStatus
	original.documentStatus = origin.DocumentStatus
	if err = original.originalLiveV1(e.now()); err != nil {
		return nil, err
	}
	expectedOrigin, err := requestOriginFromCredentialV1(&original)
	if err != nil {
		return nil, err
	}
	if err = requestOriginHashContextV1(ctx, &original, &expectedOrigin); err != nil {
		return nil, err
	}
	expectedIntent := acceptedIntentFromPrivateV1(currentIntent)
	expectedOB, err := json.Marshal(expectedOrigin)
	if err != nil || !bytes.Equal(expectedOB, originBody) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	expectedIB, err := json.Marshal(expectedIntent)
	if err != nil || !bytes.Equal(expectedIB, intentBody) {
		return nil, ErrInvalidNoticeEvidence
	}
	// Value-copy rows: this does not rewrite current lookup or locked SQL rows.
	rc := *current
	rec := *current.Recipient
	doc := *current.Document
	rec.MagicTokenHash = append([]byte(nil), original.tokenHash[:]...)
	rec.MagicTokenExpiresAt = original.recipientExpiry
	rec.Status = original.recipientStatus
	doc.ExpiresAt = original.documentExpiry
	doc.Status = original.documentStatus
	rc.Recipient = &rec
	rc.Document = &doc
	rc.presentedCredential = &original
	reboundIntent := *currentIntent
	reboundIntent.credential = &original
	if !original.matchesContextV1(&rc) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = e.requestPayloadPrivateAdmissionV1(ctx, current, currentIntent, true); err != nil {
		return nil, err
	}
	result := &reboundRequestPayloadV1{context: &rc, intent: &reboundIntent, payload: &durableRequestPayloadV1{header: header, origin: bytes.Clone(originBody), intent: bytes.Clone(intentBody), release: release}}
	if err = requestPayloadCheckContextV1(ctx); err != nil {
		return nil, err
	}
	success = true
	return result, nil
}
