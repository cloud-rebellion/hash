// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The provider offers time-of-read observations, not an atomic remote snapshot.
// An observation may enter a sealing intent only within this bounded interval.
const CRMObservationMaxAge = 45 * time.Second

var ErrCRMReviewRequired = errors.New("CRM values changed; update and review the document before sending")

type CRMConnectionReader interface {
	GetCRMConnectionByOrg(context.Context, uuid.UUID) (*generated.CrmConnection, error)
}
type CRMConnectionVerifier interface {
	GetCRMConnectionByOrgForShare(context.Context, uuid.UUID) (*generated.CrmConnection, error)
}

type CRMRecords struct {
	Store  CRMConnectionReader
	Client *crmconnection.Client
	Keys   *crmconnection.Keyring
	Origin string
}

// CRMValueObservation is emitted only from a typed server observation. It
// describes a read, not identity/authority/key-scope or legal verification.
// Generation is a decimal string so clients cannot round a bigint revision.
type CRMValueObservation struct {
	ConnectionID    uuid.UUID `json:"connection_id"`
	Generation      string    `json:"generation"`
	Origin          string    `json:"origin"`
	CRMTeamID       string    `json:"crm_team_id"`
	CRMUserID       string    `json:"crm_user_id"`
	RecordUpdatedAt time.Time `json:"record_updated_at"`
	ObservedAt      time.Time `json:"observed_at"`
	BodySHA256      string    `json:"body_sha256"`
	ValueSHA256     string    `json:"value_sha256"`
	Transformation  string    `json:"transformation,omitempty"`
}

type crmReportFence struct {
	identity    crmconnection.Identity
	completedAt time.Time
	observation CRMValueObservation
}

func isCRMKind(kind string) bool {
	return kind == string(SourceCRMDeal) || kind == string(SourceCRMContact) || kind == string(SourceCRMCompany)
}

func (c *CRMRecords) observe(ctx context.Context, doc *generated.Document, bindings []*generated.DocumentVariableBinding) (*crmconnection.Snapshot, error) {
	refs := []crmconnection.RecordRef{}
	for _, b := range bindings {
		if b != nil && isCRMKind(b.SourceKind) {
			refs = append(refs, crmconnection.RecordRef{Kind: crmconnection.RecordKind(b.SourceKind), ID: b.SourceRef})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	if c == nil || c.Store == nil || c.Client == nil || c.Keys == nil || doc.OrgID == uuid.Nil {
		return nil, ErrNotConfigured
	}
	row, err := c.Store.GetCRMConnectionByOrg(ctx, doc.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotConfigured
	}
	if err != nil {
		return nil, ErrSourceFreshness
	}
	if row == nil || row.OrgID != doc.OrgID || row.Status != "active" || row.Origin != c.Origin {
		return nil, ErrNotConfigured
	}
	id := connectionIdentity(row)
	// The native Send store holds the actual shared provider dimension across
	// this concrete synchronous account/record/body/decode call. Existing stores
	// retain their original behavior; this is no caller callback or byte grant.
	if native, ok := c.Store.(interface {
		HoldCRMRecordReadV1(context.Context, uuid.UUID) (func(), error)
	}); ok {
		release, holdErr := native.HoldCRMRecordReadV1(ctx, doc.OrgID)
		if holdErr != nil {
			return nil, ErrSourceFreshness
		}
		defer release()
	}
	snapshot, err := c.Client.ReadRecords(ctx, crmconnection.Connection{Identity: id, Enabled: true, VerifiedAt: row.VerifiedAt.Time, Ciphertext: row.CredentialCiphertext}, c.Keys, refs)
	if err != nil {
		return nil, ErrSourceFreshness
	}
	if err = validateCRMRelationships(snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func connectionIdentity(row *generated.CrmConnection) crmconnection.Identity {
	return crmconnection.Identity{ID: row.ID, OrgID: row.OrgID, Generation: row.Generation,
		Origin: row.Origin, CRMTeamID: row.CrmTeamID, CRMUserID: row.CrmUserID}
}

// V1 permits one selected deal/contact/company per document. A multi-record
// customer selection must be supported by the provider's exact foreign IDs;
// null/absent relationships never turn into guessed joins.
func validateCRMRelationships(s crmconnection.Snapshot) error {
	selected := map[crmconnection.RecordKind]crmconnection.RecordObservation{}
	for _, r := range s.Records {
		if _, exists := selected[r.Kind]; exists {
			return ErrSourceFreshness
		}
		selected[r.Kind] = r
	}
	require := func(from crmconnection.RecordKind, path string, to crmconnection.RecordKind) error {
		a, hasA := selected[from]
		b, hasB := selected[to]
		if !hasA || !hasB {
			return nil
		}
		link, ok := a.Relationships[path]
		if !ok || !link.Present || link.Null || link.Value != b.ID {
			return ErrSourceFreshness
		}
		return nil
	}
	if err := require(crmconnection.Deal, "contact_id", crmconnection.Contact); err != nil {
		return err
	}
	if err := require(crmconnection.Deal, "company_id", crmconnection.Company); err != nil {
		return err
	}
	return require(crmconnection.Contact, "company_id", crmconnection.Company)
}

// ValidateCRMSelection applies the same exact one-record-per-kind relationship
// policy to a server-observed selection before contractual fields are mapped.
func ValidateCRMSelection(snapshot crmconnection.Snapshot) error {
	return validateCRMRelationships(snapshot)
}

func crmValue(snapshot *crmconnection.Snapshot, b *generated.DocumentVariableBinding) (string, *CRMValueObservation, *crmReportFence, error) {
	if snapshot == nil {
		return "", nil, nil, ErrSourceFreshness
	}
	record, ok := snapshot.Record(crmconnection.RecordKind(b.SourceKind), b.SourceRef)
	if !ok {
		return "", nil, nil, ErrSourceFreshness
	}
	value, err := record.Value(b.SourcePath)
	if err != nil {
		return "", nil, nil, ErrSourceFreshness
	}
	sum := sha256.Sum256([]byte(value))
	proof := &CRMValueObservation{ConnectionID: snapshot.Identity.ID, Generation: strconv.FormatInt(snapshot.Identity.Generation, 10), Origin: snapshot.Identity.Origin,
		CRMTeamID: snapshot.Identity.CRMTeamID, CRMUserID: snapshot.Identity.CRMUserID,
		RecordUpdatedAt: record.RecordUpdatedAt, ObservedAt: record.ObservedAt,
		BodySHA256: record.BodySHA256, ValueSHA256: hex.EncodeToString(sum[:])}
	if b.SourceKind == string(SourceCRMContact) && b.SourcePath == "full_name" {
		proof.Transformation = "trim-first-and-last-name-v1"
	}
	return value, proof, &crmReportFence{identity: snapshot.Identity, completedAt: snapshot.CompletedAt, observation: *proof}, nil
}

// CheckCRMReports must run under the final authorized transaction. FOR SHARE
// keeps the mapped credential generation active through the caller's commit.
// It performs no network request and cannot prove future upstream changes.
func CheckCRMReports(ctx context.Context, q CRMConnectionVerifier, orgID uuid.UUID, report []ResolveReport) error {
	var checked *crmReportFence
	for _, entry := range report {
		if entry.crmFence == nil {
			continue
		}
		fence := entry.crmFence
		if err := checkCRMReportValue(entry); err != nil {
			return err
		}
		if fence.identity.OrgID != orgID || !crmObservationCurrent(fence.completedAt, time.Now()) {
			return ErrSourceFreshness
		}
		if checked != nil {
			if checked.identity != fence.identity || !checked.completedAt.Equal(fence.completedAt) {
				return ErrSourceFreshness
			}
			continue
		}
		if q == nil {
			return ErrSourceFreshness
		}
		row, err := q.GetCRMConnectionByOrgForShare(ctx, orgID)
		if err != nil || row == nil || row.Status != "active" || connectionIdentity(row) != fence.identity {
			return ErrSourceFreshness
		}
		checked = fence
	}
	return CheckCRMReportDeadlines(report, time.Now())
}

func crmObservationCurrent(at, now time.Time) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) <= CRMObservationMaxAge
}

func checkCRMReportValue(entry ResolveReport) error {
	if entry.CRMObservation == nil || entry.ResolvedFrom != "source" || entry.crmFence == nil {
		return ErrSourceFreshness
	}
	sum := sha256.Sum256([]byte(entry.Value))
	if entry.CRMObservation.ValueSHA256 != hex.EncodeToString(sum[:]) || entry.CRMObservation.ConnectionID != entry.crmFence.identity.ID || entry.CRMObservation.Generation != strconv.FormatInt(entry.crmFence.identity.Generation, 10) {
		return ErrSourceFreshness
	}
	if entry.CRMObservation.Origin != entry.crmFence.identity.Origin || entry.CRMObservation.CRMTeamID != entry.crmFence.identity.CRMTeamID || entry.CRMObservation.CRMUserID != entry.crmFence.identity.CRMUserID {
		return ErrSourceFreshness
	}
	return nil
}

// ValidateFreshCRMReport requires the private resolver observation and original
// binding snapshot. Exported JSON fields alone never attest a fresh CRM read.
// The caller must additionally hold/recheck the active connection generation.
func ValidateFreshCRMReport(entry ResolveReport, orgID, docID uuid.UUID, now time.Time) error {
	b := entry.bindingSnapshot
	if orgID == uuid.Nil || docID == uuid.Nil || b == nil || entry.crmFence == nil ||
		b.DocumentID != docID || b.VariableName != entry.Variable || b.SourceKind != entry.SourceKind ||
		b.SourceRef != entry.SourceRef || b.SourcePath != entry.SourcePath || !isCRMKind(b.SourceKind) ||
		entry.crmFence.identity.OrgID != orgID || !crmObservationCurrent(entry.crmFence.completedAt, now) ||
		entry.CRMObservation == nil || *entry.CRMObservation != entry.crmFence.observation {
		return ErrSourceFreshness
	}
	return checkCRMReportValue(entry)
}

func CheckCRMReportDeadlines(report []ResolveReport, now time.Time) error {
	for _, entry := range report {
		if entry.crmFence != nil && (!crmObservationCurrent(entry.crmFence.completedAt, now) || checkCRMReportValue(entry) != nil) {
			return ErrSourceFreshness
		}
	}
	return nil
}

// Trusted fresh CRM reads may confirm reviewed values but must not silently
// replace the agreement while Send is already creating a ceremony.
func CheckReviewedCRMValues(doc *generated.Document, report []ResolveReport) error {
	values, err := blocks.ParseVariableValues(doc.VariablesJson)
	if err != nil {
		return err
	}
	for _, entry := range report {
		if entry.crmFence != nil {
			value, exists := values[entry.Variable]
			if !exists || value != entry.Value {
				return ErrCRMReviewRequired
			}
		}
	}
	return nil
}
