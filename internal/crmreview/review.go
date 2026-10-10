// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package crmreview binds explicit human mapping review to current content and
// account authority. It performs no provider I/O or writes and never modifies
// historical HTML source domains, signed bytes or existing evidence.
package crmreview

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const MaxBindings = 128

var (
	ErrReviewRequired = errors.New("CRM mapping or document changed; review and apply the current CRM mapping before sending")
	ErrInvalid        = errors.New("invalid CRM mapping review state")
)

type semanticBinding struct {
	DocumentID uuid.UUID `json:"document_id"`
	Variable   string    `json:"variable"`
	Kind       string    `json:"kind"`
	Ref        string    `json:"ref"`
	Path       string    `json:"path"`
	Fallback   string    `json:"fallback"`
}

type fullBinding struct {
	semanticBinding
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	LastValue    string `json:"last_value"`
	LastResolved string `json:"last_resolved"`
	LastError    string `json:"last_error"`
}

func crmKind(kind string) bool {
	return kind == string(resolver.SourceCRMDeal) || kind == string(resolver.SourceCRMContact) || kind == string(resolver.SourceCRMCompany)
}

func sortedBindings(rows []*generated.DocumentVariableBinding) ([]*generated.DocumentVariableBinding, error) {
	if len(rows) > MaxBindings {
		return nil, ErrInvalid
	}
	copyRows := append([]*generated.DocumentVariableBinding(nil), rows...)
	seen := make(map[string]bool, len(rows))
	var documentID uuid.UUID
	for _, row := range copyRows {
		if row == nil || row.DocumentID == uuid.Nil || seen[row.VariableName] ||
			resolver.ValidateBinding(row.VariableName, resolver.SourceKind(row.SourceKind), row.SourceRef, row.SourcePath, row.Fallback) != nil {
			return nil, ErrInvalid
		}
		if documentID != uuid.Nil && documentID != row.DocumentID {
			return nil, ErrInvalid
		}
		documentID = row.DocumentID
		seen[row.VariableName] = true
	}
	sort.Slice(copyRows, func(i, j int) bool { return copyRows[i].VariableName < copyRows[j].VariableName })
	return copyRows, nil
}

func semantic(row *generated.DocumentVariableBinding) semanticBinding {
	return semanticBinding{DocumentID: row.DocumentID, Variable: row.VariableName, Kind: row.SourceKind, Ref: row.SourceRef, Path: row.SourcePath, Fallback: row.Fallback}
}

func finiteTimestamp(stamp pgtype.Timestamptz) bool {
	return stamp.Valid && stamp.InfinityModifier == pgtype.Finite && !stamp.Time.IsZero()
}

func hash(domain string, value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain + "\x00"))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FullBindingFingerprint covers the entire ledger, including non-CRM members,
// exact UTC revision timestamps and observation state. It never sorts in place.
func FullBindingFingerprint(rows []*generated.DocumentVariableBinding) (string, error) {
	sorted, err := sortedBindings(rows)
	if err != nil {
		return "", err
	}
	full := make([]fullBinding, 0, len(sorted))
	for _, row := range sorted {
		if !finiteTimestamp(row.CreatedAt) || !finiteTimestamp(row.UpdatedAt) || row.UpdatedAt.Time.Before(row.CreatedAt.Time) ||
			(row.LastResolved.Valid && !finiteTimestamp(row.LastResolved)) || len(row.LastValue) > crmconnection.MaxScalarBytes || len(row.LastError) > crmconnection.MaxScalarBytes || !utf8.ValidString(row.LastValue) || !utf8.ValidString(row.LastError) {
			return "", ErrInvalid
		}
		last := ""
		if row.LastResolved.Valid {
			last = row.LastResolved.Time.UTC().Format(time.RFC3339Nano)
		}
		full = append(full, fullBinding{semanticBinding: semantic(row), CreatedAt: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano), UpdatedAt: row.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), LastValue: row.LastValue, LastResolved: last, LastError: row.LastError})
	}
	return hash("hash-crm-full-bindings-v1", full)
}

// CRMSemanticDigest covers exact CRM membership/ref/path/fallback, excluding
// observation caches and timestamps. Explicit removal changes this digest.
func CRMSemanticDigest(rows []*generated.DocumentVariableBinding) (string, error) {
	sorted, err := sortedBindings(rows)
	if err != nil {
		return "", err
	}
	crm := make([]semanticBinding, 0, len(sorted))
	for _, row := range sorted {
		if crmKind(row.SourceKind) {
			crm = append(crm, semantic(row))
		}
	}
	return hash("hash-crm-semantic-bindings-v1", crm)
}

// ContentCommitment reuses the validated HTML source commitment. Blocks get a
// new review-only domain over their strict canonical tree and exact strings.
// Uploaded PDF printed text is not an editable CRM destination.
func ContentCommitment(doc *generated.Document) (string, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil {
		return "", ErrInvalid
	}
	if len(doc.HtmlSourceJson) > 0 || len(doc.HtmlCurrentSourceJson) > 0 || doc.HtmlCurrentMaterializationID.Valid {
		return htmlsource.Commitment(doc)
	}
	if doc.SourceKind != "blocks" || len(doc.BlocksJson) > blocks.MaxImportSourceBytes || len(doc.VariablesJson) > blocks.MaxImportSourceBytes ||
		sourcejson.Validate(doc.BlocksJson) != nil || !validUnicodeEscapes(doc.BlocksJson) || !exactBlockKeys(doc.BlocksJson) {
		return "", ErrInvalid
	}
	tree, err := blocks.ParseCanonicalTree(doc.BlocksJson)
	if err != nil {
		return "", ErrInvalid
	}
	variables := bytes.TrimSpace(doc.VariablesJson)
	if len(variables) == 0 {
		variables = []byte(`{}`)
	}
	if sourcejson.Validate(variables) != nil || !validUnicodeEscapes(variables) {
		return "", ErrInvalid
	}
	values, err := blocks.ParseVariableValues(variables)
	if err != nil {
		return "", ErrInvalid
	}
	for _, value := range values {
		if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return "", ErrInvalid
		}
	}
	return hash("hash-crm-block-content-v1", struct {
		DocumentID uuid.UUID         `json:"document_id"`
		OrgID      uuid.UUID         `json:"org_id"`
		Tree       *blocks.Tree      `json:"tree"`
		Values     map[string]string `json:"values"`
	}{doc.ID, doc.OrgID, tree, values})
}

// Struct decoders match field names case-insensitively. The current review
// domain accepts only the persisted canonical spellings, preventing aliases
// such as version/Version or id/ID from selecting a last contractual value.
func exactBlockKeys(raw []byte) bool {
	var tree map[string]json.RawMessage
	if json.Unmarshal(raw, &tree) != nil || tree == nil {
		return false
	}
	for key := range tree {
		if key != "version" && key != "blocks" {
			return false
		}
	}
	var inspect func(json.RawMessage) bool
	inspect = func(raw json.RawMessage) bool {
		var rows []map[string]json.RawMessage
		if json.Unmarshal(raw, &rows) != nil {
			return false
		}
		for _, row := range rows {
			if row == nil {
				return false
			}
			for key := range row {
				if key != "id" && key != "type" && key != "attrs" && key != "text" && key != "content" && key != "rows" {
					return false
				}
			}
			if child, ok := row["content"]; ok && !inspect(child) {
				return false
			}
		}
		return true
	}
	if raw, ok := tree["blocks"]; ok {
		return inspect(raw)
	}
	return true
}

// encoding/json replaces unpaired UTF-16 escapes with U+FFFD. Reject that
// ambiguity before hashing contractual strings; literal escaped backslashes
// and correctly paired supplementary characters remain distinct and valid.
func validUnicodeEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' {
			continue
		}
		if i+1 >= len(raw) {
			return false
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		if i+4 >= len(raw) {
			return false
		}
		value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value < 0xD800 || value > 0xDBFF {
			continue
		}
		if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return true
}

func hexDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validReview(doc *generated.Document, review *generated.DocumentCrmMappingReview) bool {
	if review == nil || review.DocumentID != doc.ID || review.ReviewedBy == uuid.Nil || !hexDigest(review.BindingDigest) || !hexDigest(review.ContentCommitment) ||
		!finiteTimestamp(review.CreatedAt) || !finiteTimestamp(review.UpdatedAt) || review.UpdatedAt.Time.Before(review.CreatedAt.Time) {
		return false
	}
	if !review.HasMappings {
		return !review.ConnectionID.Valid && !review.ConnectionGeneration.Valid && review.Origin == "" && review.CrmTeamID == "" && review.CrmUserID == ""
	}
	return review.ConnectionID.Valid && review.ConnectionGeneration.Valid && crmconnection.ValidateIdentity(crmconnection.Identity{ID: uuid.UUID(review.ConnectionID.Bytes), OrgID: doc.OrgID, Generation: review.ConnectionGeneration.Int64, Origin: review.Origin, CRMTeamID: review.CrmTeamID, CRMUserID: review.CrmUserID}) == nil
}

// ReviewMatches deliberately permits ordinary unbound documents without a row,
// and explicit unlink reviews after later manual content changes. A previously
// mapped review never becomes valid merely by deleting the final CRM binding.
func ReviewMatches(doc *generated.Document, bindings []*generated.DocumentVariableBinding, review *generated.DocumentCrmMappingReview, conn *generated.CrmConnection) (bool, error) {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil {
		return false, ErrInvalid
	}
	sorted, err := sortedBindings(bindings)
	if err != nil {
		return false, err
	}
	count := 0
	for _, row := range sorted {
		if row.DocumentID != doc.ID {
			return false, ErrInvalid
		}
		if crmKind(row.SourceKind) {
			count++
		}
	}
	if review == nil {
		return count == 0, nil
	}
	if !validReview(doc, review) {
		return false, ErrInvalid
	}
	digest, err := CRMSemanticDigest(sorted)
	if err != nil {
		return false, err
	}
	if count == 0 {
		return !review.HasMappings && review.BindingDigest == digest, nil
	}
	if !review.HasMappings || review.BindingDigest != digest || conn == nil || conn.OrgID != doc.OrgID || conn.Status != "active" ||
		conn.ID != uuid.UUID(review.ConnectionID.Bytes) || conn.Generation != review.ConnectionGeneration.Int64 || conn.Origin != review.Origin ||
		conn.CrmTeamID != review.CrmTeamID || conn.CrmUserID != review.CrmUserID {
		return false, nil
	}
	content, err := ContentCommitment(doc)
	if err != nil {
		return false, err
	}
	return review.ContentCommitment == content, nil
}

type sendReader interface {
	DocumentHasCRMBindings(context.Context, generated.DocumentHasCRMBindingsParams) (bool, error)
	ListCRMMappingBindingsForShare(context.Context, generated.ListCRMMappingBindingsForShareParams) ([]*generated.DocumentVariableBinding, error)
	GetDocumentCRMMappingReviewForShare(context.Context, generated.GetDocumentCRMMappingReviewForShareParams) (*generated.DocumentCrmMappingReview, error)
	GetCRMConnectionByOrgForShare(context.Context, uuid.UUID) (*generated.CrmConnection, error)
}

// CheckForSend runs only under the already authorized parent/family locks,
// before any binding observation, frozen value, token or sealing-intent write.
// Missing resolver wiring cannot bypass its mandatory trusted report checks.
func CheckForSend(ctx context.Context, q *generated.Queries, doc *generated.Document, reports []resolver.ResolveReport) error {
	if q == nil {
		return ErrReviewRequired
	}
	return checkForSend(ctx, q, doc, reports, time.Now())
}

func checkForSend(ctx context.Context, q sendReader, doc *generated.Document, reports []resolver.ResolveReport, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if q == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.Status != "draft" {
		return ErrReviewRequired
	}
	review, err := q.GetDocumentCRMMappingReviewForShare(ctx, generated.GetDocumentCRMMappingReviewForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		review = nil
	} else if err != nil {
		return err
	}
	hasCRM, err := q.DocumentHasCRMBindings(ctx, generated.DocumentHasCRMBindingsParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	// An exact full-ledger EXISTS, under the caller's parent lock, permits
	// ordinary manual documents of any existing ledger size. A retained mapped
	// review still cannot be bypassed by deleting every CRM binding.
	if !hasCRM && (review == nil || !review.HasMappings) {
		matches, err := ReviewMatches(doc, nil, review, nil)
		if err != nil || !matches {
			return ErrReviewRequired
		}
		for _, entry := range reports {
			if crmKind(entry.SourceKind) || entry.CRMObservation != nil {
				return ErrReviewRequired
			}
		}
		return ctx.Err()
	}
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return err
	}
	sorted, err := sortedBindings(bindings)
	if err != nil {
		return ErrReviewRequired
	}
	var conn *generated.CrmConnection
	if review != nil && review.HasMappings {
		conn, err = q.GetCRMConnectionByOrgForShare(ctx, doc.OrgID)
		if errors.Is(err, pgx.ErrNoRows) {
			conn = nil
		} else if err != nil {
			return err
		}
	}
	matches, err := ReviewMatches(doc, sorted, review, conn)
	if err != nil || !matches {
		return ErrReviewRequired
	}
	crm := make(map[string]*generated.DocumentVariableBinding)
	for _, binding := range sorted {
		if crmKind(binding.SourceKind) {
			crm[binding.VariableName] = binding
		}
	}
	if len(crm) == 0 {
		for _, entry := range reports {
			if crmKind(entry.SourceKind) || entry.CRMObservation != nil {
				return ErrReviewRequired
			}
		}
		return ctx.Err()
	}
	values, err := blocks.ParseVariableValues(doc.VariablesJson)
	if err != nil {
		return ErrReviewRequired
	}
	seen := make(map[string]bool, len(crm))
	for _, entry := range reports {
		if !crmKind(entry.SourceKind) {
			if entry.CRMObservation != nil {
				return ErrReviewRequired
			}
			continue
		}
		binding := crm[entry.Variable]
		value, present := values[entry.Variable]
		if binding == nil || seen[entry.Variable] || !present || value != entry.Value || binding.SourceKind != entry.SourceKind || binding.SourceRef != entry.SourceRef || binding.SourcePath != entry.SourcePath ||
			resolver.ValidateFreshCRMReport(entry, doc.OrgID, doc.ID, now) != nil {
			return ErrReviewRequired
		}
		seen[entry.Variable] = true
	}
	if len(seen) != len(crm) {
		return ErrReviewRequired
	}
	if err := resolver.CheckCRMReports(ctx, q, doc.OrgID, reports); err != nil {
		return ErrReviewRequired
	}
	return ctx.Err()
}
