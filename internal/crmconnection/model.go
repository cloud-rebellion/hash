// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package crmconnection reads bounded, tenant-verified BrightCRM observations.
// It does not authorize Hash mutations, hold database locks, or claim an atomic
// snapshot of a remote service. Callers must recheck the original connection
// generation and observation deadline in their final authorized transaction.
package crmconnection

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	MaxOpaqueIDBytes         = 256
	MaxResponseBytes         = 256 * 1024
	MaxScalarBytes           = 16 * 1024
	MaxUniqueRecords         = 16
	MaxRecordReferences      = 128
	MaxSnapshotResponseBytes = (MaxUniqueRecords + 2) * MaxResponseBytes
	BatchTimeout             = 15 * time.Second
	RequestTimeout           = 10 * time.Second
	MaxClockSkew             = 5 * time.Minute
)

var (
	ErrNotConfigured     = errors.New("CRM connection not configured")
	ErrIdentity          = errors.New("CRM connection identity invalid or changed")
	ErrCredential        = errors.New("CRM credential invalid or unavailable")
	ErrResponse          = errors.New("CRM response invalid or unavailable")
	ErrFieldUnavailable  = errors.New("CRM scalar field unavailable")
	ErrRecordUnavailable = errors.New("CRM record unavailable")
	ErrRateLimited       = errors.New("CRM rate limit reached")
	ErrUpstream          = errors.New("CRM service unavailable")
	ErrLimit             = errors.New("CRM observation exceeds supported limit")
)

// Identity pins both the local owner and the remote credential's account.
// Remote IDs are opaque CUID2-compatible strings, never Hash UUIDs or legal IDs.
type Identity struct {
	ID         uuid.UUID `json:"connection_id"`
	OrgID      uuid.UUID `json:"org_id"`
	Generation int64     `json:"generation"`
	Origin     string    `json:"origin"`
	CRMTeamID  string    `json:"crm_team_id"`
	CRMUserID  string    `json:"crm_user_id"`
}

type Connection struct {
	Identity
	Enabled    bool
	VerifiedAt time.Time
	Ciphertext []byte
}

type RecordKind string

const (
	Deal    RecordKind = "crm.deal"
	Contact RecordKind = "crm.contact"
	Company RecordKind = "crm.company"
)

type RecordRef struct {
	Kind RecordKind `json:"kind"`
	ID   string     `json:"id"`
}

// Scalar preserves absent, null and successfully empty values independently.
// Value contains exact strings, json.Number decimal text or canonical booleans.
type Scalar struct {
	Present bool   `json:"present"`
	Null    bool   `json:"null"`
	Value   string `json:"value"`
}

type CredentialObservation struct {
	CRMUserID  string    `json:"crm_user_id"`
	CRMTeamID  string    `json:"crm_team_id"`
	IsActive   bool      `json:"is_active"`
	Name       string    `json:"name,omitempty"`
	Email      string    `json:"email,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	BodySHA256 string    `json:"body_sha256"`
}

type RecordObservation struct {
	Kind            RecordKind        `json:"kind"`
	ID              string            `json:"id"`
	CRMTeamID       string            `json:"crm_team_id"`
	ObservedAt      time.Time         `json:"observed_at"`
	RecordUpdatedAt time.Time         `json:"record_updated_at"`
	BodySHA256      string            `json:"body_sha256"`
	Fields          map[string]Scalar `json:"fields"`
	Relationships   map[string]Scalar `json:"relationships"`
}

type Snapshot struct {
	Identity         Identity              `json:"identity"`
	StartedAt        time.Time             `json:"started_at"`
	CompletedAt      time.Time             `json:"completed_at"`
	CredentialBefore CredentialObservation `json:"credential_before"`
	CredentialAfter  CredentialObservation `json:"credential_after"`
	Records          []RecordObservation   `json:"records"`
}

// Record returns a defensive copy so an adapter cannot mutate a shared snapshot.
func (s Snapshot) Record(kind RecordKind, id string) (RecordObservation, bool) {
	for _, r := range s.Records {
		if r.Kind == kind && r.ID == id {
			r.Fields = cloneScalars(r.Fields)
			r.Relationships = cloneScalars(r.Relationships)
			return r, true
		}
	}
	return RecordObservation{}, false
}

func cloneScalars(src map[string]Scalar) map[string]Scalar {
	dst := make(map[string]Scalar, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Value selects only the reviewed scalar catalog. Whole objects, nested JSON,
// absent fields and permission-filtered nulls are never contractual strings.
func (r RecordObservation) Value(path string) (string, error) {
	if _, ok := fieldCatalog(r.Kind)[path]; !ok {
		return "", ErrFieldUnavailable
	}
	v, ok := r.Fields[path]
	if !ok || !v.Present || v.Null {
		return "", ErrFieldUnavailable
	}
	return v.Value, nil
}

func ValidateRecordRef(ref RecordRef) error {
	if ref.Kind != Deal && ref.Kind != Contact && ref.Kind != Company {
		return ErrIdentity
	}
	return validateOpaqueID(ref.ID)
}

func validateOpaqueID(id string) error {
	if id == "" || len(id) > MaxOpaqueIDBytes {
		return ErrIdentity
	}
	for i := range len(id) {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ErrIdentity
		}
	}
	return nil
}

func ValidateIdentity(id Identity) error { return validateIdentity(id, false) }

func validateIdentity(id Identity, allowUnmapped bool) error {
	if id.ID == uuid.Nil || id.OrgID == uuid.Nil || id.Generation <= 0 {
		return ErrIdentity
	}
	origin, err := CanonicalOrigin(id.Origin, true)
	if err != nil || origin != id.Origin {
		return ErrIdentity
	}
	if allowUnmapped && id.CRMTeamID == "" && id.CRMUserID == "" {
		return nil
	}
	if validateOpaqueID(id.CRMTeamID) != nil || validateOpaqueID(id.CRMUserID) != nil {
		return ErrIdentity
	}
	return nil
}

// CanonicalOrigin accepts an origin, never a customer-controlled API path.
// HTTP is allowed only through the caller's explicit development setting.
func CanonicalOrigin(raw string, allowHTTPDevelopment bool) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || len(raw) > 2048 {
		return "", ErrIdentity
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrIdentity
	}
	if u.Scheme != "https" && !(allowHTTPDevelopment && u.Scheme == "http") {
		return "", ErrIdentity
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.HasSuffix(host, ".") {
		return "", ErrIdentity
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", ErrIdentity
			}
			for i := range len(label) {
				c := label[i]
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
					return "", ErrIdentity
				}
			}
		}
	}
	port := u.Port()
	if port != "" {
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return "", ErrIdentity
		}
		if u.Scheme == "https" && port == "443" || u.Scheme == "http" && port == "80" {
			port = ""
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", ErrIdentity
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}
