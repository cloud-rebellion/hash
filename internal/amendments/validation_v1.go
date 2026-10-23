// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxHistoryV1 = 64
const MaxNoticeRecipientsV1 = 32

var (
	ErrInputV1                     = errors.New("invalid later amendment request")
	ErrChangedV1                   = errors.New("agreement head or reviewed amendment changed")
	ErrUnavailableV1               = errors.New("later amendment processing unavailable")
	ErrNoticeArtifactUnavailableV1 = errors.New("version-pinned notice file delivery unavailable")
)

func ValidModeV1(m ModeV1) bool {
	return m == SignatureV1 || m == AcknowledgementV1 || m == AgreedNoticeV1
}
func RevisionV1(s string) (int64, error) {
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 || strconv.FormatInt(n, 10) != s || n > MaxHistoryV1 {
		return 0, ErrInputV1
	}
	return n, nil
}
func textV1(s string, n int) bool {
	return len(s) > 0 && len(s) <= n && utf8.ValidString(s) && !strings.ContainsRune(s, 0) && strings.TrimSpace(s) == s
}
func (b BasisV1) ValidateV1(mode ModeV1) error {
	if !ValidModeV1(mode) {
		return ErrInputV1
	}
	switch b.Kind {
	case "frozen_agreement_policy":
		if b.FrozenPolicyID == nil || *b.FrozenPolicyID == uuid.Nil || b.ClauseReference != "" || b.ReviewedClause != "" || len(b.AllowedModes) != 0 || len(b.AllowedChannels) != 0 || b.EffectiveCondition != "" {
			return ErrInputV1
		}
		return nil
	case "reviewed_legacy_clause":
		if b.FrozenPolicyID != nil || !textV1(b.ClauseReference, 512) || !textV1(b.ReviewedClause, 8192) || !textV1(b.EffectiveCondition, 2048) || len(b.AllowedModes) < 1 || len(b.AllowedModes) > 3 || len(b.AllowedChannels) > 1 {
			return ErrInputV1
		}
		found := false
		for i, m := range b.AllowedModes {
			if !ValidModeV1(m) {
				return ErrInputV1
			}
			for j := 0; j < i; j++ {
				if b.AllowedModes[j] == m {
					return ErrInputV1
				}
			}
			found = found || m == mode
		}
		if !found {
			return ErrInputV1
		}
		for _, c := range b.AllowedChannels {
			if c != "email" {
				return ErrInputV1
			}
		}
		if mode == AgreedNoticeV1 && (len(b.AllowedChannels) != 1 || b.AllowedChannels[0] != "email") {
			return ErrInputV1
		}
		return nil
	default:
		return ErrInputV1
	}
}
func (in CreateV1) ValidateV1(original uuid.UUID) error {
	n, e := RevisionV1(in.ExpectedHeadRevision)
	if e != nil || n == MaxHistoryV1 || original == uuid.Nil || in.RequestID == uuid.Nil || in.AmendmentDocumentID == uuid.Nil || in.AmendmentDocumentID == original || in.ExpectedDocumentUpdatedAt.IsZero() || in.ExpectedDocumentUpdatedAt.Year() < 2000 || in.ExpectedDocumentUpdatedAt.Year() > 9999 || !in.CoverReviewed {
		return ErrInputV1
	}
	if (n == 0) != (in.ExpectedHeadID == nil) || (in.ExpectedHeadID != nil && *in.ExpectedHeadID == uuid.Nil) {
		return ErrInputV1
	}
	return in.Basis.ValidateV1(in.Mode)
}
func (in IssueNoticeV1) ValidateV1() error {
	if n, e := RevisionV1(in.ExpectedHeadRevision); e != nil || n < 1 {
		return ErrInputV1
	}
	if in.RequestID == uuid.Nil || !in.Reviewed || in.ExpectedDocumentUpdatedAt.IsZero() || !textV1(in.Subject, 256) || strings.ContainsAny(in.Subject, "\r\n") || !textV1(in.Text, 16384) || len(in.RecipientEmails) < 1 || len(in.RecipientEmails) > MaxNoticeRecipientsV1 {
		return ErrInputV1
	}
	for i, email := range in.RecipientEmails {
		a, e := mail.ParseAddress(email)
		if e != nil || a.Address != email || a.Name != "" || len(email) > 254 || strings.ContainsAny(email, "\r\n\x00") {
			return ErrInputV1
		}
		for j := 0; j < i; j++ {
			if strings.EqualFold(email, in.RecipientEmails[j]) {
				return ErrInputV1
			}
		}
	}
	return nil
}

// Exact JSON input order is intentional: a replay cannot silently alter a
// reviewed mode, condition, cover confirmation, recipient or notice byte.
func DigestV1(domain string, v any) (string, error) {
	raw, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func RequestDigestV1(in CreateV1) (string, error) {
	return DigestV1("hash:later-amendment-request:v1", in)
}
func BasisDigestV1(in BasisV1) (string, error) { return DigestV1("hash:later-amendment-basis:v1", in) }
func NoticeDigestV1(in IssueNoticeV1) (string, error) {
	return DigestV1("hash:later-amendment-notice:v1", in)
}
func DeliveryStateV1(status string) (string, error) {
	switch status {
	case "pending":
		return "queued", nil
	case "retrying":
		return "retrying", nil
	case "sent":
		return "provider_accepted", nil
	case "failed":
		return "failed", nil
	default:
		return "", ErrUnavailableV1
	}
}
func ValidTimestampV1(t time.Time) bool { return !t.IsZero() && t.Year() >= 2000 && t.Year() <= 9999 }
