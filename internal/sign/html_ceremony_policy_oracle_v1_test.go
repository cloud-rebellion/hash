// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// The three oracle bodies below are saved byte-for-byte from the original
// production predicates, except their names and the private oracle call.
// These synthetic rows prove exact pure predicate/error compatibility only.
// They do not prove actual SQL observations, native ownership, route ordering,
// actor permission, source validation or an accepted signing ceremony.

func htmlCeremonyOriginalNoticeOracleV1(rc *RecipientContext, notice article13.Evidence) error {
	if rc == nil || rc.Document == nil || rc.Recipient == nil {
		return ErrInvalidNoticeEvidence
	}
	if err := notice.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNoticeEvidence, err)
	}
	snapshot := notice.Snapshot
	if snapshot.OrgID != rc.Document.OrgID || snapshot.DocumentID != rc.Document.ID ||
		snapshot.RecipientID != rc.Recipient.ID || !rc.Document.SentAt.Valid ||
		!rc.Document.Article13NoticeEpochAt.Valid ||
		!rc.Document.Article13NoticeEpochAt.Time.Equal(rc.Document.SentAt.Time) ||
		snapshot.Schema != rc.Document.Article13NoticeSchema ||
		snapshot.SentAt != rc.Document.SentAt.Time.UTC().Format(time.RFC3339Nano) {
		return ErrInvalidNoticeEvidence
	}
	return nil
}

func (p *presentedCredentialV1) htmlCeremonyOriginalLockedOracleV1(rc *RecipientContext, rec *generated.Recipient, doc *generated.Document, now time.Time) error {
	if !p.matchesContextV1(rc) || rec == nil || doc == nil || rec.ID != p.recipientID || rec.DocumentID != p.documentID || doc.ID != p.documentID || doc.OrgID != p.orgID ||
		len(rec.MagicTokenHash) != sha256.Size || subtle.ConstantTimeCompare(p.tokenHash[:], rec.MagicTokenHash) != 1 || rec.Role != p.role {
		return ErrMagicLinkExpired
	}
	if err := p.originalLiveV1(now); err != nil {
		return err
	}
	if !presentedStampEqualV1(doc.SentAt, p.sentAt) || !presentedStampEqualV1(doc.Article13NoticeEpochAt, p.noticeEpoch) || doc.Article13NoticeSchema != p.noticeSchema ||
		doc.Article13NoticeEpochV61Committed != p.noticeCommitted || doc.Name != p.documentName || doc.LawfulBasis != p.lawfulBasis {
		return ErrInvalidNoticeEvidence
	}
	return checkLockedMagicLinkExpiry(rec, doc, now)
}

func htmlCeremonyOriginalCredentialOracleV1(rc *RecipientContext, fresh *generated.Recipient, doc *generated.Document, now time.Time) error {
	if rc != nil && rc.presentedCredential != nil {
		if err := rc.presentedCredential.htmlCeremonyOriginalLockedOracleV1(rc, fresh, doc, now); err != nil {
			return err
		}
	}
	if rc == nil || rc.Recipient == nil || rc.Document == nil || fresh == nil || doc == nil ||
		fresh.ID != rc.Recipient.ID || fresh.DocumentID != doc.ID || doc.ID != rc.Document.ID || doc.OrgID != rc.Document.OrgID ||
		len(rc.Recipient.MagicTokenHash) == 0 || subtle.ConstantTimeCompare(rc.Recipient.MagicTokenHash, fresh.MagicTokenHash) != 1 {
		return ErrMagicLinkExpired
	}
	// A later deadline extension cannot revive a request admitted under an
	// earlier expiry. Both the original receipt and retained row must be live.
	if err := checkMagicLinkExpiry(rc.Recipient, rc.Document, now); err != nil {
		return err
	}
	return checkLockedMagicLinkExpiry(fresh, doc, now)
}

func htmlCeremonyAssertSameErrorV1(t *testing.T, want, got error) {
	t.Helper()
	if (want == nil) != (got == nil) {
		t.Fatalf("original=%v pins=%v", want, got)
	}
	if want == nil {
		return
	}
	if want.Error() != got.Error() {
		t.Fatalf("original=%q pins=%q", want.Error(), got.Error())
	}
	for _, sentinel := range []error{ErrInvalidNoticeEvidence, ErrMagicLinkExpired} {
		if errors.Is(want, sentinel) != errors.Is(got, sentinel) {
			t.Fatalf("sentinel %v original=%v pins=%v", sentinel, want, got)
		}
	}
}

func TestHTMLCeremonyNoticePinsOriginalOracleV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RecipientContext, *article13.Evidence)
		valid  bool
	}{
		{"unchanged", nil, true},
		{"missing document", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document = nil }, false},
		{"missing recipient", func(rc *RecipientContext, _ *article13.Evidence) { rc.Recipient = nil }, false},
		{"invalid evidence digest", func(_ *RecipientContext, e *article13.Evidence) { e.Digest = "bad" }, false},
		{"foreign document", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document.ID = uuid.New() }, false},
		{"foreign org", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document.OrgID = uuid.New() }, false},
		{"foreign recipient", func(rc *RecipientContext, _ *article13.Evidence) { rc.Recipient.ID = uuid.New() }, false},
		{"missing sent", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document.SentAt.Valid = false }, false},
		{"missing epoch", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document.Article13NoticeEpochAt.Valid = false }, false},
		{"new epoch", func(rc *RecipientContext, _ *article13.Evidence) {
			rc.Document.Article13NoticeEpochAt.Time = rc.Document.SentAt.Time.Add(time.Nanosecond)
		}, false},
		{"changed schema", func(rc *RecipientContext, _ *article13.Evidence) { rc.Document.Article13NoticeSchema = "different" }, false},
		{"same instant different zone", func(rc *RecipientContext, _ *article13.Evidence) {
			rc.Document.SentAt.Time = rc.Document.SentAt.Time.In(time.FixedZone("fixture", 3600))
			rc.Document.Article13NoticeEpochAt = rc.Document.SentAt
		}, true},
		// This original predicate deliberately does not replace later committed/name/
		// lawful-basis credential checks. Preserve that separation exactly.
		{"commitment checked later", func(rc *RecipientContext, _ *article13.Evidence) {
			rc.Document.Article13NoticeEpochV61Committed = false
		}, true},
		{"document text checked later", func(rc *RecipientContext, _ *article13.Evidence) {
			rc.Document.Name = "changed"
			rc.Document.LawfulBasis = "consent"
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			e := presentedCredentialTestInputV1(t, rc).Notice
			if tc.mutate != nil {
				tc.mutate(rc, &e)
			}
			want := htmlCeremonyOriginalNoticeOracleV1(rc, e)
			var got error
			if rc == nil || rc.Document == nil || rc.Recipient == nil {
				got = ErrInvalidNoticeEvidence
			} else {
				got = validateHTMLCeremonyNoticePinsV1(htmlCeremonyDocumentPinsForV1(rc.Document), rc.Recipient.ID, e)
			}
			htmlCeremonyAssertSameErrorV1(t, want, got)
			if (got == nil) != tc.valid {
				t.Fatalf("valid=%v got=%v", tc.valid, got)
			}
		})
	}
	rc := (*RecipientContext)(nil)
	htmlCeremonyAssertSameErrorV1(t, htmlCeremonyOriginalNoticeOracleV1(rc, article13.Evidence{}), validateHTMLCeremonyNoticePinsV1(htmlCeremonyDocumentPinsV1{}, uuid.Nil, article13.Evidence{}))
}

func TestHTMLCeremonyCredentialPinsOriginalOracleV1(t *testing.T) {
	type fixture struct {
		rc    *RecipientContext
		fresh *generated.Recipient
		doc   *generated.Document
		now   time.Time
	}
	cases := []struct {
		name   string
		mutate func(*fixture)
		want   error
	}{
		{"unchanged", nil, nil},
		{"nil context", func(f *fixture) { f.rc = nil }, ErrMagicLinkExpired},
		{"nil fresh recipient", func(f *fixture) { f.fresh = nil }, ErrMagicLinkExpired},
		{"nil fresh document", func(f *fixture) { f.doc = nil }, ErrMagicLinkExpired},
		{"foreign fresh document", func(f *fixture) { f.doc.ID = uuid.New() }, ErrMagicLinkExpired},
		{"foreign fresh org", func(f *fixture) { f.doc.OrgID = uuid.New() }, ErrMagicLinkExpired},
		{"foreign recipient", func(f *fixture) { f.fresh.ID = uuid.New() }, ErrMagicLinkExpired},
		{"foreign recipient parent", func(f *fixture) { f.fresh.DocumentID = uuid.New() }, ErrMagicLinkExpired},
		{"short fresh hash", func(f *fixture) { f.fresh.MagicTokenHash = []byte{1} }, ErrMagicLinkExpired},
		{"rotated fresh hash", func(f *fixture) { f.fresh.MagicTokenHash[0] ^= 1 }, ErrMagicLinkExpired},
		{"changed fresh role", func(f *fixture) { f.fresh.Role = "observer" }, ErrMagicLinkExpired},
		{"changed fresh name", func(f *fixture) { f.doc.Name = "new notice purpose" }, ErrInvalidNoticeEvidence},
		{"changed fresh lawful basis", func(f *fixture) { f.doc.LawfulBasis = "consent" }, ErrInvalidNoticeEvidence},
		{"changed fresh schema", func(f *fixture) { f.doc.Article13NoticeSchema = "different" }, ErrInvalidNoticeEvidence},
		{"changed fresh committed flag", func(f *fixture) { f.doc.Article13NoticeEpochV61Committed = false }, ErrInvalidNoticeEvidence},
		{"changed fresh sent", func(f *fixture) { f.doc.SentAt.Time = f.doc.SentAt.Time.Add(time.Nanosecond) }, ErrInvalidNoticeEvidence},
		{"changed fresh epoch", func(f *fixture) {
			f.doc.Article13NoticeEpochAt.Time = f.doc.Article13NoticeEpochAt.Time.Add(time.Nanosecond)
		}, ErrInvalidNoticeEvidence},
		{"changed original source pin", func(f *fixture) { f.rc.Document.SourceKind = "html" }, ErrMagicLinkExpired},
		{"changed original name", func(f *fixture) { f.rc.Document.Name = "mutable original" }, ErrMagicLinkExpired},
		{"changed original deadline", func(f *fixture) { f.rc.Document.ExpiresAt.Time = f.now.Add(time.Hour) }, ErrMagicLinkExpired},
		{"fresh recipient expired", func(f *fixture) { f.fresh.MagicTokenExpiresAt.Time = f.now.Add(-time.Nanosecond) }, ErrMagicLinkExpired},
		{"fresh document expired", func(f *fixture) { f.doc.ExpiresAt.Time = f.now.Add(-time.Nanosecond) }, ErrMagicLinkExpired},
		{"equal fresh deadline historical boundary", func(f *fixture) { f.fresh.MagicTokenExpiresAt.Time = f.now; f.doc.ExpiresAt.Time = f.now }, nil},
		{"original expiry not revived by later fresh rows", func(f *fixture) {
			f.now = f.rc.Recipient.MagicTokenExpiresAt.Time.Add(time.Nanosecond)
			f.fresh.MagicTokenExpiresAt.Time = f.now.Add(time.Hour)
			f.doc.ExpiresAt.Time = f.now.Add(time.Hour)
		}, ErrMagicLinkExpired},
		{"original equality historical boundary", func(f *fixture) { f.now = f.rc.Recipient.MagicTokenExpiresAt.Time }, nil},
		{"fresh zero timestamp", func(f *fixture) {
			f.fresh.MagicTokenExpiresAt = pgtype.Timestamptz{Valid: true}
			f.doc.ExpiresAt = pgtype.Timestamptz{Valid: true}
		}, nil},
		{"fresh positive infinity zero Time", func(f *fixture) {
			f.fresh.MagicTokenExpiresAt = pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity}
			f.doc.ExpiresAt = f.fresh.MagicTokenExpiresAt
		}, nil},
		{"fresh negative infinity zero Time", func(f *fixture) {
			f.fresh.MagicTokenExpiresAt = pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.NegativeInfinity}
			f.doc.ExpiresAt = f.fresh.MagicTokenExpiresAt
		}, nil},
		{"infinite modifier retains original Time comparison", func(f *fixture) {
			f.fresh.MagicTokenExpiresAt = pgtype.Timestamptz{Valid: true, InfinityModifier: pgtype.Infinity, Time: f.now.Add(-time.Second)}
		}, ErrMagicLinkExpired},
		{"identity before changed notice", func(f *fixture) { f.fresh.MagicTokenHash[0] ^= 1; f.doc.Name = "changed" }, ErrMagicLinkExpired},
		{"original expiry before changed notice", func(f *fixture) {
			f.now = f.rc.Recipient.MagicTokenExpiresAt.Time.Add(time.Nanosecond)
			f.doc.Name = "changed"
		}, ErrMagicLinkExpired},
		{"notice change before fresh expiry", func(f *fixture) { f.doc.Name = "changed"; f.fresh.MagicTokenExpiresAt.Time = f.now.Add(-time.Second) }, ErrInvalidNoticeEvidence},
		{"no receipt preserves legacy role behavior", func(f *fixture) { f.rc.presentedCredential = nil; f.fresh.Role = "observer" }, nil},
		{"no receipt still checks both deadlines", func(f *fixture) {
			f.rc.presentedCredential = nil
			f.fresh.MagicTokenExpiresAt.Time = f.now.Add(-time.Second)
		}, ErrMagicLinkExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			doc := *rc.Document
			x := &fixture{rc: rc, fresh: presentedFreshRecipientTestV1(rc), doc: &doc, now: f.now}
			if tc.mutate != nil {
				tc.mutate(x)
			}
			want := htmlCeremonyOriginalCredentialOracleV1(x.rc, x.fresh, x.doc, x.now)
			got := validateLockedRecipientPinsV1(x.rc, x.fresh, htmlCeremonyDocumentPinsForV1(x.doc), x.now)
			htmlCeremonyAssertSameErrorV1(t, want, got)
			if tc.want == nil {
				if got != nil {
					t.Fatal(got)
				}
			} else if !errors.Is(got, tc.want) {
				t.Fatalf("want %v got %v", tc.want, got)
			}
		})
	}
}

func TestHTMLCeremonyPinsNoticeAndCredentialMixedRefusalsV1(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	notice := presentedCredentialTestInputV1(t, rc).Notice
	doc := *rc.Document
	doc.Article13NoticeEpochAt.Time = doc.Article13NoticeEpochAt.Time.Add(time.Second)
	locked := *rc
	locked.Document = &doc
	recipient := presentedFreshRecipientTestV1(rc)
	recipient.MagicTokenHash[0] ^= 1
	// The original RequestChanges prefix calls locked-notice before credential.
	// Compare that exact short-circuit composition; actual route order is a
	// separate integration assertion, not established by this pure oracle.
	original := htmlCeremonyOriginalNoticeOracleV1(&locked, notice)
	if original == nil {
		original = htmlCeremonyOriginalCredentialOracleV1(rc, recipient, &doc, f.now)
	}
	pins := htmlCeremonyDocumentPinsForV1(&doc)
	staged := validateHTMLCeremonyNoticePinsV1(pins, rc.Recipient.ID, notice)
	if staged == nil {
		staged = validateLockedRecipientPinsV1(rc, recipient, pins, f.now)
	}
	htmlCeremonyAssertSameErrorV1(t, original, staged)
	if !errors.Is(staged, ErrInvalidNoticeEvidence) {
		t.Fatal(staged)
	}
}
