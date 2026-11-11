// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package sign

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
)

func localizedFittedInputTestV1(t *testing.T, rc *RecipientContext, locale string) SignInput {
	t.Helper()
	in := presentedCredentialTestInputV1(t, rc)
	material, err := article13.LocalizedNoticeV1(rc.Document.Name, rc.Document.LawfulBasis, locale)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := in.Notice.Snapshot
	snapshot.PurposeSummary, snapshot.LegalBasisDisclosure, snapshot.Copy = material.PurposeSummary, material.LegalBasisDisclosure, material.Copy
	in.Notice, err = article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func TestFittedNoticeLocaleV1UsesSameActualServerCopyAndRefusesOtherLanguage(t *testing.T) {
	for _, locale := range []string{"en", "sv", "unknown"} {
		t.Run(locale, func(t *testing.T) {
			fixture := newPresentedCredentialTestFixtureV1(t)
			fixture.db.recipient.Locale = locale
			rc := fixture.lookup(t)
			in := localizedFittedInputTestV1(t, rc, locale)
			if _, err := fixture.engine.issueFittedSigningIntentV1(context.Background(), rc, in); err != nil {
				t.Fatal("actual matching server disclosure refused", err)
			}
			other := "sv"
			if locale == "sv" {
				other = "en"
			}
			stale := localizedFittedInputTestV1(t, rc, other)
			if _, err := fixture.engine.issueFittedSigningIntentV1(context.Background(), rc, stale); !errors.Is(err, ErrInvalidNoticeEvidence) {
				t.Fatal("another-language notice crossed native intent gate", err)
			}
			if err := stale.Notice.Validate(); err != nil {
				t.Fatal("historical snapshot validity was reinterpreted by current locale", err)
			}
		})
	}
}

func TestLockedNoticeLocaleV1RejectsLanguageChangeAcrossWait(t *testing.T) {
	fixture := newPresentedCredentialTestFixtureV1(t)
	fixture.db.recipient.Locale = "sv"
	original := fixture.lookup(t)
	in := localizedFittedInputTestV1(t, original, "sv")
	if _, err := fixture.engine.issueFittedSigningIntentV1(context.Background(), original, in); err != nil {
		t.Fatal(err)
	}
	fresh := presentedFreshRecipientTestV1(original)
	fresh.Locale = "sv"
	if err := ValidateLockedRecipientCredential(original, fresh, original.Document, fixture.now); err != nil {
		t.Fatal("matching locked locale refused", err)
	}
	// The barrier models a changed authoritative row while the request waits.
	// Its send/receive orders the write before the actual postwait predicate.
	resume := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		<-resume
		done <- ValidateLockedRecipientCredential(original, fresh, original.Document, fixture.now)
	}()
	fresh.Locale = "en"
	close(resume)
	if err := <-done; !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatal("changed locked locale did not require fresh acknowledgement", err)
	}
	// The legacy/QES branch retains identity/expiry guards and the same check.
	legacy := &RecipientContext{Recipient: original.Recipient, Document: original.Document}
	if err := ValidateLockedRecipientCredential(legacy, fresh, original.Document, fixture.now); !errors.Is(err, ErrInvalidNoticeEvidence) {
		t.Fatal("legacy locked path ignored changed locale", err)
	}
	original.Recipient.Locale = "unknown"
	if err := ValidateLockedRecipientCredential(legacy, fresh, original.Document, fixture.now); err != nil {
		t.Fatal("equivalent English fallback created a false language conflict", err)
	}
}

func TestSwedishFittedNoticeV1PreservesCancellationAndNoSideEffects(t *testing.T) {
	fixture := newPresentedCredentialTestFixtureV1(t)
	fixture.db.recipient.Locale = "sv"
	rc := fixture.lookup(t)
	in := localizedFittedInputTestV1(t, rc, "sv")
	calls := fixture.db.calls
	cause := errors.New("private cancellation detail")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(cause)
	if _, err := fixture.engine.issueFittedSigningIntentV1(ctx, rc, in); !errors.Is(err, context.Canceled) || !errors.Is(err, cause) || strings.Contains(err.Error(), cause.Error()) {
		t.Fatal("cancellation identity or disclosure contract changed", err)
	}
	if fixture.db.calls != calls {
		t.Fatal("cancelled localized intent performed new SQL work")
	}
}

func TestLockedNoticeLocaleV1PreservesExpiredCredentialRefusal(t *testing.T) {
	fixture := newPresentedCredentialTestFixtureV1(t)
	fixture.db.recipient.Locale = "sv"
	original := fixture.lookup(t)
	fresh := presentedFreshRecipientTestV1(original)
	fresh.Locale = "en"
	fresh.MagicTokenExpiresAt.Time = fixture.now.Add(-time.Nanosecond)
	for _, rc := range []*RecipientContext{original, {Recipient: original.Recipient, Document: original.Document}} {
		if err := ValidateLockedRecipientCredential(rc, fresh, original.Document, fixture.now); !errors.Is(err, ErrMagicLinkExpired) {
			t.Fatal("new notice check ran ahead of existing credential expiry", err)
		}
	}
}
