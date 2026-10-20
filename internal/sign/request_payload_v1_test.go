// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These native tests use actual generated LookupByToken and private issuance
// over explicit synthetic SQL rows. They do not prove owned PostgreSQL, M89
// resource collection, atomic sidecar capture, restart or fitted dispatch.
type requestPayloadTestAdmissionV1 struct {
	calls, releases      int
	budget               requestPayloadBudgetV1
	err                  error
	maxOrigin, maxIntent int64
	before               func(requestPayloadBudgetV1)
}

func (a *requestPayloadTestAdmissionV1) AcquireRequestPayloadV1(_ context.Context, b requestPayloadBudgetV1) (func(), error) {
	a.calls++
	a.budget = b
	if a.before != nil {
		a.before(b)
	}
	if a.err != nil {
		return nil, a.err
	}
	if (a.maxOrigin > 0 && b.OriginBytes > a.maxOrigin) || (a.maxIntent > 0 && b.IntentBytes > a.maxIntent) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	return func() { a.releases++ }, nil
}
func requestPayloadTestIssueV1(t *testing.T, f *presentedCredentialTestFixtureV1) (*RecipientContext, *fittedSigningIntentV1) {
	t.Helper()
	rc := f.lookup(t)
	i, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, presentedCredentialTestInputV1(t, rc))
	if err != nil {
		t.Fatal(err)
	}
	return rc, i
}
func requestPayloadTestCaptureV1(t *testing.T, f *presentedCredentialTestFixtureV1, rc *RecipientContext, i *fittedSigningIntentV1) (*durableRequestPayloadV1, *requestPayloadTestAdmissionV1) {
	t.Helper()
	a := &requestPayloadTestAdmissionV1{}
	p, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.releaseV1)
	return p, a
}
func TestRequestPayloadV1ActualIssuerCanonicalRoundTrip(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	p, a := requestPayloadTestCaptureV1(t, f, rc, i)
	if a.calls != 1 || a.budget.OriginBytes != int64(len(p.origin)) || a.budget.IntentBytes != int64(len(p.intent)) || a.budget.WorkingBytes <= a.budget.OriginBytes+a.budget.IntentBytes {
		t.Fatalf("incorrect admitted byte metadata: %+v", a.budget)
	}
	if p.header.OriginSHA256 != sha256.Sum256(p.origin) || p.header.IntentSHA256 != sha256.Sum256(p.intent) || p.header.IntentSHA256 != p.header.SemanticIntentSHA256 {
		t.Fatal("body commitments differ from independent SHA oracle")
	}
	var wire acceptedIntentWireV1
	if err := json.Unmarshal(p.intent, &wire); err != nil {
		t.Fatal(err)
	}
	canonical, err := i.notice.Snapshot.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := json.Marshal(wire.Notice.Snapshot)
	if err != nil || !bytes.Equal(canonical, frozen) {
		t.Fatal("private wire changed Article13 canonical snapshot")
	}
	if wire.Notice.evidenceV1() != i.notice {
		t.Fatal("full legal material was changed or omitted")
	}
	fresh, freshIntent := requestPayloadTestIssueV1(t, f)
	b := &requestPayloadTestAdmissionV1{}
	rebound, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, freshIntent, p.header, p.origin, p.intent, b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rebound.payload.origin, p.origin) || !bytes.Equal(rebound.payload.intent, p.intent) || !rebound.intent.credential.matchesContextV1(rebound.context) {
		t.Fatal("rebound private origin differs")
	}
	rebound.payload.releaseV1()
	rebound.payload.releaseV1()
	if b.releases != 1 {
		t.Fatal("lease release is not exactly once")
	}
	p.releaseV1()
	p.releaseV1()
	if a.releases != 1 {
		t.Fatal("capture lease release is not exactly once")
	}
}
func TestRequestPayloadV1RequiresActualSameEnginePrivateIssue(t *testing.T) {
	cases := []struct {
		name   string
		change func(*presentedCredentialTestFixtureV1, **RecipientContext, **fittedSigningIntentV1)
	}{
		{"exported context only", func(_ *presentedCredentialTestFixtureV1, rc **RecipientContext, _ **fittedSigningIntentV1) {
			copyRC := **rc
			copyRC.presentedCredential = nil
			*rc = &copyRC
		}},
		{"intent absent", func(_ *presentedCredentialTestFixtureV1, _ **RecipientContext, i **fittedSigningIntentV1) { *i = nil }},
		{"other lookup receipt", func(f *presentedCredentialTestFixtureV1, rc **RecipientContext, _ **fittedSigningIntentV1) {
			*rc = f.lookup(t)
		}},
		{"different engine", func(f *presentedCredentialTestFixtureV1, _ **RecipientContext, _ **fittedSigningIntentV1) {
			f.engine = &Engine{Now: func() time.Time { return f.now }}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc, i := requestPayloadTestIssueV1(t, f)
			tc.change(f, &rc, &i)
			a := &requestPayloadTestAdmissionV1{}
			if _, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, a); err == nil {
				t.Fatal("unproven issuer admitted")
			}
			if a.calls != 0 {
				t.Fatal("unproven issuer consumed body admission")
			}
		})
	}
}
func TestRequestPayloadV1MutationAfterIssuanceCannotRewriteOrigin(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RecipientContext)
	}{
		{"token", func(rc *RecipientContext) { rc.Recipient.MagicTokenHash[0] ^= 1 }},
		{"recipient deadline", func(rc *RecipientContext) {
			rc.Recipient.MagicTokenExpiresAt.Time = rc.Recipient.MagicTokenExpiresAt.Time.Add(time.Hour)
		}},
		{"document deadline", func(rc *RecipientContext) { rc.Document.ExpiresAt.Time = rc.Document.ExpiresAt.Time.Add(time.Hour) }},
		{"raw controller whitespace", func(rc *RecipientContext) {
			rc.LawfulBasisConfirmation.ControllerName = " " + rc.LawfulBasisConfirmation.ControllerName
		}},
		{"organization", func(rc *RecipientContext) { rc.ControllerOrg.Name += " renamed" }},
		{"notice epoch", func(rc *RecipientContext) {
			rc.Document.Article13NoticeEpochAt.Time = rc.Document.Article13NoticeEpochAt.Time.Add(time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc, i := requestPayloadTestIssueV1(t, f)
			tc.mutate(rc)
			a := &requestPayloadTestAdmissionV1{}
			if _, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, a); err == nil {
				t.Fatal("mutated private request admitted")
			}
			if a.releases != a.calls {
				t.Fatal("admitted refusal leaked resource lease")
			}
		})
	}
}
func TestRequestPayloadV1RenewalPreservesOriginalTTLAndSemanticIntent(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	first, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	originalRecipient := rc.Recipient.MagicTokenExpiresAt
	originalDocument := rc.Document.ExpiresAt
	f.db.recipient.MagicTokenExpiresAt.Time = f.db.recipient.MagicTokenExpiresAt.Time.Add(time.Hour)
	f.db.document.ExpiresAt.Time = f.db.document.ExpiresAt.Time.Add(time.Hour)
	f.db.recipient.Status = "viewed"
	f.db.document.Status = "in_progress"
	fresh, freshIntent := requestPayloadTestIssueV1(t, f)
	second, _ := requestPayloadTestCaptureV1(t, f, fresh, freshIntent)
	if first.header.OriginSHA256 == second.header.OriginSHA256 || first.header.SemanticIntentSHA256 != second.header.SemanticIntentSHA256 {
		t.Fatal("mutable origin changed semantic intent or was not captured")
	}
	a := &requestPayloadTestAdmissionV1{}
	rebound, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, freshIntent, first.header, first.origin, first.intent, a)
	if err != nil {
		t.Fatal(err)
	}
	defer rebound.payload.releaseV1()
	if !presentedStampEqualV1(rebound.context.Recipient.MagicTokenExpiresAt, originalRecipient) || !presentedStampEqualV1(rebound.context.Document.ExpiresAt, originalDocument) || rebound.context.Recipient.Status != rc.Recipient.Status || rebound.context.Document.Status != rc.Document.Status {
		t.Fatal("renewal extended original scope/deadlines")
	}
	if !presentedStampEqualV1(fresh.Recipient.MagicTokenExpiresAt, f.db.recipient.MagicTokenExpiresAt) {
		t.Fatal("rebind rewrote fresh lookup")
	}
	if err := ValidateLockedRecipientCredential(rebound.context, presentedFreshRecipientTestV1(fresh), fresh.Document, f.now); err != nil {
		t.Fatal(err)
	}
	f.now = originalRecipient.Time.Add(time.Second)
	_, err = f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, freshIntent, first.header, first.origin, first.intent, &requestPayloadTestAdmissionV1{})
	if !errors.Is(err, ErrMagicLinkExpired) {
		t.Fatalf("original expired request revived: %v", err)
	}
}
func TestRequestPayloadV1NullDeadlineRemainsAbsentOnRebind(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	f.db.document.ExpiresAt = pgtype.Timestamptz{}
	rc, i := requestPayloadTestIssueV1(t, f)
	first, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	var wire requestOriginWireV1
	if err := json.Unmarshal(first.origin, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.DocumentExpiry.Valid || wire.DocumentExpiry.Value != "" {
		t.Fatal("absent deadline lost its nullness")
	}
	f.db.document.ExpiresAt = pgtype.Timestamptz{Valid: true, Time: f.now.Add(time.Hour)}
	fresh, freshIntent := requestPayloadTestIssueV1(t, f)
	rebound, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, freshIntent, first.header, first.origin, first.intent, &requestPayloadTestAdmissionV1{})
	if err != nil {
		t.Fatal(err)
	}
	defer rebound.payload.releaseV1()
	if rebound.context.Document.ExpiresAt.Valid || rebound.intent.credential.documentExpiry.Valid {
		t.Fatal("current finite expiry was substituted into original absence")
	}
}
func TestRequestPayloadV1FullOriginalContextAndIntentRequiredOnRebind(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*presentedCredentialTestFixtureV1)
	}{
		{"token rotated", func(f *presentedCredentialTestFixtureV1) {
			f.db.recipient.MagicTokenHash = bytes.Clone(f.digest)
			f.db.recipient.MagicTokenHash[0] ^= 1
			f.digest = bytes.Clone(f.db.recipient.MagicTokenHash)
		}},
		{"raw controller normalized equivalently", func(f *presentedCredentialTestFixtureV1) {
			f.db.confirmation.ControllerName = " " + f.db.confirmation.ControllerName + " "
		}},
		{"raw org context", func(f *presentedCredentialTestFixtureV1) { f.db.org.Name = " " + f.db.org.Name }},
		{"confirmation time", func(f *presentedCredentialTestFixtureV1) {
			f.db.confirmation.ConfirmedAt.Time = f.db.confirmation.ConfirmedAt.Time.Add(time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc, i := requestPayloadTestIssueV1(t, f)
			p, _ := requestPayloadTestCaptureV1(t, f, rc, i)
			tc.mutate(f)
			fresh, fi := requestPayloadTestIssueV1(t, f)
			a := &requestPayloadTestAdmissionV1{}
			if _, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, fi, p.header, p.origin, p.intent, a); err == nil {
				t.Fatal("changed original raw scope accepted")
			}
			if a.releases != a.calls {
				t.Fatal("rebind refusal leaked lease")
			}
		})
	}
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	p, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	fresh := f.lookup(t)
	in := presentedCredentialTestInputV1(t, fresh)
	in.TypedName = "Different accepted signer"
	fi, err := f.engine.issueFittedSigningIntentV1(context.Background(), fresh, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, fi, p.header, p.origin, p.intent, &requestPayloadTestAdmissionV1{}); err == nil {
		t.Fatal("different accepted name rebound")
	}
}
func TestRequestPayloadV1TamperedBodiesAndClosedCanonicalEncoding(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	p, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	corrupt := bytes.Clone(p.origin)
	corrupt[len(corrupt)/2] ^= 1
	if _, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), rc, i, p.header, corrupt, p.intent, &requestPayloadTestAdmissionV1{}); err == nil {
		t.Fatal("changed body matched trusted original commitment")
	}
	// Recomputed metadata below exercises canonical-format rejection only. It
	// is not a claim that client-supplied hashes authenticate a captured origin.
	cases := []struct {
		name string
		body []byte
	}{
		{"whitespace", append([]byte(" "), p.origin...)},
		{"duplicate schema", bytes.Replace(p.origin, []byte(`{"schema":`), []byte(`{"schema":"hash-presented-request-origin-v1","schema":`), 1)},
		{"unknown field", bytes.Replace(p.origin, []byte(`{"schema":`), []byte(`{"unexpected":true,"schema":`), 1)},
		{"JSON null stamp", bytes.Replace(p.origin, []byte(`"document_expiry":`), []byte(`"document_expiry":null,"discarded":`), 1)},
		{"trailing value", append(bytes.Clone(p.origin), []byte("{}")...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header := p.header
			header.OriginBytes = int64(len(tc.body))
			header.OriginSHA256 = sha256.Sum256(tc.body)
			a := &requestPayloadTestAdmissionV1{}
			if _, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), rc, i, header, tc.body, p.intent, a); err == nil {
				t.Fatal("noncanonical/unknown JSON accepted")
			}
			if a.releases != a.calls {
				t.Fatal("canonical refusal leaked lease")
			}
		})
	}
	var wire requestOriginWireV1
	if err := json.Unmarshal(p.origin, &wire); err != nil {
		t.Fatal(err)
	}
	wire.DocumentExpiry.Valid = false
	altered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	header := p.header
	header.OriginBytes = int64(len(altered))
	header.OriginSHA256 = sha256.Sum256(altered)
	if _, err = f.engine.rebindDurableRequestPayloadV1(context.Background(), rc, i, header, altered, p.intent, &requestPayloadTestAdmissionV1{}); err == nil {
		t.Fatal("false timestamp with retained nonempty value accepted")
	}
}
func TestRequestPayloadV1ExactBudgetRefusesBeforeDigestSerialization(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	good := i.notice
	// Fault injection keeps the envelope shape valid but makes the digest wrong.
	// Admission must run before the full digest checker serializes Snapshot.
	i.notice.Digest = strings.Repeat("0", 64)
	denied := errors.New("test exact byte admission denied")
	a := &requestPayloadTestAdmissionV1{err: denied}
	if _, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, a); !errors.Is(err, denied) {
		t.Fatalf("serialized/check-digested before admission: %v", err)
	}
	if a.calls != 1 || a.releases != 0 {
		t.Fatal("wrong denial lifecycle")
	}
	i.notice = good
	p, admitted := requestPayloadTestCaptureV1(t, f, rc, i)
	ob, ib := int64(len(p.origin)), int64(len(p.intent))
	a = &requestPayloadTestAdmissionV1{before: func(b requestPayloadBudgetV1) {
		if b.OriginBytes != ob || b.IntentBytes != ib {
			t.Fatal("estimated rather than exact wire cost")
		}
	}, err: denied}
	if _, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, a); !errors.Is(err, denied) {
		t.Fatal("one-byte-below caller admission not retained")
	}
	if admitted.budget.OriginBytes != ob || admitted.budget.IntentBytes != ib {
		t.Fatal("positive exact boundary differs")
	}
	for _, tc := range []struct {
		name           string
		origin, intent int64
		accepted       bool
	}{{"origin one byte below", ob - 1, ib, false}, {"intent one byte below", ob, ib - 1, false}, {"exact bytes", ob, ib, true}} {
		t.Run(tc.name, func(t *testing.T) {
			limit := &requestPayloadTestAdmissionV1{maxOrigin: tc.origin, maxIntent: tc.intent}
			result, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, limit)
			if (err == nil) != tc.accepted {
				t.Fatalf("exact budget boundary: %v", err)
			}
			if result != nil {
				result.releaseV1()
			}
			if limit.calls != 1 || limit.releases != boolRequestPayloadTestV1(tc.accepted) {
				t.Fatal("incorrect boundary lease lifecycle")
			}
		})
	}
	if _, err := f.engine.captureDurableRequestPayloadV1(context.Background(), rc, i, nil); err == nil {
		t.Fatal("missing resource authority admitted")
	}
	header := p.header
	header.OriginBytes = requestOriginMaxBytesV1 + 1
	a = &requestPayloadTestAdmissionV1{}
	if _, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), rc, i, header, p.origin, p.intent, a); err == nil || a.calls != 0 {
		t.Fatal("over-ceiling metadata dispatched to body admission")
	}
}
func TestRequestPayloadV1UnboundedRawContextUsesExactCommitmentLoan(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rawPrefix := strings.Repeat(" ", 300000)
	f.db.org.Name = rawPrefix + f.db.org.Name
	f.db.confirmation.ControllerName = rawPrefix + f.db.confirmation.ControllerName
	rc, i := requestPayloadTestIssueV1(t, f)
	p, a := requestPayloadTestCaptureV1(t, f, rc, i)
	var w requestOriginWireV1
	if err := json.Unmarshal(p.origin, &w); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(f.db.confirmation.ControllerName))
	if w.ControllerName.SHA256 != hexForRequestPayloadTestV1(digest) || w.ControllerName.Bytes != int64(len(f.db.confirmation.ControllerName)) || a.budget.RawContextBytes < 600000 {
		t.Fatal("raw bytes were trimmed, arbitrarily capped, or uncharged")
	}
	if bytes.Contains(p.origin, []byte(rawPrefix)) || len(p.origin) >= requestOriginMaxBytesV1 {
		t.Fatal("unbounded raw context copied into body")
	}
	fresh, fi := requestPayloadTestIssueV1(t, f)
	r, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), fresh, fi, p.header, p.origin, p.intent, &requestPayloadTestAdmissionV1{})
	if err != nil {
		t.Fatal(err)
	}
	r.payload.releaseV1()
}
func hexForRequestPayloadTestV1(value [sha256.Size]byte) string {
	const digits = "0123456789abcdef"
	var out [64]byte
	for j, b := range value {
		out[j*2] = digits[b>>4]
		out[j*2+1] = digits[b&15]
	}
	return string(out[:])
}
func TestRequestPayloadV1MaximumLegalEvidenceAndExactJSONOracle(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	in := presentedCredentialTestInputV1(t, rc)
	in.TypedName = strings.Repeat("<", 200)
	in.Font = "Homemade Apple"
	in.Notice.Snapshot.Processor = strings.Repeat("<", 200)
	in.Notice.Snapshot.SupervisoryAuthority = strings.Repeat("&", 300)
	in.Notice.Snapshot.PolicyURL = "/" + strings.Repeat("<", 2047)
	evidence, err := article13.NewEvidence(in.Notice.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	in.Notice = evidence
	i, err = f.engine.issueFittedSigningIntentV1(context.Background(), rc, in)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	if !bytes.Contains(p.intent, []byte(`\u003c`)) {
		t.Fatal("escaping fixture did not exercise HTML expansion")
	}
	// All27 Copy fields at4000 bytes are supported Article13 schema material.
	// This isolated wire-budget oracle does NOT forge a private fitted intent:
	// the actual fitted issuer correctly requires current RenderedCopyV1 words.
	snapshot := in.Notice.Snapshot
	copyValue := reflect.ValueOf(&snapshot.Copy).Elem()
	for n := 0; n < copyValue.NumField(); n++ {
		copyValue.Field(n).SetString(strings.Repeat("<", 4000))
	}
	snapshot.Controller = strings.Repeat("<", 200)
	snapshot.Processor = strings.Repeat("<", 200)
	snapshot.PurposeSummary = strings.Repeat("<", 2000)
	snapshot.LegalBasisDisclosure = strings.Repeat("<", 2000)
	snapshot.SupervisoryAuthority = strings.Repeat("<", 300)
	if err = snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
	evidence, err = article13.NewEvidence(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	w := acceptedIntentFromPrivateV1(i)
	w.Notice = requestNoticeFromArticle13V1(evidence)
	if err = w.validateShapeV1(); err != nil {
		t.Fatal(err)
	}
	exact, err := requestExactJSONBytesV1(context.Background(), w)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(w)
	if err != nil || exact != int64(len(body)) || exact > acceptedIntentMaxBytesV1 || exact < 650000 {
		t.Fatalf("max legal evidence size mismatch: %d / %d / %v", exact, len(body), err)
	}
	origin, err := requestOriginFromCredentialV1(rc.presentedCredential)
	if err != nil {
		t.Fatal(err)
	}
	origin.DocumentName = strings.Repeat("<", 65536)
	origin.Role = strings.Repeat("r", 64)
	if err = origin.validateV1(); err != nil {
		t.Fatal(err)
	}
	exact, err = requestExactJSONBytesV1(context.Background(), origin)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(origin)
	if err != nil || exact != int64(len(body)) || exact > requestOriginMaxBytesV1 {
		t.Fatal("65536-byte original name was not admitted exactly")
	}
	for _, s := range []string{"quote\"slash\\", "line\n\r\t\b\f\x00", "<>&", "\u2028\u2029", "合法🙂"} {
		exact, err = requestExactJSONBytesV1(context.Background(), s)
		body, marshalErr := json.Marshal(s)
		if err != nil || marshalErr != nil || exact != int64(len(body)) {
			t.Fatalf("stdlib string escaping differs for fixture: %d/%d %v", exact, len(body), err)
		}
	}
}
func TestRequestPayloadV1CancellationKeepsPrivateCauseAndReleasesLease(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	cause := errors.New("private payload retirement reason")
	ctx, cancel := context.WithCancelCause(context.Background())
	a := &requestPayloadTestAdmissionV1{before: func(requestPayloadBudgetV1) { cancel(cause) }}
	_, err := f.engine.captureDurableRequestPayloadV1(ctx, rc, i, a)
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || err.Error() != ErrSigningAdmissionUnavailableV1.Error() || a.releases != 1 {
		t.Fatalf("cancellation authority/cause/release mismatch: %v %+v", err, a)
	}
	for _, phase := range []string{"escaped counter", "raw context hash", "closed decode"} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(cause)
			switch phase {
			case "escaped counter":
				_, err = requestExactJSONBytesV1(ctx, strings.Repeat("\\", 100000))
			case "raw context hash":
				_, err = requestRawCommitmentV1(ctx, strings.Repeat(" ", 100000))
			case "closed decode":
				var w requestOriginWireV1
				err = requestDecodeCanonicalV1(ctx, []byte("{}"), &w)
			}
			if !errors.Is(err, cause) || err.Error() != ErrSigningAdmissionUnavailableV1.Error() {
				t.Fatal("private cancellation cause lost")
			}
		})
	}
}
func TestRequestPayloadV1ScopeHeaderCannotRebindAnotherTenant(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc, i := requestPayloadTestIssueV1(t, f)
	p, _ := requestPayloadTestCaptureV1(t, f, rc, i)
	for _, name := range []string{"org", "document", "recipient", "epoch", "semantic"} {
		t.Run(name, func(t *testing.T) {
			h := p.header
			switch name {
			case "org":
				h.OrgID = uuid.New()
			case "document":
				h.DocumentID = uuid.New()
			case "recipient":
				h.RecipientID = uuid.New()
			case "epoch":
				h.CeremonyEpoch = f.now.UTC().Format(time.RFC3339Nano)
			case "semantic":
				h.SemanticIntentSHA256[0] ^= 1
			}
			a := &requestPayloadTestAdmissionV1{}
			if _, err := f.engine.rebindDurableRequestPayloadV1(context.Background(), rc, i, h, p.origin, p.intent, a); err == nil || a.calls != 0 {
				t.Fatal("foreign/changed scope reached body work")
			}
		})
	}
}

func boolRequestPayloadTestV1(value bool) int {
	if value {
		return 1
	}
	return 0
}

type requestPayloadProgressContextTestV1 struct {
	context.Context
	checks, at int
	cancel     context.CancelCauseFunc
	cause      error
}

func (c *requestPayloadProgressContextTestV1) Err() error {
	c.checks++
	if c.checks == c.at {
		c.cancel(c.cause)
	}
	return c.Context.Err()
}
func TestRequestPayloadV1CancellationDuringEscapesHashAndDecode(t *testing.T) {
	cause := errors.New("private mid-body request cancellation")
	for _, phase := range []string{"escaped counter", "raw hash", "typed decode"} {
		t.Run(phase, func(t *testing.T) {
			base, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			ctx := &requestPayloadProgressContextTestV1{Context: base, at: 3, cancel: cancel, cause: cause}
			var err error
			switch phase {
			case "escaped counter":
				_, err = requestExactJSONBytesV1(ctx, strings.Repeat("\\", 100000))
			case "raw hash":
				_, err = requestRawCommitmentV1(ctx, strings.Repeat(" ", 100000))
			case "typed decode":
				body, marshalErr := json.Marshal(strings.Repeat("\\", 100000))
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				var result string
				err = requestDecodeCanonicalV1(ctx, body, &result)
			}
			if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || err.Error() != ErrSigningAdmissionUnavailableV1.Error() || ctx.checks < 3 {
				t.Fatalf("mid-work cancellation missed or disclosed: %v (%d checks)", err, ctx.checks)
			}
		})
	}
}
