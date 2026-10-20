//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

// Pure controls for NEW403 handoff/refusal contracts. These tests do not
// produce a browser/worker/native/renderer result and are unexecuted in packet.
import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func packageBrowserProtocolFixture403() packageBrowserStage403 {
	root := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	provider := uuid.MustParse("20000000-0000-0000-0000-000000000002")
	customer := uuid.MustParse("30000000-0000-0000-0000-000000000003")
	return packageBrowserStage403{Schema: 1, Stage: 1, RootID: root, AttemptID: uuid.MustParse("40000000-0000-0000-0000-000000000004"), PackageID: uuid.MustParse("50000000-0000-0000-0000-000000000005"), Revision: "1", Generation: "3", RootUpdatedAt: "2026-10-19T12:00:00Z", NoticeEpoch: "2026-10-19T12:00:01Z", ManifestSHA256: strings.Repeat("a", 64), LegalSHA256: strings.Repeat("b", 64), IncorporationVersion: "hash-package-incorporation-v1", IncorporationSHA256: strings.Repeat("c", 64), Members: []packageBrowserMember403{{ID: root, Title: "Main", SHA256: strings.Repeat("d", 64), Bytes: 1024, Pages: 2, SourceCommitment: strings.Repeat("e", 64), Materialization: 1}, {ID: uuid.MustParse("60000000-0000-0000-0000-000000000006"), Title: "DPA", Category: "DPA", SHA256: strings.Repeat("f", 64), Bytes: 512, Pages: 1}, {ID: uuid.MustParse("70000000-0000-0000-0000-000000000007"), Title: "NDA", Category: "NDA", SHA256: strings.Repeat("1", 64), Bytes: 512, Pages: 1}}, Parties: []packageBrowserParty403{{RecipientID: provider, Name: "Provider", Role: "provider", Email: "provider@example.test", Token: strings.Repeat("a", 43), NoticeDigest: strings.Repeat("2", 64)}, {RecipientID: customer, Name: "Customer", Role: "customer", Email: "customer@example.test", Token: strings.Repeat("b", 43), NoticeDigest: strings.Repeat("3", 64)}}, Fields: []map[string]any{{"id": "provider-field", "recipient_id": provider}, {"id": "customer-field", "recipient_id": customer}}}
}
func packageBrowserCloneStage403(t *testing.T, value packageBrowserStage403) packageBrowserStage403 {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("private synthetic vector encoding failed")
	}
	var copy packageBrowserStage403
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("private synthetic vector copy failed")
	}
	return copy
}
func packageBrowserSecondFixture403(t *testing.T, first packageBrowserStage403) packageBrowserStage403 {
	second := packageBrowserCloneStage403(t, first)
	second.Stage = 2
	second.AttemptID = uuid.MustParse("80000000-0000-0000-0000-000000000008")
	second.Revision = "2"
	second.RootUpdatedAt = "2026-10-19T12:00:02Z"
	second.NoticeEpoch = "2026-10-19T12:00:03Z"
	second.ManifestSHA256 = strings.Repeat("4", 64)
	second.LegalSHA256 = strings.Repeat("5", 64)
	second.Members[0].SHA256 = strings.Repeat("6", 64)
	second.Members[0].SourceCommitment = strings.Repeat("7", 64)
	second.Members[0].Materialization = 2
	second.Parties[0].Token = strings.Repeat("c", 43)
	second.Parties[1].Token = strings.Repeat("d", 43)
	return second
}
func TestPackageBrowser403TwoExactStageVectors(t *testing.T) {
	first := packageBrowserProtocolFixture403()
	second := packageBrowserSecondFixture403(t, first)
	if packageBrowserValidateStage403(first, nil) != nil || packageBrowserValidateStage403(second, &first) != nil {
		t.Fatal("declared two-stage protocol rejected")
	}
}
func TestPackageBrowser403ChangedStageAndOriginalAnnexRefusals(t *testing.T) {
	first := packageBrowserProtocolFixture403()
	for _, name := range []string{"schema", "stage", "root", "attempt", "package", "revision", "generation", "clock", "epoch", "manifest", "legal", "incorporation", "annex-hash", "annex-order", "annex-title", "annex-id", "main-hash", "main-source", "materialization", "party-id", "party-role", "party-name", "reused-token", "cross-reused-token", "duplicate-token", "member-count", "party-count", "field-count", "aggregate-bytes", "aggregate-pages"} {
		t.Run(name, func(t *testing.T) {
			second := packageBrowserSecondFixture403(t, first)
			switch name {
			case "schema":
				second.Schema = 2
			case "stage":
				second.Stage = 3
			case "root":
				second.RootID = uuid.New()
			case "attempt":
				second.AttemptID = first.AttemptID
			case "package":
				second.PackageID = uuid.New()
			case "revision":
				second.Revision = "3"
			case "generation":
				second.Generation = "03"
			case "clock":
				second.RootUpdatedAt = "not-time"
			case "epoch":
				second.NoticeEpoch = first.NoticeEpoch
			case "manifest":
				second.ManifestSHA256 = first.ManifestSHA256
			case "legal":
				second.LegalSHA256 = first.LegalSHA256
			case "incorporation":
				second.IncorporationSHA256 = strings.Repeat("8", 64)
			case "annex-hash":
				second.Members[1].SHA256 = strings.Repeat("9", 64)
			case "annex-order":
				second.Members[1], second.Members[2] = second.Members[2], second.Members[1]
			case "annex-title":
				second.Members[1].Title = "Later DPA"
			case "annex-id":
				second.Members[1].ID = uuid.New()
			case "main-hash":
				second.Members[0].SHA256 = first.Members[0].SHA256
			case "main-source":
				second.Members[0].SourceCommitment = first.Members[0].SourceCommitment
			case "materialization":
				second.Members[0].Materialization = 1
			case "party-id":
				second.Parties[0].RecipientID = uuid.New()
			case "party-role":
				second.Parties[0].Role = "signer"
			case "party-name":
				second.Parties[0].Name = "Other identity"
			case "reused-token":
				second.Parties[0].Token = first.Parties[0].Token
			case "cross-reused-token":
				second.Parties[0].Token = first.Parties[1].Token
			case "duplicate-token":
				second.Parties[1].Token = second.Parties[0].Token
			case "member-count":
				second.Members = second.Members[:2]
			case "party-count":
				second.Parties = second.Parties[:1]
			case "field-count":
				second.Fields = second.Fields[:1]
			case "aggregate-bytes":
				second.Members[0].Bytes = 50 << 20
			case "aggregate-pages":
				second.Members[0].Pages = 500
			}
			if packageBrowserValidateStage403(second, &first) == nil {
				t.Fatal("changed exact stage accepted")
			}
		})
	}
}
func TestPackageBrowser403MissingOrMalformedPrivateStageRefuses(t *testing.T) {
	for _, name := range []string{"missing-token", "bad-token", "bad-digest", "zero-root", "duplicate-member", "duplicate-party", "unknown-role", "empty-email", "second-without-first"} {
		t.Run(name, func(t *testing.T) {
			stage := packageBrowserProtocolFixture403()
			switch name {
			case "missing-token":
				stage.Parties[0].Token = ""
			case "bad-token":
				stage.Parties[0].Token = strings.Repeat("!", 43)
			case "bad-digest":
				stage.ManifestSHA256 = strings.Repeat("A", 64)
			case "zero-root":
				stage.RootID = uuid.Nil
			case "duplicate-member":
				stage.Members[2] = stage.Members[1]
			case "duplicate-party":
				stage.Parties[1] = stage.Parties[0]
			case "unknown-role":
				stage.Parties[0].Role = "observer"
			case "empty-email":
				stage.Parties[0].Email = ""
			case "second-without-first":
				stage.Stage = 2
			}
			if packageBrowserValidateStage403(stage, nil) == nil {
				t.Fatal("invalid private stage accepted")
			}
		})
	}
}
func TestPackageBrowser403DoneProtocolExactPositiveAndRefusals(t *testing.T) {
	if ok, err := packageBrowserDecodeDone403([]byte(`{"exit_code":0,"verified":true}`)); err != nil || !ok {
		t.Fatal("exact done rejected")
	}
	for _, raw := range []string{`{}`, `{"verified":true}`, `{"exit_code":0}`, `{"exit_code":0,"verified":false}`, `{"exit_code":1,"verified":true}`, `{"exit_code":0,"verified":true,"extra":true}`, `{"exit_code":0,"verified":false,"verified":true}`, `{"exit_code":0,"verified":true,"verifi\u0065d":true}`, `{"exit_code":"0","verified":true}`, `{"exit_code":0,"verified":true} {}`, strings.Repeat(" ", 1025)} {
		if ok, err := packageBrowserDecodeDone403([]byte(raw)); err == nil || ok {
			t.Fatal("invalid done accepted")
		}
	}
}
func TestPackageBrowser403PrivateFileReaderRefusesSymlinksModesAndOverflow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "done.json")
	if ok, err := packageBrowserReadDone403(path); err != nil || ok {
		t.Fatal("missing done became success")
	}
	raw := []byte(`{"exit_code":0,"verified":true}`)
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write fixture")
	}
	if ok, err := packageBrowserReadDone403(path); err != nil || !ok {
		t.Fatal("private regular done refused")
	}
	if os.Chmod(path, 0644) != nil {
		t.Fatal("chmod fixture")
	}
	if ok, err := packageBrowserReadDone403(path); err == nil || ok {
		t.Fatal("public file accepted")
	}
	_ = os.Remove(path)
	target := filepath.Join(dir, "target.json")
	if os.WriteFile(target, raw, 0600) != nil || os.Symlink(target, path) != nil {
		t.Fatal("symlink fixture")
	}
	if ok, err := packageBrowserReadDone403(path); err == nil || ok {
		t.Fatal("symlink accepted")
	}
	_ = os.Remove(path)
	if os.WriteFile(path, bytes.Repeat([]byte{'x'}, 1025), 0600) != nil {
		t.Fatal("oversize fixture")
	}
	if ok, err := packageBrowserReadDone403(path); err == nil || ok {
		t.Fatal("oversized done accepted")
	}
}
func TestPackageBrowser403PrivateWriterFreshBoundedAndNoOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "private.json")
	if packageBrowserPrivate256(path, map[string]string{"synthetic": "one"}) != nil {
		t.Fatal("private writer failed")
	}
	before, _ := os.ReadFile(path)
	if packageBrowserPrivate256(path, map[string]string{"synthetic": "two"}) == nil {
		t.Fatal("private handoff overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("failed overwrite changed handoff")
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("handoff mode differs")
	}
	if packageBrowserPrivate256(filepath.Join(dir, "large.json"), strings.Repeat("x", 65537)) == nil {
		t.Fatal("oversized handoff accepted")
	}
}
func TestPackageBrowser403StatusWrapperPreservesImplicitHTTP200(t *testing.T) {
	r := httptest.NewRecorder()
	w := &packageBrowserStatus403{ResponseWriter: r}
	_, _ = w.Write([]byte("owned"))
	if w.code != http.StatusOK || r.Code != http.StatusOK || r.Body.String() != "owned" {
		t.Fatal("status forwarding differs")
	}
}
func TestPackageBrowser403ClockTokenAndDecimalBoundaryControls(t *testing.T) {
	if !packageBrowserClock403(time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)) || packageBrowserClock403("2026-10-19T14:00:00+02:00") {
		t.Fatal("canonical UTC clock boundary differs")
	}
	for _, raw := range []string{"0", "-1", "01", "+1", "9223372036854775808"} {
		if _, ok := packageBrowserPositive403(raw); ok {
			t.Fatal("invalid positive decimal accepted")
		}
	}
	for _, raw := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 44), strings.Repeat("a", 42) + "/"} {
		if packageBrowserToken403(raw) {
			t.Fatal("invalid token alphabet/length accepted")
		}
	}
}

func TestPackageBrowser403OneOwnedRevisionPUTAndNoOverwrite(t *testing.T) {
	org := uuid.MustParse("90000000-0000-0000-0000-000000000009")
	oldKey := "org/" + org.String() + "/documents/10000000-0000-0000-0000-000000000001.pdf"
	newKey := "org/" + org.String() + "/documents/20000000-0000-0000-0000-000000000002.pdf"
	nextKey := "org/" + org.String() + "/documents/30000000-0000-0000-0000-000000000003.pdf"
	fresh := func() *packageBrowserPeer403 {
		base := &htmlCreationStorageE2E{importStoragePeer: &importStoragePeer{objects: map[string][]byte{oldKey: []byte("original")}}}
		return &packageBrowserPeer403{strict: &completedPackagePeer248{main: &packageRetentionNativePeer240{base: base}, mainKey: oldKey, originalKeys: map[string]struct{}{oldKey: {}}}, org: org}
	}
	put := func(peer *packageBrowserPeer403, key string, authorized bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "http://owned/hash-import-fixture/"+key, strings.NewReader("owned-new-body"))
		r.Header.Set("Content-Type", "application/pdf")
		if authorized {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 controlled-synthetic")
		}
		w := httptest.NewRecorder()
		peer.ServeHTTP(w, r)
		return w
	}
	for _, name := range []string{"before-first-Send", "without-SDK-auth", "existing-object"} {
		t.Run(name, func(t *testing.T) {
			peer := fresh()
			key := newKey
			authorized := true
			if name != "before-first-Send" {
				peer.revision403(true)
			}
			if name == "without-SDK-auth" {
				authorized = false
			}
			if name == "existing-object" {
				key = oldKey
			}
			if put(peer, key, authorized).Code != 400 || peer.revisionKey != "" || string(peer.strict.main.base.objects[oldKey]) != "original" {
				t.Fatal("unowned draft write or original overwrite accepted")
			}
		})
	}
	peer := fresh()
	peer.revision403(true)
	if put(peer, newKey, true).Code != 200 || peer.revisionKey != newKey || string(peer.strict.main.base.objects[newKey]) != "owned-new-body" {
		t.Fatal("one declared revision PUT failed")
	}
	if peer.register403(nextKey) == nil {
		t.Fatal("wrong revision registered as retained original")
	}
	if peer.register403(newKey) != nil {
		t.Fatal("actual new key failed registration")
	}
	if _, ok := peer.strict.originalKeys[newKey]; !ok {
		t.Fatal("new exact key not passed to original retention policy")
	}
	if put(peer, nextKey, true).Code != 400 || string(peer.strict.main.base.objects[oldKey]) != "original" {
		t.Fatal("second draft write or original overwrite accepted")
	}
}

func TestPackageBrowser403HTTPObservationForwardsRoutesAndRequiresExactJourney(t *testing.T) {
	root := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	counts := &packageBrowserHTTPCounts403{}
	forwarded := 0
	wrapped := counts.handler403(root, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded++; w.WriteHeader(http.StatusAccepted) }))
	staff := "/api/v1/documents/" + root.String()
	public := "/sign/" + strings.Repeat("a", 43)
	paths := []string{staff + "/send", public + "/comments", staff + "/comments", public + "/request-changes", staff + "/change-requests/20000000-0000-0000-0000-000000000002/approve", staff + "/revise", staff + "/html/revisions", staff + "/send", public + "/sign", public + "/sign"}
	for _, path := range paths {
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "http://owned"+path, nil))
		if w.Code != http.StatusAccepted {
			t.Fatal("route return changed")
		}
	}
	if !counts.exact403() || forwarded != len(paths) {
		t.Fatal("actual selected mutation observation incomplete")
	}
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://owned"+staff+"/send", nil))
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "http://owned/api/v1/documents/30000000-0000-0000-0000-000000000003/send", nil))
	if !counts.exact403() {
		t.Fatal("GET or foreign staff document changed selected counts")
	}
	wrapped.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "http://owned"+public+"/sign", nil))
	if counts.exact403() {
		t.Fatal("repeated signature request became an exact successful journey")
	}
}
