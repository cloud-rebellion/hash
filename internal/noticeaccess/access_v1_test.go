// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package noticeaccess

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func fileFixture483() ([]byte, [32]byte) {
	id := uuid.New()
	files := amendments.FileSetV1{Schema: "hash-amendment-files-v1", DocumentID: id, SourceCommitmentSHA256: strings.Repeat("a", 64), PackageGeneration: "0", Files: []amendments.FileV1{{Position: 0, DocumentID: id, Title: "Reviewed DPA", Key: "org/exact.pdf", VersionID: "version+one/==", SHA256: strings.Repeat("b", 64), Bytes: 128, Pages: 1, IntakeReportSHA256: strings.Repeat("c", 64)}}}
	raw, _ := json.Marshal(files)
	return raw, domainHashV1("hash:later-amendment-files:v1", raw)
}
func TestNoticeCapability483PurposeFormatAndForeignCredentials(t *testing.T) {
	raw := "hn1." + base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	digest, err := TokenDigestV1(raw)
	if err != nil || digest == ([32]byte{}) {
		t.Fatal("fresh notice token rejected")
	}
	for _, foreign := range []string{raw[4:], "sign." + raw[4:], raw + "=", raw + "extra", strings.ToUpper(raw), "hn1." + strings.Repeat("!", 43)} {
		if _, err := TokenDigestV1(foreign); err == nil {
			t.Fatal("foreign/malformed credential accepted")
		}
	}
	if digest == domainHashV1("hash:another-purpose:v1", []byte(raw)) {
		t.Fatal("purpose domain collapsed")
	}
}
func TestNoticeFrozenFiles483VersionHashAndBounds(t *testing.T) {
	raw, pin := fileFixture483()
	files, err := DecodeFilesV1(raw, pin)
	if err != nil {
		t.Fatal(err)
	}
	version := FileVersionSHA256V1(files.Files[0])
	changed := files.Files[0]
	changed.VersionID = "version-two"
	if version == FileVersionSHA256V1(changed) {
		t.Fatal("provider version omitted from public opaque identity")
	}
	for _, which := range []string{"digest", "latest", "development", "position", "bytes", "pages", "report", "foreign-main", "unknown-field"} {
		t.Run(which, func(t *testing.T) {
			var f amendments.FileSetV1
			if json.Unmarshal(raw, &f) != nil {
				t.Fatal("fixture")
			}
			switch which {
			case "latest":
				f.Files[0].VersionID = ""
			case "development":
				f.Files[0].VersionID = storage.DevelopmentVersionID
			case "position":
				f.Files[0].Position = 1
			case "bytes":
				f.Files[0].Bytes = MaxFileBytesV1 + 1
			case "pages":
				f.Files[0].Pages = 0
			case "report":
				f.Files[0].IntakeReportSHA256 = ""
			case "foreign-main":
				f.Files[0].DocumentID = uuid.New()
			}
			body, _ := json.Marshal(f)
			if which == "unknown-field" {
				body = []byte(strings.TrimSuffix(string(body), "}") + `,"authority":true}`)
			}
			sum := domainHashV1("hash:later-amendment-files:v1", body)
			if which == "digest" {
				sum[0] ^= 1
			}
			if _, err := DecodeFilesV1(body, sum); err == nil {
				t.Fatal("unbound/latest/invalid frozen file accepted")
			}
		})
	}
}
func TestNoticePrivateQueue483ExactExistingSQLFrame(t *testing.T) {
	message := dispatch.Message{To: "legal@example.test", Subject: "Notice å", HTML: "<p>Exact</p>", Text: "Exact\nbytes", ReplyTo: "owner@example.test", FromName: "Hash"}
	sum, err := QueueMessageSHA256V1(message)
	if err != nil || hex.EncodeToString(sum[:]) != "36ca8cd078de4d4b206bebce34bc908c629bfdf639e2683a835d974eee348f1c" {
		t.Fatal("UTF8/int8send queue contract changed")
	}
	message.Headers = map[string]string{"X-Other": "unreviewed"}
	if _, err := QueueMessageSHA256V1(message); err == nil {
		t.Fatal("unbound headers accepted")
	}
}
func TestNoticeCookie483IsolatedFromSenderAndSignerPurposes(t *testing.T) {
	cookies, err := auth.NewSignedCookie(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 64)
	good, err := cookies.MintPurpose(cookiePurposeV1, payload, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cookies.Verify(good); err == nil {
		t.Fatal("notice cookie became sender login")
	}
	wrong, _ := cookies.MintPurpose("signer-read-v1", payload, time.Minute)
	staff := cookies.Mint(payload, time.Minute)
	for _, token := range []string{wrong, staff} {
		if _, err := cookies.VerifyPurpose(cookiePurposeV1, token); err == nil {
			t.Fatal("foreign session became notice access")
		}
	}
}
func TestNoticePrepared483BorrowHoldsActualGrantUntilLastUse(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	limits := workguard.VectorV1{ParentBytes: 4096}
	work, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 2, MaxOrganisationGrants: 2})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := work.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	prepared := &PreparedV1{state: &preparedStateV1{grant: grant, input: InputV1{OrgID: org}}}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- prepared.WithInputV1(func(in InputV1) error {
			if in.OrgID != org {
				return errors.New("wrong owned input")
			}
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	prepared.CloseConsumerV1()
	if work.SnapshotV1(org).Organisation.ParentBytes != 1024 {
		t.Fatal("close credited a live borrower")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if work.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("joined owned input not released")
	}
	if prepared.WithInputV1(func(InputV1) error { return nil }) == nil {
		t.Fatal("closed producer reused")
	}
}
func TestNoticeHTTP483UnavailableAndForeignAccessNeverFallsIntoSPA(t *testing.T) {
	router := chi.NewRouter()
	MountV1(router, nil)
	router.NotFound(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	for _, path := range []string{"/api/v1/notices/" + uuid.NewString(), "/api/v1/notices/" + uuid.NewString() + "/files/0"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != 503 || response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unavailable route fell through or cached", response.Code)
		}
	}
}
func TestNoticePublic483DTOHasNoSignerResponseOrStorageLocator(t *testing.T) {
	raw, _ := json.Marshal(PublicV1{Schema: SchemaV1, Files: []PublicFileV1{{Position: 0, Title: "Exact later file", PDFSHA256: strings.Repeat("a", 64), PDFBytes: 123, PDFPages: 1, FileVersionSHA256: strings.Repeat("b", 64)}}})
	for _, forbidden := range []string{`"signed"`, `"accepted"`, `"effective"`, `"recipient_email"`, `"key"`, `"version_id"`, `"token"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatal("public DTO expands authority/private scope", forbidden)
		}
	}
}

func TestNoticeFrozenFiles483AggregateBudgetsAndImportedPDF(t *testing.T) {
	raw, pin := fileFixture483()
	files, e := DecodeFilesV1(raw, pin)
	if e != nil {
		t.Fatal(e)
	}
	files.SourceCommitmentSHA256 = ""
	raw, _ = json.Marshal(files)
	pin = domainHashV1("hash:later-amendment-files:v1", raw)
	if _, e = DecodeFilesV1(raw, pin); e != nil {
		t.Fatal("genuine imported PDF requires no invented HTML source commitment")
	}
	for _, which := range []string{"bytes", "pages", "count"} {
		t.Run(which, func(t *testing.T) {
			f := files
			f.Files = append([]amendments.FileV1(nil), files.Files...)
			count := 2
			if which == "count" {
				count = MaxFilesV1 + 1
			}
			for len(f.Files) < count {
				next := f.Files[0]
				next.Position = int16(len(f.Files))
				next.DocumentID = uuid.New()
				f.Files = append(f.Files, next)
			}
			if which == "bytes" {
				f.Files[0].Bytes = MaxTotalFileBytesV1
				f.Files[1].Bytes = 1
			}
			if which == "pages" {
				f.Files[0].Pages = int32(MaxTotalPagesV1)
				f.Files[1].Pages = 1
			}
			body, _ := json.Marshal(f)
			sum := domainHashV1("hash:later-amendment-files:v1", body)
			if _, e = DecodeFilesV1(body, sum); e == nil {
				t.Fatal("aggregate provider/public budget accepted")
			}
		})
	}
}

func TestNoticeFrozenFiles483PreservesOpaqueVersionBytes(t *testing.T) {
	raw, pin := fileFixture483()
	f, e := DecodeFilesV1(raw, pin)
	if e != nil {
		t.Fatal(e)
	}
	exact := " frozen terminal+/opaque=version "
	f.Files[0].VersionID = exact
	raw, _ = json.Marshal(f)
	pin = domainHashV1("hash:later-amendment-files:v1", raw)
	observed, e := DecodeFilesV1(raw, pin)
	if e != nil || observed.Files[0].VersionID != exact {
		t.Fatal("opaque provider identity was normalized/refused")
	}
	for _, bad := range []string{" null ", " " + storage.DevelopmentVersionID + " ", "   ", "version\u0001control"} {
		f.Files[0].VersionID = bad
		raw, _ = json.Marshal(f)
		pin = domainHashV1("hash:later-amendment-files:v1", raw)
		if _, e = DecodeFilesV1(raw, pin); e == nil {
			t.Fatal("reserved/control provider identity accepted")
		}
	}
}
