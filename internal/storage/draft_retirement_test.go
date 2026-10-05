// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package storage

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type draftDeleteTransport func(*http.Request) (*http.Response, error)

func (f draftDeleteTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDraftSourceRetirementDeletesExactVersionWithoutBypass(t *testing.T) {
	for _, test := range []struct {
		status int
		code   string
		ok     bool
	}{
		{204, "", true},
		{403, "AccessDenied", false},
		{404, "NoSuchKey", true},
		{404, "NoSuchVersion", true},
	} {
		t.Run(http.StatusText(test.status)+test.code, func(t *testing.T) {
			calls := 0
			transport := draftDeleteTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != "DELETE" || r.URL.Query().Get("versionId") != "pinned/source+version" || r.URL.Path != "/hash/org/example/documents/source.pdf" {
					t.Fatalf("wrong retirement identity: %s %s", r.Method, r.URL.String())
				}
				if r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
					t.Fatal("retirement bypassed retention")
				}
				body := ""
				if test.code != "" {
					body = `<Error><Code>` + test.code + `</Code><Message>fixture response</Message></Error>`
				}
				return &http.Response{StatusCode: test.status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			})
			mc, err := minio.New("storage.example.test", &minio.Options{Region: "us-east-1", Transport: transport, Creds: credentials.NewStaticV4("fixture", "fixture", "")})
			if err != nil {
				t.Fatal(err)
			}
			client := &Client{mc: mc, bucket: "hash", requireEvidenceLock: true}
			err = client.DeleteDraftSource(context.Background(), "org/example/documents/source.pdf", "pinned/source+version")
			if (err == nil) != test.ok || calls != 1 {
				t.Fatalf("retirement status=%d calls=%d err=%v", test.status, calls, err)
			}
		})
	}
}

func TestDraftSourceRetirementRejectsMissingPinBeforeIO(t *testing.T) {
	client := &Client{requireEvidenceLock: true}
	for _, version := range []string{"", " ", DevelopmentVersionID} {
		if err := client.DeleteDraftSource(context.Background(), "source.pdf", version); err == nil {
			t.Fatal("invalid source pin admitted")
		}
	}
}
