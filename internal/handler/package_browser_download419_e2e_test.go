//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

// Test-only incoming HTTP observations for native browser downloads which
// Chromium does not expose through Playwright's request event. No request or
// response bytes are consumed, replaced or retained by this observer.
import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type packageBrowserNativeDownloadRequest419 struct {
	Schema           int    `json:"schema"`
	Source           string `json:"source"`
	Slot             int    `json:"slot"`
	Sequence         int    `json:"sequence"`
	URLSHA256        string `json:"url_sha256"`
	GET              bool   `json:"get"`
	EmptyBody        bool   `json:"empty_body"`
	TLS              bool   `json:"tls"`
	AuthorityMatches bool   `json:"authority_matches"`
}

type packageBrowserNativeDownloads419 struct {
	mu        sync.Mutex
	armed     bool
	failed    bool
	authority string
	uris      [4]string
	files     [4]string
	seen      [4]bool
	rows      [4]packageBrowserNativeDownloadRequest419
	sequence  int
}

func packageBrowserNativeDownloadPaths419(dir string) [4]string {
	var paths [4]string
	for i := range paths {
		paths[i] = filepath.Join(dir, "native-download419-"+strconv.Itoa(i)+".json")
	}
	return paths
}

// The caller has independently verified native terminal state, credentials,
// versions and artifacts before arming, and has not published its handoff yet.
// Only the actual HTTPS server's outer403 wrapper calls observe419. Direct
// native oracle Routes() reads never enter that wrapper.
func (o *packageBrowserNativeDownloads419) arm419(base *url.URL, terminal packageBrowserTerminal403, dir string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	bad := errors.New("exact private native download observation required")
	if o.armed || base == nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" || base.ForceQuery || len(base.Host) > 256 || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || terminal.Schema != 1 || terminal.RootID == uuid.Nil || terminal.AttemptID == uuid.Nil || terminal.PackageID == uuid.Nil || len(terminal.Parties) != 2 || !packageBrowserToken403(terminal.Parties[0].Token) || !packageBrowserToken403(terminal.Parties[1].Token) || terminal.Parties[0].Token == terminal.Parties[1].Token {
		o.failed = true
		return bad
	}
	o.authority = base.Host
	o.files = packageBrowserNativeDownloadPaths419(dir)
	for i, party := range terminal.Parties {
		o.uris[2*i] = "/sign/" + party.Token + "/final-pdf"
		o.uris[2*i+1] = "/sign/" + party.Token + "/audit-cert"
	}
	o.armed = true
	return nil
}

func (o *packageBrowserNativeDownloads419) observe419(r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.armed {
		return
	}
	if r == nil || r.URL == nil {
		o.failed = true
		return
	}
	// Descriptor and original-member requests continue through their existing
	// native response/EOF proofs. Only final/report download routes are selected.
	candidate := strings.HasPrefix(r.URL.Path, "/sign/") && (strings.HasSuffix(r.URL.Path, "/final-pdf") || strings.HasSuffix(r.URL.Path, "/audit-cert"))
	if !candidate {
		return
	}
	slot := -1
	for i, uri := range o.uris {
		if r.RequestURI == uri {
			slot = i
			break
		}
	}
	// Incoming net/http requests use NoBody when their parsed entity length is
	// zero. Requiring its identity as well as both framing fields refuses a
	// hidden/chunked/nonempty body without calling Read or changing the request.
	if o.failed || slot < 0 || o.sequence >= 4 || slot != o.sequence || o.seen[slot] || r.Method != http.MethodGet || r.Body != http.NoBody || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.TLS == nil || r.Host != o.authority || r.URL.Path != o.uris[slot] || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.User != nil || r.URL.Scheme != "" || r.URL.Host != "" {
		o.failed = true
		return
	}
	sum := sha256.Sum256([]byte("https://" + r.Host + r.RequestURI))
	row := packageBrowserNativeDownloadRequest419{Schema: 1, Source: "native-server-http419", Slot: slot, Sequence: o.sequence + 1, URLSHA256: hex.EncodeToString(sum[:]), GET: true, EmptyBody: true, TLS: true, AuthorityMatches: true}
	raw, err := json.Marshal(row)
	if err != nil || len(raw) < 1 || len(raw) > 1024 {
		o.failed = true
		return
	}
	// Exclusive fresh0600 publication completes before the original handler is
	// invoked. Errors are closed state only; never raw paths, URLs or IO text.
	f, err := os.OpenFile(o.files[slot], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		o.failed = true
		return
	}
	chmodErr := f.Chmod(0600)
	n, writeErr := f.Write(raw)
	closeErr := f.Close()
	if chmodErr != nil || writeErr != nil || n != len(raw) || closeErr != nil {
		o.failed = true
		return
	}
	o.rows[slot], o.seen[slot] = row, true
	o.sequence++
}

// A browser done file does not establish these facts. Native acceptance after
// done requires all four distinct ordered real HTTPS requests and no fault.
func (o *packageBrowserNativeDownloads419) complete419() ([]packageBrowserNativeDownloadRequest419, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.armed || o.failed || o.sequence != 4 {
		return nil, errors.New("four exact native HTTP downloads required")
	}
	for i, row := range o.rows {
		if !o.seen[i] || row.Schema != 1 || row.Source != "native-server-http419" || row.Slot != i || row.Sequence != i+1 || !packageBrowserDigest403(row.URLSHA256) || !row.GET || !row.EmptyBody || !row.TLS || !row.AuthorityMatches {
			return nil, errors.New("four exact native HTTP downloads required")
		}
	}
	return append([]packageBrowserNativeDownloadRequest419(nil), o.rows[:]...), nil
}

func packageBrowserNativeFixture419(t *testing.T) (*packageBrowserNativeDownloads419, *url.URL, packageBrowserTerminal403, string) {
	t.Helper()
	base, err := url.Parse("https://127.0.0.1:9443")
	if err != nil {
		t.Fatal("fixed synthetic origin unavailable")
	}
	terminal := packageBrowserTerminal403{Schema: 1, RootID: uuid.MustParse("10000000-0000-0000-0000-000000000001"), AttemptID: uuid.MustParse("20000000-0000-0000-0000-000000000002"), PackageID: uuid.MustParse("30000000-0000-0000-0000-000000000003"), Parties: []packageBrowserCompletedParty403{{Token: strings.Repeat("a", 43)}, {Token: strings.Repeat("b", 43)}}}
	dir := t.TempDir()
	o := &packageBrowserNativeDownloads419{}
	if err := o.arm419(base, terminal, dir); err != nil {
		t.Fatal("declared synthetic observer refused")
	}
	return o, base, terminal, dir
}

func packageBrowserNativeRequest419(t *testing.T, base *url.URL, terminal packageBrowserTerminal403, slot int) *http.Request {
	t.Helper()
	suffix := "/final-pdf"
	if slot%2 == 1 {
		suffix = "/audit-cert"
	}
	// httptest creates a parsed server request, including TLS and NoBody. Keep
	// the actual origin-form RequestURI, as the real HTTPS server receives it.
	r := httptest.NewRequest(http.MethodGet, base.String()+"/sign/"+terminal.Parties[slot/2].Token+suffix, nil)
	r.URL.Scheme, r.URL.Host = "", ""
	r.RequestURI = r.URL.RequestURI()
	return r
}

func TestPackageBrowserNativeDownload419ExactTLSRequestsAndUntouchedForwarding(t *testing.T) {
	o, base, terminal, dir := packageBrowserNativeFixture419(t)
	counts := &packageBrowserHTTPCounts403{downloads: o}
	var received *http.Request
	forwarded := 0
	wrapped := counts.handler403(terminal.RootID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded++
		received = r
		// The witness must already be closed, bounded and private when the
		// unchanged original route is entered, not after its response.
		st, err := os.Lstat(packageBrowserNativeDownloadPaths419(dir)[forwarded-1])
		if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > 1024 {
			t.Fatal("witness not published before original handler")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	var fileRows []packageBrowserNativeDownloadRequest419
	for slot := 0; slot < 4; slot++ {
		r := packageBrowserNativeRequest419(t, base, terminal, slot)
		originalURL, originalBody, originalURI := r.URL, r.Body, r.RequestURI
		w := httptest.NewRecorder()
		wrapped.ServeHTTP(w, r)
		if received != r || r.URL != originalURL || r.Body != originalBody || r.RequestURI != originalURI || w.Code != http.StatusAccepted {
			t.Fatal("observer altered original request or route return")
		}
		raw, err := os.ReadFile(packageBrowserNativeDownloadPaths419(dir)[slot])
		if err != nil || len(raw) > 1024 || bytes.Contains(raw, []byte(terminal.Parties[slot/2].Token)) || bytes.Contains(raw, []byte("/sign/")) {
			t.Fatal("witness missing, oversized or private")
		}
		var row packageBrowserNativeDownloadRequest419
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&row) != nil || decoder.Decode(&struct{}{}) != io.EOF {
			t.Fatal("closed witness JSON required")
		}
		sum := sha256.Sum256([]byte(base.String() + originalURI))
		if row != (packageBrowserNativeDownloadRequest419{Schema: 1, Source: "native-server-http419", Slot: slot, Sequence: slot + 1, URLSHA256: hex.EncodeToString(sum[:]), GET: true, EmptyBody: true, TLS: true, AuthorityMatches: true}) {
			t.Fatal("actual fixed URL/method/body witness changed")
		}
		fileRows = append(fileRows, row)
	}
	rows, err := o.complete419()
	if err != nil || !reflect.DeepEqual(rows, fileRows) || forwarded != 4 || counts.send.Load() != 0 || counts.signatures.Load() != 0 {
		t.Fatal("independent native observation incomplete or altered mutation counts")
	}
}

type packageBrowserUnreadBody419 struct{ reads int }

func (b *packageBrowserUnreadBody419) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *packageBrowserUnreadBody419) Close() error             { return nil }

func TestPackageBrowserNativeDownload419InvalidIncomingRequestRefusals(t *testing.T) {
	for _, name := range []string{"method", "body", "nil-body", "content-length", "chunked", "tls", "authority", "query", "force-query", "raw-path", "wrong-token", "absolute-uri", "out-of-order"} {
		t.Run(name, func(t *testing.T) {
			o, base, terminal, dir := packageBrowserNativeFixture419(t)
			r := packageBrowserNativeRequest419(t, base, terminal, 0)
			unread := &packageBrowserUnreadBody419{}
			switch name {
			case "method":
				r.Method = http.MethodPost
			case "body":
				r.Body = unread
			case "nil-body":
				r.Body = nil
			case "content-length":
				r.ContentLength = 1
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "tls":
				r.TLS = nil
			case "authority":
				r.Host = "127.0.0.1:9444"
			case "query":
				r.URL.RawQuery = "extra=1"
				r.RequestURI += "?extra=1"
			case "force-query":
				r.URL.ForceQuery = true
				r.RequestURI += "?"
			case "raw-path":
				r.URL.RawPath = strings.Replace(r.URL.Path, "/sign/", "/%73ign/", 1)
			case "wrong-token":
				r.URL.Path = "/sign/" + strings.Repeat("c", 43) + "/final-pdf"
				r.RequestURI = r.URL.Path
			case "absolute-uri":
				r.RequestURI = base.String() + r.RequestURI
			case "out-of-order":
				r = packageBrowserNativeRequest419(t, base, terminal, 1)
			}
			originalBody, originalURI, originalMethod := r.Body, r.RequestURI, r.Method
			forwarded := false
			wrapped := (&packageBrowserHTTPCounts403{downloads: o}).handler403(terminal.RootID, http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
				forwarded = got == r
				w.WriteHeader(http.StatusTeapot)
			}))
			w := httptest.NewRecorder()
			wrapped.ServeHTTP(w, r)
			if !forwarded || w.Code != http.StatusTeapot || r.Body != originalBody || r.RequestURI != originalURI || r.Method != originalMethod || unread.reads != 0 {
				t.Fatal("refused observation consumed or modified request/response")
			}
			if _, err := o.complete419(); err == nil || !o.failed {
				t.Fatal("malformed actual HTTP observation accepted")
			}
			for _, path := range packageBrowserNativeDownloadPaths419(dir) {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("refused request published a witness")
				}
			}
		})
	}
}

func TestPackageBrowserNativeDownload419MissingDuplicateAndLateFaultRefuse(t *testing.T) {
	for _, name := range []string{"missing", "duplicate", "late-query"} {
		t.Run(name, func(t *testing.T) {
			o, base, terminal, _ := packageBrowserNativeFixture419(t)
			limit := 4
			if name == "missing" {
				limit = 3
			}
			for i := 0; i < limit; i++ {
				o.observe419(packageBrowserNativeRequest419(t, base, terminal, i))
			}
			if limit == 4 {
				if _, err := o.complete419(); err != nil {
					t.Fatal("positive prefix refused")
				}
				r := packageBrowserNativeRequest419(t, base, terminal, 0)
				if name == "late-query" {
					r.RequestURI += "?extra=1"
					r.URL.RawQuery = "extra=1"
				}
				o.observe419(r)
			}
			if _, err := o.complete419(); err == nil {
				t.Fatal("missing, duplicate or late contradictory request accepted")
			}
		})
	}
}

func TestPackageBrowserNativeDownload419FreshExclusiveWitnessRequired(t *testing.T) {
	for _, name := range []string{"regular", "symlink", "directory"} {
		t.Run(name, func(t *testing.T) {
			o, base, terminal, dir := packageBrowserNativeFixture419(t)
			path := packageBrowserNativeDownloadPaths419(dir)[0]
			sentinel := []byte("unchanged private sentinel")
			target := filepath.Join(dir, "untouched")
			if err := os.WriteFile(target, sentinel, 0600); err != nil {
				t.Fatal("control setup failed")
			}
			var err error
			switch name {
			case "regular":
				err = os.WriteFile(path, sentinel, 0600)
			case "symlink":
				err = os.Symlink(target, path)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal("exclusive control setup failed")
			}
			o.observe419(packageBrowserNativeRequest419(t, base, terminal, 0))
			if _, err := o.complete419(); err == nil || !o.failed {
				t.Fatal("preexisting witness accepted or overwritten")
			}
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, sentinel) {
				t.Fatal("refused witness changed an unrelated file")
			}
			if name == "regular" {
				got, err = os.ReadFile(path)
				if err != nil || !bytes.Equal(got, sentinel) {
					t.Fatal("existing witness bytes overwritten")
				}
			}
		})
	}
}

func TestPackageBrowserNativeDownload419ArmAndUnrelatedRoutesBoundaries(t *testing.T) {
	o, base, terminal, dir := packageBrowserNativeFixture419(t)
	other := httptest.NewRequest(http.MethodGet, base.String()+"/sign/"+terminal.Parties[0].Token+"/completed-package", nil)
	o.observe419(other)
	other.URL.Path += "/members/0/pdf"
	o.observe419(other)
	if o.sequence != 0 || o.failed {
		t.Fatal("existing native descriptor/member proof traffic was selected")
	}
	for i := 0; i < 4; i++ {
		o.observe419(packageBrowserNativeRequest419(t, base, terminal, i))
	}
	if _, err := o.complete419(); err != nil {
		t.Fatal("unrelated traffic broke exact positive case")
	}
	if o.arm419(base, terminal, dir) == nil {
		t.Fatal("observer rearm accepted")
	}
	if _, err := o.complete419(); err == nil {
		t.Fatal("rearm did not invalidate terminal acceptance")
	}
}

func TestPackageBrowserNativeDownload419InvalidArmRefusals(t *testing.T) {
	for _, name := range []string{"http", "host", "query", "force-query", "party-count", "duplicate-token", "invalid-token", "relative-dir"} {
		t.Run(name, func(t *testing.T) {
			_, base, terminal, dir := packageBrowserNativeFixture419(t)
			o := &packageBrowserNativeDownloads419{}
			switch name {
			case "http":
				base.Scheme = "http"
			case "host":
				base.Host = "example.test:9443"
			case "query":
				base.RawQuery = "extra=1"
			case "force-query":
				base.ForceQuery = true
			case "party-count":
				terminal.Parties = terminal.Parties[:1]
			case "duplicate-token":
				terminal.Parties[1].Token = terminal.Parties[0].Token
			case "invalid-token":
				terminal.Parties[0].Token = "invalid"
			case "relative-dir":
				dir = "relative"
			}
			if o.arm419(base, terminal, dir) == nil || o.armed || !o.failed {
				t.Fatal("undeclared native observation scope armed")
			}
		})
	}
}
