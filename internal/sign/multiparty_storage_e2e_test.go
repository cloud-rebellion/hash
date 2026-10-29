//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// A bounded synthetic version/retention protocol peer lets the integration
// journeys use the production concrete Client and its owned IO boundary. It
// does not establish any real provider's Object Lock enforcement.
func (s *multipartyVersionStore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	const bucket = "hash-sign-fixture"
	const prefix = "/" + bucket + "/"
	if r.URL.Path == "/"+bucket || r.URL.Path == prefix {
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.Method == http.MethodHead:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Query().Has("versioning"):
			fmt.Fprint(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
		case r.Method == http.MethodGet && r.URL.Query().Has("object-lock"):
			fmt.Fprint(w, `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
		case r.Method == http.MethodGet && r.URL.Query().Has("versions"):
			s.mu.Lock()
			defer s.mu.Unlock()
			fmt.Fprintf(w, `<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>%s</Name><IsTruncated>false</IsTruncated>`, bucket)
			keys := make([]string, 0, len(s.objects))
			for key := range s.objects {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, index := range keys {
				row := s.objects[index]
				key := strings.TrimSuffix(index, "|"+row.version)
				if !strings.HasPrefix(key, r.URL.Query().Get("prefix")) {
					continue
				}
				fmt.Fprint(w, `<Version><Key>`)
				_ = xml.EscapeText(w, []byte(key))
				fmt.Fprintf(w, `</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><LastModified>%s</LastModified><ETag>fixture</ETag><Size>%d</Size><StorageClass>STANDARD</StorageClass></Version>`, row.version, time.Now().UTC().Format(time.RFC3339), len(row.body))
			}
			fmt.Fprint(w, `</ListVersionsResult>`)
		default:
			http.Error(w, "unexpected synthetic bucket operation", http.StatusBadRequest)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.Error(w, "unexpected synthetic object path", http.StatusBadRequest)
		return
	}
	key, version := strings.TrimPrefix(r.URL.Path, prefix), r.URL.Query().Get("versionId")
	// Preserve the recovery test's post-intent failure boundary. No fixture
	// error masks an initial PUT/readback failure before the intent is durable.
	if r.URL.Query().Has("retention") && s.failFinalRetention.Load() && strings.Contains(key, "/final-") && s.finalizationIntentPresent != nil && s.finalizationIntentPresent() {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>synthetic final retention outage</Message></Error>`)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodPut && !r.URL.Query().Has("retention") {
		body, err := io.ReadAll(io.LimitReader(r.Body, (16<<20)+1))
		if err != nil || len(body) > 16<<20 {
			http.Error(w, "invalid synthetic upload", http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
			body, err = io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(body)))
			if err != nil {
				http.Error(w, "invalid synthetic chunked upload", http.StatusBadRequest)
				return
			}
		}
		var until time.Time
		mode, deadline := r.Header.Get("X-Amz-Object-Lock-Mode"), r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date")
		if mode != "" || deadline != "" {
			until, err = time.Parse(time.RFC3339, deadline)
			if err != nil || mode != "COMPLIANCE" || !until.After(time.Now()) {
				http.Error(w, "invalid synthetic COMPLIANCE write deadline", http.StatusBadRequest)
				return
			}
		} else if !multipartyDraftIntakeKeyE2E(key) {
			// Native PDF intake writes an initially mutable draft source. Send
			// must later apply and verify retention on this exact version.
			// Final/certificate/signature evidence still requires COMPLIANCE.
			http.Error(w, "missing synthetic COMPLIANCE write deadline", http.StatusBadRequest)
			return
		}
		row := multipartyVersionObject{body: body, version: uuid.NewString(), digest: sha256.Sum256(body), contentType: r.Header.Get("Content-Type"), retainUntil: until}
		s.objects[key+"|"+row.version] = row
		w.Header().Set("X-Amz-Version-Id", row.version)
		w.Header().Set("ETag", `"`+hex.EncodeToString(row.digest[:])+`"`)
		w.WriteHeader(http.StatusOK)
		return
	}
	var row multipartyVersionObject
	found := false
	if version != "" {
		row, found = s.objects[key+"|"+version]
	} else {
		// Evidence keys are content-addressed and this peer never overwrites an
		// existing logical key; a second version is deliberately rejected.
		for index, candidate := range s.objects {
			if index == key+"|"+candidate.version {
				if found {
					http.Error(w, "ambiguous synthetic latest version", http.StatusConflict)
					return
				}
				row, found = candidate, true
			}
		}
	}
	if !found {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<Error><Code>NoSuchKey</Code><Message>synthetic exact version absent</Message></Error>`)
		return
	}
	if r.URL.Query().Has("retention") {
		w.Header().Set("Content-Type", "application/xml")
		if r.Method == http.MethodGet {
			if row.retainUntil.IsZero() {
				fmt.Fprint(w, `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`)
				return
			}
			fmt.Fprintf(w, `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`, row.retainUntil.UTC().Format(time.RFC3339))
			return
		}
		var request struct {
			Mode            string
			RetainUntilDate time.Time
		}
		if r.Method != http.MethodPut || xml.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&request) != nil || request.Mode != "COMPLIANCE" || !request.RetainUntilDate.After(time.Now()) || request.RetainUntilDate.Before(row.retainUntil) {
			http.Error(w, "invalid synthetic retention extension", http.StatusBadRequest)
			return
		}
		row.retainUntil = request.RetainUntilDate
		s.objects[key+"|"+row.version] = row
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "unexpected synthetic object operation", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", row.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(row.body)))
	w.Header().Set("ETag", `"`+hex.EncodeToString(row.digest[:])+`"`)
	w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	w.Header().Set("X-Amz-Version-Id", row.version)
	w.Header().Set("X-Amz-Server-Side-Encryption", "AES256")
	if r.Method == http.MethodGet {
		_, _ = w.Write(row.body)
	}
}

func multipartyDraftIntakeKeyE2E(key string) bool {
	parts := strings.Split(key, "/")
	if len(parts) != 4 || parts[0] != "org" || parts[2] != "documents" || !strings.HasSuffix(parts[3], ".pdf") {
		return false
	}
	org, orgErr := uuid.Parse(parts[1])
	source, sourceErr := uuid.Parse(strings.TrimSuffix(parts[3], ".pdf"))
	return orgErr == nil && sourceErr == nil && org != uuid.Nil && source != uuid.Nil
}
