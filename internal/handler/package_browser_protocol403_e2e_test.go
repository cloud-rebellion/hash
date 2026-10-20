//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

// Test-only protocol for the separately numbered real negotiated-package
// fixture. No controller/driver, application mutation seam or new report schema.
import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const packageBrowserRequest403 = "Please change the scope to Revised agreed terms"
const packageBrowserRecipientComment403 = "Package403 recipient: please use Revised agreed terms"
const packageBrowserOwnerComment403 = "Package403 owner: I will revise the scope and send a new package"
const packageBrowserRevisedScope403 = "Revised agreed terms"
const packageBrowserRevisionSummary403 = "Package403 agreed scope revision"

type packageBrowserMember403 struct {
	ID               uuid.UUID `json:"id"`
	Title            string    `json:"title"`
	Category         string    `json:"category"`
	SHA256           string    `json:"sha256"`
	Bytes            int64     `json:"bytes"`
	Pages            int32     `json:"pages"`
	SourceCommitment string    `json:"sourceCommitment,omitempty"`
	Materialization  int32     `json:"materializationRevision,omitempty"`
}
type packageBrowserParty403 struct {
	RecipientID  uuid.UUID `json:"recipientID"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	Email        string    `json:"email"`
	Token        string    `json:"token,omitempty"`
	NoticeDigest string    `json:"noticeDigest,omitempty"`
}
type packageBrowserStage403 struct {
	Schema               int                       `json:"schema"`
	Stage                int                       `json:"stage"`
	RootID               uuid.UUID                 `json:"rootID"`
	AttemptID            uuid.UUID                 `json:"attemptID"`
	PackageID            uuid.UUID                 `json:"packageID"`
	Revision             string                    `json:"revision"`
	Generation           string                    `json:"generation"`
	RootUpdatedAt        string                    `json:"rootUpdatedAt"`
	NoticeEpoch          string                    `json:"noticeEpoch"`
	ManifestSHA256       string                    `json:"manifestSHA256"`
	LegalSHA256          string                    `json:"legalSHA256"`
	IncorporationVersion string                    `json:"incorporationVersion"`
	IncorporationSHA256  string                    `json:"incorporationSHA256"`
	Members              []packageBrowserMember403 `json:"members"`
	Parties              []packageBrowserParty403  `json:"parties"`
	Fields               []map[string]any          `json:"fields"`
}

func packageBrowserDigest403(value string) bool {
	if len(value) != 64 {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(raw) == value
}
func packageBrowserPositive403(value string) (int64, bool) {
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}
func packageBrowserClock403(value string) bool {
	at, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !at.IsZero() && at.UTC().Format(time.RFC3339Nano) == value
}
func packageBrowserToken403(value string) bool {
	if len(value) != 43 {
		return false
	}
	for _, c := range value {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Validate exact declared stages, not a permission/freeze shortcut. Values are
// later constructed only from actual native effects and version-verified bodies.
func packageBrowserValidateStage403(current packageBrowserStage403, prior *packageBrowserStage403) error {
	bad := errors.New("invalid exact negotiated package browser stage")
	if current.Schema != 1 || current.Stage < 1 || current.Stage > 2 || current.RootID == uuid.Nil || current.AttemptID == uuid.Nil || current.PackageID == uuid.Nil || !packageBrowserClock403(current.RootUpdatedAt) || !packageBrowserClock403(current.NoticeEpoch) || !packageBrowserDigest403(current.ManifestSHA256) || !packageBrowserDigest403(current.LegalSHA256) || !packageBrowserDigest403(current.IncorporationSHA256) || current.IncorporationVersion == "" || len(current.Members) != 3 || len(current.Parties) != 2 || len(current.Fields) != 2 {
		return bad
	}
	revision, ok := packageBrowserPositive403(current.Revision)
	if !ok {
		return bad
	}
	if _, ok := packageBrowserPositive403(current.Generation); !ok {
		return bad
	}
	seen := map[uuid.UUID]bool{}
	var totalBytes int64
	var totalPages int32
	for i, member := range current.Members {
		if member.ID == uuid.Nil || seen[member.ID] || member.Title == "" || !packageBrowserDigest403(member.SHA256) || member.Bytes <= 0 || member.Bytes > 50<<20 || member.Pages < 1 || member.Pages > 500 {
			return bad
		}
		seen[member.ID] = true
		totalBytes += member.Bytes
		totalPages += member.Pages
		if totalBytes > 50<<20 || totalPages > 500 {
			return bad
		}
		if i == 0 {
			if member.ID != current.RootID || !packageBrowserDigest403(member.SourceCommitment) || member.Materialization < 1 {
				return bad
			}
		} else if member.Category != []string{"DPA", "NDA"}[i-1] || member.SourceCommitment != "" || member.Materialization != 0 {
			return bad
		}
	}
	seen = map[uuid.UUID]bool{}
	roles := map[string]bool{}
	tokens := map[string]bool{}
	for _, party := range current.Parties {
		if party.RecipientID == uuid.Nil || seen[party.RecipientID] || party.Name == "" || party.Email == "" || (party.Role != "provider" && party.Role != "customer") || roles[party.Role] || tokens[party.Token] || !packageBrowserToken403(party.Token) || !packageBrowserDigest403(party.NoticeDigest) {
			return bad
		}
		seen[party.RecipientID] = true
		roles[party.Role] = true
		tokens[party.Token] = true
	}
	if prior == nil {
		if current.Stage != 1 {
			return bad
		}
		return nil
	}
	oldRevision, ok := packageBrowserPositive403(prior.Revision)
	if !ok || packageBrowserValidateStage403(*prior, nil) != nil {
		return bad
	}
	before, err := time.Parse(time.RFC3339Nano, prior.NoticeEpoch)
	after, e := time.Parse(time.RFC3339Nano, current.NoticeEpoch)
	if current.Stage != 2 || current.RootID != prior.RootID || current.PackageID != prior.PackageID || current.AttemptID == prior.AttemptID || revision != oldRevision+1 || current.ManifestSHA256 == prior.ManifestSHA256 || current.LegalSHA256 == prior.LegalSHA256 || current.IncorporationVersion != prior.IncorporationVersion || current.IncorporationSHA256 != prior.IncorporationSHA256 || err != nil || e != nil || !after.After(before) || current.Members[1] != prior.Members[1] || current.Members[2] != prior.Members[2] || current.Members[0].ID != prior.Members[0].ID || current.Members[0].SHA256 == prior.Members[0].SHA256 || current.Members[0].SourceCommitment == prior.Members[0].SourceCommitment || current.Members[0].Materialization != prior.Members[0].Materialization+1 {
		return bad
	}
	for _, party := range current.Parties {
		matched := false
		for _, old := range prior.Parties {
			if party.Token == old.Token {
				return bad
			}
			if party.RecipientID == old.RecipientID {
				if party.Name != old.Name || party.Role != old.Role || party.Email != old.Email || party.Token == old.Token {
					return bad
				}
				matched = true
			}
		}
		if !matched {
			return bad
		}
	}
	return nil
}

// Bounded strict reader for the original two-key completion protocol. A done
// file is a browser claim only; all independent native checks remain mandatory.
func packageBrowserReadDone403(path string) (bool, error) {
	st, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() < 1 || st.Size() > 1024 {
		return false, errors.New("private bounded regular browser completion required")
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 1025))
	err = errors.Join(readErr, f.Close())
	if err != nil || len(raw) > 1024 {
		return false, errors.Join(err, errors.New("bounded browser completion required"))
	}
	return packageBrowserDecodeDone403(raw)
}
func packageBrowserDecodeDone403(raw []byte) (bool, error) {
	bad := errors.New("browser did not verify negotiated package")
	if len(raw) == 0 || len(raw) > 1024 {
		return false, bad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return false, bad
	}
	seen := map[string]bool{}
	exit, verified := -1, false
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return false, bad
		}
		seen[name] = true
		switch name {
		case "exit_code":
			if d.Decode(&exit) != nil {
				return false, bad
			}
		case "verified":
			if d.Decode(&verified) != nil {
				return false, bad
			}
		default:
			return false, bad
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return false, bad
	}
	if _, err = d.Token(); err != io.EOF || len(seen) != 2 || exit != 0 || !verified {
		return false, bad
	}
	return true, nil
}
