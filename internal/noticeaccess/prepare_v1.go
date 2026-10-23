// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package noticeaccess

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrUnavailableV1 = errors.New("notice access unavailable")
var ErrDeniedV1 = errors.New("notice access invalid, revoked or expired")
var ErrPreconditionV1 = errors.New("notice exact-file commitment differs")

// Construct once from the actual process runtime. No caller-supplied verifier,
// latest-object fallback, signer engine or data-authority callback is accepted.
type EngineV1 struct {
	pool      *pgxpool.Pool
	store     *storage.Client
	cookies   *auth.SignedCookie
	work      *workguard.CoordinatorV1
	publicURL string
	mu        sync.Mutex
	pending   [64]*physicalV1
}
type physicalV1 struct {
	read   *storage.PackagePDFLocalReadV1
	retain *storage.PackagePDFLocalRetentionV1
	active bool
}

func NewV1(pool *pgxpool.Pool, store *storage.Client, cookies *auth.SignedCookie, work *workguard.CoordinatorV1, publicURL string) (*EngineV1, error) {
	u, err := url.Parse(publicURL)
	if pool == nil || store == nil || cookies == nil || work == nil || err != nil || u.User != nil || u.Host == "" || u.ForceQuery || strings.ContainsAny(publicURL, "?#") || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && config.IsLocalDevelopment(publicURL))) {
		return nil, ErrUnavailableV1
	}
	return &EngineV1{pool: pool, store: store, cookies: cookies, work: work, publicURL: strings.TrimRight(publicURL, "/")}, nil
}
func (e *EngineV1) physicalSlotV1() (*physicalV1, error) {
	if e == nil {
		return nil, ErrUnavailableV1
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, s := range e.pending {
		if s == nil || (!s.active && ((s.read != nil && s.read.RetiredV1()) || (s.retain != nil && s.retain.RetiredV1()))) {
			next := &physicalV1{active: true}
			e.pending[i] = next
			return next, nil
		}
	}
	return nil, ErrUnavailableV1
}
func (e *EngineV1) closePhysicalV1(s *physicalV1) {
	if s == nil {
		return
	}
	if s.read != nil {
		s.read.CloseConsumerV1()
	}
	if s.retain != nil {
		s.retain.CloseConsumerV1()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s.active = false
	for i, x := range e.pending {
		if x == s && ((s.read == nil && s.retain == nil) || (s.read != nil && s.read.RetiredV1()) || (s.retain != nil && s.retain.RetiredV1())) {
			e.pending[i] = nil
			return
		}
	}
	// Unresolved actual retirement remains reachable and charged. Subsequent
	// requests re-observe it; cancellation never credits a provider grant.
}
func hex32V1(v string) bool {
	if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" || strings.Trim(v, "0") == "" {
		return false
	}
	return true
}
func domainHashV1(domain string, body []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(body)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func TokenDigestV1(raw string) ([32]byte, error) {
	if len(raw) != TokenLengthV1 || !strings.HasPrefix(raw, "hn1.") {
		return [32]byte{}, ErrDeniedV1
	}
	body, err := base64.RawURLEncoding.Strict().DecodeString(raw[4:])
	defer clear(body)
	if err != nil || len(body) != 32 || base64.RawURLEncoding.EncodeToString(body) != raw[4:] {
		return [32]byte{}, ErrDeniedV1
	}
	return domainHashV1("hash:amendment-notice-access:v1", []byte(raw)), nil
}
func validAddressV1(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && len(s) <= 254 && !strings.ContainsAny(s, "\r\n\x00")
}
func opaqueLocatorV1(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func DecodeFilesV1(raw []byte, expected [32]byte) (amendments.FileSetV1, error) {
	var out amendments.FileSetV1
	if len(raw) < 2 || len(raw) > MaxFileSetBytesV1 || domainHashV1("hash:later-amendment-files:v1", raw) != expected {
		return out, ErrUnavailableV1
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&out) != nil || decoder.Decode(new(any)) != io.EOF || out.Schema != "hash-amendment-files-v1" || out.DocumentID == uuid.Nil || (out.SourceCommitmentSHA256 != "" && !hex32V1(out.SourceCommitmentSHA256)) || len(out.Files) < 1 || len(out.Files) > MaxFilesV1 {
		return out, ErrUnavailableV1
	}
	var totalBytes, totalPages int64
	for i, f := range out.Files {
		if f.Position != int16(i) || f.DocumentID == uuid.Nil || len(f.Title) < 1 || len(f.Title) > 512 || !opaqueLocatorV1(f.Key) || !opaqueLocatorV1(f.VersionID) || !utf8.ValidString(f.Title) || strings.TrimSpace(f.VersionID) == "null" || strings.TrimSpace(f.VersionID) == storage.DevelopmentVersionID || strings.ContainsAny(f.Key+f.VersionID+f.Title, "\x00\r\n") || !hex32V1(f.SHA256) || !hex32V1(f.IntakeReportSHA256) || f.Bytes < 1 || f.Bytes > MaxFileBytesV1 || f.Pages < 1 || int64(f.Pages) > MaxTotalPagesV1 {
			return amendments.FileSetV1{}, ErrUnavailableV1
		}
		totalBytes += f.Bytes
		totalPages += int64(f.Pages)
		if totalBytes > MaxTotalFileBytesV1 || totalPages > MaxTotalPagesV1 {
			return amendments.FileSetV1{}, ErrUnavailableV1
		}
	}
	if out.Files[0].DocumentID != out.DocumentID {
		return amendments.FileSetV1{}, ErrUnavailableV1
	}
	return out, nil
}

type ProofV1 struct {
	OrgID, NoticeID, AmendmentID, OriginalDocumentID, DocumentID, IssuedBy uuid.UUID
	NoticeSHA256, FileCommitmentSHA256                                     [32]byte
	IssuedAt, RetainUntil                                                  time.Time
	RecipientEmails                                                        []string
}
type PreparedV1 struct{ state *preparedStateV1 }
type preparedStateV1 struct {
	mu         sync.Mutex
	grant      *workguard.GrantV1
	proof      ProofV1
	input      InputV1
	deliveries []DeliveryV1
	active     int
	closed     bool
}

func (e *EngineV1) MatchesCoordinatorV1(work *workguard.CoordinatorV1) bool {
	return e != nil && work != nil && e.work == work
}
func (h *PreparedV1) CloseConsumerV1() { h.CloseV1() }
func (h *PreparedV1) WithInputV1(fn func(InputV1) error) error {
	if h == nil || h.state == nil || fn == nil {
		return ErrUnavailableV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.grant == nil {
		s.mu.Unlock()
		return ErrUnavailableV1
	}
	s.active++
	input := s.input
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.clearV1(); s.mu.Unlock() }()
	return fn(input)
}
func (h *PreparedV1) WithProofV1(fn func(ProofV1) error) error { return h.borrowV1(-1, fn, nil) }
func (h *PreparedV1) WithDeliveryV1(position int, fn func(DeliveryV1) error) error {
	return h.borrowV1(position, nil, fn)
}
func (h *PreparedV1) borrowV1(position int, proof func(ProofV1) error, delivery func(DeliveryV1) error) error {
	if h == nil || h.state == nil {
		return ErrUnavailableV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.grant == nil || (position < 0 && proof == nil) || (position >= 0 && (delivery == nil || position >= len(s.deliveries))) {
		s.mu.Unlock()
		return ErrUnavailableV1
	}
	s.active++
	p := s.proof
	var d DeliveryV1
	if position >= 0 {
		d = s.deliveries[position]
	}
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.clearV1(); s.mu.Unlock() }()
	if position < 0 {
		return proof(p)
	}
	return delivery(d)
}
func (s *preparedStateV1) clearV1() {
	if !s.closed || s.active != 0 {
		return
	}
	for i := range s.deliveries {
		s.deliveries[i] = DeliveryV1{}
	}
	s.deliveries = nil
	s.proof = ProofV1{}
	clear(s.input.FileSetBytes)
	s.input = InputV1{}
	if s.grant != nil {
		s.grant.Close()
		s.grant = nil
	}
}
func (h *PreparedV1) CloseV1() {
	if h != nil && h.state != nil {
		h.state.mu.Lock()
		h.state.closed = true
		h.state.clearV1()
		h.state.mu.Unlock()
	}
}
func (e *EngineV1) PrepareV1(ctx context.Context, in InputV1) (out *PreparedV1, failure error) {
	if e == nil || e.work == nil || e.store == nil || ctx == nil || ctx.Err() != nil || in.OrgID == uuid.Nil || in.NoticeID == uuid.Nil || in.AmendmentID == uuid.Nil || in.OriginalDocumentID == uuid.Nil || in.DocumentID == uuid.Nil || in.IssuedBy == uuid.Nil || len(in.FileSetBytes) > MaxFileSetBytesV1 || in.NoticeSHA256 == ([32]byte{}) || len(in.Subject) < 1 || len(in.Subject) > 256 || strings.ContainsAny(in.Subject, "\r\n\x00") || len(in.Text) < 1 || len(in.Text) > 16384 || !utf8.ValidString(in.Subject+in.Text+in.FromName) || strings.ContainsRune(in.Text, 0) || len(in.RecipientEmails) < 1 || len(in.RecipientEmails) > 32 || len(in.FromName) > 512 || strings.ContainsAny(in.FromName, "\r\n\x00") || (in.ReplyTo != "" && !validAddressV1(in.ReplyTo)) || in.IssuedAt.IsZero() || in.IssuedAt.Location() != time.UTC || in.IssuedAt.Before(time.Now().Add(-time.Minute)) || in.IssuedAt.After(time.Now().Add(time.Minute)) || !in.RetainUntil.Equal(storage.EvidenceRetentionDeadline(in.IssuedAt, 7)) || in.RetainUntil.Location() != time.UTC || in.RetainUntil.Nanosecond() != 0 {
		return nil, ErrUnavailableV1
	}
	for i, email := range in.RecipientEmails {
		if !validAddressV1(email) {
			return nil, ErrUnavailableV1
		}
		for j := 0; j < i; j++ {
			if strings.EqualFold(email, in.RecipientEmails[j]) {
				return nil, ErrUnavailableV1
			}
		}
	}
	cost := int64(1<<20) + 4*int64(len(in.FileSetBytes)) + int64(len(in.RecipientEmails))*(12*int64(len(in.Subject)+len(in.Text)+len(in.ReplyTo)+len(in.FromName))+16384)
	grant, err := e.work.TryAcquireV1(ctx, in.OrgID, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		return nil, ErrUnavailableV1
	}
	state := &preparedStateV1{grant: grant}
	out = &PreparedV1{state: state}
	defer func() {
		if failure != nil {
			out.CloseV1()
			out = nil
		}
	}()
	files, err := DecodeFilesV1(in.FileSetBytes, in.FileCommitmentSHA256)
	if err != nil || files.DocumentID != in.DocumentID {
		return out, ErrUnavailableV1
	}
	typed, err := json.Marshal(files)
	if err != nil {
		return out, ErrUnavailableV1
	}
	defer clear(typed)
	claimed, err := json.Marshal(in.FileSet)
	defer clear(claimed)
	if err != nil || !bytes.Equal(typed, claimed) {
		return out, ErrUnavailableV1
	}
	for _, file := range files.Files {
		sum, _ := hex.DecodeString(file.SHA256)
		slot, err := e.physicalSlotV1()
		if err != nil {
			return out, err
		}
		handle, _, readErr := e.store.RetainPackagePDFLocalOwnedV1(ctx, file.Key, file.VersionID, sum, file.Bytes, in.RetainUntil, e.work, in.OrgID)
		slot.retain = handle
		if readErr == nil {
			readErr = handle.WithRetainedV1(func(until time.Time) error {
				if until.Before(in.RetainUntil) {
					return ErrUnavailableV1
				}
				return nil
			})
		}
		e.closePhysicalV1(slot)
		if readErr != nil {
			return out, ErrUnavailableV1
		}
	}
	state.input = in
	state.input.FileSetBytes = append([]byte(nil), in.FileSetBytes...)
	state.input.FileSet = files
	state.input.RecipientEmails = append([]string(nil), in.RecipientEmails...)
	state.proof = ProofV1{in.OrgID, in.NoticeID, in.AmendmentID, in.OriginalDocumentID, in.DocumentID, in.IssuedBy, in.NoticeSHA256, in.FileCommitmentSHA256, in.IssuedAt, in.RetainUntil, append([]string(nil), in.RecipientEmails...)}
	for _, recipient := range in.RecipientEmails {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			clear(secret)
			return out, ErrUnavailableV1
		}
		token := "hn1." + base64.RawURLEncoding.EncodeToString(secret)
		clear(secret)
		digest, err := TokenDigestV1(token)
		if err != nil {
			return out, err
		}
		link := e.publicURL + "/notice/" + in.NoticeID.String() + "#access=" + token
		text := in.Text + "\n\nRead the exact files declared in this notice:\n" + link + "\n\nThis link permits reading only. It does not request a signature or acknowledgement. Link expires " + in.IssuedAt.Add(AccessTTL).Format(time.RFC3339) + ".\n"
		htmlBody := "<p>" + strings.ReplaceAll(html.EscapeString(in.Text), "\n", "<br>") + "</p><p><a href=\"" + html.EscapeString(link) + "\">Read the exact notice files</a></p><p>Reading is not a signature, acknowledgement or verified delivery receipt. Link expires " + in.IssuedAt.Add(AccessTTL).Format(time.RFC3339) + ".</p>"
		message := dispatch.Message{To: recipient, Subject: in.Subject, HTML: htmlBody, Text: text, ReplyTo: in.ReplyTo, FromName: in.FromName}
		messageSHA, err := QueueMessageSHA256V1(message)
		if err != nil {
			return out, err
		}
		state.deliveries = append(state.deliveries, DeliveryV1{AccessID: uuid.New(), EmailDeliveryID: uuid.New(), OrgID: in.OrgID, NoticeID: in.NoticeID, RecipientEmail: recipient, TokenSHA256: digest, FileCommitmentSHA256: in.FileCommitmentSHA256, MessageSHA256: messageSHA, CreatedAt: in.IssuedAt, ExpiresAt: in.IssuedAt.Add(AccessTTL), Message: message})
	}
	return out, nil
}
func FileVersionSHA256V1(file amendments.FileV1) string {
	raw, _ := json.Marshal(file)
	sum := domainHashV1("hash:notice-file-version:v1", raw)
	return hex.EncodeToString(sum[:])
}
func ExpectedFileETagV1(commitment, file string) string {
	return fmt.Sprintf("\"%s.%s\"", commitment, file)
}

// Exact parity with existing hash_package_send_message_sha256_v1: seven UTF8
// strings, each framed by signed int8send byte length (nonnegative here).
// The notice mail adapter deliberately emits no custom transport headers.
func QueueMessageSHA256V1(message dispatch.Message) ([32]byte, error) {
	if len(message.Headers) != 0 {
		return [32]byte{}, ErrUnavailableV1
	}
	h := sha256.New()
	_, _ = h.Write([]byte("hash:package-send-message:v1\x00"))
	var frame [8]byte
	for _, value := range []string{message.To, message.Subject, message.HTML, message.Text, message.ReplyTo, message.FromName, "{}"} {
		binary.BigEndian.PutUint64(frame[:], uint64(len(value)))
		_, _ = h.Write(frame[:])
		_, _ = h.Write([]byte(value))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
