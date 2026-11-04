// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package workspacesmtp owns encrypted per-organization SMTP settings and
// genuine retained-outbox routing. It never infers tenant identity from mail.
package workspacesmtp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrInput       = errors.New("invalid workspace SMTP settings")
	ErrStale       = errors.New("workspace SMTP revision changed; reload and review")
	ErrUnavailable = errors.New("workspace SMTP unavailable or not configured")
	ErrTestBusy    = errors.New("workspace SMTP test already pending or requested recently")
)

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLSMode     string `json:"tls_mode"`
	SenderName  string `json:"sender_name"`
	SenderEmail string `json:"sender_email"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}
type Input struct {
	ExpectedRevision  int64   `json:"expected_revision"`
	Host              string  `json:"host"`
	Port              int     `json:"port"`
	TLSMode           string  `json:"tls_mode"`
	SenderName        string  `json:"sender_name"`
	SenderEmail       string  `json:"sender_email"`
	CredentialsAction string  `json:"credentials_action"`
	Username          *string `json:"username,omitempty"`
	Password          *string `json:"password,omitempty"`
}
type SafeSettings struct {
	SchemaVersion int        `json:"schema_version"`
	Revision      int64      `json:"revision"`
	Mode          string     `json:"mode"`
	Configured    bool       `json:"configured"`
	Host          string     `json:"host"`
	Port          int        `json:"port"`
	TLSMode       string     `json:"tls_mode"`
	SenderName    string     `json:"sender_name"`
	SenderEmail   string     `json:"sender_email"`
	UsernameSet   bool       `json:"username_set"`
	PasswordSet   bool       `json:"password_set"`
	UpdatedAt     *time.Time `json:"updated_at"`
}
type TestStatus struct {
	DeliveryID             uuid.UUID `json:"delivery_id"`
	Status                 string    `json:"status"`
	SMTPAccepted           bool      `json:"smtp_accepted"`
	InboxDeliveryConfirmed bool      `json:"inbox_delivery_confirmed"`
}
type Service struct {
	MIMEWork     dispatch.ServiceEmailMIMEAdmissionV1
	Pool         *pgxpool.Pool
	Audit        *audit.Logger
	Box          *secretbox.Box
	AllowPrivate bool                                               // installation local-development predicate, never tenant input
	newMailer    func(dispatch.SMTPConfig) (dispatch.Mailer, error) // private transport-consumer fixture seam
}
type row struct {
	revision int64
	mode     string
	sealed   []byte
	updated  pgtype.Timestamptz
}

func read(ctx context.Context, tx pgx.Tx, org uuid.UUID, share bool) (row, error) {
	var r row
	query := `SELECT revision,mode,config_ciphertext,updated_at FROM org_smtp_settings_v1 WHERE org_id=$1`
	if share {
		query += ` FOR SHARE`
	}
	err := tx.QueryRow(ctx, query, org).Scan(&r.revision, &r.mode, &r.sealed, &r.updated)
	if errors.Is(err, pgx.ErrNoRows) {
		return row{mode: "unconfigured"}, nil
	}
	return r, err
}
func aad(org uuid.UUID, revision int64) []byte {
	b, _ := json.Marshal(struct {
		Purpose  string
		Org      uuid.UUID
		Revision int64
	}{"hash.workspace-smtp.v1", org, revision})
	return b
}
func text(value string, limit int) bool {
	if !utf8.ValidString(value) || len(value) > limit {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.TrimSpace(host) != host {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validate(c Config) error {
	if !validHost(c.Host) || !((c.TLSMode == "starttls" && c.Port == 587) || (c.TLSMode == "tls" && c.Port == 465)) || !text(c.SenderName, 200) || !text(c.SenderEmail, 254) || !text(c.Username, 256) || !text(c.Password, 4096) || (c.Username == "") != (c.Password == "") {
		return ErrInput
	}
	a, e := mail.ParseAddress(c.SenderEmail)
	if e != nil || a.Address != c.SenderEmail || a.Name != "" {
		return ErrInput
	}
	return nil
}
func configForInput(in Input, old *Config) (Config, error) {
	if !validHost(in.Host) {
		return Config{}, ErrInput
	}
	c := Config{Host: strings.ToLower(in.Host), Port: in.Port, TLSMode: in.TLSMode, SenderName: in.SenderName, SenderEmail: in.SenderEmail}
	switch in.CredentialsAction {
	case "keep":
		if old == nil || in.Username != nil || in.Password != nil || c.Host != strings.ToLower(old.Host) || c.Port != old.Port || c.TLSMode != old.TLSMode {
			return Config{}, ErrInput
		}
		c.Username, c.Password = old.Username, old.Password
	case "replace":
		if in.Username == nil || in.Password == nil {
			return Config{}, ErrInput
		}
		c.Username, c.Password = *in.Username, *in.Password
	default:
		return Config{}, ErrInput
	}
	if validate(c) != nil {
		return Config{}, ErrInput
	}
	return c, nil
}

// This is an encrypted private JSON payload, never HTML. HTML escaping could
// expand a contract-valid 4096-byte password beyond the ciphertext bound.
func encodeConfig(c Config) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if encoder.Encode(c) != nil || buffer.Len() > 12288 {
		return nil, ErrInput
	}
	return buffer.Bytes(), nil
}

func (s Service) open(org uuid.UUID, r row) (Config, error) {
	var c Config
	if s.Box == nil || org == uuid.Nil || r.mode != "configured" || r.revision < 1 || len(r.sealed) < 30 || len(r.sealed) > 12288 {
		return c, ErrUnavailable
	}
	raw, _, e := s.Box.Open(r.sealed, aad(org, r.revision))
	if e != nil || len(raw) > 12288 {
		return c, ErrUnavailable
	}
	defer clear(raw)
	if json.Unmarshal(raw, &c) != nil || validate(c) != nil {
		return Config{}, ErrUnavailable
	}
	return c, nil
}
func (s Service) safe(org uuid.UUID, r row) (SafeSettings, error) {
	out := SafeSettings{SchemaVersion: 1, Revision: r.revision, Mode: r.mode}
	if r.updated.Valid {
		t := r.updated.Time
		out.UpdatedAt = &t
	}
	if r.mode == "configured" {
		c, e := s.open(org, r)
		if e != nil {
			return SafeSettings{}, e
		}
		out.Configured = true
		out.Host = c.Host
		out.Port = c.Port
		out.TLSMode = c.TLSMode
		out.SenderName = c.SenderName
		out.SenderEmail = c.SenderEmail
		out.UsernameSet = c.Username != ""
		out.PasswordSet = c.Password != ""
	}
	return out, nil
}
func (s Service) owner(ctx context.Context, a authoring.Actor, fn func(context.Context, pgx.Tx, *authoring.MemberGuard) (audit.PendingEvent, error)) error {
	if s.Pool == nil || s.Audit == nil || s.Box == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return ErrUnavailable
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	g, e := authoring.LockOwner(ctx, tx, a)
	if e != nil {
		return e
	}
	pending, e := fn(ctx, tx, g)
	if e != nil {
		return e
	}
	if e = g.Recheck(ctx); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	if pending.ID != uuid.Nil {
		s.Audit.Publish(pending)
	}
	return nil
}
func (s Service) Get(ctx context.Context, a authoring.Actor) (out SafeSettings, err error) {
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) (audit.PendingEvent, error) {
		r, e := read(ctx, tx, a.OrgID, false)
		if e == nil {
			out, e = s.safe(a.OrgID, r)
		}
		return audit.PendingEvent{}, e
	})
	return
}
func (s Service) Save(ctx context.Context, a authoring.Actor, in Input) (out SafeSettings, err error) {
	if in.ExpectedRevision < 0 || in.ExpectedRevision == math.MaxInt64 {
		return out, ErrInput
	}
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) (audit.PendingEvent, error) {
		r, e := read(ctx, tx, a.OrgID, false)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		if r.revision != in.ExpectedRevision {
			return audit.PendingEvent{}, ErrStale
		}
		var previous *Config
		if in.CredentialsAction == "keep" {
			v, e := s.open(a.OrgID, r)
			if e != nil {
				return audit.PendingEvent{}, ErrInput
			}
			previous = &v
		}
		c, e := configForInput(in, previous)
		if e != nil {
			return audit.PendingEvent{}, e
		}

		revision := r.revision + 1
		raw, e := encodeConfig(c)
		if e != nil {
			return audit.PendingEvent{}, ErrInput
		}
		sealed, e := s.Box.Seal(raw, aad(a.OrgID, revision))
		clear(raw)
		if e != nil || len(sealed) > 12288 {
			return audit.PendingEvent{}, ErrUnavailable
		}
		_, e = tx.Exec(ctx, `INSERT INTO org_smtp_settings_v1(org_id,revision,mode,config_ciphertext) VALUES($1,$2,'configured',$3) ON CONFLICT(org_id) DO UPDATE SET revision=EXCLUDED.revision,mode='configured',config_ciphertext=EXCLUDED.config_ciphertext,updated_at=clock_timestamp()`, a.OrgID, revision, sealed)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		fresh, e := read(ctx, tx, a.OrgID, false)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		out, e = s.safe(a.OrgID, fresh)
		if e != nil {
			return audit.PendingEvent{}, e
		}
		return s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: a.OrgID, ActorUserID: &a.UserID, Kind: "workspace_smtp.updated", Payload: map[string]any{"revision": revision, "mode": "configured"}})
	})
	return
}
func (s Service) Disable(ctx context.Context, a authoring.Actor, expected int64) (out SafeSettings, err error) {
	if expected < 0 || expected == math.MaxInt64 {
		return out, ErrInput
	}
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) (audit.PendingEvent, error) {
		r, e := read(ctx, tx, a.OrgID, false)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		if r.revision != expected {
			return audit.PendingEvent{}, ErrStale
		}
		_, e = tx.Exec(ctx, `INSERT INTO org_smtp_settings_v1(org_id,revision,mode) VALUES($1,$2,'disabled') ON CONFLICT(org_id) DO UPDATE SET revision=EXCLUDED.revision,mode='disabled',config_ciphertext=NULL,updated_at=clock_timestamp()`, a.OrgID, expected+1)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		r, e = read(ctx, tx, a.OrgID, false)
		if e == nil {
			out, e = s.safe(a.OrgID, r)
		}
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		return s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: a.OrgID, ActorUserID: &a.UserID, Kind: "workspace_smtp.disabled", Payload: map[string]any{"revision": expected + 1}})
	})
	return
}

const testSubject = "Hash workspace SMTP test — synthetic"
const testText = "This is a synthetic SMTP configuration test requested by your authenticated workspace owner. It contains no document, signing request or tracking. SMTP acceptance does not confirm inbox delivery."
const testHTML = "<p>" + testText + "</p>"

func (s Service) Test(ctx context.Context, a authoring.Actor, expected int64) (out TestStatus, err error) {
	if expected < 1 {
		return out, ErrInput
	}
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) (audit.PendingEvent, error) {
		r, e := read(ctx, tx, a.OrgID, false)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		if r.revision != expected {
			return audit.PendingEvent{}, ErrStale
		}
		if _, e = s.open(a.OrgID, r); e != nil {
			return audit.PendingEvent{}, e
		}
		u, e := generated.New(tx).GetUserForShare(ctx, generated.GetUserForShareParams{ID: a.UserID, OrgID: a.OrgID})
		if e != nil || u.Role != string(auth.RoleOwner) {
			return audit.PendingEvent{}, auth.ErrMutationPermissionRevoked
		}
		address, e := mail.ParseAddress(u.Email)
		if e != nil || address.Address != u.Email {
			return audit.PendingEvent{}, ErrInput
		}
		var updated uuid.UUID
		e = tx.QueryRow(ctx, `UPDATE org_smtp_settings_v1 SET last_test_at=clock_timestamp() WHERE org_id=$1 AND revision=$2 AND mode='configured' AND(last_test_at IS NULL OR last_test_at<clock_timestamp()-interval '60 seconds') AND NOT EXISTS(SELECT 1 FROM org_smtp_test_requests_v1 t JOIN email_deliveries d ON d.id=t.email_delivery_id WHERE t.org_id=$1 AND d.status IN ('pending','retrying')) RETURNING org_id`, a.OrgID, expected).Scan(&updated)
		if errors.Is(e, pgx.ErrNoRows) {
			return audit.PendingEvent{}, ErrTestBusy
		}
		if e != nil || updated != a.OrgID {
			return audit.PendingEvent{}, ErrUnavailable
		}
		var id uuid.UUID
		e = tx.QueryRow(ctx, `INSERT INTO email_deliveries(smtp_org_id,smtp_purpose,to_email,subject,html_body,text_body,reply_to,from_name,headers_json) VALUES($1,'workspace_test',$2,$3,$4,$5,'','','{}') RETURNING id`, a.OrgID, u.Email, testSubject, testHTML, testText).Scan(&id)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		_, e = tx.Exec(ctx, `INSERT INTO org_smtp_test_requests_v1(email_delivery_id,org_id,owner_id,settings_revision) VALUES($1,$2,$3,$4)`, id, a.OrgID, a.UserID, expected)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		out = TestStatus{DeliveryID: id, Status: "pending"}
		return s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: a.OrgID, ActorUserID: &a.UserID, Kind: "workspace_smtp.test_queued", Payload: map[string]any{"delivery_id": id, "revision": expected}})
	})
	return
}
func (s Service) TestStatus(ctx context.Context, a authoring.Actor, id uuid.UUID) (out TestStatus, err error) {
	if id == uuid.Nil {
		return out, ErrInput
	}
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, _ *authoring.MemberGuard) (audit.PendingEvent, error) {
		e := tx.QueryRow(ctx, `SELECT d.id,d.status FROM org_smtp_test_requests_v1 t JOIN email_deliveries d ON d.id=t.email_delivery_id WHERE t.org_id=$1 AND t.owner_id=$2 AND t.email_delivery_id=$3 AND d.smtp_org_id=t.org_id AND d.smtp_purpose='workspace_test'`, a.OrgID, a.UserID, id).Scan(&out.DeliveryID, &out.Status)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		out.SMTPAccepted = out.Status == "sent"
		return audit.PendingEvent{}, nil
	})
	return
}

// Deliver holds the native settings SHARE lock through the one bounded SMTP
// attempt. No mutable transport cache, recipient-based lookup or silent fallback.
func (s Service) Deliver(ctx context.Context, d *generated.EmailDelivery, msg dispatch.Message, installation dispatch.Mailer) error {
	if s.Pool == nil || d == nil || !d.SmtpOrgID.Valid || uuid.UUID(d.SmtpOrgID.Bytes) == uuid.Nil || (d.SmtpPurpose != "workspace" && d.SmtpPurpose != "workspace_test") {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	org := uuid.UUID(d.SmtpOrgID.Bytes)
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return ErrUnavailable
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	var testRevision int64
	if d.SmtpPurpose == "workspace_test" {
		var lockedOrg uuid.UUID
		if e = tx.QueryRow(ctx, `SELECT id FROM orgs WHERE id=$1 FOR KEY SHARE`, org).Scan(&lockedOrg); e != nil || lockedOrg != org {
			return ErrUnavailable
		}
		var owner uuid.UUID
		var email, role string
		var sampleKind pgtype.Text
		var sampleRevision pgtype.Int8
		var subjectHash, htmlHash, textHash []byte
		e = tx.QueryRow(ctx, `SELECT t.owner_id,t.settings_revision,u.email,u.role,t.template_kind,t.template_revision,t.subject_sha256,t.html_sha256,t.text_sha256 FROM org_smtp_test_requests_v1 t JOIN users u ON u.id=t.owner_id AND u.org_id=t.org_id WHERE t.email_delivery_id=$1 AND t.org_id=$2 FOR SHARE OF u,t`, d.ID, org).Scan(&owner, &testRevision, &email, &role, &sampleKind, &sampleRevision, &subjectHash, &htmlHash, &textHash)
		if e != nil || owner == uuid.Nil || role != string(auth.RoleOwner) || email != d.ToEmail || !workspaceTestContentMatchesV1(d, msg, sampleKind, sampleRevision, subjectHash, htmlHash, textHash) {
			return ErrUnavailable
		}
	}
	// Match owner mutation lock order: organization, live owner/test receipt, then
	// settings. All remain retained through bounded SMTP acceptance.
	r, e := read(ctx, tx, org, true)
	if e != nil {
		return ErrUnavailable
	}
	if d.SmtpPurpose == "workspace_test" && testRevision != r.revision {
		return ErrUnavailable
	}

	msg.OrgID = org // derive the MIME resource tenant before either delivery branch
	if r.mode == "installation_legacy" && r.revision == 0 && r.sealed == nil && d.SmtpPurpose == "workspace" {
		if installation == nil {
			return ErrUnavailable
		}
		return installation.Send(ctx, msg)
	}
	c, e := s.open(org, r)
	if e != nil {
		return e
	}
	sender := (&mail.Address{Name: c.SenderName, Address: c.SenderEmail}).String()
	cfg := dispatch.SMTPConfig{Host: c.Host, Port: c.Port, TLSMode: c.TLSMode, User: c.Username, Password: c.Password, From: sender, PublicOnly: true, AllowPrivate: s.AllowPrivate, MIMEWork: s.MIMEWork}
	var m dispatch.Mailer
	if s.newMailer == nil {
		m, e = dispatch.NewSMTPMailer(cfg)
	} else {
		m, e = s.newMailer(cfg)
	}
	if e != nil {
		return ErrUnavailable
	}
	msg.FromName = "" // configured sender is authoritative, never another org display name
	if e = m.Send(ctx, msg); e != nil {
		if errors.Is(e, context.Canceled) {
			return context.Canceled
		}
		if errors.Is(e, context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return ErrUnavailable
	}
	return nil
}
