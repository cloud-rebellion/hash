// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package workspacesmtp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/secretbox"
	"github.com/google/uuid"
)

func syntheticConfig() Config {
	return Config{Host: "smtp.example.invalid", Port: 587, TLSMode: "starttls", SenderName: "Example workspace", SenderEmail: "sender@example.invalid", Username: "synthetic-user", Password: "synthetic-password"}
}
func TestWorkspaceSMTPValidation730(t *testing.T) {
	valid := syntheticConfig()
	if validate(valid) != nil {
		t.Fatal("synthetic SMTP config refused")
	}
	for name, change := range map[string]func(*Config){
		"plaintext": func(c *Config) { c.TLSMode = ""; c.Port = 1025 }, "tls-port": func(c *Config) { c.TLSMode = "tls" }, "starttls-port": func(c *Config) { c.Port = 465 }, "url": func(c *Config) { c.Host = "https://smtp.example.invalid" }, "space": func(c *Config) { c.Host = " smtp.example.invalid" }, "header": func(c *Config) { c.SenderName = "x\r\nBcc: other@example.invalid" }, "display-address": func(c *Config) { c.SenderEmail = "Other <sender@example.invalid>" }, "bad-address": func(c *Config) { c.SenderEmail = "not-an-address" }, "half-auth": func(c *Config) { c.Password = "" }, "user-control": func(c *Config) { c.Username = "user\n" }, "long-secret": func(c *Config) { c.Password = strings.Repeat("x", 4097) }, "invalid-utf8": func(c *Config) { c.SenderName = string([]byte{0xff}) },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			change(&c)
			if !errors.Is(validate(c), ErrInput) {
				t.Fatal("unsafe config accepted")
			}
		})
	}
	valid.Port, valid.TLSMode = 465, "tls"
	if validate(valid) != nil {
		t.Fatal("implicit TLS refused")
	}
	valid.Username, valid.Password = "", ""
	if validate(valid) != nil {
		t.Fatal("explicit TLS relay refused")
	}
}
func TestWorkspaceSMTPCredentialKeepBindsNormalizedEndpoint730(t *testing.T) {
	old := syntheticConfig()
	in := Input{Host: "SMTP.EXAMPLE.INVALID", Port: 587, TLSMode: "starttls", SenderName: "New display", SenderEmail: "new@example.invalid", CredentialsAction: "keep"}
	c, e := configForInput(in, &old)
	if e != nil || c.Host != "smtp.example.invalid" || c.Username != old.Username || c.Password != old.Password || c.SenderName != "New display" {
		t.Fatal("same endpoint keep failed")
	}
	for name, change := range map[string]func(*Input){"host": func(v *Input) { v.Host = "attacker.example.invalid" }, "port": func(v *Input) { v.Port = 465 }, "mode": func(v *Input) { v.TLSMode = "tls" }, "username": func(v *Input) { v.Username = &old.Username }, "password": func(v *Input) { v.Password = &old.Password }} {
		t.Run(name, func(t *testing.T) {
			v := in
			change(&v)
			if _, e := configForInput(v, &old); !errors.Is(e, ErrInput) {
				t.Fatal("stored credential redirected or replaced implicitly")
			}
		})
	}
	if _, e := configForInput(in, nil); !errors.Is(e, ErrInput) {
		t.Fatal("keep minted missing credentials")
	}
	user, pass := "", ""
	in.CredentialsAction = "replace"
	in.Username, in.Password = &user, &pass
	c, e = configForInput(in, nil)
	if e != nil || c.Username != "" || c.Password != "" {
		t.Fatal("explicit no-auth TLS relay failed")
	}
	in.Host = "replacement.example.invalid"
	user, pass = "new-user", "new-password"
	c, e = configForInput(in, &old)
	if e != nil || c.Host != in.Host || c.Password != "new-password" {
		t.Fatal("explicit replacement refused")
	}
	in.Password = nil
	if _, e = configForInput(in, &old); !errors.Is(e, ErrInput) {
		t.Fatal("missing explicit password accepted")
	}
}
func TestWorkspaceSMTPSecretboxPurposeOrgRevisionAndSafeOutput730(t *testing.T) {
	box, e := secretbox.New(bytes.Repeat([]byte{7}, 32), nil)
	if e != nil {
		t.Fatal(e)
	}
	s := Service{Box: box}
	org := uuid.New()
	c := syntheticConfig()
	raw, _ := json.Marshal(c)
	sealed, e := box.Seal(raw, aad(org, 2))
	if e != nil {
		t.Fatal(e)
	}
	r := row{revision: 2, mode: "configured", sealed: sealed}
	got, e := s.open(org, r)
	if e != nil || got != c {
		t.Fatal("correct row failed")
	}
	for name, mutate := range map[string]func(*row){"revision": func(v *row) { v.revision = 3 }, "mode": func(v *row) { v.mode = "disabled" }, "cipher": func(v *row) { v.sealed = append([]byte(nil), v.sealed...); v.sealed[len(v.sealed)-1] ^= 1 }} {
		t.Run(name, func(t *testing.T) {
			v := r
			mutate(&v)
			if _, e := s.open(org, v); !errors.Is(e, ErrUnavailable) {
				t.Fatal("row replay/tamper accepted")
			}
		})
	}
	if _, e := s.open(uuid.New(), r); !errors.Is(e, ErrUnavailable) {
		t.Fatal("cross-org ciphertext accepted")
	}
	safe, e := s.safe(org, r)
	if e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(safe)
	if bytes.Contains(body, []byte(c.Password)) || bytes.Contains(body, []byte(c.Username)) || bytes.Contains(body, []byte("ciphertext")) || !safe.UsernameSet || !safe.PasswordSet || !safe.Configured {
		t.Fatal("safe output disclosed credential or lost capabilities")
	}
	// A valid 4096-byte password can expand in JSON; opening must use the
	// reviewed ciphertext bound rather than an unrelated eight-KiB ceiling.
	escaped := c
	escaped.Password = strings.Repeat("\\", 4096)
	encoded, _ := json.Marshal(escaped)
	if len(encoded) <= 8192 {
		t.Fatal("fixture lacks actual JSON expansion")
	}
	blob, e := box.Seal(encoded, aad(org, 3))
	if e != nil {
		t.Fatal(e)
	}
	if got, e := s.open(org, row{revision: 3, mode: "configured", sealed: blob}); e != nil || got.Password != escaped.Password {
		t.Fatal("valid escaped credential refused")
	}
	for _, character := range []string{"<", ">", "&", "\\", "\""} {
		boundary := c
		boundary.Password = strings.Repeat(character, 4096)
		encoded, e := encodeConfig(boundary)
		if e != nil {
			t.Fatal("contract-valid password failed private encoding")
		}
		blob, e := box.Seal(encoded, aad(org, 4))
		if e != nil || len(blob) > 12288 {
			t.Fatal("private ciphertext exceeds reviewed bound")
		}
		got, e := s.open(org, row{revision: 4, mode: "configured", sealed: blob})
		if e != nil || got.Password != boundary.Password {
			t.Fatal("private encoding changed valid credential")
		}
	}
	for _, mode := range []string{"unconfigured", "installation_legacy", "disabled"} {
		v, e := s.safe(org, row{mode: mode})
		if e != nil || v.Configured || v.Host != "" || v.Port != 0 || v.UsernameSet || v.PasswordSet {
			t.Fatal("missing settings invented a configured transport")
		}
	}
}

type noNetworkMailer struct{ calls int }

func (m *noNetworkMailer) Send(context.Context, dispatch.Message) error { m.calls++; return nil }
func TestWorkspaceSMTPMissingAuthorityNeverFallsBack730(t *testing.T) {
	legacy := &noNetworkMailer{}
	if e := (Service{}).Deliver(context.Background(), nil, dispatch.Message{}, legacy); !errors.Is(e, ErrUnavailable) || legacy.calls != 0 {
		t.Fatal("missing tenant authority used installation sender")
	}
	if _, e := (Service{}).Test(context.Background(), authoring.Actor{}, 0); !errors.Is(e, ErrInput) {
		t.Fatal("unconfigured test accepted")
	}
	if strings.Contains(testText, "http") || strings.Contains(testHTML, "src=") || !strings.Contains(testText, "synthetic") || !strings.Contains(testText, "does not confirm inbox") {
		t.Fatal("synthetic test claims tracking/business/inbox delivery")
	}
}
