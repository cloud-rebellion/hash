// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/workspacesmtp"
)

const smtp730Input = `{"expected_revision":0,"host":"smtp.example.invalid","port":587,"tls_mode":"starttls","sender_name":"Example","sender_email":"sender@example.invalid","credentials_action":"replace","username":"synthetic","password":"synthetic"}`

func TestWorkspaceSMTPStrictOwnerInput730(t *testing.T) {
	in, e := decodeWorkspaceSMTPInputJSON([]byte(smtp730Input))
	if e != nil || in.Host != "smtp.example.invalid" || in.Username == nil || *in.Username != "synthetic" {
		t.Fatal("valid closed input refused", e)
	}
	for name, raw := range map[string]string{
		"extra-org": strings.Replace(smtp730Input, `"host":`, `"org_id":"foreign","host":`, 1), "case-alias": strings.Replace(smtp730Input, `"host":`, `"Host":`, 1), "duplicate": strings.Replace(smtp730Input, `"host":`, `"host":"other","host":`, 1), "missing": strings.Replace(smtp730Input, `"port":587,`, "", 1), "null-host": strings.Replace(smtp730Input, `"smtp.example.invalid"`, `null`, 1), "null-user": strings.Replace(smtp730Input, `"username":"synthetic"`, `"username":null`, 1), "null-password": strings.Replace(smtp730Input, `"password":"synthetic"`, `"password":null`, 1), "keep-fields": strings.Replace(smtp730Input, `"replace"`, `"keep"`, 1), "trailing": smtp730Input + "{}", "overflow": strings.Repeat(" ", 33<<10) + smtp730Input,
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := decodeWorkspaceSMTPInputJSON([]byte(raw)); !errors.Is(e, workspacesmtp.ErrInput) {
				t.Fatal("ambiguous or caller-scoped SMTP input accepted")
			}
		})
	}
	keep := strings.Replace(smtp730Input, `,"username":"synthetic","password":"synthetic"`, "", 1)
	keep = strings.Replace(keep, `"replace"`, `"keep"`, 1)
	in, e = decodeWorkspaceSMTPInputJSON([]byte(keep))
	if e != nil || in.Username != nil || in.Password != nil {
		t.Fatal("keep manufactured credential values")
	}
}
