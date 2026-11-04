// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func emailDesignMIMEFixture760(t *testing.T) (Message, string) {
	t.Helper()
	design := DefaultServiceEmailDesignV1()
	design.Logo = designLogo760(t)
	_, body, text, err := RenderServiceEmailV1(KindInvite, designContext760(), &ServiceEmailTemplateV1{DesignJSON: designJSON760(t, design)})
	if err != nil {
		t.Fatal(err)
	}
	return Message{OrgID: uuid.New(), To: "recipient@example.invalid", Subject: "Contract", HTML: body, Text: text, ReplyTo: "owner@example.invalid", FromName: "Workspace"}, design.Logo.SHA256
}

func TestServiceEmailDesign760MIMEEmbedsExactCommittedLogoAndNativeParts(t *testing.T) {
	msg, digest := emailDesignMIMEFixture760(t)
	wire, err := buildMIME("Workspace <sender@example.invalid>", msg)
	if err != nil {
		t.Fatal(err)
	}
	message, err := mail.ReadMessage(strings.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	media, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || media != "multipart/related" || params["boundary"] != "hash-related-"+digest {
		t.Fatal("wrong deterministic related MIME", err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	alternative, err := reader.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	media, params, err = mime.ParseMediaType(alternative.Header.Get("Content-Type"))
	if err != nil || media != "multipart/alternative" {
		t.Fatal("native alternative parts lost", err)
	}
	parts := multipart.NewReader(alternative, params["boundary"])
	plain, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	text, err := io.ReadAll(plain)
	if err != nil || string(text) != msg.Text {
		t.Fatal("plain native content changed", err)
	}
	html, err := parts.NextPart()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(html)
	if err != nil || !bytes.Contains(body, []byte(`src="cid:hash-logo-`+digest+`@hash.invalid"`)) || bytes.Contains(body, []byte("data:image")) || bytes.Contains(body, []byte("data-hash-logo=")) || !bytes.Contains(body, []byte(designContext760().SignURL)) {
		t.Fatal("native action or self-contained CID lost", err)
	}
	logo, err := reader.NextPart()
	if err != nil || logo.Header.Get("Content-ID") != "<hash-logo-"+digest+"@hash.invalid>" || logo.Header.Get("Content-Type") != "image/png" {
		t.Fatal("committed inline part missing", err)
	}
	encoded, err := io.ReadAll(logo)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := base64.StdEncoding.DecodeString(string(encoded))
	expected, _ := base64.StdEncoding.DecodeString(designLogo760(t).DataBase64)
	if err != nil || !bytes.Equal(actual, expected) {
		t.Fatal("inline bytes differ from frozen committed logo", err)
	}
	if _, err := reader.NextPart(); err != io.EOF {
		t.Fatal("unexpected additional remote or tracking part", err)
	}
	if message.Header.Get("Reply-To") != msg.ReplyTo || !strings.Contains(message.Header.Get("From"), "sender@example.invalid") {
		t.Fatal("authenticated sender/reply-to changed")
	}
}

func TestServiceEmailDesign760MIMERefusesMissingOwnerAndBadCommitmentBeforeNetwork(t *testing.T) {
	msg, digest := emailDesignMIMEFixture760(t)
	mailer, err := NewSMTPMailer(SMTPConfig{Host: "smtp.example.invalid", Port: 587, From: "sender@example.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	dials := 0
	mailer.dialContext = func(context.Context, string, string) (net.Conn, error) {
		dials++
		return nil, errors.New("unexpected network")
	}
	if err := mailer.Send(context.Background(), msg); !errors.Is(err, ErrServiceEmailMIMEV1) || dials != 0 {
		t.Fatal("unowned logo reached SMTP", err, dials)
	}
	for _, body := range []string{strings.Replace(msg.HTML, digest, strings.Repeat("0", 64), 1), strings.Replace(msg.HTML, "data:image/png;base64,", "https://tracker.invalid/", 1), msg.HTML + msg.HTML} {
		bad := msg
		bad.HTML = body
		if _, err := buildMIME("sender@example.invalid", bad); !errors.Is(err, ErrServiceEmailMIMEV1) {
			t.Fatal("bad digest/remote/duplicate inline logo accepted", err)
		}
	}
}

func TestServiceEmailDesign760MarkerTextDoesNotSelectOrRepeatMIMEConversion(t *testing.T) {
	for _, logo := range []bool{false, true} {
		context := designContext760()
		context.DocumentName = "The literal data-hash-logo= marker"
		var tpl *ServiceEmailTemplateV1
		if logo {
			design := DefaultServiceEmailDesignV1()
			design.Logo = designLogo760(t)
			tpl = &ServiceEmailTemplateV1{DesignJSON: designJSON760(t, design)}
		}
		subject, body, text, err := RenderServiceEmailV1(KindInvite, context, tpl)
		if err != nil {
			t.Fatal(err)
		}
		if serviceEmailHasInlineLogoV1(body) != logo {
			t.Fatal("ordinary title text selected native conversion")
		}
		wire, err := buildMIME("sender@example.invalid", Message{To: "recipient@example.invalid", Subject: subject, HTML: body, Text: text})
		if err != nil || !strings.Contains(wire, "data-hash-logo=") {
			t.Fatal("marker text changed legacy bytes or repeated CID conversion", err)
		}
	}
}
