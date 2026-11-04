// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"errors"
	"html"
	"math"
	"net/mail"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/config"
	"github.com/google/uuid"
)

var ErrSenderEventNoticeV1 = errors.New("sender event notice unavailable")

// SenderEventNoticeOutputBoundV1 is a logical producer bound, not a grant or
// measured heap. The actual native caller acquires it BEFORE parsing, escaping,
// formatting or reading returned queue bodies. It prices HTML expansion and
// detached message/SQL/driver copies, including the fixed M120 workspace route.
func SenderEventNoticeOutputBoundV1(documentBytes, recipientBytes, urlBytes int64) (int64, int64, error) {
	total := int64(4096 + 254)
	for _, n := range [...]int64{documentBytes, recipientBytes, urlBytes} {
		if n < 0 || n > (math.MaxInt64-total) {
			return 0, 0, ErrSenderEventNoticeV1
		}
		total += n
	}
	if total > math.MaxInt64/64 {
		return 0, 0, ErrSenderEventNoticeV1
	}
	return total * 64, total * 16, nil
}

// Built-in operational notice only. No signing capability, contract attachment,
// recipient magic link, tracking pixel or custom HTML is included. The native
// producer supplies the locked document's sender and actual audited event.
func SenderEventNoticeMessageV1(kind, publicURL, to string, document uuid.UUID, documentName, recipientName string) (Message, error) {
	if document == uuid.Nil || len(to) < 3 || len(to) > 254 || len(publicURL) < 1 || len(publicURL) > 1024 || !utf8.ValidString(documentName) || !utf8.ValidString(recipientName) {
		return Message{}, ErrSenderEventNoticeV1
	}
	a, err := mail.ParseAddress(to)
	u, urlErr := url.Parse(publicURL)
	if err != nil || a.Name != "" || a.Address != to || strings.ContainsAny(to, "\r\n\x00") || urlErr != nil || u.User != nil || u.Host == "" || strings.ContainsAny(publicURL, "?#\r\n\x00") || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && config.IsLocalDevelopment(publicURL))) {
		return Message{}, ErrSenderEventNoticeV1
	}
	subject, action := "", ""
	switch kind {
	case "document.viewed":
		subject, action = "Hash: document viewed", "viewed"
	case "document.signed":
		subject, action = "Hash: recipient signed", "signed"
	default:
		return Message{}, ErrSenderEventNoticeV1
	}
	if recipientName == "" {
		recipientName = "A recipient"
	}
	link := strings.TrimRight(publicURL, "/") + "/documents/" + document.String()
	body := recipientName + " " + action + " your document: " + documentName + "."
	ending := "Open Hash to review the current document status and its evidence. Sign in is required."
	return Message{To: to, Subject: subject, Text: body + "\n\n" + ending + "\n" + link + "\n", HTML: "<p>" + html.EscapeString(body) + "</p><p>" + html.EscapeString(ending) + "</p><p><a href=\"" + html.EscapeString(link) + "\">Open Hash</a></p>", FromName: "Hash"}, nil
}
