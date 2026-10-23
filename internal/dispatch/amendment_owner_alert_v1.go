// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package dispatch

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/google/uuid"
	"html"
	"io"
	"net/mail"
	"net/url"
	"strings"
)

const AmendmentOwnerAlertHeaderV1 = "X-Hash-Operational-Event"
const AmendmentOwnerAlertPurposeV1 = "amendment-owner-v1"

// PostgreSQL jsonb::text framing, exactly matching the existing queue digest.
const AmendmentOwnerAlertHeadersJSONV1 = `{"X-Hash-Operational-Event": "amendment-owner-v1"}`

var ErrAmendmentOwnerAlertV1 = errors.New("amendment owner alert unavailable")

// Pure bounded message construction. This grants no authority: the native
// adapter supplies the fresh actual original SenderID/email and stores its
// queue/event binding in the same mutation transaction. No contract names,
// clauses, party addresses, mode/legal-effect assertion or capability is mailed.
func AmendmentOwnerAlertMessageV1(kind, publicURL, to string, original uuid.UUID) (Message, error) {
	if len(to) < 3 || len(to) > 254 || len(publicURL) < 1 || len(publicURL) > 1024 || original == uuid.Nil {
		return Message{}, ErrAmendmentOwnerAlertV1
	}
	a, e := mail.ParseAddress(to)
	u, urlErr := url.Parse(publicURL)
	if e != nil || a.Name != "" || a.Address != to || len(to) > 254 || strings.ContainsAny(to, "\r\n\x00") || original == uuid.Nil || len(publicURL) > 1024 || urlErr != nil || u.User != nil || u.Host == "" || strings.ContainsAny(publicURL, "?#") || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && config.IsLocalDevelopment(publicURL))) {
		return Message{}, ErrAmendmentOwnerAlertV1
	}
	subject, text := "", ""
	switch kind {
	case "document.amendment_linked":
		subject = "Hash: later agreement proposal"
		text = "A later proposal was linked to an agreement you own. Review its current history in Hash."
	case "document.amendment_notice_queued":
		subject = "Hash: agreement notice queued"
		text = "An agreed-process notice was queued for an agreement you own. Review its current history in Hash. Queueing does not prove delivery, acknowledgement, signature or legal effectiveness."
	default:
		return Message{}, ErrAmendmentOwnerAlertV1
	}
	link := strings.TrimRight(publicURL, "/") + "/documents/" + original.String()
	return Message{To: to, Subject: subject, Text: text + "\n\nOpen Hash (sign in required):\n" + link + "\n", HTML: "<p>" + html.EscapeString(text) + "</p><p><a href=\"" + html.EscapeString(link) + "\">Open Hash (sign in required)</a></p>", FromName: "Hash", Headers: map[string]string{AmendmentOwnerAlertHeaderV1: AmendmentOwnerAlertPurposeV1}}, nil
}
func AmendmentOwnerAlertMessageSHA256V1(m Message) ([32]byte, error) {
	if len(m.Headers) != 1 || m.Headers[AmendmentOwnerAlertHeaderV1] != AmendmentOwnerAlertPurposeV1 || m.FromName != "Hash" || m.ReplyTo != "" {
		return [32]byte{}, ErrAmendmentOwnerAlertV1
	}
	h := sha256.New()
	_, _ = io.WriteString(h, "hash:package-send-message:v1\x00")
	var size [8]byte
	for _, s := range []string{m.To, m.Subject, m.HTML, m.Text, m.ReplyTo, m.FromName, AmendmentOwnerAlertHeadersJSONV1} {
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		_, _ = h.Write(size[:])
		_, _ = io.WriteString(h, s)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}
