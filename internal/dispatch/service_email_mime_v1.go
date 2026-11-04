// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package dispatch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	nethtml "golang.org/x/net/html"
	"io"
	"strings"
)

// This is installed only from the original configured worker WorkRuntime.
// It prices the actual message, never a request-supplied resource vector.
type ServiceEmailMIMEAdmissionV1 interface {
	ServiceEmailMIMEV1(context.Context, Message) (func(), error)
}

var ErrServiceEmailMIMEV1 = errors.New("email logo MIME ownership or commitment unavailable")

const ServiceEmailMIMEBytesV1 = 2 << 20

func serviceEmailHasInlineLogoV1(body string) bool {
	// Text such as a document title may contain the marker's spelling. Only
	// an image tag can select native MIME conversion; after the actual tag is
	// rewritten to CID, unrelated text cannot recursively select it again.
	for {
		start := strings.Index(body, "<img")
		if start < 0 {
			return false
		}
		body = body[start+4:]
		end := strings.IndexByte(body, '>')
		if end < 0 {
			return strings.Contains(body, "data-hash-logo=")
		}
		if strings.Contains(body[:end], "data-hash-logo=") {
			return true
		}
		body = body[end+1:]
	}
}
func ServiceEmailMIMEWorkingBytesV1(msg Message) (int64, error) {
	if len(msg.HTML) > ServiceEmailDesignRenderedBytesV1+65536 || len(msg.Text) > ServiceEmailDesignRenderedBytesV1+65536 || len(msg.Subject) > ServiceEmailRenderedSubjectBytesV1+256 || len(msg.To) > 320 || len(msg.ReplyTo) > 320 || len(msg.FromName) > 512 {
		return 0, ErrServiceEmailMIMEV1
	}
	n := int64(len(msg.HTML) + len(msg.Text) + len(msg.Subject) + len(msg.To) + len(msg.ReplyTo) + len(msg.FromName))
	headers := 0
	for k, v := range msg.Headers {
		headers += len(k) + len(v)
		if len(k) > 80 || headers > 16384 {
			return 0, ErrServiceEmailMIMEV1
		}
	}
	n += int64(headers)
	// Bounded tokenizer/rewritten HTML, native MIME alternative, related MIME,
	// exact decoded raster bytes and base64 line copies remain live through DATA.
	return 12*n + 262144, nil
}

type emailInlineLogoV1 struct{ rawTag, rewrittenTag, encoded, media, digest, cid string }

func serviceEmailInlineLogoV1(body string) (emailInlineLogoV1, bool, error) {
	var logo emailInlineLogoV1
	if len(body) > ServiceEmailDesignRenderedBytesV1+65536 {
		return logo, false, ErrServiceEmailMIMEV1
	}
	tokenizer := nethtml.NewTokenizer(strings.NewReader(body))
	found := false
	for count := 0; ; count++ {
		if count > 8192 {
			return logo, false, ErrServiceEmailMIMEV1
		}
		kind := tokenizer.Next()
		if kind == nethtml.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return logo, false, ErrServiceEmailMIMEV1
			}
			break
		}
		if kind != nethtml.StartTagToken && kind != nethtml.SelfClosingTagToken {
			continue
		}
		raw := string(tokenizer.Raw())
		tag := tokenizer.Token()
		if tag.Data != "img" {
			continue
		}
		attrs := map[string]string{}
		for _, a := range tag.Attr {
			if _, exists := attrs[a.Key]; exists {
				return logo, false, ErrServiceEmailMIMEV1
			}
			attrs[a.Key] = a.Val
		}
		digest := attrs["data-hash-logo"]
		if digest == "" {
			continue
		}
		if found || len(digest) != 64 {
			return logo, false, ErrServiceEmailMIMEV1
		}
		digestBytes, e := hex.DecodeString(digest)
		if e != nil || len(digestBytes) != 32 || hex.EncodeToString(digestBytes) != digest {
			return logo, false, ErrServiceEmailMIMEV1
		}
		media, encoded := "", ""
		for _, candidate := range []string{"image/png", "image/jpeg"} {
			prefix := "data:" + candidate + ";base64,"
			if strings.HasPrefix(attrs["src"], prefix) {
				media = candidate
				encoded = strings.TrimPrefix(attrs["src"], prefix)
			}
		}
		if media == "" || len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(ServiceEmailDesignLogoBytesV1) {
			return logo, false, ErrServiceEmailMIMEV1
		}
		marker := ` data-hash-logo="` + digest + `"`
		source := `src="data:` + media + `;base64,` + encoded + `"`
		if strings.Count(raw, marker) != 1 || strings.Count(raw, source) != 1 {
			return logo, false, ErrServiceEmailMIMEV1
		}
		cid := "hash-logo-" + digest + "@hash.invalid"
		rewritten := strings.Replace(raw, marker, "", 1)
		rewritten = strings.Replace(rewritten, source, `src="cid:`+cid+`"`, 1)
		logo = emailInlineLogoV1{raw, rewritten, encoded, media, digest, cid}
		found = true
	}
	return logo, found, nil
}

// Called only after SMTP.Send's actual native MIME working-set grant. The
// renderer/frozen outbox remain self-contained; only this final wire conversion
// substitutes deterministic CID and embeds those SAME digest-checked bytes.
func buildServiceEmailInlineMIMEV1(from string, msg Message) (string, error) {
	if _, err := ServiceEmailMIMEWorkingBytesV1(msg); err != nil {
		return "", err
	}
	logo, found, err := serviceEmailInlineLogoV1(msg.HTML)
	if err != nil {
		return "", err
	}
	if !found {
		return "", ErrServiceEmailMIMEV1
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(logo.encoded)
	if err != nil || len(decoded) == 0 || len(decoded) > ServiceEmailDesignLogoBytesV1 {
		return "", ErrServiceEmailMIMEV1
	}
	digest := sha256.Sum256(decoded)
	if hex.EncodeToString(digest[:]) != logo.digest {
		return "", ErrServiceEmailMIMEV1
	}
	msg.HTML = strings.Replace(msg.HTML, logo.rawTag, logo.rewrittenTag, 1)
	// This invocation has no native marker and therefore follows the original
	// unmodified alternative builder, including every validated From/header rule.
	base, err := buildMIME(from, msg)
	if err != nil {
		return "", err
	}
	split := strings.Index(base, "\r\n\r\n")
	if split < 0 {
		return "", ErrServiceEmailMIMEV1
	}
	headers, body := base[:split], base[split+4:]
	lines := strings.Split(headers, "\r\n")
	alternative := ""
	boundary := "hash-related-" + logo.digest
	var head strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(line, "Content-Type: ") {
			if alternative != "" {
				return "", ErrServiceEmailMIMEV1
			}
			alternative = strings.TrimPrefix(line, "Content-Type: ")
			fmt.Fprintf(&head, "Content-Type: multipart/related; boundary=\"%s\"\r\n", boundary)
		} else {
			head.WriteString(line)
			head.WriteString("\r\n")
		}
	}
	if !strings.HasPrefix(alternative, "multipart/alternative;") {
		return "", ErrServiceEmailMIMEV1
	}
	measured := head.Len() + len(body) + len(logo.encoded) + (len(logo.encoded)/76+1)*2 + 4096
	if measured > ServiceEmailMIMEBytesV1 {
		return "", ErrServiceEmailMIMEV1
	}
	var out strings.Builder
	out.Grow(measured)
	out.WriteString(head.String())
	out.WriteString("\r\n")
	fmt.Fprintf(&out, "--%s\r\nContent-Type: %s\r\n\r\n", boundary, alternative)
	out.WriteString(body)
	out.WriteString("\r\n")
	fmt.Fprintf(&out, "--%s\r\nContent-Type: %s\r\nContent-Transfer-Encoding: base64\r\nContent-ID: <%s>\r\nContent-Disposition: inline; filename=\"logo.%s\"\r\n\r\n", boundary, logo.media, logo.cid, map[string]string{"image/png": "png", "image/jpeg": "jpg"}[logo.media])
	for offset := 0; offset < len(logo.encoded); offset += 76 {
		end := offset + 76
		if end > len(logo.encoded) {
			end = len(logo.encoded)
		}
		out.WriteString(logo.encoded[offset:end])
		out.WriteString("\r\n")
	}
	fmt.Fprintf(&out, "--%s--\r\n", boundary)
	if out.Len() > measured {
		return "", ErrServiceEmailMIMEV1
	}
	return out.String(), nil
}
