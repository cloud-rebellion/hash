// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"io"
	"strconv"
	"time"
)

const packageLayoutHTTPProfileV1 HTMLAuthoringInputProfileV1 = 244
const packageLayoutMCPProfileV1 HTMLAuthoringInputProfileV1 = 242
const packageLayoutInputLimitV1 int64 = 16384

var ErrDocumentPackageLayoutInputTooLargeV1 = errors.New("attachment layout request exceeds16384bytes")

type DocumentPackageLayoutMemberV1 struct {
	DocumentID      uuid.UUID
	Title, Category string
}
type DocumentPackageLayoutInputV1 struct {
	Root     uuid.UUID
	Expected time.Time
	Draft    DocumentPackageDraftExpectedV1
	Members  [16]DocumentPackageLayoutMemberV1
	Count    int
}

func (f *ApplicationSessionFactoryV1) NewDocumentPackageLayoutHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationDocumentPackageInputV1, error) {
	return f.newDocumentPackageInputV1(ctx, org, packageLayoutHTTPProfileV1, nil)
}
func (f *ApplicationSessionFactoryV1) NewDocumentPackageLayoutArgumentsV1(ctx context.Context, org uuid.UUID, raw []byte) (*ApplicationDocumentPackageInputV1, error) {
	if len(raw) > int(packageLayoutInputLimitV1) {
		return nil, ErrDocumentPackageLayoutInputTooLargeV1
	}
	return f.newDocumentPackageInputV1(ctx, org, packageLayoutMCPProfileV1, raw)
}
func (h *ApplicationDocumentPackageInputV1) ReadLayoutHTTPV1(ctx context.Context, root uuid.UUID, body io.ReadCloser) error {
	if h == nil || h.state == nil || h.state.profile != packageLayoutHTTPProfileV1 || body == nil || root == uuid.Nil {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, true); e != nil {
		return e
	}
	defer h.state.finishV1()
	raw, e := io.ReadAll(io.LimitReader(body, packageLayoutInputLimitV1+1))
	if e != nil {
		return errors.Join(ErrDocumentPackageInputV1, e)
	}
	if len(raw) > int(packageLayoutInputLimitV1) {
		return ErrDocumentPackageLayoutInputTooLargeV1
	}
	return h.parseLayoutV1(ctx, root, raw, false)
}
func (h *ApplicationDocumentPackageInputV1) ReadLayoutArgumentsV1(ctx context.Context) error {
	if h == nil || h.state == nil || h.state.profile != packageLayoutMCPProfileV1 {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, true); e != nil {
		return e
	}
	defer h.state.finishV1()
	return h.parseLayoutV1(ctx, uuid.Nil, h.state.raw, true)
}
func (h *ApplicationDocumentPackageInputV1) parseLayoutV1(ctx context.Context, root uuid.UUID, raw []byte, mcp bool) error {
	in, e := decodeDocumentPackageLayoutV1(ctx, root, raw, mcp)
	if e != nil {
		return e
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumerClosed || s.retired || ctx.Err() != nil {
		return ErrDocumentPackageInputV1
	}
	s.raw = raw
	s.packageLayout = &in
	s.ready = true
	return nil
}
func (h *ApplicationDocumentPackageInputV1) WithLayoutV1(ctx context.Context, org uuid.UUID, fn func(DocumentPackageLayoutInputV1) error) error {
	if h == nil || h.state == nil || fn == nil || (h.state.profile != packageLayoutHTTPProfileV1 && h.state.profile != packageLayoutMCPProfileV1) {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, false); e != nil {
		return e
	}
	defer h.state.finishV1()
	s := h.state
	s.mu.Lock()
	if s.org != org || s.packageLayout == nil || s.packageUsed {
		s.mu.Unlock()
		return ErrDocumentPackageInputV1
	}
	s.packageUsed = true
	in := *s.packageLayout
	s.mu.Unlock()
	return fn(in)
}
func packageLayoutTextV1(d *json.Decoder) (string, error) {
	t, e := d.Token()
	s, ok := t.(string)
	if e != nil || !ok {
		return "", ErrDocumentPackageInputV1
	}
	return s, nil
}
func decodeDocumentPackageLayoutV1(ctx context.Context, root uuid.UUID, raw []byte, mcp bool) (out DocumentPackageLayoutInputV1, failure error) {
	failure = ErrDocumentPackageInputV1
	if len(raw) < 2 || len(raw) > int(packageLayoutInputLimitV1) {
		return
	}
	if _, e := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw); e != nil {
		return
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var t json.Token
	var e error
	t, e = d.Token()
	if e != nil || t != json.Delim('{') {
		return
	}
	fields := [5]string{"expected_updated_at", "expected_package_id", "expected_generation", "members", "document_id"}
	var texts [5]string
	seen := uint8(0)
	for d.More() {
		key, e := packageLayoutTextV1(d)
		if e != nil {
			return out, failure
		}
		slot := -1
		for i, k := range fields {
			if key == k {
				slot = i
				break
			}
		}
		if slot < 0 || (!mcp && slot == 4) || seen&(1<<slot) != 0 {
			return out, failure
		}
		seen |= 1 << slot
		if slot != 3 {
			texts[slot], e = packageLayoutTextV1(d)
			if e != nil {
				return out, failure
			}
			continue
		}
		t, e = d.Token()
		if e != nil || t != json.Delim('[') {
			return out, failure
		}
		for d.More() {
			if out.Count == 16 {
				return out, failure
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('{') {
				return out, failure
			}
			var vals [3]string
			memberSeen := uint8(0)
			for d.More() {
				k, e := packageLayoutTextV1(d)
				if e != nil {
					return out, failure
				}
				i := -1
				switch k {
				case "document_id":
					i = 0
				case "title":
					i = 1
				case "category":
					i = 2
				}
				if i < 0 || memberSeen&(1<<i) != 0 {
					return out, failure
				}
				memberSeen |= 1 << i
				vals[i], e = packageLayoutTextV1(d)
				if e != nil {
					return out, failure
				}
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') || memberSeen != 7 {
				return out, failure
			}
			id, e := packageUUIDV1(vals[0])
			if e != nil || !documentPackageWriteLabelV1(vals[1], 512, false) || !documentPackageWriteLabelV1(vals[2], 128, true) {
				return out, failure
			}
			for i := 0; i < out.Count; i++ {
				if out.Members[i].DocumentID == id {
					return out, failure
				}
			}
			out.Members[out.Count] = DocumentPackageLayoutMemberV1{DocumentID: id, Title: vals[1], Category: vals[2]}
			out.Count++
		}
		t, e = d.Token()
		if e != nil || t != json.Delim(']') {
			return out, failure
		}
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') {
		return
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return
	}
	required := uint8(15)
	if mcp {
		required = 31
	}
	if seen != required {
		return
	}
	if mcp {
		root, e = packageUUIDV1(texts[4])
		if e != nil {
			return out, failure
		}
	}
	if root == uuid.Nil {
		return
	}
	out.Root = root
	out.Expected, e = time.Parse(time.RFC3339Nano, texts[0])
	if e != nil || out.Expected.IsZero() || out.Expected.UTC().Year() < 1 || out.Expected.UTC().Year() > 9999 || len(texts[0]) > 64 {
		return out, failure
	}
	out.Expected = out.Expected.UTC()
	out.Draft.PackageID, e = packageUUIDV1(texts[1])
	if e != nil {
		return out, failure
	}
	out.Draft.Generation, e = strconv.ParseInt(texts[2], 10, 64)
	if e != nil || out.Draft.Generation < 1 || strconv.FormatInt(out.Draft.Generation, 10) != texts[2] {
		return out, failure
	}
	for i := 0; i < out.Count; i++ {
		if out.Members[i].DocumentID == root {
			return out, failure
		}
	}
	return out, ctx.Err()
}
