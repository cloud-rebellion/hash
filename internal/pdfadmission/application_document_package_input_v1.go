// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"io"
	"strconv"
	"time"
	"unsafe"
)

var ErrDocumentPackageInputV1 = errors.New("invalid attachment selection request")
var ErrDocumentPackageInputTooLargeV1 = errors.New("attachment selection request exceeds4096bytes")

const packageInventoryMCPProfileV1 HTMLAuthoringInputProfileV1 = 243
const packageHTTPProfileV1 HTMLAuthoringInputProfileV1 = 245
const packageMCPProfileV1 HTMLAuthoringInputProfileV1 = 246
const packageInputLimitV1 int64 = 4096

type DocumentPackageSelectionInputV1 struct {
	Root, Member uuid.UUID
	Expected     [2]time.Time
	Draft        DocumentPackageDraftExpectedV1
	Intent       DocumentPackageAttachmentIntentV1
}
type ApplicationDocumentPackageInputV1 struct {
	state *applicationHTMLAuthoringInputStateV1
}

func (f *ApplicationSessionFactoryV1) NewDocumentPackageHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationDocumentPackageInputV1, error) {
	return f.newDocumentPackageInputV1(ctx, org, packageHTTPProfileV1, nil)
}
func (f *ApplicationSessionFactoryV1) NewDocumentPackageArgumentsV1(ctx context.Context, org uuid.UUID, raw []byte) (*ApplicationDocumentPackageInputV1, error) {
	if len(raw) > int(packageInputLimitV1) {
		return nil, ErrDocumentPackageInputTooLargeV1
	}
	return f.newDocumentPackageInputV1(ctx, org, packageMCPProfileV1, raw)
}
func (f *ApplicationSessionFactoryV1) newDocumentPackageInputV1(ctx context.Context, org uuid.UUID, profile HTMLAuthoringInputProfileV1, raw []byte) (*ApplicationDocumentPackageInputV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) || (profile != packageHTTPProfileV1 && profile != packageMCPProfileV1 && profile != packageInventoryMCPProfileV1 && profile != packageLayoutHTTPProfileV1 && profile != packageLayoutMCPProfileV1) {
		return nil, ErrDocumentPackageInputV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		return nil, ErrDocumentPackageInputV1
	}
	// Full4097-byte read, decoder/token strings, duplicate tracking, typed intent,
	// fixed response/JSON encoding and scalar scratch precede allocations.
	limit := packageInputLimitV1
	if profile == packageLayoutHTTPProfileV1 || profile == packageLayoutMCPProfileV1 {
		limit = packageLayoutInputLimitV1
	}
	cost := 128*(limit+1) + 65536 + 4*int64(unsafe.Sizeof(applicationHTMLAuthoringInputStateV1{})) + 4*int64(unsafe.Sizeof(DocumentPackageSelectionInputV1{}))
	if limit == packageLayoutInputLimitV1 {
		cost += 4 * int64(unsafe.Sizeof(DocumentPackageLayoutInputV1{}))
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: limit, packageContext: ctx}
	p.htmlInputProducers[s] = struct{}{}
	release, e := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if e != nil {
		delete(p.htmlInputProducers, s)
		return nil, errors.Join(ErrDocumentPackageInputV1, e)
	}
	s.releases = []func(){release}
	if profile == packageMCPProfileV1 || profile == packageInventoryMCPProfileV1 || profile == packageLayoutMCPProfileV1 {
		s.raw = bytes.Clone(raw)
	}
	return &ApplicationDocumentPackageInputV1{state: s}, nil
}
func (h *ApplicationDocumentPackageInputV1) beginV1(ctx context.Context, reading bool) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrDocumentPackageInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || ctx != s.packageContext ||
		(reading && s.readStarted) || (!reading && !s.ready) {
		return ErrDocumentPackageInputV1
	}
	if reading {
		s.readStarted = true
	}
	s.active++
	return nil
}
func (h *ApplicationDocumentPackageInputV1) CloseConsumerV1() {
	if h != nil {
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
func (h *ApplicationDocumentPackageInputV1) ReadHTTPV1(ctx context.Context, root uuid.UUID, body io.ReadCloser) error {
	if body == nil || root == uuid.Nil || h == nil || h.state == nil || h.state.profile != packageHTTPProfileV1 {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, true); e != nil {
		return e
	}
	defer h.state.finishV1()
	raw, e := io.ReadAll(io.LimitReader(body, packageInputLimitV1+1))
	if e != nil {
		return errors.Join(ErrDocumentPackageInputV1, e)
	}
	if len(raw) > int(packageInputLimitV1) {
		return ErrDocumentPackageInputTooLargeV1
	}
	return h.parseV1(ctx, root, raw, false)
}
func (h *ApplicationDocumentPackageInputV1) ReadArgumentsV1(ctx context.Context) error {
	if h == nil || h.state == nil || (h.state.profile != packageMCPProfileV1 && h.state.profile != packageInventoryMCPProfileV1) {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, true); e != nil {
		return e
	}
	defer h.state.finishV1()
	return h.parseV1(ctx, uuid.Nil, h.state.raw, true)
}
func (h *ApplicationDocumentPackageInputV1) parseV1(ctx context.Context, root uuid.UUID, raw []byte, mcp bool) error {
	var in DocumentPackageSelectionInputV1
	var e error
	if h.state.profile == packageInventoryMCPProfileV1 {
		in.Root, e = decodeDocumentPackageRootV1(ctx, raw)
	} else {
		in, e = decodeDocumentPackageSelectionV1(ctx, root, raw, mcp)
	}
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
	s.packageSelection = &in
	s.ready = true
	return nil
}

// This real original-context borrower joins the service's last use even if a
// copied shell closes concurrently. It supplies choices, never PDF/report pins.
func (h *ApplicationDocumentPackageInputV1) WithSelectionV1(ctx context.Context, org uuid.UUID, consume func(DocumentPackageSelectionInputV1) error) error {
	if consume == nil || h == nil || h.state == nil || h.state.profile == packageInventoryMCPProfileV1 {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, false); e != nil {
		return e
	}
	defer h.state.finishV1()
	s := h.state
	s.mu.Lock()
	if s.org != org || s.packageSelection == nil || s.packageUsed {
		s.mu.Unlock()
		return ErrDocumentPackageInputV1
	}
	s.packageUsed = true
	value := *s.packageSelection
	s.mu.Unlock()
	return consume(value)
}
func packageUUIDV1(s string) (uuid.UUID, error) {
	id, e := uuid.Parse(s)
	if e != nil || id == uuid.Nil || id.String() != s {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	return id, nil
}
func decodeDocumentPackageSelectionV1(ctx context.Context, root uuid.UUID, raw []byte, mcp bool) (DocumentPackageSelectionInputV1, error) {
	var out DocumentPackageSelectionInputV1
	if len(raw) < 2 || len(raw) > int(packageInputLimitV1) {
		return out, ErrDocumentPackageInputV1
	}
	// Validate literal UTF8/paired surrogate/NUL and full JSON without copying or
	// recursive map expansion. The closed scalar grammar below is stricter.
	if _, e := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw); e != nil {
		return out, ErrDocumentPackageInputV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return out, ErrDocumentPackageInputV1
	}
	var texts [9]string
	seen := uint16(0)
	fields := [9]string{"member_document_id", "expected_updated_at", "expected_member_updated_at", "expected_package_id", "expected_generation", "ordinal", "title", "category", "document_id"}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return out, ErrDocumentPackageInputV1
		}
		text, ok := key.(string)
		if !ok {
			return out, ErrDocumentPackageInputV1
		}
		slot := -1
		for i, k := range fields {
			if text == k {
				slot = i
				break
			}
		}
		if slot < 0 || (!mcp && slot == 8) || seen&(1<<slot) != 0 {
			return out, ErrDocumentPackageInputV1
		}
		seen |= 1 << slot
		value, e := d.Token()
		if e != nil {
			return out, ErrDocumentPackageInputV1
		}
		if slot == 5 {
			n, ok := value.(json.Number)
			if !ok {
				return out, ErrDocumentPackageInputV1
			}
			v, e := strconv.ParseInt(string(n), 10, 16)
			if e != nil || strconv.FormatInt(v, 10) != string(n) || v < 1 || v > 16 {
				return out, ErrDocumentPackageInputV1
			}
			out.Intent.Ordinal = int16(v)
		} else {
			text, ok := value.(string)
			if !ok {
				return out, ErrDocumentPackageInputV1
			}
			texts[slot] = text
		}
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') {
		return out, ErrDocumentPackageInputV1
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return out, ErrDocumentPackageInputV1
	}
	required := uint16(255)
	if mcp {
		required = 511
	}
	if seen != required {
		return out, ErrDocumentPackageInputV1
	}
	if mcp {
		root, e = packageUUIDV1(texts[8])
		if e != nil {
			return out, e
		}
	}
	out.Root = root
	out.Member, e = packageUUIDV1(texts[0])
	if e != nil || root == uuid.Nil || root == out.Member {
		return out, ErrDocumentPackageInputV1
	}
	for i, k := range []int{1, 2} {
		stamp, e := time.Parse(time.RFC3339Nano, texts[k])
		if e != nil || stamp.IsZero() || stamp.UTC().Year() < 1 || stamp.UTC().Year() > 9999 || len(texts[k]) > 64 {
			return out, ErrDocumentPackageInputV1
		}
		out.Expected[i] = stamp.UTC()
	}
	generation, e := strconv.ParseInt(texts[4], 10, 64)
	if e != nil || generation < 0 || strconv.FormatInt(generation, 10) != texts[4] {
		return out, ErrDocumentPackageInputV1
	}
	if texts[3] != "" {
		out.Draft.PackageID, e = packageUUIDV1(texts[3])
		if e != nil {
			return out, e
		}
	}
	out.Draft.Generation = generation
	if (out.Draft.PackageID == uuid.Nil) != (generation == 0) {
		return out, ErrDocumentPackageInputV1
	}
	out.Intent.Title = texts[6]
	out.Intent.Category = texts[7]
	if !documentPackageWriteLabelV1(out.Intent.Title, 512, false) || !documentPackageWriteLabelV1(out.Intent.Category, 128, true) {
		return out, ErrDocumentPackageInputV1
	}
	return out, ctx.Err()
}

func (f *ApplicationSessionFactoryV1) NewDocumentPackageInventoryArgumentsV1(ctx context.Context, org uuid.UUID, raw []byte) (*ApplicationDocumentPackageInputV1, error) {
	if len(raw) > int(packageInputLimitV1) {
		return nil, ErrDocumentPackageInputTooLargeV1
	}
	return f.newDocumentPackageInputV1(ctx, org, packageInventoryMCPProfileV1, raw)
}
func (h *ApplicationDocumentPackageInputV1) WithInventoryV1(ctx context.Context, org uuid.UUID, consume func(uuid.UUID) error) error {
	if consume == nil || h == nil || h.state == nil || h.state.profile != packageInventoryMCPProfileV1 {
		return ErrDocumentPackageInputV1
	}
	if e := h.beginV1(ctx, false); e != nil {
		return e
	}
	defer h.state.finishV1()
	s := h.state
	s.mu.Lock()
	if s.org != org || s.packageSelection == nil || s.packageUsed {
		s.mu.Unlock()
		return ErrDocumentPackageInputV1
	}
	s.packageUsed = true
	root := s.packageSelection.Root
	s.mu.Unlock()
	return consume(root)
}
func decodeDocumentPackageRootV1(ctx context.Context, raw []byte) (uuid.UUID, error) {
	if len(raw) < 2 || len(raw) > int(packageInputLimitV1) {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	if _, e := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw); e != nil {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	key, e := d.Token()
	if e != nil || key != "document_id" {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	v, e := d.Token()
	s, ok := v.(string)
	if e != nil || !ok {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	if _, e = d.Token(); !errors.Is(e, io.EOF) {
		return uuid.Nil, ErrDocumentPackageInputV1
	}
	return packageUUIDV1(s)
}
