// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"

	"github.com/bright-interaction/hash/internal/htmlmaster"
)

// RetainDesignBundleV1 admits the catalog's measured exact-version read before
// object buffers or base64 are allocated. The catalog retains the returned
// last-use callback; closing the input cannot retire an active bundle read.
// Measures are fixed bounds supplied by the server resolver, never MCP JSON.
func (h *ApplicationHTMLAuthoringInputV1) RetainDesignBundleV1(ctx context.Context, profileBytes, metadataBytes, rawBytes, base64Bytes int64, count int) (func(), error) {
	if h == nil || h.state == nil || !applicationContextV1(ctx) || profileBytes < 0 || profileBytes > 64<<10 || metadataBytes < 0 || metadataBytes > 128<<10 || rawBytes < 0 || rawBytes > htmlmaster.MaxTotalAssetBytes || base64Bytes < 0 || base64Bytes > int64(base64.StdEncoding.EncodedLen(htmlmaster.MaxTotalAssetBytes))+int64(htmlmaster.MaxAssets*4) || count < 0 || count > htmlmaster.MaxAssets {
		return nil, ErrHTMLAuthoringInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || !s.ready || s.profile != HTMLTemplateMasterInputV1 {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLAuthoringInputV1
	}
	s.active++
	s.mu.Unlock()
	p.mu.Unlock()
	cost := int64(0)
	for _, n := range []int64{profileBytes, metadataBytes, rawBytes, base64Bytes} {
		if !htmlInputAddV1(&cost, n, 16) {
			s.finishV1()
			return nil, ErrHTMLAuthoringInputV1
		}
	}
	if !htmlInputAddV1(&cost, int64(count), 4096) {
		s.finishV1()
		return nil, ErrHTMLAuthoringInputV1
	}
	if err := s.holdCanonicalResourcesV1(ctx, cost); err != nil {
		s.finishV1()
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(s.finishV1) }, nil
}

// ExpandDesignAssetsV1 is a fixed producer for server-resolved brand assets.
// The catalog caller retains its verified bundle; this method grants actual
// parser/marshal memory BEFORE expanding bytes, then feeds the complete output
// through the ordinary native input and canonicalizer. No cost/tenant witness,
// catalog type, replacement canonical object or foreign transaction is accepted.
// Both original and returned consumers must survive their actual last use.
func (h *ApplicationHTMLAuthoringInputV1) ExpandDesignAssetsV1(ctx context.Context, assets []htmlmaster.Asset) (expanded *ApplicationHTMLAuthoringInputV1, failure error) {
	if h == nil || h.state == nil || !applicationContextV1(ctx) || len(assets) == 0 || len(assets) > htmlmaster.MaxAssets {
		return nil, ErrHTMLAuthoringInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || !s.ready || s.canonicalStarted || s.profile != HTMLTemplateMasterInputV1 {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLAuthoringInputV1
	}
	s.canonicalStarted = true
	s.active++
	raw := s.raw
	s.mu.Unlock()
	p.mu.Unlock()
	defer s.finishV1()
	// Raw request decoding/master decoding, 6x JSON escaping and both marshal
	// buffer generations are bounded by 16x actual source bytes. Asset structs
	// and names/maps have a separate fixed allowance. Native output admission
	// separately prices parsing, pixels, compilation and writer revalidation.
	cost := int64(0)
	if !htmlInputAddV1(&cost, int64(len(raw)), 16) {
		return nil, ErrHTMLAuthoringInputV1
	}
	for _, asset := range assets {
		if len(asset.Name) == 0 || len(asset.Name) > 64 || len(asset.MediaType) > 128 || len(asset.SHA256) != 64 || len(asset.DataBase64) > base64.StdEncoding.EncodedLen(htmlmaster.MaxAssetBytes) {
			return nil, htmlInputCanonicalInvalidV1()
		}
		if !htmlInputAddV1(&cost, int64(len(asset.Name)+len(asset.MediaType)+len(asset.SHA256)+len(asset.DataBase64)), 16) || !htmlInputAddV1(&cost, 1, 4096) {
			return nil, ErrHTMLAuthoringInputV1
		}
	}
	if err := s.holdCanonicalResourcesV1(ctx, cost); err != nil {
		return nil, err
	}
	var input struct {
		Name            string          `json:"name"`
		Master          json.RawMessage `json:"html_master_json"`
		Defaults        json.RawMessage `json:"variables_json,omitempty"`
		ExpectedVersion int32           `json:"expected_version,omitempty"`
	}
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, htmlInputCanonicalInvalidV1()
	}
	master, err := htmlmaster.Decode(input.Master)
	if err != nil {
		return nil, err
	}
	if len(master.Assets)+len(assets) > htmlmaster.MaxAssets {
		return nil, htmlInputCanonicalInvalidV1()
	}
	names := make(map[string]bool, len(master.Assets)+len(assets))
	for _, a := range master.Assets {
		if names[a.Name] {
			return nil, htmlInputCanonicalInvalidV1()
		}
		names[a.Name] = true
	}
	for _, a := range assets {
		if names[a.Name] {
			return nil, htmlInputCanonicalInvalidV1()
		}
		names[a.Name] = true
		master.Assets = append(master.Assets, a)
	}
	input.Master, err = json.Marshal(master)
	if err != nil || len(input.Master) > htmlmaster.MaxMasterJSONBytes {
		return nil, htmlInputCanonicalInvalidV1()
	}
	body, err := json.Marshal(input)
	if err != nil || len(body) > int(s.limit) {
		return nil, htmlInputCanonicalInvalidV1()
	}
	if ctx.Err() != nil {
		return nil, ErrHTMLAuthoringInputV1
	}
	f := &ApplicationSessionFactoryV1{state: p}
	expanded, err = f.NewHTMLAuthoringInputV1(ctx, s.org, HTMLTemplateMasterInputV1)
	if err != nil {
		return nil, err
	}
	if _, err = expanded.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(body))); err != nil {
		expanded.CloseConsumerV1()
		return nil, err
	}
	return expanded, nil
}
