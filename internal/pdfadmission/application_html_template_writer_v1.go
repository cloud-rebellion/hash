// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

type HTMLTemplateWriterInputV1 struct {
	Name             string
	Master, Defaults []byte
	ContentSHA256    string
	ActorID          uuid.UUID
}
type ApplicationHTMLTemplateWriterV1 struct {
	mu                       sync.Mutex
	session                  *ApplicationSessionV1
	queries                  *generated.Queries
	input                    HTMLTemplateWriterInputV1
	digest                   []byte
	masterWire, defaultsWire int64
	attempted                bool
	closeConsumer            func()
}

// Only actual canonical producer inputs are admitted. Their agreed provenance
// is retained byte-for-byte; this writer neither creates prose nor approves it.
func (h *ApplicationSessionV1) NewHTMLTemplateWriterV1(ctx context.Context, in HTMLTemplateWriterInputV1) (*ApplicationHTMLTemplateWriterV1, error) {
	if h == nil || h.state == nil || in.ActorID == uuid.Nil || len(in.Name) < 1 || len(in.Name) > 800 {
		return nil, ErrHTMLAuthoringReadV1
	}
	masterWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, in.Master)
	if err != nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	defaultsWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, in.Defaults)
	if err != nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(in.Name)), int64(len(in.Master)), int64(len(in.Defaults)))
	if err != nil {
		return nil, err
	}
	wire, err := htmlAuthoringSumV1(masterWire, defaultsWire)
	if err != nil {
		return nil, err
	}
	closeConsumer, err := h.acquireHTMLAuthoringV1(ctx, "locked-html-template-write", raw, wire)
	if err != nil {
		return nil, err
	}
	s := h.state
	s.mu.Lock()
	if s.htmlWriterStarted || s.closed || s.unknown || s.ended || !s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s {
		s.mu.Unlock()
		closeConsumer()
		return nil, ErrHTMLAuthoringReadV1
	}
	s.htmlWriterStarted = true
	s.mu.Unlock()
	// All validation, canonical buffers and SQL input/output now have a real loan.
	content, err := htmlmaster.CanonicalTemplate(in.Master, in.Defaults)
	digest, digestErr := hex.DecodeString(in.ContentSHA256)
	if err != nil || digestErr != nil || len(digest) != 32 || content.SHA256 != in.ContentSHA256 || !bytes.Equal(content.MasterJSON, in.Master) || !bytes.Equal(content.DefaultsJSON, in.Defaults) {
		closeConsumer()
		return nil, ErrHTMLAuthoringReadV1
	}
	in.Master, in.Defaults = bytes.Clone(in.Master), bytes.Clone(in.Defaults)
	return &ApplicationHTMLTemplateWriterV1{session: h, queries: generated.New(&applicationOwnedDBTXV1{session: s}), input: in, digest: digest, masterWire: masterWire, defaultsWire: defaultsWire, closeConsumer: closeConsumer}, nil
}
func (w *ApplicationHTMLTemplateWriterV1) PersistV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*generated.Template, error) {
	if w == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.attempted || w.session == nil || w.session.state == nil || w.closeConsumer == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	s := w.session.state
	s.mu.Lock()
	valid := applicationContextV1(ctx) && !s.closed && !s.unknown && !s.ended && !s.retired && s.callbackActive && !s.sqlActive && ctx.Value(applicationSessionCallbackKeyV1{}) == s
	org, id := s.org, s.document
	s.mu.Unlock()
	if !valid {
		return nil, ErrHTMLAuthoringReadV1
	}
	var expectedVersion int32
	var blocks, fields, sanitization int64
	if reader != nil {
		reader.mu.Lock()
		if reader.session != w.session || !reader.valid(ctx) || reader.updateID != id || reader.updateVersion <= 0 {
			reader.mu.Unlock()
			return nil, ErrHTMLAuthoringReadV1
		}
		expectedVersion, blocks, fields, sanitization = reader.updateVersion, reader.updateBlocksWire, reader.updateFieldsWire, reader.updateSanitizationWire
		reader.mu.Unlock()
	} else {
		fields = 2
	}
	w.attempted = true
	var t *generated.Template
	var err error
	if reader == nil {
		// The primary-key INSERT, not UUID/time/snapshot equality, proves new birth.
		t, err = w.queries.CreateFreshHTMLTemplateV1(ctx, generated.CreateFreshHTMLTemplateV1Params{ID: id, OrgID: org, Name: w.input.Name, HtmlMasterJson: w.input.Master, VariablesJson: w.input.Defaults, HtmlContentSha256: w.digest, CreatedBy: w.input.ActorID})
	} else {
		t, err = w.queries.UpdateHTMLTemplate(ctx, generated.UpdateHTMLTemplateParams{ID: id, OrgID: org, Name: w.input.Name, HtmlMasterJson: w.input.Master, VariablesJson: w.input.Defaults, HtmlContentSha256: w.digest, ExpectedVersion: expectedVersion})
	}
	if err != nil {
		return nil, err
	}
	if t == nil || t.ID != id || t.OrgID != org || !bytes.Equal(t.HtmlContentSha256, w.digest) || int64(len(t.HtmlMasterJson)) > w.masterWire || int64(len(t.VariablesJson)) > w.defaultsWire ||
		int64(len(t.BlocksJson)) != blocks || int64(len(t.FieldsJson)) != fields || int64(len(t.PdfSanitizationReport)) != sanitization {
		return nil, ErrHTMLAuthoringReadV1
	}
	revision, err := w.queries.InsertHTMLTemplateRevision(ctx, generated.InsertHTMLTemplateRevisionParams{TemplateID: id, OrgID: org, ExpectedVersion: t.Version, HtmlMasterJson: w.input.Master, VariablesJson: w.input.Defaults, ContentSha256: w.digest, CreatedBy: w.input.ActorID})
	if err != nil {
		return nil, err
	}
	if revision == nil || revision.TemplateID != id || revision.OrgID != org || revision.Version != t.Version || int64(len(revision.HtmlMasterJson)) > w.masterWire || int64(len(revision.VariablesJson)) > w.defaultsWire {
		return nil, ErrHTMLAuthoringReadV1
	}
	tm, err := w.queries.MeasureHTMLAuthoringTemplateV1(ctx, generated.MeasureHTMLAuthoringTemplateV1Params{TemplateID: id, OrgID: org})
	if err != nil {
		return nil, err
	}
	rm, err := w.queries.MeasureHTMLAuthoringRevisionV1(ctx, generated.MeasureHTMLAuthoringRevisionV1Params{TemplateID: id, OrgID: org, Version: t.Version})
	if err != nil {
		return nil, err
	}
	if tm == nil || rm == nil || tm.TemplateID != id || tm.OrgID != org || rm.TemplateID != id || rm.OrgID != org || rm.Version != t.Version ||
		tm.MasterWireBytes < 1 || tm.MasterWireBytes > w.masterWire || tm.VariablesWireBytes < 1 || tm.VariablesWireBytes > w.defaultsWire ||
		tm.BlocksWireBytes != blocks || tm.FieldsWireBytes != fields || tm.SanitizationWireBytes != sanitization ||
		rm.MasterWireBytes < 1 || rm.MasterWireBytes > w.masterWire || rm.VariablesWireBytes < 1 || rm.VariablesWireBytes > w.defaultsWire {
		return nil, ErrHTMLAuthoringReadV1
	}
	return t, nil
}
func (w *ApplicationHTMLTemplateWriterV1) CloseConsumerV1() {
	if w != nil && w.closeConsumer != nil {
		w.closeConsumer()
	}
}
