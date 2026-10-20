// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

var ErrHTMLRevisionWriterV1 = errors.New("pdfadmission: owned HTML revision writer unavailable")

// Only the actual final registered SQL stage can construct this writer. Its
// original/candidate/current proofs and every source/collection consumer remain
// owned through returned-row, final policy, commit and response consumption.
type ApplicationHTMLRevisionWriterV1 struct {
	mu                                                                                                                                               sync.Mutex
	self                                                                                                                                             *ApplicationHTMLRevisionWriterV1
	stage                                                                                                                                            *applicationHTMLRevisionSQLV1
	source                                                                                                                                           *applicationHTMLRevisionSourceOwnerV1
	candidate                                                                                                                                        *applicationHTMLRevisionCandidateV1
	collections                                                                                                                                      *ApplicationHTMLRevisionCollectionsV1
	session                                                                                                                                          *ApplicationSessionV1
	queries                                                                                                                                          *generated.Queries
	original, updated                                                                                                                                *generated.Document
	row                                                                                                                                              *generated.HtmlDocumentMaterialization
	validation                                                                                                                                       *htmlsource.RevisionValidationV1
	freshFields                                                                                                                                      []*generated.DocumentField
	freshFieldIDs                                                                                                                                    []uuid.UUID
	sourceWireUpper, originWireUpper, variablesWireUpper, reportWireUpper                                                                            int64
	closeConsumers                                                                                                                                   []func()
	releaseCollection                                                                                                                                func()
	active                                                                                                                                           int
	closed, resourcesClosed, appendAttempted, appended, fieldsAttempted, fieldsWritten, measured, versionAttempted, versionWritten, responseBorrowed bool
}

func (h *ApplicationHTMLRevisionSQLV1) NewWriterV1(call context.Context, source *ApplicationHTMLRevisionSourceV1, candidate *ApplicationHTMLRevisionCandidateV1, collections *ApplicationHTMLRevisionCollectionsV1) (*ApplicationHTMLRevisionWriterV1, error) {
	if h == nil || h.state == nil || source == nil || source.state == nil || candidate == nil || candidate.state == nil || collections == nil {
		return nil, ErrHTMLRevisionWriterV1
	}
	stage := h.state
	s, c := source.state, candidate.state
	s.mu.Lock()
	var boundReader *ApplicationHTMLRevisionReaderV1
	if s.snapshot != nil {
		boundReader = s.snapshot.owner
	}
	s.mu.Unlock()
	if boundReader == nil {
		return nil, ErrHTMLRevisionWriterV1
	}
	stage.mu.Lock()
	matched := stage.purpose == HTMLRevisionMutationV1 && stage.reader == boundReader && stage.session == s.binding.session && !stage.consumerClosed && stage.writer == nil
	stage.mu.Unlock()
	if !matched || s.operation != stage.operation || c.source == nil || c.source.operation != stage.operation || collections.reader != stage.reader {
		return nil, ErrHTMLRevisionWriterV1
	}
	if err := s.beginV1(); err != nil {
		return nil, err
	}
	keepSource := false
	defer func() {
		if !keepSource {
			s.finishV1()
		}
	}()
	if err := c.beginV1(); err != nil {
		return nil, err
	}
	keepCandidate := false
	defer func() {
		if !keepCandidate {
			c.finishV1()
		}
	}()
	releaseCollection, err := collections.beginV1(call, stage.operation.document)
	if err != nil {
		return nil, err
	}
	keepCollection := false
	defer func() {
		if !keepCollection {
			releaseCollection()
		}
	}()
	s.mu.Lock()
	valid := !s.processing && s.validation != nil && s.currentValidated && s.stateValidated
	oldValidation := s.validation
	s.mu.Unlock()
	if !valid || !oldValidation.MatchesDocumentV1(c.source.snapshot.document) || !oldValidation.MatchesDocumentV1(s.snapshot.document) || !htmlRevisionCollectionSessionV1(call, stage.session) {
		return nil, ErrHTMLRevisionWriterV1
	}
	sourceWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, c.sourceJSON)
	if err != nil {
		return nil, err
	}
	originWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, s.snapshot.document.HtmlSourceJson)
	if err != nil {
		return nil, err
	}
	variablesWire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, c.document.VariablesJson)
	if err != nil {
		return nil, err
	}
	reportWire := int64(2) // exact Project COALESCE(NULL report,'{}'::jsonb)
	if len(c.report) > 0 {
		reportWire, err = sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, c.report)
		if err != nil {
			return nil, err
		}
	}
	// Complete new Document + immutable row + version snapshot + fixed generated
	// field options are fresh outputs from THIS candidate. Old blocks/metadata
	// remain included; no old-row measurement or JSONB equality is substituted.
	wire, err := htmlAuthoringSumV1(originWire, originWire, originWire, originWire, sourceWire, sourceWire, sourceWire, sourceWire,
		variablesWire, variablesWire, variablesWire, variablesWire, reportWire, reportWire, reportWire, reportWire,
		3*int64(len(s.snapshot.document.BlocksJson)), 3*int64(len(s.snapshot.document.Metadata)), 2*2048)
	if err != nil {
		return nil, err
	}
	raw, err := htmlAuthoringSumV1(signerDocumentRawBytesV1(c.document), int64(len(c.summary)), int64(len(c.document.PdfStorageKey.String)), int64(len(c.document.PdfStorageVersionID.String)), int64(len(c.document.PdfSha256)))
	if err != nil {
		return nil, err
	}
	closeWriter, err := stage.reader.authoring.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, err
	}
	out := &ApplicationHTMLRevisionWriterV1{stage: stage, source: s, candidate: c, collections: collections, session: stage.session,
		queries: generated.New(&applicationOwnedDBTXV1{session: stage.session.state}), original: s.snapshot.document,
		sourceWireUpper: sourceWire, originWireUpper: originWire, variablesWireUpper: variablesWire, reportWireUpper: reportWire,
		closeConsumers: []func(){closeWriter}, releaseCollection: releaseCollection}
	out.self = out
	keepSource = true
	keepCandidate = true
	keepCollection = true // ownership transfers to out before possible refusal
	stage.mu.Lock()
	if stage.consumerClosed || stage.writer != nil {
		stage.mu.Unlock()
		out.CloseConsumerV1()
		return nil, ErrHTMLRevisionWriterV1
	}
	stage.writer = out
	stage.mu.Unlock()
	keepSource = true
	keepCandidate = true
	keepCollection = true
	return out, nil
}
func (w *ApplicationHTMLRevisionWriterV1) validV1(call context.Context) bool {
	return w != nil && w.self == w && !w.closed && !w.resourcesClosed && w.session != nil && w.source != nil && w.candidate != nil &&
		applicationContextV1(w.source.binding.ctx) && htmlRevisionCollectionSessionV1(call, w.session)
}
func (w *ApplicationHTMLRevisionWriterV1) beginV1(call context.Context) (func(), error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLRevisionWriterV1
	}
	w.mu.Lock()
	if !w.validV1(call) {
		w.mu.Unlock()
		return nil, ErrHTMLRevisionWriterV1
	}
	w.active++
	w.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			w.active--
			closes, collection, candidate, source := w.retireLockedV1()
			w.mu.Unlock()
			htmlRevisionWriterReleaseV1(closes, collection, candidate, source)
		})
	}, nil
}
func (w *ApplicationHTMLRevisionWriterV1) retireLockedV1() ([]func(), func(), *applicationHTMLRevisionCandidateV1, *applicationHTMLRevisionSourceOwnerV1) {
	if !w.closed || w.resourcesClosed || w.active != 0 {
		return nil, nil, nil, nil
	}
	w.resourcesClosed = true
	closes, collection, candidate, source := w.closeConsumers, w.releaseCollection, w.candidate, w.source
	w.closeConsumers = nil
	w.releaseCollection = nil
	w.original = nil
	w.updated = nil
	w.row = nil
	w.validation = nil
	w.freshFields = nil
	w.freshFieldIDs = nil
	w.candidate = nil
	w.source = nil
	w.collections = nil
	w.queries = nil
	return closes, collection, candidate, source
}
func htmlRevisionWriterReleaseV1(closes []func(), collection func(), candidate *applicationHTMLRevisionCandidateV1, source *applicationHTMLRevisionSourceOwnerV1) {
	for _, close := range closes {
		close()
	}
	if collection != nil {
		collection()
	}
	if candidate != nil {
		candidate.finishV1()
	}
	if source != nil {
		source.finishV1()
	}
}
func (w *ApplicationHTMLRevisionWriterV1) CloseConsumerV1() {
	if w == nil || w.self != w {
		return
	}
	w.mu.Lock()
	w.closed = true
	closes, collection, candidate, source := w.retireLockedV1()
	w.mu.Unlock()
	htmlRevisionWriterReleaseV1(closes, collection, candidate, source)
}
