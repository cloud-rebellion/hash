// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrHTMLAuthoringInputV1 = errors.New("pdfadmission: owned HTML authoring input unavailable")

// These fixed profiles are selected only at the actual authenticated route.
// No Content-Length, tenant witness, caller cost or capacity declaration is used.
type HTMLAuthoringInputProfileV1 uint8

const (
	HTMLTemplateMasterInputV1 HTMLAuthoringInputProfileV1 = iota + 1
	HTMLTemplateApprovalInputV1
	HTMLTemplatePreviewInputV1
	HTMLDocumentCreationInputV1
	HTMLCRMTemplateSearchInputV1
	HTMLCRMTemplateObservationInputV1
	HTMLCreationClosureInputV1
	HTMLDocumentRevisionInputV1
	HTMLPreSignAPISourceInputV1
	HTMLPreSignSupersessionInputV1
)

// Copied public shells share the original private owner. Neither a copied
// mutex/release slice nor a foreign SQL transaction can retire this producer.
type ApplicationHTMLAuthoringInputV1 struct {
	state *applicationHTMLAuthoringInputStateV1
}
type applicationHTMLAuthoringInputStateV1 struct {
	mu                                                            sync.Mutex
	factory                                                       *applicationSessionFactoryStateV1
	org                                                           uuid.UUID
	profile                                                       HTMLAuthoringInputProfileV1
	limit                                                         int64
	releases                                                      []func()
	raw                                                           []byte
	packageSelection                                              *DocumentPackageSelectionInputV1
	packageLayout                                                 *DocumentPackageLayoutInputV1
	packageContext                                                context.Context
	packageUsed                                                   bool
	shape                                                         htmlAuthoringInputShapeV1
	active                                                        int
	readStarted, ready, canonicalStarted, consumerClosed, retired bool
}

func (f *ApplicationSessionFactoryV1) NewHTMLAuthoringInputV1(ctx context.Context, org uuid.UUID, profile HTMLAuthoringInputProfileV1) (*ApplicationHTMLAuthoringInputV1, error) {
	limit, err := htmlAuthoringInputLimitV1(profile)
	if err != nil || f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLAuthoringInputV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil {
		return nil, ErrHTMLAuthoringInputV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, profile: profile, limit: limit}
	// Registration and finite nonblocking grant installation are atomic with
	// shutdown. Reconciliation cannot delete an empty owner before it installs.
	p.htmlInputProducers[s] = struct{}{}
	cost, err := htmlAuthoringInputReadResourcesV1(limit)
	if err != nil {
		delete(p.htmlInputProducers, s)
		return nil, ErrHTMLAuthoringInputV1
	}
	release, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		return nil, errors.Join(ErrHTMLAuthoringInputV1, err)
	}
	s.releases = []func(){release}
	return &ApplicationHTMLAuthoringInputV1{state: s}, nil
}

func (s *applicationHTMLAuthoringInputStateV1) finishV1() {
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	s.active--
	s.releaseIfCompleteV1()
	s.mu.Unlock()
	p.mu.Unlock()
}
func (s *applicationHTMLAuthoringInputStateV1) releaseIfCompleteV1() {
	if s.retired || !s.consumerClosed || s.active != 0 {
		return
	}
	s.retired = true
	s.raw = nil
	s.packageSelection = nil
	s.packageLayout = nil
	s.packageContext = nil
	for _, release := range s.releases {
		release()
	}
	s.releases = nil
	delete(s.factory.htmlInputProducers, s)
}
func (h *ApplicationHTMLAuthoringInputV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
	s.mu.Unlock()
	p.mu.Unlock()
}

// Read the real body once into one exact-capacity buffer. The raw allowance is
// installed before make/read; typed parser allowance is installed before bytes
// reach the unchanged strict/typed decoders. HTTP transport/session accounting
// is separate. Cancellation cannot release a still-blocked original Read.
func (h *ApplicationHTMLAuthoringInputV1) ReadBodyV1(ctx context.Context, body io.ReadCloser) ([]byte, error) {
	if h == nil || h.state == nil || body == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLAuthoringInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || s.readStarted {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLAuthoringInputV1
	}
	s.readStarted = true
	s.active++
	s.mu.Unlock()
	p.mu.Unlock()
	defer s.finishV1()
	raw := make([]byte, int(s.limit)+1)
	reader := http.MaxBytesReader(nil, body, s.limit)
	used := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(ErrHTMLAuthoringInputV1, err)
		}
		n, err := reader.Read(raw[used:])
		used += n
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if used == len(raw) {
			return nil, &http.MaxBytesError{Limit: s.limit}
		}
	}
	raw = raw[:used]
	shape, err := htmlAuthoringInputShapeForV1(ctx, s.profile, raw)
	if err != nil {
		return nil, err
	}
	cost, err := htmlAuthoringInputParseResourcesV1(s.profile, shape)
	if err != nil {
		return nil, errors.Join(ErrHTMLAuthoringInputV1, err)
	}
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		return nil, ErrHTMLAuthoringInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		return nil, errors.Join(ErrHTMLAuthoringInputV1, err)
	}
	s.releases = append(s.releases, release)
	s.raw = raw
	s.shape = shape
	s.ready = true
	return raw, nil
}
