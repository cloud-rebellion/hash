// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrPackageResponseRequestV1 = errors.New("pdfadmission: owned package response unavailable")
var ErrPackageResponseRequiredV1 = errors.New("pdfadmission: current package consent required")
var ErrPackageResponseChangedV1 = errors.New("pdfadmission: package response observation changed")

// Public copies share the original native request, its immutable reader scope,
// deadline and funded observation strings. No caller identity or DBTX is used.
type ApplicationPackageResponseRequestV1 struct {
	state *applicationPackageResponseRequestV1
}
type applicationPackageResponseRequestV1 struct {
	mu                                        sync.Mutex
	self                                      *applicationPackageResponseRequestV1
	factory                                   *ApplicationSessionFactoryV1
	reader                                    *ApplicationSignerReaderV1
	scope                                     applicationSignerScopeSnapshotV1
	ctx                                       context.Context
	cancel                                    context.CancelFunc
	grant                                     *workguard.GrantV1
	expected                                  documentpackage.ResponseV1
	present                                   bool
	kind                                      string
	sent, notice, documentExpiry, tokenExpiry pgtype.Timestamptz
	rootSHA                                   [sha256.Size]byte
	rootSHAValid                              bool
	active                                    int
	bound, consumerClosed, closed             bool
}

func (f *ApplicationSessionFactoryV1) NewPackageResponseRequestV1(ctx context.Context, r *ApplicationSignerReaderV1, expected *documentpackage.ResponseV1, kind string) (*ApplicationPackageResponseRequestV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) || (kind != "signed" && kind != "accepted") {
		return nil, ErrPackageResponseRequestV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrPackageResponseRequestV1
	}
	if expected != nil && expected.ValidateV1() != nil {
		return nil, documentpackage.ErrResponseV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.finishScope == nil || r.session == nil || r.models == nil || r.models.Document == nil || r.models.Recipient == nil {
		return nil, ErrPackageResponseRequestV1
	}
	d, rec := r.models.Document, r.models.Recipient
	if d.ID != r.scope.document || d.OrgID != r.scope.org || rec.ID != r.scope.recipient || rec.DocumentID != r.scope.document || !applicationStampV1(rec.MagicTokenExpiresAt) || !time.Now().Before(rec.MagicTokenExpiresAt.Time) || (d.ExpiresAt.Valid && (!applicationStampV1(d.ExpiresAt) || !time.Now().Before(d.ExpiresAt.Time))) {
		return nil, ErrSignerReadCredentialV1
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	available := registered && !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		return nil, ErrPackageResponseRequestV1
	}
	// Exact fixed controls plus bounded validated hex/version strings, cloned
	// only after grant admission. Capture payloads and SQL outputs buy separate
	// real body loans from their native producers.
	raw := int64(8*unsafe.Sizeof(applicationPackageResponseRequestV1{}) + 8*unsafe.Sizeof(applicationPackageResponseMutationV1{}))
	if expected != nil {
		for _, text := range [...]string{expected.ManifestSHA256, expected.LegalCommitmentSHA256, expected.IncorporationVersion, expected.IncorporationSHA256} {
			if !htmlInputAddV1(&raw, int64(len(text)), 8) {
				return nil, ErrPackageResponseRequestV1
			}
		}
	}
	grant, err := coordinator.TryAcquireV1(ctx, r.scope.org, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return nil, errors.Join(ErrPackageResponseRequestV1, err)
	}
	call, cancel := context.WithCancel(ctx)
	s := &applicationPackageResponseRequestV1{factory: f, reader: r, scope: r.scope, ctx: call, cancel: cancel, grant: grant, present: expected != nil, kind: kind, sent: d.SentAt, notice: d.Article13NoticeEpochAt, documentExpiry: d.ExpiresAt, tokenExpiry: rec.MagicTokenExpiresAt, rootSHAValid: len(d.PdfSha256) == sha256.Size}
	if expected != nil {
		s.expected = documentpackage.ResponseV1{ManifestSHA256: strings.Clone(expected.ManifestSHA256), LegalCommitmentSHA256: strings.Clone(expected.LegalCommitmentSHA256), IncorporationVersion: strings.Clone(expected.IncorporationVersion), IncorporationSHA256: strings.Clone(expected.IncorporationSHA256), Consent: expected.Consent}
	}
	copy(s.rootSHA[:], d.PdfSha256)
	s.self = s
	r.blockSigningBorrowers++
	return &ApplicationPackageResponseRequestV1{state: s}, nil
}

func (h *ApplicationPackageResponseRequestV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.consumerClosed {
		s.mu.Unlock()
		return
	}
	s.consumerClosed = true
	s.cancel()
	r, grant := s.retireLockedV1()
	s.mu.Unlock()
	retireAcknowledgementRequestV1(r, grant)
}

func (s *applicationPackageResponseRequestV1) retireLockedV1() (*ApplicationSignerReaderV1, *workguard.GrantV1) {
	if !s.consumerClosed || s.closed || s.active != 0 {
		return nil, nil
	}
	s.closed = true
	r, grant := s.reader, s.grant
	s.reader, s.factory, s.grant = nil, nil, nil
	s.expected = documentpackage.ResponseV1{}
	return r, grant
}
