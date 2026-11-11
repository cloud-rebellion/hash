// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
)

type serviceEmailControlContextKeyV1 struct{}

// ApplicationServiceEmailControlV1 is only a process-resource owner. Existing
// owner/member/CAS transactions retain all SQL and mutation authority. It uses
// the configured process coordinator, never a new coordinator or caller vector.
type ApplicationServiceEmailControlV1 struct {
	mu             sync.Mutex
	self           *ApplicationServiceEmailControlV1
	admission      *WorkAdmissionV1
	org            uuid.UUID
	grant          *workguard.GrantV1
	closes         []func()
	closed         bool
	reads          int
	workBorrowers  int
	sampleReserved bool
}

func (a *WorkAdmissionV1) NewServiceEmailControlV1(ctx context.Context, org uuid.UUID) (context.Context, *ApplicationServiceEmailControlV1, error) {
	if a == nil || a.coordinator == nil || ctx == nil || ctx.Err() != nil || org == uuid.Nil {
		return ctx, nil, ErrWorkRuntimeV1
	}
	grant, err := a.coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 2 << 20})
	if err != nil {
		return ctx, nil, err
	}
	o := &ApplicationServiceEmailControlV1{admission: a, org: org, grant: grant}
	o.self = o
	return context.WithValue(ctx, serviceEmailControlContextKeyV1{}, o), o, nil
}
func ServiceEmailControlFromContextV1(ctx context.Context) *ApplicationServiceEmailControlV1 {
	if ctx == nil {
		return nil
	}
	o, _ := ctx.Value(serviceEmailControlContextKeyV1{}).(*ApplicationServiceEmailControlV1)
	return o
}
func (o *ApplicationServiceEmailControlV1) validLockedV1(ctx context.Context) bool {
	return o != nil && o.self == o && !o.closed && o.grant != nil && ctx != nil && ctx.Err() == nil && ServiceEmailControlFromContextV1(ctx) == o
}
func (o *ApplicationServiceEmailControlV1) AdmitSourceV1(ctx context.Context, h *generated.GetServiceEmailTemplateHeaderV1Row) error {
	if o == nil {
		return ErrWorkRuntimeV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) || h == nil || o.reads >= 20 {
		return ErrWorkRuntimeV1
	}
	_, wire, err := applicationServiceEmailSourceWorkV1(h, o.org, h.Kind)
	if err != nil {
		return err
	}
	if err = o.grant.TryGrowParentV1(ctx, 8*wire+applicationServiceEmailHeaderWorkV1()); err != nil {
		return err
	}
	// A retained reset edition has no source payload. Its header and parent
	// bookkeeping remain owned; there is no DB body to acquire a zero-cost
	// grant for. Non-empty editions retain their exact staging loan.
	if wire > 0 {
		close, err := o.admission.acquire(ctx, o.org, workguard.VectorV1{DBStagingBytes: wire})
		if err != nil {
			return err
		}
		o.closes = append(o.closes, close)
	}
	o.reads++
	return nil
}

// The original bounded request has been decoded. Retain its canonical source
// and worst-case escaped JSON response copies; raster/parser work belongs to a
// separate synchronous loan, retired after its actual last use.
func (o *ApplicationServiceEmailControlV1) AdmitInputV1(ctx context.Context, subject, html, text, design string) error {
	if o == nil {
		return ErrWorkRuntimeV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) || len(subject) > dispatch.ServiceEmailSubjectSourceBytesV1 || len(html) > dispatch.ServiceEmailHTMLSourceBytesV1 || len(text) > dispatch.ServiceEmailTextSourceBytesV1 || len(design) > dispatch.ServiceEmailDesignSourceBytesV1 {
		return ErrWorkRuntimeV1
	}
	n := int64(len(subject)+len(html)+len(text)+len(design))*8 + 65536
	return o.grant.TryGrowParentV1(ctx, n)
}

// BeginTemplateWorkV1 derives transient sanitizer/tree/raster work from the
// exact bounded template. The caller closes it only when validation/rendering
// has returned; returned canonical strings remain covered by AdmitSource/Input.
// Catalog iteration never retains one raster workspace per saved edition.
func (o *ApplicationServiceEmailControlV1) BeginTemplateWorkV1(ctx context.Context, tpl dispatch.ServiceEmailTemplateV1) (func(), error) {
	if o == nil {
		return nil, ErrServiceEmailControlV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) || len(tpl.SubjectTemplate) > dispatch.ServiceEmailSubjectSourceBytesV1 || len(tpl.HTMLTemplate) > dispatch.ServiceEmailHTMLSourceBytesV1 || len(tpl.TextTemplate) > dispatch.ServiceEmailTextSourceBytesV1 || len(tpl.DesignJSON) > dispatch.ServiceEmailDesignSourceBytesV1 {
		return nil, ErrServiceEmailControlV1
	}
	n := int64(len(tpl.SubjectTemplate)+len(tpl.HTMLTemplate)+len(tpl.TextTemplate)+len(tpl.DesignJSON))*64 + 65536
	if tpl.DesignJSON != "" {
		n += dispatch.ServiceEmailDesignFixedWorkBytesV1
	}
	closeWork, err := o.admission.acquire(ctx, o.org, workguard.VectorV1{ParentBytes: n})
	if err != nil {
		return nil, err
	}
	o.workBorrowers++
	var once sync.Once
	return func() {
		once.Do(func() {
			// The synchronous parser/render has returned. Its own grant retires
			// now, while source/serialized output keep their original owner.
			closeWork()
			o.mu.Lock()
			o.workBorrowers--
			closes := o.retireLockedV1()
			o.mu.Unlock()
			for _, close := range closes {
				close()
			}
		})
	}, nil
}

func (o *ApplicationServiceEmailControlV1) AdmitSyntheticPreviewV1(ctx context.Context) error {
	if o == nil {
		return ErrWorkRuntimeV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) {
		return ErrWorkRuntimeV1
	}
	return o.grant.TryGrowParentV1(ctx, 12*dispatch.ServiceEmailDesignRenderedBytesV1+65536)
}
func (o *ApplicationServiceEmailControlV1) CloseConsumerV1() {
	if o == nil {
		return
	}
	o.mu.Lock()
	if o.self != o || o.closed {
		o.mu.Unlock()
		return
	}
	o.closed = true
	closes := o.retireLockedV1()
	o.mu.Unlock()
	for _, close := range closes {
		close()
	}
}

// A closing HTTP/MCP consumer cannot retire retained input while an actual
// synchronous parser/render still uses it. No new work starts after Close.
func (o *ApplicationServiceEmailControlV1) retireLockedV1() []func() {
	if !o.closed || o.workBorrowers != 0 {
		return nil
	}
	closes := make([]func(), 0, len(o.closes)+1)
	for i := len(o.closes) - 1; i >= 0; i-- {
		closes = append(closes, o.closes[i])
	}
	o.closes = nil
	if o.grant != nil {
		closes = append(closes, o.grant.Close)
		o.grant = nil
	}
	return closes
}

var ErrServiceEmailControlV1 = errors.New("email design requires its original process resource owner")

// ReserveSampleOutputV1 prices the fixed synthetic prefix/notice, bounded full
// self-contained render, frozen outbox strings, digest/JSON/MIME copies before
// the sample helper allocates any of them. It supplies no send or SQL authority.
func (o *ApplicationServiceEmailControlV1) ReserveSampleOutputV1(ctx context.Context) error {
	return o.reserveMessageOutputV1(ctx, 2*dispatch.ServiceEmailDesignRenderedBytesV1)
}

// ReserveNativeOutputV1 uses the same bounded render/result workspace as the
// existing sample operation, plus subject/row overhead in its DB staging loan.
// It creates no sample receipt, destination, send, audit or SQL authority.
func (o *ApplicationServiceEmailControlV1) ReserveNativeOutputV1(ctx context.Context) error {
	return o.reserveMessageOutputV1(ctx, 2*dispatch.ServiceEmailDesignRenderedBytesV1+dispatch.ServiceEmailRenderedSubjectBytesV1+65536)
}

func (o *ApplicationServiceEmailControlV1) reserveMessageOutputV1(ctx context.Context, staging int64) error {
	if o == nil {
		return ErrServiceEmailControlV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) || o.sampleReserved {
		return ErrServiceEmailControlV1
	}
	if err := o.grant.TryGrowParentV1(ctx, 16*dispatch.ServiceEmailDesignRenderedBytesV1+65536+dispatch.ServiceEmailDesignFixedWorkBytesV1+64*(dispatch.ServiceEmailDesignSourceBytesV1+dispatch.ServiceEmailSubjectSourceBytesV1+dispatch.ServiceEmailHTMLSourceBytesV1+dispatch.ServiceEmailTextSourceBytesV1)); err != nil {
		return err
	}
	close, err := o.admission.acquire(ctx, o.org, workguard.VectorV1{DBStagingBytes: staging})
	if err != nil {
		return err
	}
	o.closes = append(o.closes, close)
	o.sampleReserved = true
	return nil
}

// AdmitNativeContextV1 prices the actual concrete producer strings before any
// native-template expansion or selected-edition parsing. Values are not copied,
// interpreted, or exported, and callers supply no size vector.
func (o *ApplicationServiceEmailControlV1) AdmitNativeContextV1(ctx context.Context, c dispatch.TemplateContext) error {
	if o == nil {
		return ErrServiceEmailControlV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.validLockedV1(ctx) {
		return ErrServiceEmailControlV1
	}
	var total int64
	for _, value := range []string{c.DocumentName, c.SenderName, c.SenderEmail, c.RecipientName, c.OrgName, c.Locale,
		c.SignURL, c.BeaconURL, c.DownloadURL, c.AuditCertURL, c.PackagePortalURL, c.DownloadExpiresAt,
		c.DeclineReason, c.BrandColor, c.ChangeQuote, c.ChangeContext, c.ChangeProposed,
		c.OpenURL, c.ApproveURL, c.DenyURL, c.QuotaKind, c.PeriodResetAt, c.UpgradeURL, c.PlanName} {
		if int64(len(value)) > dispatch.ServiceEmailDesignRenderedBytesV1-total {
			return ErrServiceEmailControlV1
		}
		total += int64(len(value))
	}
	return o.grant.TryGrowParentV1(ctx, 64*total+65536)
}

func (o *ApplicationServiceEmailControlV1) MatchesOrgV1(ctx context.Context, org uuid.UUID) bool {
	if o == nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.validLockedV1(ctx) && o.org == org
}
