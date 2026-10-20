// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type DocumentPackageLayoutResultV1 struct {
	PackageID   uuid.UUID `json:"package_id"`
	Generation  int64     `json:"generation,string"`
	UpdatedAt   time.Time `json:"updated_at"`
	ChangedRows int64     `json:"changed_rows"`
	EventID     uuid.UUID `json:"event_id"`
}

// Fixed metadata edit: ordered IDs already selected, labels and omissions only.
// The original staff gate runs in this native transaction. The caller rechecks
// it after audit before the actual native COMMIT; no live source/provider read.
func (r *ApplicationHTMLRevisionReaderV1) ApplyDocumentPackageLayoutV1(call context.Context, in DocumentPackageLayoutInputV1, actor uuid.UUID, ip, ua string, appendAudit func(context.Context, *ApplicationHTMLAuditEventConsumerV1) error) (out DocumentPackageLayoutResultV1, failure error) {
	if r == nil || r.self != r || actor == uuid.Nil || appendAudit == nil || in.Count < 0 || in.Count > 16 || len(ip) > 64 || len(ua) > 1024 || !utf8.ValidString(ip) || !utf8.ValidString(ua) {
		return out, ErrDocumentPackageWriteV1
	}
	r.mu.Lock()
	valid := r.valid(call) && r.bodyComplete && r.snapshot != nil && r.snapshot.document != nil && r.packageBinding == nil
	if !valid || in.Root != r.snapshot.document.ID || !in.Expected.Equal(r.snapshot.document.UpdatedAt.Time) {
		r.mu.Unlock()
		return out, ErrDocumentPackageSourceChangedV1
	}
	r.mu.Unlock()
	before, e := r.ReadDocumentPackageInventoryV1(call)
	if e != nil {
		return out, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || before.PackageID != in.Draft.PackageID.String() || before.Generation != strconv.FormatInt(in.Draft.Generation, 10) {
		return out, ErrDocumentPackageSourceChangedV1
	}
	delta := int64(len(before.Members))
	textBytes := int64(0)
	for i := 0; i < in.Count; i++ {
		m := in.Members[i]
		if m.DocumentID == uuid.Nil || m.DocumentID == in.Root || !documentPackageWriteLabelV1(m.Title, 512, false) || !documentPackageWriteLabelV1(m.Category, 128, true) {
			return out, ErrDocumentPackageWriteV1
		}
		found := false
		for j := 0; j < i; j++ {
			if in.Members[j].DocumentID == m.DocumentID {
				return out, ErrDocumentPackageWriteV1
			}
		}
		for _, old := range before.Members {
			if old.DocumentID == m.DocumentID {
				found = true
				if old.Ordinal == int16(i+1) && old.Title == m.Title && old.Category == m.Category {
					delta--
				}
				break
			}
		}
		if !found {
			return out, ErrDocumentPackageWriteV1
		}
		textBytes += int64(len(m.Title) + len(m.Category))
	}
	out = DocumentPackageLayoutResultV1{PackageID: in.Draft.PackageID, Generation: in.Draft.Generation, UpdatedAt: before.UpdatedAt, ChangedRows: delta}
	if delta == 0 {
		return out, call.Err()
	}
	if in.Draft.Generation > math.MaxInt64-delta {
		return DocumentPackageLayoutResultV1{}, ErrDocumentPackageWriteV1
	}
	sizes, e := r.queries.GetDocumentPackageDraftSizesV1(call, generated.GetDocumentPackageDraftSizesV1Params{PackageID: in.Draft.PackageID, DocumentID: in.Root, OrgID: r.snapshot.document.OrgID, ExpectedGeneration: in.Draft.Generation})
	if e != nil {
		return DocumentPackageLayoutResultV1{}, e
	}
	if sizes == nil || sizes.MemberCount != int64(len(before.Members)) || sizes.ReportBytes < 0 || sizes.ReportBytes > sizes.MemberCount*65536 || sizes.RawTextBytes < 0 || sizes.RawTextBytes > sizes.MemberCount*4096 {
		return DocumentPackageLayoutResultV1{}, ErrDocumentPackageWriteV1
	}
	// Fund array binds, both audit layouts and old/new trigger proof overlaps
	// before producing them. Legacy NULL proof contributes zero bytes.
	raw := int64(1<<20) + 16*(sizes.RawTextBytes+textBytes+int64(len(ip)+len(ua)))
	wire := int64(1<<20) + 32*sizes.ReportBytes + 16*sizes.RawTextBytes
	close, e := r.authoring.acquireOwnedRetainedBodyV1(call, raw, wire)
	if e != nil {
		return DocumentPackageLayoutResultV1{}, e
	}
	r.closeConsumers = append(r.closeConsumers, close)
	ids := make([]uuid.UUID, in.Count)
	titles := make([]string, in.Count)
	categories := make([]string, in.Count)
	previous := make([]map[string]any, len(before.Members))
	desired := make([]map[string]any, in.Count)
	for i, m := range before.Members {
		previous[i] = map[string]any{"document_id": m.DocumentID.String(), "ordinal": int(m.Ordinal), "title": strings.Clone(m.Title), "category": strings.Clone(m.Category)}
	}
	for i := 0; i < in.Count; i++ {
		m := in.Members[i]
		ids[i] = m.DocumentID
		titles[i] = strings.Clone(m.Title)
		categories[i] = strings.Clone(m.Category)
		desired[i] = map[string]any{"document_id": m.DocumentID.String(), "ordinal": i + 1, "title": titles[i], "category": categories[i]}
	}
	org := r.snapshot.document.OrgID
	changed, e := r.queries.ApplyOwnedDocumentAttachmentLayoutV1(call, generated.ApplyOwnedDocumentAttachmentLayoutV1Params{DocumentID: in.Root, OrgID: org, ExpectedUpdatedAt: pgtype.Timestamptz{Time: before.UpdatedAt, Valid: true}, PackageID: in.Draft.PackageID, ExpectedGeneration: in.Draft.Generation, MemberIds: ids, Titles: titles, Categories: categories})
	if e != nil {
		return DocumentPackageLayoutResultV1{}, e
	}
	if changed != delta {
		return DocumentPackageLayoutResultV1{}, ErrDocumentPackageWriteV1
	}
	clock, e := r.queries.GetDocumentPackageMutationClockV1(call, generated.GetDocumentPackageMutationClockV1Params{PackageID: in.Draft.PackageID, DocumentID: in.Root, OrgID: org})
	if e != nil {
		return DocumentPackageLayoutResultV1{}, e
	}
	if clock == nil || clock.PackageID != in.Draft.PackageID || clock.DocumentID != in.Root || clock.OrgID != org || clock.DraftGeneration != in.Draft.Generation+delta || !applicationStampV1(clock.UpdatedAt) || !clock.UpdatedAt.Time.After(before.UpdatedAt) {
		return DocumentPackageLayoutResultV1{}, ErrDocumentPackageWriteV1
	}
	payload := map[string]any{"schema": "hash-attachment-layout-v1", "package_id": in.Draft.PackageID.String(), "draft_generation": strconv.FormatInt(clock.DraftGeneration, 10), "before": previous, "after": desired}
	event, e := r.session.NewHTMLAuditEventV1(call, HTMLAuditDocumentAttachmentLayoutV1, org, in.Root, pgtype.UUID{}, pgtype.UUID{Bytes: actor, Valid: true}, HTMLAuditDocumentAttachmentLayoutV1.KindV1(), ip, ua, payload)
	if e != nil {
		return DocumentPackageLayoutResultV1{}, e
	}
	if e = appendAudit(call, event); e != nil {
		event.CloseConsumerV1()
		return DocumentPackageLayoutResultV1{}, e
	}
	event.mu.Lock()
	appended := event.used && event.attempted && event.eventID != uuid.Nil && !event.closed
	id := event.eventID
	event.mu.Unlock()
	if !appended {
		event.CloseConsumerV1()
		return DocumentPackageLayoutResultV1{}, errors.Join(ErrDocumentPackageWriteV1, call.Err())
	}
	out.Generation = clock.DraftGeneration
	out.UpdatedAt = clock.UpdatedAt.Time
	out.EventID = id
	return out, call.Err()
}
