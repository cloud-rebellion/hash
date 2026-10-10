// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package docintake

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
)

type templateIntakeQueries struct {
	createParams []generated.CreatePDFDocumentParams
	document     *generated.Document
	createErr    error
	reportErr    error
	beforeCreate func()
	reportIDs    []uuid.UUID
}

func (q *templateIntakeQueries) CreatePDFDocument(_ context.Context, params generated.CreatePDFDocumentParams) (*generated.Document, error) {
	q.createParams = append(q.createParams, params)
	if q.beforeCreate != nil {
		q.beforeCreate()
	}
	return q.document, q.createErr
}

func (q *templateIntakeQueries) UpdateMetadataRedactionReport(_ context.Context, params generated.UpdateMetadataRedactionReportParams) error {
	q.reportIDs = append(q.reportIDs, params.ID)
	return q.reportErr
}

type templateIntakeStore struct {
	key               string
	contentType       string
	storedBytes       []byte
	stored            storage.StoredObject
	putErr            error
	deleteErr         error
	deletions         []OwnedPDFSource
	deleteCtxErr      error
	deleteHasDeadline bool
}

func (s *templateIntakeStore) PutVersioned(_ context.Context, key, contentType string, data []byte) (storage.StoredObject, error) {
	s.key, s.contentType = key, contentType
	s.storedBytes = bytes.Clone(data)
	s.stored = storage.StoredObject{VersionID: "template-source-exact-version", SHA256: sha256.Sum256(data)}
	return s.stored, s.putErr
}

func (s *templateIntakeStore) DeleteVersion(ctx context.Context, key, versionID string, digest []byte) error {
	owned := OwnedPDFSource{Key: key, VersionID: versionID}
	copy(owned.SHA256[:], digest)
	s.deletions = append(s.deletions, owned)
	s.deleteCtxErr = ctx.Err()
	_, s.deleteHasDeadline = ctx.Deadline()
	return s.deleteErr
}

func TestCreatePDFTemplateDocumentReturnsOwnedPutIdentityAndForwardsTemplateExpiry(t *testing.T) {
	orgID, userID, templateID := uuid.New(), uuid.New(), uuid.New()
	expires := pgtype.Timestamptz{Time: time.Date(2026, 11, 10, 15, 0, 0, 0, time.UTC), Valid: true}
	// The returned row deliberately has unrelated/stale source fields. Cleanup
	// ownership must still come from the actual write, not this query result.
	q := &templateIntakeQueries{document: &generated.Document{ID: uuid.New(), TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PdfStorageKey: pgtype.Text{String: "foreign/shared-template.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "stale-row-version", Valid: true}, PdfSha256: bytes.Repeat([]byte{5}, 32)}}
	st := &templateIntakeStore{}
	doc, pages, owned, err := CreatePDFTemplateDocument(context.Background(), q, st, orgID, userID, "Fresh master", templateID, expires, intakeTestPDF(t))
	if err != nil {
		t.Fatal(err)
	}
	if doc != q.document || pages != 1 || len(q.createParams) != 1 || len(q.reportIDs) != 1 || q.reportIDs[0] != doc.ID {
		t.Fatalf("intake result doc/pages/report = %v/%d/%v", doc, pages, q.reportIDs)
	}
	params := q.createParams[0]
	if params.OrgID != orgID || params.SenderID != userID || params.Name != "Fresh master" || !params.TemplateID.Valid || uuid.UUID(params.TemplateID.Bytes) != templateID || params.ExpiresAt != expires {
		t.Fatalf("template/expiry/actor parameters changed: %+v", params)
	}
	if !strings.HasPrefix(st.key, "org/"+orgID.String()+"/documents/") || st.contentType != "application/pdf" || len(st.storedBytes) == 0 {
		t.Fatal("fresh sanitized source was not stored under tenant document path")
	}
	if owned.Key != st.key || owned.VersionID != st.stored.VersionID || owned.SHA256 != st.stored.SHA256 || owned.Key == doc.PdfStorageKey.String || owned.VersionID == doc.PdfStorageVersionID.String {
		t.Fatalf("owned identity depends on returned row: %+v", owned)
	}
	if params.PdfStorageKey.String != owned.Key || params.PdfStorageVersionID.String != owned.VersionID || !bytes.Equal(params.PdfSha256, owned.SHA256[:]) || !params.EvidenceVersionPinsRequired {
		t.Fatal("DB insertion did not receive exact owned object commitment")
	}
	if len(st.deletions) != 0 {
		t.Fatal("successful intake deleted its caller-owned source")
	}
}

func TestCreatePDFTemplateDocumentRejectsNilIdentityBeforeIntakeOrStorage(t *testing.T) {
	for _, missing := range []string{"organization", "user", "template"} {
		t.Run(missing, func(t *testing.T) {
			orgID, userID, templateID := uuid.New(), uuid.New(), uuid.New()
			switch missing {
			case "organization":
				orgID = uuid.Nil
			case "user":
				userID = uuid.Nil
			case "template":
				templateID = uuid.Nil
			}
			q, st := &templateIntakeQueries{}, &templateIntakeStore{}
			doc, pages, owned, err := CreatePDFTemplateDocument(context.Background(), q, st, orgID, userID, "Invalid identity", templateID, pgtype.Timestamptz{}, []byte("not a PDF"))
			if err == nil || errors.Is(err, ErrSanitizePDF) || doc != nil || pages != 0 || owned != (OwnedPDFSource{}) || st.key != "" || len(q.createParams) != 0 {
				t.Fatalf("invalid identity reached intake/storage: doc=%v pages=%d owned=%+v error=%v", doc, pages, owned, err)
			}
		})
	}
}

func TestCreatePDFTemplateDocumentCompensatesPostStoreFailureDespiteCancellation(t *testing.T) {
	for _, phase := range []string{"insert", "redaction report"} {
		t.Run(phase, func(t *testing.T) {
			dbErr := errors.New("post-store database failure")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			q := &templateIntakeQueries{document: &generated.Document{ID: uuid.New()}, beforeCreate: cancel}
			if phase == "insert" {
				q.createErr = dbErr
			} else {
				q.reportErr = dbErr
			}
			st := &templateIntakeStore{}
			doc, pages, owned, err := CreatePDFTemplateDocument(ctx, q, st, uuid.New(), uuid.New(), "Failure", uuid.New(), pgtype.Timestamptz{}, intakeTestPDF(t))
			if !errors.Is(err, dbErr) || doc != nil || pages != 0 || owned != (OwnedPDFSource{}) || len(st.deletions) != 1 {
				t.Fatalf("failure compensation = %v/%d/%+v/%v", doc, pages, owned, err)
			}
			want := OwnedPDFSource{Key: st.key, VersionID: st.stored.VersionID, SHA256: st.stored.SHA256}
			if st.deletions[0] != want || st.deleteCtxErr != nil || !st.deleteHasDeadline {
				t.Fatalf("cleanup did not use detached bounded exact identity: %+v, context error %v", st.deletions, st.deleteCtxErr)
			}
		})
	}
}

func TestCreatePDFTemplateDocumentRetainsDatabaseAndExactCleanupFailureCauses(t *testing.T) {
	dbErr, cleanupErr := errors.New("database failure"), errors.New("exact object cleanup failure")
	q := &templateIntakeQueries{createErr: dbErr}
	st := &templateIntakeStore{deleteErr: cleanupErr}
	_, _, owned, err := CreatePDFTemplateDocument(context.Background(), q, st, uuid.New(), uuid.New(), "Failure", uuid.New(), pgtype.Timestamptz{}, intakeTestPDF(t))
	if !errors.Is(err, dbErr) || !errors.Is(err, cleanupErr) || owned != (OwnedPDFSource{}) || len(st.deletions) != 1 || st.deletions[0].VersionID != st.stored.VersionID || st.deletions[0].SHA256 != st.stored.SHA256 {
		t.Fatalf("failed exact cleanup lost its causes/identity: %v", err)
	}
}
