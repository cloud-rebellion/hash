//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/ordinarypage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These tests exercise real PostgreSQL88, generated guarded85/87/88 signing
// setup plus the86 journal APIs, and the
// public writer constructor. Selected package/geometry pins and storage are
// synthetic protocol fixtures: no renderer, S3, Object Lock, encryption, legal
// assurance, completed index/certificate or active application Sign is proved.
// Run only against an explicitly owned disposable PostgreSQL database.
type fittedOutputPGFixtureE2E struct {
	f          *multipartyPDFFixture
	op         *generated.DocumentFinalizationPreparation
	request    FittedOutputRequestV1
	body       []byte
	writer     *FittedOutputJournalV1
	store      *fittedOutputPGStoreE2E
	witness    *fittedOutputPGWitnessE2E
	writerPool *pgxpool.Pool
	sqlGuard   *workguard.CoordinatorV1
}

func fittedOutputPGMustE2E(t *testing.T, label string, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(label)
	}
}
func fittedOutputPGStampE2E(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}
func fittedOutputPGHashE2E(raw []byte) []byte { sum := sha256.Sum256(raw); return bytes.Clone(sum[:]) }
func fittedOutputPGJSONE2E(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	fittedOutputPGMustE2E(t, "marshal synthetic protocol descriptor", err)
	return raw
}
func fittedOutputPGCloseTxE2E(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func fittedOutputPGDigestE2E(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != sha256.Size {
		t.Fatal("invalid fixture digest")
	}
	return raw
}

// Full real current document/fields/parties and exact source tuple are frozen.
// Geometry/ordinary PDF/capture inspection receipts remain synthetic lineage;
// this fixture does not mint a hot producer or claim a renderer/worker proof.
func fittedOutputPGAdmissionBasisE2E(t *testing.T, f *multipartyPDFFixture, doc *generated.Document, fields []*generated.DocumentField, source manualfit.SourceTupleV1, geometry sanitize.PDFManualGeometry) *pdfadmission.BasisV1 {
	t.Helper()
	parties, err := f.q.ListRecipientsByDocument(f.ctx, f.docID)
	fittedOutputPGMustE2E(t, "read ALL actual admission parties", err)
	roles, err := pdflayout.RequiredRoles(doc, parties, fields, len(geometry.Pages))
	fittedOutputPGMustE2E(t, "derive current actual required roles", err)
	recipe := ordinarypage.KnownRecipeV1()
	input := pdfadmission.InputV1{OrgID: f.orgID, DocumentID: f.docID, OriginalDocumentName: doc.Name, CeremonyEpoch: doc.SentAt.Time.UTC(), SourceKind: doc.SourceKind, RequiresSignature: doc.RequiresSignature, Source: source, Geometry: geometry, RequiredRoles: roles, RoutingMode: doc.RoutingMode, RenderRecipe: pdfadmission.RenderRecipeV1{Schema: recipe.Schema, RecipeID: recipe.RecipeID, HTMLTemplateSHA256: recipe.HTMLTemplateSHA256, CoreCSSSHA256: recipe.CoreCSSSHA256, MeasurementSHA256: recipe.MeasurementSHA256, SnapshotSHA256: recipe.SnapshotSHA256, PrintRecipeSHA256: recipe.PrintRecipeSHA256, BrandingCSS: "/* synthetic capture provenance; exact stored current rows */"}}
	for _, font := range recipe.Fonts {
		input.RenderRecipe.Fonts = append(input.RenderRecipe.Fonts, pdfadmission.FontAssetV1{File: font.File, Family: font.Family, SHA256: font.SHA256, Bytes: font.Bytes})
	}
	for _, party := range parties {
		input.Parties = append(input.Parties, pdfadmission.PartyV1{OrgID: f.orgID, DocumentID: f.docID, ID: party.ID, Role: party.Role, Email: party.Email, Name: party.Name, OrderIndex: party.OrderIndex, Locale: party.Locale})
	}
	for _, field := range fields {
		coords := make([]string, 0, 4)
		for _, number := range []pgtype.Numeric{field.XPct, field.YPct, field.WPct, field.HPct} {
			value, e := fittedDecimalV1(number)
			fittedOutputPGMustE2E(t, "encode exact admission coordinate", e)
			coords = append(coords, value)
		}
		input.Fields = append(input.Fields, pdfadmission.FieldV1{OrgID: f.orgID, DocumentID: f.docID, ID: field.ID, RecipientID: uuid.UUID(field.RecipientID.Bytes), RecipientValid: field.RecipientID.Valid, Type: field.Type, Page: field.Page, Required: field.Required, X: coords[0], Y: coords[1], W: coords[2], H: coords[3], ValueValid: field.Value.Valid, Value: field.Value.String})
	}
	basis, err := pdfadmission.BuildV1(input)
	fittedOutputPGMustE2E(t, "build canonical88 basis from actual current rows", err)
	return basis
}
func fittedOutputPGCaptureAdmissionE2E(t *testing.T, f *multipartyPDFFixture, basis *pdfadmission.BasisV1, owner uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	input := basis.Input()
	pages := make([]int32, 0, len(basis.OrdinaryPages()))
	for _, page := range basis.OrdinaryPages() {
		pages = append(pages, int32(page))
	}
	if len(pages) != 1 {
		t.Fatal("fixture requires one original ordinary page")
	}
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	fittedOutputPGMustE2E(t, "begin actual literal88 capture", err)
	defer fittedOutputPGCloseTxE2E(tx)
	q := generated.New(tx)
	_, err = q.CapturePDFSigningAdmissionV1(f.ctx, generated.CapturePDFSigningAdmissionV1Params{ID: id, OrgID: f.orgID, DocumentID: f.docID, CeremonyEpoch: fittedOutputPGStampE2E(input.CeremonyEpoch), OriginalDocumentName: input.OriginalDocumentName, SourceStorageKey: input.Source.Key, SourceVersionID: input.Source.VersionID, SourceSha256: fittedOutputPGDigestE2E(t, input.Source.SHA256), SourceBytes: input.Source.Bytes, SourcePages: int32(len(input.Geometry.Pages)), StaticBasisPayload: basis.CanonicalJSON(), StaticBasisSha256: fittedOutputPGDigestE2E(t, basis.SHA256()), StaticBasisBodySha256: fittedOutputPGDigestE2E(t, basis.CanonicalSHA256()), GeometryPayload: basis.GeometryJSON(), GeometryPayloadSha256: fittedOutputPGDigestE2E(t, basis.GeometryJSONSHA256()), GeometryPagesPayload: basis.GeometryPagesJSON(), GeometrySha256: fittedOutputPGDigestE2E(t, basis.GeometryPagesSHA256()), FieldsPayload: basis.FieldsJSON(), FieldsSha256: fittedOutputPGDigestE2E(t, basis.FieldsSHA256()), PartiesPayload: basis.PartiesJSON(), PartiesSha256: fittedOutputPGDigestE2E(t, basis.PartiesSHA256()), RenderRecipePayload: basis.RenderRecipeJSON(), RenderRecipeSha256: fittedOutputPGDigestE2E(t, basis.RenderRecipeSHA256()), OrdinaryRecipePayload: basis.OrdinaryRecipeJSON(), OrdinaryRecipeSha256: fittedOutputPGDigestE2E(t, basis.OrdinaryRecipeSHA256()), BrandingContextSha256: fittedOutputPGDigestE2E(t, basis.BrandingCSSSHA256()), ExpectedOrdinaryPages: pages, RequiredParties: int32(len(input.Parties)), FieldCount: int32(len(input.Fields)), BaseBytesLimit: 8 << 20, DescriptorBytesLimit: 1 << 20, FinalPdfBytesLimit: 1 << 20, FitsIndexBytesLimit: 1 << 20, CertificatePdfBytesLimit: 1 << 20, CertificatePayloadBytesLimit: 64 << 10, CertificateSignatureBytesLimit: 256, EventsBytesLimit: 1 << 20, VersionsBytesLimit: 1 << 20, ArchiveManifestBytesLimit: 64 << 10, ArchiveBudgetBytes: 160 << 20, ProcessingBudgetBytes: 50 << 20, OwnerID: owner, LeaseUntil: fittedOutputPGStampE2E(time.Now().Add(time.Minute))})
	fittedOutputPGMustE2E(t, "capture immutable bounded88 basis", err)
	_, err = q.ActivatePDFSigningAdmissionCandidateV1(f.ctx, generated.ActivatePDFSigningAdmissionCandidateV1Params{AdmissionID: id, OrgID: f.orgID, DocumentID: f.docID, StaticBasisSha256: fittedOutputPGDigestE2E(t, basis.SHA256())})
	fittedOutputPGMustE2E(t, "activate exact current88 candidate", err)
	plans, err := pdfadmission.OrdinaryPlansV1(basis)
	fittedOutputPGMustE2E(t, "derive literal ordinary plan", err)
	if len(plans) != 1 {
		t.Fatal("one original ordinary plan required")
	}
	plan := fittedOutputPGJSONE2E(t, plans[0])
	planSHA, err := ordinarypage.PlanSHA256V1(plans[0])
	fittedOutputPGMustE2E(t, "hash exact ordinary plan", err)
	body := onePagePDF(t, "Synthetic immutable ordinary admission page")
	_, err = q.CapturePDFSigningAdmissionBodyV1(f.ctx, generated.CapturePDFSigningAdmissionBodyV1Params{AdmissionID: id, OrgID: f.orgID, DocumentID: f.docID, OwnerID: owner, Page: int32(plans[0].Page), Payload: body, Sha256: fittedOutputPGHashE2E(body), Bytes: int64(len(body)), StaticBasisSha256: fittedOutputPGDigestE2E(t, basis.SHA256()), PlanPayload: plan, PlanSha256: fittedOutputPGDigestE2E(t, planSHA), PackageSha256: fittedOutputPGHashE2E([]byte("synthetic88 original package receipt")), ReportSha256: fittedOutputPGHashE2E([]byte("synthetic88 original layout receipt")), InspectionSha256: fittedOutputPGHashE2E([]byte("synthetic88 fragment inspection receipt"))})
	fittedOutputPGMustE2E(t, "capture sole original ordinary PDF and literal plan", err)
	_, err = q.MarkPDFSigningAdmissionReadyV1(f.ctx, generated.MarkPDFSigningAdmissionReadyV1Params{AdmissionID: id, OrgID: f.orgID, DocumentID: f.docID, OwnerID: owner, SourceInspectionSha256: fittedOutputPGHashE2E([]byte("synthetic88 full source inspection receipt"))})
	fittedOutputPGMustE2E(t, "ready complete immutable88 original set", err)
	fittedOutputPGMustE2E(t, "commit actual capture and ready", tx.Commit(f.ctx))
	return id
}
func fittedOutputPGCaptureFitPayloadE2E(t *testing.T, f *multipartyPDFFixture, q *generated.Queries, owner, fitID uuid.UUID, kind string, page int32, key, media string, body []byte) {
	t.Helper()
	_, err := q.CaptureSignatureFitOriginalPayload(f.ctx, generated.CaptureSignatureFitOriginalPayloadParams{PreparationID: fitID, OrgID: f.orgID, DocumentID: f.docID, OwnerID: owner, Kind: kind, Page: page, StorageKey: key, Sha256: fittedOutputPGHashE2E(body), Bytes: int64(len(body)), ContentType: media, Payload: body})
	fittedOutputPGMustE2E(t, "capture guarded immutable87 original before object reservation", err)
}

func newFittedOutputPGFixtureE2E(t *testing.T, lease time.Duration) *fittedOutputPGFixtureE2E {
	t.Helper()
	if os.Getenv("HASH_E2E_DB_URL") == "" {
		t.Skip("HASH_E2E_DB_URL required")
	}
	if os.Getenv("HASH_E2E_FITTED_OUTPUT_OWNED_PG") != "1" {
		t.Skip("HASH_E2E_FITTED_OUTPUT_OWNED_PG=1 requires an owned disposable database")
	}
	digest, versions, err := mdb.EmbeddedMigrationsIdentity()
	fittedOutputPGMustE2E(t, "read embedded migration identity", err)
	if digest != os.Getenv("HASH_E2E_EXPECT_MIGRATIONS_SHA256") || digest != "499f28ba25d98d8c1525e07865a111e0709cb65a63ce8b706bb15a9e7a295c40" || len(versions) != 88 {
		t.Fatal("root must select the exact contiguous88 migration identity")
	}
	for i, n := range versions {
		if n != int64(i+1) {
			t.Fatal("migration history is not contiguous88")
		}
	}
	f := newMultipartyPDFE2E(t, true)
	_, err = f.q.EnablePDFSigningAdmissionPolicyV1(f.ctx, generated.EnablePDFSigningAdmissionPolicyV1Params{DocumentID: f.docID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "opt actual sent fixture into guarded88", err)
	rc := f.context(t, 0)
	in := f.input(t, rc, 0)
	fields, err := f.q.ListFieldsByDocument(f.ctx, f.docID)
	fittedOutputPGMustE2E(t, "read actual sent fields", err)
	var target *generated.DocumentField
	for _, field := range fields {
		if field.Type == "signature" {
			if target != nil {
				t.Fatal("single required signature target expected")
			}
			target = field
		}
	}
	if target == nil {
		t.Fatal("missing signature target")
	}
	spanText, err := render.RenderSignatureSpan(in.TypedName, in.Font)
	fittedOutputPGMustE2E(t, "render inert original span", err)
	span := []byte(spanText)
	// Geometry/package bytes intentionally model only the guarded SQL protocol.
	pages := []sanitize.PDFManualPage{{Boxes: [5][4]float64{{0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}, {0, 0, 612, 792}}, Rotation: 0, UserUnit: 1}}
	geometry := fittedOutputPGJSONE2E(t, pages)
	source, err := f.store.GetVerifiedVersion(f.ctx, f.sourceKey, f.source.VersionID, f.source.SHA256[:])
	fittedOutputPGMustE2E(t, "read exact fixture source", err)
	coordinates := []string{}
	for _, number := range []pgtype.Numeric{target.XPct, target.YPct, target.WPct, target.HPct} {
		s, e := fittedDecimalV1(number)
		fittedOutputPGMustE2E(t, "encode original exact placement", e)
		coordinates = append(coordinates, s)
	}
	input := manualfit.AuthorityInputV1{OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, CeremonyEpoch: rc.Document.SentAt.Time.UTC(), Source: manualfit.SourceTupleV1{Key: f.sourceKey, VersionID: f.source.VersionID, SHA256: hex.EncodeToString(f.source.SHA256[:]), Bytes: int64(len(source))}, TypedName: in.TypedName, Font: in.Font, SpanSHA256: hex.EncodeToString(fittedOutputPGHashE2E(span)), ExpectedTargetIDs: []uuid.UUID{target.ID}, Targets: []manualfit.TargetV1{{ID: target.ID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, Page: 1, Required: true, X: coordinates[0], Y: coordinates[1], W: coordinates[2], H: coordinates[3]}}}
	authority, err := manualfit.BuildAuthorityV1(input, sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: input.Source.SHA256, SourceBytes: input.Source.Bytes, GeometrySHA256: hex.EncodeToString(fittedOutputPGHashE2E(geometry)), Pages: pages})
	fittedOutputPGMustE2E(t, "build synthetic85 authority", err)
	owner, fitID := uuid.New(), uuid.New()
	signingBasis := fittedOutputPGAdmissionBasisE2E(t, f, rc.Document, fields, input.Source, sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: input.Source.SHA256, SourceBytes: input.Source.Bytes, GeometrySHA256: hex.EncodeToString(fittedOutputPGHashE2E(geometry)), Pages: pages})
	admissionID := fittedOutputPGCaptureAdmissionE2E(t, f, signingBasis, owner)
	prefix := manualfit.ObjectPrefixV1(fitID, f.orgID, f.docID)
	packageBody := []byte("synthetic selected package; no renderer paint proof")
	spanPin := manualfit.ObjectPinV1{Key: prefix + "span.html", VersionID: "span+/opaque=original", SHA256: input.SpanSHA256, Bytes: int64(len(span)), ContentType: "text/html"}
	pagePin := manualfit.ObjectPinV1{Key: prefix + "page-1.fit", VersionID: "page+/opaque=original", SHA256: hex.EncodeToString(fittedOutputPGHashE2E(packageBody)), Bytes: int64(len(packageBody)), ContentType: signaturefit.MediaType}
	manifest, err := manualfit.NewManifestV1(fitID, authority, spanPin, []manualfit.PageArtifactV1{{Page: 1, InputSHA256: authority.Pages()[0].InputSHA256, Package: pagePin, PDFSHA256: hex.EncodeToString(fittedOutputPGHashE2E([]byte("synthetic PDF section"))), ReportSHA256: hex.EncodeToString(fittedOutputPGHashE2E([]byte("synthetic report"))), HTMLSHA256: hex.EncodeToString(fittedOutputPGHashE2E([]byte("synthetic html"))), FontSHA256: authority.FontInfo().SHA256, SnapshotSHA256: hex.EncodeToString(fittedOutputPGHashE2E([]byte("synthetic snapshot")))}})
	fittedOutputPGMustE2E(t, "build synthetic bound manifest", err)
	manifestBody := manifest.CanonicalJSON()
	authorityDigest, err := hex.DecodeString(authority.SHA256())
	fittedOutputPGMustE2E(t, "decode authority commitment", err)
	fitTx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	fittedOutputPGMustE2E(t, "begin actual85/87/88 atomic designation", err)
	defer fittedOutputPGCloseTxE2E(fitTx)
	fitQueries := generated.New(fitTx)
	prepareDocument, err := fitQueries.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.docID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "lock actual original authority document", err)
	prepareRecipient, err := fitQueries.GetRecipient(f.ctx, generated.GetRecipientParams{ID: rc.Recipient.ID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "read actual original authority recipient", err)
	fittedOutputPGMustE2E(t, "validate original authority notice", ValidateLockedNoticeEvidence(rc, prepareDocument, in.Notice))
	fittedOutputPGMustE2E(t, "validate original authority credential", ValidateLockedRecipientCredential(rc, prepareRecipient, prepareDocument, time.Now()))
	_, err = fitQueries.ReserveSignatureFitPreparation(f.ctx, generated.ReserveSignatureFitPreparationParams{ID: fitID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, CeremonyEpoch: fittedOutputPGStampE2E(input.CeremonyEpoch), AuthoritySha256: authorityDigest, SourceStorageKey: input.Source.Key, SourceVersionID: input.Source.VersionID, SourceSha256: f.source.SHA256[:], SourceBytes: input.Source.Bytes, GeometrySha256: fittedOutputPGHashE2E(geometry), SpanSha256: fittedOutputPGHashE2E(span), ReservedBytes: int64(len(span) + len(packageBody) + len(manifestBody) + 4096), ExpectedObjects: 3, OwnerID: owner, LeaseUntil: fittedOutputPGStampE2E(time.Now().Add(30 * time.Second))})
	fittedOutputPGMustE2E(t, "reserve guarded85 preparation", err)
	_, err = fitQueries.CaptureSignatureFitOriginalAuthority(f.ctx, generated.CaptureSignatureFitOriginalAuthorityParams{PreparationID: fitID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, OwnerID: owner, CeremonyEpoch: fittedOutputPGStampE2E(input.CeremonyEpoch), AuthorityPayload: authority.CanonicalJSON(), AuthoritySha256: authorityDigest, AuthorityBytes: int64(len(authority.CanonicalJSON())), OccupiedPages: []int32{1}})
	fittedOutputPGMustE2E(t, "capture real canonical87 original authority", err)
	fittedOutputPGCaptureFitPayloadE2E(t, f, fitQueries, owner, fitID, "span", 0, spanPin.Key, spanPin.ContentType, span)
	_, err = fitQueries.DesignatePDFSigningAdmissionFitPreparationV1(f.ctx, generated.DesignatePDFSigningAdmissionFitPreparationV1Params{AdmissionID: admissionID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, PreparationID: pgtype.UUID{Bytes: [16]byte(fitID), Valid: true}, OwnerID: pgtype.UUID{Bytes: [16]byte(owner), Valid: true}})
	fittedOutputPGMustE2E(t, "bind actual87 authority to88 future slot", err)
	fittedOutputPGMustE2E(t, "commit atomic85/87/88 designation", fitTx.Commit(f.ctx))
	for _, part := range []struct {
		kind                string
		page                int32
		key, version, media string
		body                []byte
	}{{kind: "span", key: spanPin.Key, version: spanPin.VersionID, media: spanPin.ContentType, body: span}, {kind: "page", page: 1, key: pagePin.Key, version: pagePin.VersionID, media: pagePin.ContentType, body: packageBody}, {kind: "manifest", key: prefix + "manifest.json", version: "manifest+/opaque=original", media: "application/json", body: manifestBody}} {
		if part.kind != "span" {
			fittedOutputPGCaptureFitPayloadE2E(t, f, f.q, owner, fitID, part.kind, part.page, part.key, part.media, part.body)
		}
		_, err = f.q.ReserveSignatureFitObject(f.ctx, generated.ReserveSignatureFitObjectParams{PreparationID: fitID, OrgID: f.orgID, OwnerID: owner, Kind: part.kind, Page: part.page, StorageKey: part.key, Sha256: fittedOutputPGHashE2E(part.body), Bytes: int64(len(part.body)), ContentType: part.media})
		fittedOutputPGMustE2E(t, "reserve guarded85 object", err)
		_, err = f.q.MarkSignatureFitUploadAttempted(f.ctx, generated.MarkSignatureFitUploadAttemptedParams{PreparationID: fitID, OrgID: f.orgID, OwnerID: owner, Kind: part.kind, Page: part.page})
		fittedOutputPGMustE2E(t, "persist synthetic85 original attempt", err)
		_, err = f.q.PinSignatureFitObjectVersion(f.ctx, generated.PinSignatureFitObjectVersionParams{PreparationID: fitID, OrgID: f.orgID, OwnerID: owner, Kind: part.kind, Page: part.page, VersionID: part.version})
		fittedOutputPGMustE2E(t, "pin synthetic85 exact version", err)
		_, err = f.q.MarkSignatureFitObjectReadbackVerified(f.ctx, generated.MarkSignatureFitObjectReadbackVerifiedParams{PreparationID: fitID, OrgID: f.orgID, OwnerID: owner, Kind: part.kind, Page: part.page, VersionID: part.version, Sha256: fittedOutputPGHashE2E(part.body), Bytes: int64(len(part.body))})
		fittedOutputPGMustE2E(t, "checkpoint synthetic85 readback", err)
	}
	_, err = f.q.MarkSignatureFitPreparationPrepared(f.ctx, generated.MarkSignatureFitPreparationPreparedParams{ID: fitID, OrgID: f.orgID, OwnerID: owner})
	fittedOutputPGMustE2E(t, "prepare guarded85 inventory", err)
	_, err = f.q.MarkSignatureFitSelectionCommitAttempted(f.ctx, generated.MarkSignatureFitSelectionCommitAttemptedParams{ID: fitID, OrgID: f.orgID, OwnerID: owner})
	fittedOutputPGMustE2E(t, "persist85 selection attempt", err)
	selected, err := f.q.SelectSignatureFitPreparation(f.ctx, generated.SelectSignatureFitPreparationParams{ID: uuid.New(), PreparationID: fitID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, CeremonyEpoch: fittedOutputPGStampE2E(input.CeremonyEpoch), AuthoritySha256: authorityDigest})
	fittedOutputPGMustE2E(t, "select guarded85 inventory", err)
	_, err = f.q.MarkSignatureFitRetentionStarted(f.ctx, generated.MarkSignatureFitRetentionStartedParams{ID: selected.ID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "start synthetic85 floor checkpoint", err)
	selected, err = f.q.MarkSignatureFitRetentionComplete(f.ctx, generated.MarkSignatureFitRetentionCompleteParams{ID: selected.ID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "complete synthetic85 floor checkpoint", err)
	tx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	fittedOutputPGMustE2E(t, "begin actual fitted signature transaction", err)
	defer fittedOutputPGCloseTxE2E(tx)
	q := generated.New(tx)
	locked, err := q.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.docID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "lock signature document", err)
	fresh, err := q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: rc.Recipient.ID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "read original actual recipient", err)
	fittedOutputPGMustE2E(t, "validate original notice", ValidateLockedNoticeEvidence(rc, locked, in.Notice))
	fittedOutputPGMustE2E(t, "validate original credential", ValidateLockedRecipientCredential(rc, fresh, locked, time.Now()))
	n, err := q.RequireDocumentFitsIndex(f.ctx, generated.RequireDocumentFitsIndexParams{DocumentID: f.docID, OrgID: f.orgID, CeremonyEpoch: fittedOutputPGStampE2E(input.CeremonyEpoch)})
	fittedOutputPGMustE2E(t, "bind first fitted requirement", err)
	if n != 1 {
		t.Fatal("missing first fitted requirement")
	}
	sig, err := q.InsertFittedManualSignatureV1(f.ctx, generated.InsertFittedManualSignatureV1Params{DocumentID: f.docID, RecipientID: rc.Recipient.ID, FieldID: target.ID, Font: in.Font, TypedName: in.TypedName, ImageStorageKey: selected.SpanStorageKey, ImageSha256: selected.SpanSha256, ImageVersionID: pgtype.Text{String: selected.SpanVersionID, Valid: true}})
	fittedOutputPGMustE2E(t, "insert guarded fitted SQL signature", err)
	_, err = q.CreateSignatureFitCompanion(f.ctx, generated.CreateSignatureFitCompanionParams{SignatureID: sig.ID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, FieldID: target.ID, SelectionID: selected.ID, SpanSha256: selected.SpanSha256})
	fittedOutputPGMustE2E(t, "insert reciprocal companion", err)
	fittedOutputPGMustE2E(t, "mark actual recipient signed", q.SetRecipientStatus(f.ctx, generated.SetRecipientStatusParams{ID: rc.Recipient.ID, DocumentID: f.docID, Status: "signed"}))
	_, err = q.SetDocumentStatus(f.ctx, generated.SetDocumentStatusParams{ID: f.docID, OrgID: f.orgID, Status: "in_progress"})
	fittedOutputPGMustE2E(t, "mark actual document progress", err)
	payload, err := responseAuditPayload(map[string]any{"font": in.Font, "typed_name": in.TypedName, "image_sha256": hex.EncodeToString(sig.ImageSha256), "signature_id": sig.ID}, in.Notice)
	fittedOutputPGMustE2E(t, "bind actual notice audit payload", err)
	pending, err := f.engine.Audit.LogTx(f.ctx, tx, audit.Entry{OrgID: f.orgID, DocumentID: &f.docID, RecipientID: &rc.Recipient.ID, Kind: audit.KindDocumentSigned, IP: in.IP, UserAgent: in.UserAgent, Payload: payload})
	fittedOutputPGMustE2E(t, "atomically append signature audit", err)
	_, err = q.SealAndBindPDFSigningAdmissionV1(f.ctx, generated.SealAndBindPDFSigningAdmissionV1Params{SignatureID: sig.ID, AdmissionID: admissionID, OrgID: f.orgID, DocumentID: f.docID, RecipientID: rc.Recipient.ID, FieldID: target.ID, ReviewedBasisSha256: fittedOutputPGDigestE2E(t, signingBasis.SHA256()), SelectionID: selected.ID, SignedEventID: pending.ID, AdmissionOwnerID: owner})
	fittedOutputPGMustE2E(t, "bind exact actual signature audit and first88 seal", err)
	finalCredential, err := q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: rc.Recipient.ID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "read original credential before actual commit", err)
	fittedOutputPGMustE2E(t, "recheck original credential before signature commit", ValidateLockedRecipientCredential(rc, finalCredential, locked, time.Now()))
	fittedOutputPGMustE2E(t, "commit signature companion flag status and audit", tx.Commit(f.ctx))
	f.engine.Audit.Publish(pending)
	binding, err := f.q.GetPDFSigningAdmissionSignatureBindingV1(f.ctx, generated.GetPDFSigningAdmissionSignatureBindingV1Params{SignatureID: sig.ID, OrgID: f.orgID, DocumentID: f.docID})
	fittedOutputPGMustE2E(t, "read committed actual88 signature seal audit pair", err)
	if binding.AdmissionID != admissionID || binding.SelectionID != selected.ID || binding.SignedEventID != pending.ID || !bytes.Equal(binding.StaticBasisSha256, fittedOutputPGDigestE2E(t, signingBasis.SHA256())) || !bytes.Equal(binding.ReviewedBasisSha256, binding.StaticBasisSha256) {
		t.Fatal("committed88 binding differs from real original signature and review")
	}
	storedOriginals, err := f.q.ListSignatureFitOriginalPayloadMetadata(f.ctx, generated.ListSignatureFitOriginalPayloadMetadataParams{PreparationID: fitID, OrgID: f.orgID, DocumentID: f.docID})
	fittedOutputPGMustE2E(t, "read retained87 original inventory", err)
	if len(storedOriginals) != 3 {
		t.Fatal("selected85 operation lacks complete immutable87 original inventory")
	}
	finalTx, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	fittedOutputPGMustE2E(t, "begin actual completion claim", err)
	defer fittedOutputPGCloseTxE2E(finalTx)
	fq := generated.New(finalTx)
	_, err = fq.GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.docID, OrgID: f.orgID})
	fittedOutputPGMustE2E(t, "lock completion claim", err)
	doc, err := fq.BeginDocumentFinalization(f.ctx, generated.BeginDocumentFinalizationParams{ID: f.docID, OrgID: f.orgID, RetentionYears: 7})
	fittedOutputPGMustE2E(t, "allocate actual completion retention", err)
	fittedOutputPGMustE2E(t, "commit actual completion claim", finalTx.Commit(f.ctx))
	_, needed, basis, err := fittedFieldSnapshotWithLegacyV1(f.docID, fields, []*generated.Signature{sig}, nil)
	fittedOutputPGMustE2E(t, "freeze original actual field basis", err)
	basePages := []int32{}
	for _, page := range needed {
		basePages = append(basePages, int32(page))
	}
	op, err := f.q.CaptureFittedFinalizationPreparation(f.ctx, generated.CaptureFittedFinalizationPreparationParams{ID: uuid.New(), DocumentID: f.docID, OrgID: f.orgID, SourcePages: 1, GeometryPagesPayload: geometry, FieldSnapshotPayload: basis, RequiredBasePages: basePages, BaseBytesLimit: 4096, FinalPdfBytesLimit: 4096, FitsIndexBytesLimit: 65536, CertificatePdfBytesLimit: 4096, CertificatePayloadBytesLimit: 4096, CertificateSignatureBytesLimit: 256, ArchiveBudgetBytes: 32 << 20, OwnerID: owner, LeaseUntil: fittedOutputPGStampE2E(time.Now().Add(lease))})
	fittedOutputPGMustE2E(t, "capture guarded original86 basis", err)
	_, err = f.q.FreezeFittedFinalizationAuditSnapshot(f.ctx, generated.FreezeFittedFinalizationAuditSnapshotParams{PreparationID: op.ID, OrgID: f.orgID, DocumentID: f.docID, OwnerID: owner, Payload: []byte("original synthetic writer context; no issuer or provider proof")})
	fittedOutputPGMustE2E(t, "freeze original86 audit context", err)
	body := []byte("original durable SQL86 final PDF protocol body; no actual PDF")
	sum := sha256.Sum256(body)
	request := FittedOutputRequestV1{OwnerID: owner, Reservation: storage.FittedFinalizationReservationV1{OrgID: f.orgID, DocumentID: f.docID, PreparationID: op.ID, Kind: "final_pdf", Key: "org/" + f.orgID.String() + "/documents/" + f.docID.String() + "/final-" + hex.EncodeToString(sum[:]) + ".pdf", SHA256: sum, Bytes: int64(len(body)), ContentType: "application/pdf", CompletionEffectiveAt: doc.CompletionEffectiveAt.Time, RetainUntil: doc.FinalizationRetainUntil.Time}}
	v := &fittedOutputPGFixtureE2E{f: f, op: op, request: request, body: body, store: &fittedOutputPGStoreE2E{}, witness: &fittedOutputPGWitnessE2E{}}
	cfg := f.pool.Config()
	cfg.MinConns = 0
	cfg.MinIdleConns = 0
	cfg.ConnConfig.RuntimeParams["application_name"] = "hash-fitted-output-" + uuid.NewString()
	// Bounded fixture server limits exceed the five-second client close budget,
	// so the blocked-cancellation case must retain charge until its owned blocker
	// releases instead of passing accidentally through a shorter lock timeout.
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "25000"
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = "20000"
	cfg.ConnConfig.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	cfg.ConnConfig.Tracer = &fittedOutputPGTraceE2E{witness: v.witness, previous: cfg.ConnConfig.Tracer}
	v.writerPool, err = pgxpool.NewWithConfig(f.ctx, cfg)
	fittedOutputPGMustE2E(t, "create saved-config writer pool", err)
	t.Cleanup(v.writerPool.Close)
	v.sqlGuard, err = workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{SQLSessions: 16}, Organisation: workguard.VectorV1{SQLSessions: 16}, MaxGrants: 64, MaxOrganisationGrants: 64})
	fittedOutputPGMustE2E(t, "create actual shared SQL coordinator", err)
	work, workErr := pdfadmission.NewWorkAdmissionV1(v.sqlGuard)
	fittedOutputPGMustE2E(t, "bind actual fixed physical SQL admission", workErr)
	v.writer, err = NewFittedOutputJournalV1(v.writerPool, v.store, v.witness.admit, work, pdfadmission.ApplicationSessionDirectProfileV1)
	fittedOutputPGMustE2E(t, "construct real PostgreSQL output writer", err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// Work retires through actual server observation; the last private observer
		// remains conservatively charged after its client closes, without a witness.
		closeErr := v.writer.CloseV1(ctx)
		if !errors.Is(closeErr, ErrFittedOutputSQLUnknownV1) {
			t.Error("last observer retirement was invented")
		}
		if v.sqlGuard.SnapshotV1(v.f.orgID).Global.SQLSessions != 1 {
			v.diagnoseObserver(t, closeErr)
			t.Error("work SQL grants leaked or observer grant was credited without proof")
		}
		v.assertPhysical(t)
	})
	v.store.putHook = func(ctx context.Context, r storage.FittedFinalizationReservationV1, raw []byte) error {
		o, e := f.q.GetFittedFinalizationOutput(ctx, generated.GetFittedFinalizationOutputParams{PreparationID: r.PreparationID, OrgID: r.OrgID, DocumentID: r.DocumentID, Kind: r.Kind, Page: r.Page})
		if e != nil || o == nil || !bytes.Equal(o.Payload, raw) || !o.UploadAttemptedAt.Valid || !o.RetentionStartedAt.Valid || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) != v.request.OwnerID || o.VersionID.Valid {
			return errors.New("synthetic PUT lacked independently visible original attempt")
		}
		v.store.visibleAttempt.Store(true)
		return nil
	}
	return v
}

type fittedOutputPGSessionE2E struct {
	conn *pgconn.PgConn
	pid  uint32
	done <-chan struct{}
}
type fittedOutputPGPermitE2E struct {
	sessions []fittedOutputPGSessionE2E
	released bool
}
type fittedOutputPGWitnessE2E struct {
	mu                 sync.Mutex
	active             *fittedOutputPGPermitE2E
	sessions           []fittedOutputPGSessionE2E
	admitted, released int
	violation          bool
	bodyQueries        atomic.Int64
	reobserved         int
	observerEvents     []fittedOutputPGObserverEventE2E
	observerDropped    int
}

func (w *fittedOutputPGWitnessE2E) admit(ctx context.Context, r FittedOutputResourceRequestV1) (func(), error) {
	if _, ok := ctx.Deadline(); !ok || r.OrgID == uuid.Nil || r.DocumentID == uuid.Nil || r.PreparationID == uuid.Nil || r.Kind != "final_pdf" || r.BodyBytes < 1 || r.WorkingBytes != 4*r.BodyBytes+11*(1<<20) {
		return nil, ErrFittedOutputResourcesV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active != nil {
		w.violation = true
		return nil, ErrFittedOutputResourcesV1
	}
	permit := &fittedOutputPGPermitE2E{}
	w.active = permit
	w.admitted++
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if permit.released || w.active != permit {
			w.violation = true
			return
		}
		for _, session := range permit.sessions {
			select {
			case <-session.done:
			default:
				w.violation = true
			}
		}
		permit.released = true
		w.active = nil
		w.released++
	}, nil
}
func (w *fittedOutputPGWitnessE2E) connected(conn *pgconn.PgConn) {
	w.mu.Lock()
	defer w.mu.Unlock()
	// The writer-only pool is never acquired/pinged. Its zero-minimum idle/background
	// maintenance does not produce journal-owned idle sessions.
	if w.active == nil {
		return
	}
	if conn == nil {
		w.violation = true
		return
	}
	session := fittedOutputPGSessionE2E{conn: conn, pid: conn.PID(), done: conn.CleanupDone()}
	// A metadata recheck under one locked transaction traces its same physical
	// connection again. Deduplicate only the exact connection/PID/cleanup triple
	// within this permit; another phase or permit still needs its own backend.
	for _, old := range w.active.sessions {
		if old.conn != conn {
			continue
		}
		if old.pid != session.pid || old.done != session.done || session.pid == 0 || session.done == nil {
			w.violation = true
			return
		}
		w.reobserved++
		return
	}
	w.sessions = append(w.sessions, session)
	w.active.sessions = append(w.active.sessions, session)
}

// Only the two fixed observer statements are recognized. Diagnostics contain
// bounded public lifecycle facts, never raw SQL, arguments, bodies or errors.
const fittedOutputPGObserverSQLE2E = "SELECT own.pid,own.backend_start,own.datid::bigint,own.usesysid::bigint,COALESCE(pg_catalog.inet_server_addr()::text,''),COALESCE(pg_catalog.inet_server_port(),0),pg_catalog.pg_postmaster_start_time(),target.pid,target.backend_start,target.datid::bigint,target.usesysid::bigint FROM pg_catalog.pg_stat_activity own LEFT JOIN pg_catalog.pg_stat_activity target ON target.pid=$1::integer WHERE own.pid=pg_catalog.pg_backend_pid()"

type fittedOutputPGTraceObserverKeyE2E struct{}
type fittedOutputPGObserverEventE2E struct {
	phase                                  string
	edge                                   string
	pid                                    uint32
	ctxCanceled, ctxDeadline, clientClosed bool
	result                                 string
}

func fittedOutputPGErrorClassE2E(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(err, context.Canceled) {
		return "cancel"
	}
	if pgconn.Timeout(err) {
		return "timeout"
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		return "postgres"
	}
	return "other"
}
func (w *fittedOutputPGWitnessE2E) observeEvent(ctx context.Context, conn *pgx.Conn, phase, edge string, err error) {
	event := fittedOutputPGObserverEventE2E{phase: phase, edge: edge, result: fittedOutputPGErrorClassE2E(err), ctxCanceled: errors.Is(ctx.Err(), context.Canceled), ctxDeadline: errors.Is(ctx.Err(), context.DeadlineExceeded)}
	if conn != nil {
		event.pid = conn.PgConn().PID()
		event.clientClosed = conn.PgConn().IsClosed()
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	const bound = 32
	if len(w.observerEvents) < bound {
		w.observerEvents = append(w.observerEvents, event)
		return
	}
	copy(w.observerEvents, w.observerEvents[1:])
	w.observerEvents[bound-1] = event
	w.observerDropped++
}
func (v *fittedOutputPGFixtureE2E) diagnoseObserver(t *testing.T, err error) {
	t.Helper()
	v.witness.mu.Lock()
	events := append([]fittedOutputPGObserverEventE2E(nil), v.witness.observerEvents...)
	dropped := v.witness.observerDropped
	v.witness.mu.Unlock()
	t.Logf("HASH_FITTED_SQL_CLEANUP class=%s unknown=%t ctx_cancelled=%t ctx_deadline=%t sql_grants=%d observer_events=%d dropped=%d", fittedOutputPGErrorClassE2E(err), errors.Is(err, ErrFittedOutputSQLUnknownV1), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), v.sqlGuard.SnapshotV1(v.f.orgID).Global.SQLSessions, len(events), dropped)
	for _, event := range events {
		t.Logf("HASH_FITTED_SQL_OBSERVER phase=%s edge=%s pid=%d ctx_cancelled=%t ctx_deadline=%t client_closed=%t result=%s", event.phase, event.edge, event.pid, event.ctxCanceled, event.ctxDeadline, event.clientClosed, event.result)
	}
}

type fittedOutputPGTraceE2E struct {
	witness  *fittedOutputPGWitnessE2E
	previous pgx.QueryTracer
}

func (q *fittedOutputPGTraceE2E) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if q.previous != nil {
		ctx = q.previous.TraceQueryStart(ctx, conn, data)
	}
	phase := ""
	switch data.SQL {
	case "SELECT pg_catalog.pg_stat_clear_snapshot()":
		phase = "clear"
	case fittedOutputPGObserverSQLE2E:
		phase = "observe"
	}
	if phase != "" {
		q.witness.observeEvent(ctx, conn, phase, "start", nil)
		ctx = context.WithValue(ctx, fittedOutputPGTraceObserverKeyE2E{}, phase)
	}
	if strings.HasPrefix(data.SQL, "-- name: GetFittedFinalizationRecoveryDocumentMetadata :one\n") {
		q.witness.connected(conn.PgConn())
	}
	if strings.HasPrefix(data.SQL, "-- name: GetFittedFinalizationOutput :one\n") {
		q.witness.bodyQueries.Add(1)
	}
	return ctx
}
func (q *fittedOutputPGTraceE2E) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if phase, ok := ctx.Value(fittedOutputPGTraceObserverKeyE2E{}).(string); ok {
		q.witness.observeEvent(ctx, conn, phase, "end", data.Err)
	}
	if q.previous != nil {
		q.previous.TraceQueryEnd(ctx, conn, data)
	}
}
func (v *fittedOutputPGFixtureE2E) assertPhysical(t *testing.T) {
	t.Helper()
	v.witness.mu.Lock()
	sessions := append([]fittedOutputPGSessionE2E(nil), v.witness.sessions...)
	bad := v.witness.violation || v.witness.active != nil || v.witness.admitted != v.witness.released
	v.witness.mu.Unlock()
	if bad {
		t.Error("resource release did not follow joined work/client/server retirement")
	}
	seen := map[uint32]bool{}
	seenConn := map[*pgconn.PgConn]bool{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, session := range sessions {
		if session.conn == nil || session.done == nil || session.pid == 0 || seen[session.pid] || seenConn[session.conn] {
			t.Error("writer phases did not use distinct positive physical PostgreSQL PIDs")
		}
		seen[session.pid] = true
		seenConn[session.conn] = true
		select {
		case <-session.done:
		default:
			t.Error("actual PgConn cleanup remains unfinished")
		}
		for {
			var present bool
			err := v.f.pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)", int32(session.pid)).Scan(&present)
			if err != nil {
				t.Error("independent physical PID observer failed")
				break
			}
			if !present {
				break
			}
			select {
			case <-ctx.Done():
				t.Error("writer backend PID remained after cleanup")
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
}
func (v *fittedOutputPGFixtureE2E) output(t *testing.T) *generated.DocumentFinalizationOutput {
	t.Helper()
	r := v.request.Reservation
	row, err := v.f.q.GetFittedFinalizationOutput(v.f.ctx, generated.GetFittedFinalizationOutputParams{PreparationID: r.PreparationID, OrgID: r.OrgID, DocumentID: r.DocumentID, Kind: r.Kind, Page: r.Page})
	fittedOutputPGMustE2E(t, "read independent original output", err)
	return row
}
func (v *fittedOutputPGFixtureE2E) reserve(t *testing.T) {
	t.Helper()
	receipt, err := v.writer.ReserveOriginalV1(v.f.ctx, v.request, v.body)
	fittedOutputPGMustE2E(t, "reserve actual original output body", err)
	if !receipt.Reserved() || receipt.AttemptCommitted() || receipt.ProviderAttempted() {
		t.Fatal("reservation invented a provider attempt")
	}
	row := v.output(t)
	if !bytes.Equal(row.Payload, v.body) || row.UploadAttemptedAt.Valid {
		t.Fatal("independent durable original body differs")
	}
}
func (v *fittedOutputPGFixtureE2E) waitExpired(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(v.f.ctx, 7*time.Second)
	defer cancel()
	for {
		var expired bool
		err := v.f.pool.QueryRow(ctx, "SELECT lease_until<=clock_timestamp() FROM document_finalization_preparations WHERE id=$1 AND org_id=$2 AND document_id=$3", v.op.ID, v.f.orgID, v.f.docID).Scan(&expired)
		fittedOutputPGMustE2E(t, "observe actual server lease", err)
		if expired {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("finite server lease observation expired")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

type fittedOutputPGStoreE2E struct {
	mu                 sync.Mutex
	puts, resolves     int
	object             storage.StoredObject
	body               []byte
	putErr, resolveErr error
	afterPut           func()
	putHook            func(context.Context, storage.FittedFinalizationReservationV1, []byte) error
	visibleAttempt     atomic.Bool
}

func (s *fittedOutputPGStoreE2E) PutFittedFinalizationReservedV1(ctx context.Context, r storage.FittedFinalizationReservationV1, body []byte) (storage.StoredObject, error) {
	s.mu.Lock()
	s.puts++
	hook, late, after := s.putHook, s.putErr, s.afterPut
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, r, body); err != nil {
			return storage.StoredObject{}, err
		}
	}
	if int64(len(body)) != r.Bytes || sha256.Sum256(body) != r.SHA256 {
		return storage.StoredObject{}, errors.New("synthetic body mismatch")
	}
	object := storage.StoredObject{VersionID: " original writer+/opaque=version ", SHA256: r.SHA256}
	s.mu.Lock()
	s.object = object
	s.body = bytes.Clone(body)
	s.mu.Unlock()
	if after != nil {
		after()
	}
	return object, late
}
func (s *fittedOutputPGStoreE2E) ResolveFittedFinalizationVersionV1(ctx context.Context, r storage.FittedFinalizationReservationV1, known string) (storage.FittedFinalizationObservationV1, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resolves++
	observation := storage.FittedFinalizationObservationV1{Object: s.object, State: storage.FittedFinalizationEmptyUnresolvedV1}
	if s.object.VersionID != "" {
		observation.State = storage.FittedFinalizationVerifiedV1
		if s.object.SHA256 != r.SHA256 || known != "" && known != s.object.VersionID || int64(len(s.body)) != r.Bytes || sha256.Sum256(s.body) != r.SHA256 {
			return storage.FittedFinalizationObservationV1{Object: s.object, State: storage.FittedFinalizationUnresolvedV1}, errors.New("synthetic exact-version mismatch")
		}
	}
	if s.resolveErr != nil {
		observation.State = storage.FittedFinalizationUnresolvedV1
	}
	return observation, s.resolveErr
}
func (s *fittedOutputPGStoreE2E) counts() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.puts, s.resolves
}

func TestFittedOutputJournalDurableOriginalAndSinglePutE2E(t *testing.T) {
	v := newFittedOutputPGFixtureE2E(t, 30*time.Second)
	v.reserve(t)
	if puts, resolves := v.store.counts(); puts != 0 || resolves != 0 {
		t.Fatal("reservation dispatched synthetic storage")
	}
	receipt, err := v.writer.UploadOriginalV1(v.f.ctx, v.request)
	fittedOutputPGMustE2E(t, "upload sole original body", err)
	if !receipt.AttemptCommitted() || !receipt.ProviderAttempted() || !receipt.Verified() || receipt.SQLUncertain() || !v.store.visibleAttempt.Load() {
		t.Fatal("acknowledged original dispatch witness missing")
	}
	row := v.output(t)
	if !row.VersionID.Valid || row.VersionID.String != receipt.Object().VersionID || !row.ReadbackVerifiedAt.Valid || !row.RetentionCompletedAt.Valid || !bytes.Equal(row.Payload, v.body) {
		t.Fatal("exact original pin/checkpoints were not durable")
	}
	beforeBody := v.witness.bodyQueries.Load()
	if beforeBody != 1 {
		t.Fatal("original body was not retrieved exactly once through the real driver")
	}
	beforeReserve := fittedOutputPGJSONE2E(t, row)
	reserved, err := v.writer.ReserveOriginalV1(v.f.ctx, v.request, v.body)
	fittedOutputPGMustE2E(t, "observe existing original reservation", err)
	if !reserved.Reserved() || !reserved.AttemptCommitted() || reserved.ProviderAttempted() || reserved.SQLUncertain() || reserved.Object().VersionID != receipt.Object().VersionID || v.witness.bodyQueries.Load() != beforeBody || !bytes.Equal(beforeReserve, fittedOutputPGJSONE2E(t, v.output(t))) {
		t.Fatal("idempotent reservation changed or lost the durable original attempt/pin")
	}
	again, err := v.writer.UploadOriginalV1(v.f.ctx, v.request)
	if !errors.Is(err, ErrFittedOutputAttemptExistsV1) || again.ProviderAttempted() {
		t.Fatal("existing original attempt permitted another upload")
	}
	before := fittedOutputPGJSONE2E(t, v.output(t))
	observed, err := v.writer.ResolveReadOnlyV1(v.f.ctx, v.request, receipt.Object().VersionID)
	fittedOutputPGMustE2E(t, "read-only exact original recovery", err)
	if !observed.Verified() || !bytes.Equal(before, fittedOutputPGJSONE2E(t, v.output(t))) {
		t.Fatal("read-only recovery mutated the journal")
	}
	checked, err := v.writer.CheckpointExactV1(v.f.ctx, v.request, observed)
	fittedOutputPGMustE2E(t, "current-owner exact checkpoint", err)
	if !checked.Verified() || checked.ProviderAttempted() || v.witness.bodyQueries.Load() != beforeBody {
		t.Fatal("checkpoint read body or dispatched another PUT")
	}
	if puts, resolves := v.store.counts(); puts != 1 || resolves != 3 {
		t.Fatal("real writer synthetic dispatch counts differ")
	}
	fittedOutputPGMustE2E(t, "reconcile physical session cleanup", v.writer.ReconcileCleanupV1(v.f.ctx))
	v.assertPhysical(t)
	v.witness.mu.Lock()
	phases := len(v.witness.sessions)
	reobserved := v.witness.reobserved
	v.witness.mu.Unlock()
	if reobserved < 1 {
		t.Fatal("same actual locked transaction metadata was not rechecked")
	}
	if phases < 9 {
		t.Fatal("writer did not expose distinct fresh physical phases")
	}
	t.Log("HASH_FITTED_OUTPUT_WRITER_WITNESS actual_postgres=true synthetic_storage=true original_body_durable=true sole_put=true attempt_visible_before_put=true distinct_sessions=true cleanup_done=true active_sign=false provider_or_legal_proof=false")
}

func TestFittedOutputJournalPositivePinSurvivesLateProviderFailureE2E(t *testing.T) {
	for _, mode := range []string{"late_error", "late_cancel", "late_resolver_error"} {
		t.Run(mode, func(t *testing.T) {
			v := newFittedOutputPGFixtureE2E(t, 30*time.Second)
			v.reserve(t)
			ctx, cancel := context.WithCancelCause(v.f.ctx)
			defer cancel(nil)
			cause := errors.New("owned synthetic cancellation cause")
			late := errors.New("synthetic private provider detail must not escape")
			switch mode {
			case "late_error":
				v.store.putErr = late
			case "late_cancel":
				v.store.afterPut = func() { cancel(cause) }
			case "late_resolver_error":
				v.store.resolveErr = late
			}
			receipt, err := v.writer.UploadOriginalV1(ctx, v.request)
			if err == nil || !receipt.ProviderAttempted() || !receipt.AttemptCommitted() || receipt.Object().VersionID == "" || receipt.Verified() {
				t.Fatal("late refusal lost original positive or invented verification")
			}
			if strings.Contains(err.Error(), late.Error()) {
				t.Fatal("writer exposed synthetic private provider detail")
			}
			if mode == "late_cancel" && (!errors.Is(err, context.Canceled) || !errors.Is(err, cause)) {
				t.Fatal("distinct original cancellation cause was lost")
			}
			row := v.output(t)
			if !row.VersionID.Valid || row.VersionID.String != receipt.Object().VersionID || row.ReadbackVerifiedAt.Valid || row.RetentionCompletedAt.Valid {
				t.Fatal("known positive was not durably preserved before late refusal")
			}
			v.store.putErr = nil
			v.store.afterPut = nil
			v.store.resolveErr = nil
			before := fittedOutputPGJSONE2E(t, row)
			observed, err := v.writer.ResolveReadOnlyV1(v.f.ctx, v.request, receipt.Object().VersionID)
			fittedOutputPGMustE2E(t, "fresh read-only recovery of positive", err)
			if !observed.Verified() || !bytes.Equal(before, fittedOutputPGJSONE2E(t, v.output(t))) {
				t.Fatal("read-only resolution changed partial checkpoints")
			}
			checked, err := v.writer.CheckpointExactV1(v.f.ctx, v.request, observed)
			fittedOutputPGMustE2E(t, "recover exact positive checkpoints", err)
			if !checked.Verified() || checked.ProviderAttempted() {
				t.Fatal("exact checkpoint reuploaded")
			}
			row = v.output(t)
			if !row.ReadbackVerifiedAt.Valid || !row.RetentionCompletedAt.Valid {
				t.Fatal("exact recovery did not complete output checkpoints")
			}
			if puts, _ := v.store.counts(); puts != 1 {
				t.Fatal("late refusal permitted replacement PUT")
			}
			v.assertPhysical(t)
		})
	}
}

func TestFittedOutputJournalCurrentOwnerAndLeaseRefuseBeforeBodyE2E(t *testing.T) {
	for _, mode := range []string{"different_owner", "expired_then_taken_over"} {
		t.Run(mode, func(t *testing.T) {
			lease := 30 * time.Second
			if mode == "expired_then_taken_over" {
				lease = 5 * time.Second
			}
			v := newFittedOutputPGFixtureE2E(t, lease)
			v.reserve(t)
			before := v.witness.bodyQueries.Load()
			denied := v.request
			if mode == "different_owner" {
				denied.OwnerID = uuid.New()
			} else {
				v.waitExpired(t)
			}
			receipt, err := v.writer.UploadOriginalV1(v.f.ctx, denied)
			if !errors.Is(err, ErrFittedOutputAuthorityV1) || receipt.ProviderAttempted() || v.witness.bodyQueries.Load() != before {
				t.Fatal("denied authority reached original body or PUT")
			}
			if puts, resolves := v.store.counts(); puts != 0 || resolves != 0 {
				t.Fatal("denied authority reached synthetic storage")
			}
			if v.output(t).UploadAttemptedAt.Valid {
				t.Fatal("denied owner invented an original marker")
			}
			if mode == "expired_then_taken_over" {
				original := v.request
				newOwner := uuid.New()
				_, err = v.f.q.ClaimFittedFinalizationPreparationLease(v.f.ctx, generated.ClaimFittedFinalizationPreparationLeaseParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: newOwner, LeaseUntil: fittedOutputPGStampE2E(time.Now().Add(30 * time.Second))})
				fittedOutputPGMustE2E(t, "claim actual expired operation", err)
				_, err = v.writer.UploadOriginalV1(v.f.ctx, original)
				if !errors.Is(err, ErrFittedOutputAuthorityV1) || v.witness.bodyQueries.Load() != before {
					t.Fatal("old owner read the original body after takeover")
				}
				v.request.OwnerID = newOwner
				receipt, err = v.writer.UploadOriginalV1(v.f.ctx, v.request)
				fittedOutputPGMustE2E(t, "new acknowledged owner uploads original body", err)
				if !receipt.Verified() {
					t.Fatal("current owner did not verify original output")
				}
			}
			v.assertPhysical(t)
		})
	}
}

func TestFittedOutputJournalBlockedCancellationPhysicallyJoinsE2E(t *testing.T) {
	v := newFittedOutputPGFixtureE2E(t, 30*time.Second)
	v.reserve(t)
	blocker, err := v.f.pool.BeginTx(v.f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	fittedOutputPGMustE2E(t, "begin owned document barrier", err)
	defer fittedOutputPGCloseTxE2E(blocker)
	_, err = generated.New(blocker).GetDocumentForUpdate(v.f.ctx, generated.GetDocumentForUpdateParams{ID: v.f.docID, OrgID: v.f.orgID})
	fittedOutputPGMustE2E(t, "hold actual document lock", err)
	var holder int32
	fittedOutputPGMustE2E(t, "read actual holder PID", blocker.QueryRow(v.f.ctx, "SELECT pg_backend_pid()").Scan(&holder))
	ctx, cancel := context.WithCancelCause(v.f.ctx)
	defer cancel(nil)
	type outcome struct {
		receipt FittedOutputReceiptV1
		err     error
	}
	result := make(chan outcome, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		receipt, err := v.writer.UploadOriginalV1(ctx, v.request)
		result <- outcome{receipt: receipt, err: err}
	}()
	defer func() {
		cancel(nil)
		fittedOutputPGCloseTxE2E(blocker)
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("owned canceled writer goroutine did not join")
		}
	}()
	waiting := false
	observeCtx, stopObserve := context.WithTimeout(v.f.ctx, 3*time.Second)
	defer stopObserve()
	for !waiting {
		select {
		case <-result:
			t.Fatal("writer returned before its owned document barrier")
		default:
		}
		err = v.f.pool.QueryRow(observeCtx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE application_name=$1 AND $2=ANY(pg_blocking_pids(a.pid)))", v.writerPool.Config().ConnConfig.RuntimeParams["application_name"], holder).Scan(&waiting)
		fittedOutputPGMustE2E(t, "observe actual blocked writer session", err)
		if !waiting {
			select {
			case <-observeCtx.Done():
				t.Fatal("writer never reached actual lock wait")
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	cause := errors.New("owned blocked writer cancellation")
	cancel(cause)
	select {
	case returned := <-result:
		if !errors.Is(returned.err, context.Canceled) || !errors.Is(returned.err, cause) || returned.receipt.ProviderAttempted() {
			t.Fatal("blocked cancellation lost cause or dispatched PUT")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("owned blocked writer failed to physically join")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("returned owned writer still active")
	}
	// The fixed profile refuses an unadmitted CancelRequest socket. Closing the
	// local connection joins the client but cannot retire a still-blocked server.
	short, stop := context.WithTimeout(v.f.ctx, 20*time.Millisecond)
	pending := v.writer.ReconcileCleanupV1(short)
	stop()
	if !errors.Is(pending, ErrFittedOutputSQLUnknownV1) || v.sqlGuard.SnapshotV1(v.f.orgID).Global.SQLSessions != 2 {
		t.Fatal("blocked server work was credited from client cancellation")
	}
	if v.witness.bodyQueries.Load() != 0 {
		t.Fatal("blocked cancellation read original body")
	}
	if puts, resolves := v.store.counts(); puts != 0 || resolves != 0 {
		t.Fatal("blocked cancellation reached synthetic storage")
	}
	fittedOutputPGMustE2E(t, "release observed document barrier", blocker.Rollback(v.f.ctx))
	cleanupErr := v.writer.ReconcileCleanupV1(v.f.ctx)
	if cleanupErr != nil {
		v.diagnoseObserver(t, cleanupErr)
	}
	fittedOutputPGMustE2E(t, "join actual retired work after blocker release", cleanupErr)
	v.assertPhysical(t)
	if v.sqlGuard.SnapshotV1(v.f.orgID).Global.SQLSessions != 1 {
		t.Fatal("actual retired journal work did not release exactly its SQL grant")
	}
	if v.output(t).UploadAttemptedAt.Valid {
		t.Fatal("canceled locked phase committed an original attempt")
	}
	// The saved pool and a physically fresh writer remain usable after cleanup.
	receipt, err := v.writer.UploadOriginalV1(v.f.ctx, v.request)
	fittedOutputPGMustE2E(t, "fresh physical retry after proven canceled pre-attempt", err)
	if !receipt.Verified() {
		t.Fatal("fresh retry did not finish exact output")
	}
	v.assertPhysical(t)
}

func TestFittedOutputJournalUnknownAttemptEmptyObservationNeverReuploadsE2E(t *testing.T) {
	v := newFittedOutputPGFixtureE2E(t, 30*time.Second)
	v.reserve(t)
	_, err := v.f.q.MarkFittedFinalizationRetentionStarted(v.f.ctx, generated.MarkFittedFinalizationRetentionStartedParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID})
	fittedOutputPGMustE2E(t, "persist parent start before ambiguous original", err)
	_, err = v.f.q.MarkFittedFinalizationOutputRetentionStarted(v.f.ctx, generated.MarkFittedFinalizationOutputRetentionStartedParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID, Kind: "final_pdf"})
	fittedOutputPGMustE2E(t, "persist output start", err)
	_, err = v.f.q.MarkFittedFinalizationOutputOriginalUploadAttempt(v.f.ctx, generated.MarkFittedFinalizationOutputOriginalUploadAttemptParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID, Kind: "final_pdf"})
	fittedOutputPGMustE2E(t, "persist original unresolved attempt", err)
	before := fittedOutputPGJSONE2E(t, v.output(t))
	observed, err := v.writer.ResolveReadOnlyV1(v.f.ctx, v.request, "")
	fittedOutputPGMustE2E(t, "observe synthetic empty provider inventory", err)
	if observed.Observation() != storage.FittedFinalizationEmptyUnresolvedV1 || observed.Verified() || observed.ProviderAttempted() || !bytes.Equal(before, fittedOutputPGJSONE2E(t, v.output(t))) {
		t.Fatal("empty observation became replacement or cleanup permission")
	}
	receipt, err := v.writer.UploadOriginalV1(v.f.ctx, v.request)
	if !errors.Is(err, ErrFittedOutputAttemptExistsV1) || receipt.ProviderAttempted() || v.witness.bodyQueries.Load() != 0 {
		t.Fatal("old unknown attempt allowed original-body replay")
	}
	if puts, resolves := v.store.counts(); puts != 0 || resolves != 1 {
		t.Fatal("empty observation dispatched synthetic PUT")
	}
	v.assertPhysical(t)
}

func TestFittedOutputJournalObservedVersionRequiresExactCheckpointE2E(t *testing.T) {
	v := newFittedOutputPGFixtureE2E(t, 30*time.Second)
	v.reserve(t)
	_, err := v.f.q.MarkFittedFinalizationRetentionStarted(v.f.ctx, generated.MarkFittedFinalizationRetentionStartedParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID})
	fittedOutputPGMustE2E(t, "start parent for unresolved original", err)
	_, err = v.f.q.MarkFittedFinalizationOutputRetentionStarted(v.f.ctx, generated.MarkFittedFinalizationOutputRetentionStartedParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID, Kind: "final_pdf"})
	fittedOutputPGMustE2E(t, "start unresolved output", err)
	_, err = v.f.q.MarkFittedFinalizationOutputOriginalUploadAttempt(v.f.ctx, generated.MarkFittedFinalizationOutputOriginalUploadAttemptParams{PreparationID: v.op.ID, OrgID: v.f.orgID, DocumentID: v.f.docID, OwnerID: v.request.OwnerID, Kind: "final_pdf"})
	fittedOutputPGMustE2E(t, "persist unresolved original marker", err)
	v.store.object = storage.StoredObject{VersionID: " observed original+/opaque=version ", SHA256: v.request.Reservation.SHA256}
	v.store.body = bytes.Clone(v.body)
	v.store.resolveErr = errors.New("unverified synthetic listing failure")
	before := fittedOutputPGJSONE2E(t, v.output(t))
	unverified, err := v.writer.ResolveReadOnlyV1(v.f.ctx, v.request, "")
	if err == nil || unverified.Object().VersionID == "" || unverified.Verified() || !bytes.Equal(before, fittedOutputPGJSONE2E(t, v.output(t))) {
		t.Fatal("unverified listing became durable original authority")
	}
	_, err = v.writer.CheckpointExactV1(v.f.ctx, v.request, unverified)
	if err == nil || v.output(t).VersionID.Valid {
		t.Fatal("unverified positive listing permanently chose original version")
	}
	v.store.resolveErr = nil
	observed, err := v.writer.ResolveReadOnlyV1(v.f.ctx, v.request, "")
	fittedOutputPGMustE2E(t, "read-only exact-history observation", err)
	if !observed.Verified() || v.output(t).VersionID.Valid {
		t.Fatal("read-only exact observation wrote a version")
	}
	receipt, err := v.writer.CheckpointExactV1(v.f.ctx, v.request, observed)
	fittedOutputPGMustE2E(t, "checkpoint independently reverified original", err)
	row := v.output(t)
	if !receipt.Verified() || !row.VersionID.Valid || row.VersionID.String != observed.Object().VersionID || !row.ReadbackVerifiedAt.Valid || !row.RetentionCompletedAt.Valid {
		t.Fatal("exact current-owner checkpoint did not preserve original")
	}
	if puts, resolves := v.store.counts(); puts != 0 || resolves != 5 || v.witness.bodyQueries.Load() != 0 {
		t.Fatal("recovery dispatched original-body/PUT or skipped fresh exact proof")
	}
	v.assertPhysical(t)
}
