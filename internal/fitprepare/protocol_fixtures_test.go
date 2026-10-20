// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitprepare

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// These fixtures reuse current-generated PDF/font/measurement bytes with explicit
// synthetic metadata rebinding. They test durable protocol behavior ONLY; no
// genuine fitting, isolated worker, SQL commit or S3 acceptance is inferred.
type reportFixtureV1 struct {
	Schema           int               `json:"schema"`
	Policy           string            `json:"policy"`
	Plan             signaturefit.Plan `json:"plan"`
	InputSHA256      string            `json:"inputSha256"`
	RecipeSHA256     string            `json:"recipeSha256"`
	HTMLSHA256       string            `json:"htmlSha256"`
	FontFile         string            `json:"fontFile"`
	FontSHA256       string            `json:"fontSha256"`
	PDFSHA256        string            `json:"pdfSha256"`
	PDFBytes         int               `json:"pdfBytes"`
	FragmentPage     int               `json:"fragmentPage"`
	SnapshotSHA256   string            `json:"snapshotSha256"`
	ChromiumProduct  string            `json:"chromiumProduct"`
	ChromiumRevision string            `json:"chromiumRevision"`
	ChromiumProtocol string            `json:"chromiumProtocol"`
	Measurement      json.RawMessage   `json:"measurement"`
}

type journalFixtureV1 struct {
	operation    *generated.SignatureFitPreparation
	objects      map[ObjectIDV1]*generated.SignatureFitObject
	events       []string
	failAfter    string
	failBefore   string
	privateError error
}

func clonePreparationTestV1(p *generated.SignatureFitPreparation) *generated.SignatureFitPreparation {
	if p == nil {
		return nil
	}
	v := *p
	v.AuthoritySha256 = bytes.Clone(p.AuthoritySha256)
	v.SourceSha256 = bytes.Clone(p.SourceSha256)
	v.GeometrySha256 = bytes.Clone(p.GeometrySha256)
	v.SpanSha256 = bytes.Clone(p.SpanSha256)
	return &v
}
func cloneObjectTestV1(o *generated.SignatureFitObject) *generated.SignatureFitObject {
	if o == nil {
		return nil
	}
	v := *o
	v.Sha256 = bytes.Clone(o.Sha256)
	return &v
}
func (j *journalFixtureV1) before(name string) error {
	j.events = append(j.events, name)
	if j.failBefore == name {
		j.failBefore = ""
		return j.privateError
	}
	return nil
}
func (j *journalFixtureV1) after(name string) error {
	if j.failAfter == name {
		j.failAfter = ""
		return j.privateError
	}
	return nil
}
func (j *journalFixtureV1) Get(ctx context.Context, arg generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error) {
	if err := j.before("get"); err != nil {
		return nil, err
	}
	if j.operation == nil || j.operation.ID != arg.ID || j.operation.OrgID != arg.OrgID {
		return nil, pgx.ErrNoRows
	}
	return clonePreparationTestV1(j.operation), nil
}
func (j *journalFixtureV1) Reserve(ctx context.Context, arg generated.ReserveSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error) {
	if err := j.before("reserve"); err != nil {
		return nil, err
	}
	if j.operation != nil {
		return nil, errors.New("duplicate")
	}
	j.operation = &generated.SignatureFitPreparation{ID: arg.ID, OrgID: arg.OrgID, DocumentID: arg.DocumentID, RecipientID: arg.RecipientID, CeremonyEpoch: arg.CeremonyEpoch, AuthoritySha256: bytes.Clone(arg.AuthoritySha256), SourceStorageKey: arg.SourceStorageKey, SourceVersionID: arg.SourceVersionID, SourceSha256: bytes.Clone(arg.SourceSha256), SourceBytes: arg.SourceBytes, GeometrySha256: bytes.Clone(arg.GeometrySha256), SpanSha256: bytes.Clone(arg.SpanSha256), ReservedBytes: arg.ReservedBytes, ExpectedObjects: arg.ExpectedObjects, OwnerID: arg.OwnerID, LeaseUntil: arg.LeaseUntil, Attempts: 1, Status: "staging"}
	return clonePreparationTestV1(j.operation), j.after("reserve")
}
func (j *journalFixtureV1) Claim(ctx context.Context, arg generated.ClaimSignatureFitPreparationLeaseParams) (*generated.SignatureFitPreparation, error) {
	if err := j.before("claim"); err != nil {
		return nil, err
	}
	if j.operation.LeaseUntil.Time.After(time.Now()) || j.operation.Attempts >= 8 {
		return nil, pgx.ErrNoRows
	}
	j.operation.OwnerID = arg.OwnerID
	j.operation.LeaseUntil = arg.LeaseUntil
	j.operation.Attempts++
	return clonePreparationTestV1(j.operation), j.after("claim")
}
func (j *journalFixtureV1) Objects(ctx context.Context, arg generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error) {
	if err := j.before("objects"); err != nil {
		return nil, err
	}
	var out []*generated.SignatureFitObject
	for _, o := range j.objects {
		out = append(out, cloneObjectTestV1(o))
	}
	return out, nil
}
func checkpointNameV1(prefix, kind string, page int32) string {
	return prefix + ":" + kind + ":" + strconv.Itoa(int(page))
}
func (j *journalFixtureV1) ReserveObject(ctx context.Context, arg generated.ReserveSignatureFitObjectParams) (*generated.SignatureFitObject, error) {
	name := checkpointNameV1("object", arg.Kind, arg.Page)
	if err := j.before(name); err != nil {
		return nil, err
	}
	id := ObjectIDV1{arg.Kind, arg.Page}
	if j.objects[id] != nil {
		return nil, pgx.ErrNoRows
	}
	o := &generated.SignatureFitObject{PreparationID: arg.PreparationID, Kind: arg.Kind, Page: arg.Page, StorageKey: arg.StorageKey, Sha256: bytes.Clone(arg.Sha256), Bytes: arg.Bytes, ContentType: arg.ContentType}
	j.objects[id] = o
	return cloneObjectTestV1(o), j.after(name)
}
func (j *journalFixtureV1) Attempt(ctx context.Context, arg generated.MarkSignatureFitUploadAttemptedParams) (*generated.SignatureFitObject, error) {
	name := checkpointNameV1("attempt", arg.Kind, arg.Page)
	if err := j.before(name); err != nil {
		return nil, err
	}
	o := j.objects[ObjectIDV1{arg.Kind, arg.Page}]
	if o.UploadAttemptedAt.Valid || j.operation.OwnerID != arg.OwnerID || !j.operation.LeaseUntil.Time.After(time.Now()) {
		return nil, pgx.ErrNoRows
	}
	o.UploadAttemptedAt = timestampV1(time.Now())
	o.UploadOwnerID = pgtype.UUID{Bytes: [16]byte(arg.OwnerID), Valid: true}
	return cloneObjectTestV1(o), j.after(name)
}
func (j *journalFixtureV1) Pin(ctx context.Context, arg generated.PinSignatureFitObjectVersionParams) (*generated.SignatureFitObject, error) {
	name := checkpointNameV1("pin", arg.Kind, arg.Page)
	if err := j.before(name); err != nil {
		return nil, err
	}
	o := j.objects[ObjectIDV1{arg.Kind, arg.Page}]
	if !o.UploadAttemptedAt.Valid || o.VersionID.Valid && o.VersionID.String != arg.VersionID {
		return nil, pgx.ErrNoRows
	}
	o.VersionID = pgtype.Text{String: arg.VersionID, Valid: true}
	return cloneObjectTestV1(o), j.after(name)
}
func (j *journalFixtureV1) Verified(ctx context.Context, arg generated.MarkSignatureFitObjectReadbackVerifiedParams) (*generated.SignatureFitObject, error) {
	name := checkpointNameV1("verified", arg.Kind, arg.Page)
	if err := j.before(name); err != nil {
		return nil, err
	}
	o := j.objects[ObjectIDV1{arg.Kind, arg.Page}]
	if !o.VersionID.Valid || o.VersionID.String != arg.VersionID || !bytes.Equal(o.Sha256, arg.Sha256) || o.Bytes != arg.Bytes {
		return nil, pgx.ErrNoRows
	}
	if !o.ReadbackVerifiedAt.Valid {
		o.ReadbackVerifiedAt = timestampV1(time.Now())
	}
	return cloneObjectTestV1(o), j.after(name)
}
func (j *journalFixtureV1) Prepared(ctx context.Context, arg generated.MarkSignatureFitPreparationPreparedParams) (*generated.SignatureFitPreparation, error) {
	if err := j.before("prepared"); err != nil {
		return nil, err
	}
	if len(j.objects) != int(j.operation.ExpectedObjects) {
		return nil, errors.New("objects missing")
	}
	var total int64
	for _, o := range j.objects {
		if !o.VersionID.Valid || !o.ReadbackVerifiedAt.Valid {
			return nil, errors.New("readback missing")
		}
		total += o.Bytes
	}
	if total > j.operation.ReservedBytes {
		return nil, errors.New("reservation ceiling exceeded")
	}
	j.operation.Status = "prepared"
	return clonePreparationTestV1(j.operation), j.after("prepared")
}

type blobFixtureV1 struct {
	version string
	raw     []byte
}
type objectsFixtureV1 struct {
	journal          *journalFixtureV1
	source           manualfit.SourceTupleV1
	sourceRaw        []byte
	blobs            map[string]blobFixtureV1
	puts             map[string]int
	events           []string
	failPutKind      string
	commitUnknownPut bool
	readHook         func(string, []byte) ([]byte, error)
}

func (o *objectsFixtureV1) GetVerifiedVersionBounded(ctx context.Context, key, version string, sha []byte, max int64) ([]byte, error) {
	o.events = append(o.events, "read:"+key)
	if o.journal.operation == nil {
		return nil, errors.New("provider I/O preceded durable operation")
	}
	var raw []byte
	if key == o.source.Key {
		if version != o.source.VersionID {
			return nil, errors.New("wrong source version")
		}
		raw = o.sourceRaw
	} else {
		b, ok := o.blobs[key]
		if !ok || b.version != version {
			return nil, errors.New("wrong exact version")
		}
		raw = b.raw
	}
	if int64(len(raw)) != max || digestV1(raw) != hex.EncodeToString(sha) {
		return nil, errors.New("wrong bounded commitment")
	}
	out := bytes.Clone(raw)
	if o.readHook != nil {
		return o.readHook(key, out)
	}
	return out, nil
}
func (o *objectsFixtureV1) ResolveFitTransientVersion(ctx context.Context, r storage.FitTransientReservation) (storage.StoredObject, bool, error) {
	o.events = append(o.events, "resolve:"+r.Key)
	b, ok := o.blobs[r.Key]
	if !ok {
		return storage.StoredObject{}, false, nil
	}
	if int64(len(b.raw)) != r.Bytes || sha256.Sum256(b.raw) != r.SHA256 {
		return storage.StoredObject{}, false, errors.New("shadow mismatch")
	}
	return storage.StoredObject{VersionID: b.version, SHA256: r.SHA256}, true, nil
}
func (o *objectsFixtureV1) PutFitTransientReserved(ctx context.Context, r storage.FitTransientReservation, raw []byte) (storage.StoredObject, error) {
	o.events = append(o.events, "put:"+r.Key)
	var found *generated.SignatureFitObject
	for _, row := range o.journal.objects {
		if row.StorageKey == r.Key {
			found = row
		}
	}
	if found == nil || !found.UploadAttemptedAt.Valid || !found.UploadOwnerID.Valid || found.UploadOwnerID.Bytes != [16]byte(o.journal.operation.OwnerID) || found.VersionID.Valid {
		return storage.StoredObject{}, errors.New("PUT without original committed attempt")
	}
	o.puts[r.Key]++
	if o.puts[r.Key] != 1 {
		return storage.StoredObject{}, errors.New("second SDK PUT")
	}
	if r.SHA256 != sha256.Sum256(raw) || r.Bytes != int64(len(raw)) {
		return storage.StoredObject{}, errors.New("wrong reserved payload")
	}
	version := " exact+/version " + strconv.Itoa(len(o.blobs)+1)
	shouldFail := found.Kind == o.failPutKind
	if !shouldFail || o.commitUnknownPut {
		o.blobs[r.Key] = blobFixtureV1{version, bytes.Clone(raw)}
	}
	if shouldFail {
		o.failPutKind = ""
		return storage.StoredObject{}, errors.New("PRIVATE_OBJECT_ERROR")
	}
	return storage.StoredObject{VersionID: version, SHA256: r.SHA256}, nil
}

type rendererFixtureV1 struct {
	packages map[int]*signaturefit.Package
	journal  *journalFixtureV1
	calls    []int
}

func (r *rendererFixtureV1) PrepareManualSignaturePageV1(ctx context.Context, plan signaturefit.Plan) (*signaturefit.Package, error) {
	if r.journal.operation == nil {
		return nil, errors.New("renderer preceded reservation")
	}
	r.calls = append(r.calls, plan.Page)
	pkg := r.packages[plan.Page]
	if pkg == nil {
		return nil, errors.New("missing synthetic page")
	}
	return signaturefit.Decode(pkg.Bytes(), plan)
}

type inspectorFixtureV1 struct {
	geometry  sanitize.PDFManualGeometry
	fragments int
	fail      bool
}

func (i *inspectorFixtureV1) Source(ctx context.Context, raw []byte) (sanitize.PDFManualGeometry, error) {
	if i.fail {
		return sanitize.PDFManualGeometry{}, errors.New("PRIVATE_WORKER_ERROR")
	}
	return i.geometry, nil
}
func (i *inspectorFixtureV1) Fragment(ctx context.Context, pdf []byte, w, h float64) (sanitize.PDFManualFragmentAdmission, error) {
	i.fragments++
	return sanitize.PDFManualFragmentAdmission{SchemaVersion: 1, Policy: sanitize.PDFManualFragmentPolicy, PDFSHA256: digestV1(pdf), PDFBytes: int64(len(pdf)), WidthPoints: w, HeightPoints: h, ObservedWidthPoints: w, ObservedHeightPoints: h, GeometrySHA256: strings.Repeat("c", 64), ContentSHA256: strings.Repeat("d", 64), ResourcesSHA256: strings.Repeat("e", 64), GroupSHA256: strings.Repeat("f", 64)}, nil
}

type preparationFixtureV1 struct {
	preparer  *PreparerV1
	request   RequestV1
	journal   *journalFixtureV1
	objects   *objectsFixtureV1
	renderer  *rendererFixtureV1
	inspector *inspectorFixtureV1
	budget    BudgetV1
}

func protocolFixtureV1(t *testing.T, file string, pageCount int) *preparationFixtureV1 {
	t.Helper()
	raw, err := os.ReadFile("../signaturefit/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var parts [5][]byte
	offset := 60
	for i := range parts {
		n := int(binary.BigEndian.Uint32(raw[8+i*4:]))
		parts[i] = bytes.Clone(raw[offset : offset+n])
		offset += n
	}
	var original reportFixtureV1
	if json.Unmarshal(parts[0], &original) != nil {
		t.Fatal("report")
	}
	sourceRaw := bytes.Repeat([]byte("s"), 100)
	source := manualfit.SourceTupleV1{Key: "opaque/source.pdf", VersionID: " original+/version= ", SHA256: digestV1(sourceRaw), Bytes: int64(len(sourceRaw))}
	spanString, err := render.RenderSignatureSpan(original.Plan.Text, original.Plan.Font)
	if err != nil {
		t.Fatal(err)
	}
	span := []byte(spanString)
	org, doc, rec := uuid.New(), uuid.New(), uuid.New()
	page := sanitize.PDFManualPage{UserUnit: 1}
	for j := range page.Boxes {
		page.Boxes[j] = [4]float64{0, 0, 1000, 600}
	}
	geometry := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes}
	in := manualfit.AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: time.Date(2026, 10, 11, 12, 0, 0, 123456000, time.UTC), Source: source, TypedName: original.Plan.Text, Font: original.Plan.Font, SpanSHA256: digestV1(span)}
	for j := 0; j < pageCount; j++ {
		geometry.Pages = append(geometry.Pages, page)
		for k := 0; k < 2; k++ {
			id := uuid.UUID{14: byte(j), 15: byte(k + 1)}
			in.ExpectedTargetIDs = append(in.ExpectedTargetIDs, id)
			y, w, h := "5.0000", "90.0000", "35.0000"
			if k == 1 {
				y, w, h = "50.0000", "80.0000", "45.0000"
			}
			in.Targets = append(in.Targets, manualfit.TargetV1{ID: id, OrgID: org, DocumentID: doc, RecipientID: rec, Page: j + 1, Required: true, X: "5.0000", Y: y, W: w, H: h})
		}
	}
	geometryJSON, _ := json.Marshal(geometry.Pages)
	geometry.GeometrySHA256 = digestV1(geometryJSON)
	authority, err := manualfit.BuildAuthorityV1(in, geometry)
	if err != nil {
		t.Fatal(err)
	}
	packages := make(map[int]*signaturefit.Package, pageCount)
	for _, plan := range authority.Pages() {
		report := original
		report.Plan = plan.Plan
		report.InputSHA256 = plan.InputSHA256
		html := bytes.ReplaceAll(parts[2], []byte(original.InputSHA256), []byte(plan.InputSHA256))
		report.HTMLSHA256 = digestV1(html)
		report.Measurement = bytes.ReplaceAll(original.Measurement, []byte(original.InputSHA256), []byte(plan.InputSHA256))
		for k, old := range original.Plan.Targets {
			report.Measurement = bytes.ReplaceAll(report.Measurement, []byte(old.ID), []byte(plan.Plan.Targets[k].ID))
		}
		reportRaw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		newParts := parts
		newParts[0], newParts[2] = reportRaw, html
		framed := make([]byte, 60)
		copy(framed, []byte("HSHFIT01"))
		for k, part := range newParts {
			binary.BigEndian.PutUint32(framed[8+k*4:], uint32(len(part)))
			framed = append(framed, part...)
		}
		sum := sha256.Sum256(reportRaw)
		copy(framed[28:60], sum[:])
		pkg, err := signaturefit.Decode(framed, plan.Plan)
		if err != nil {
			t.Fatalf("synthetic rebound package: %v", err)
		}
		packages[plan.Plan.Page] = pkg
	}
	journal := &journalFixtureV1{objects: make(map[ObjectIDV1]*generated.SignatureFitObject), privateError: errors.New("PRIVATE_JOURNAL_ERROR")}
	store := &objectsFixtureV1{journal: journal, source: source, sourceRaw: sourceRaw, blobs: make(map[string]blobFixtureV1), puts: make(map[string]int)}
	renderer := &rendererFixtureV1{packages: packages, journal: journal}
	inspector := &inspectorFixtureV1{geometry: geometry}
	f := &preparationFixtureV1{journal: journal, objects: store, renderer: renderer, inspector: inspector, budget: BudgetV1{FitBytes: 8 << 20, EvidenceOtherBytes: 1 << 20, ProcessingOtherBytes: 1 << 20}}
	f.preparer = &PreparerV1{Journal: journal, Objects: store, Renderer: renderer, Inspector: inspector}
	f.request = RequestV1{OperationID: uuid.New(), OwnerID: uuid.New(), Authority: authority, Span: span, LeaseUntil: time.Now().Add(time.Hour).Truncate(time.Microsecond)}
	f.request.Admission = func(ctx context.Context, a *manualfit.AuthorityV1) (BudgetV1, error) {
		if a.SHA256() != authority.SHA256() {
			return BudgetV1{}, ErrIdentityV1
		}
		return f.budget, nil
	}
	return f
}
