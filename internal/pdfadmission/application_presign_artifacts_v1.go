// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

var ErrPreSignArtifactsV1 = errors.New("pdfadmission: owned pre-sign artifacts unavailable")

const preSignFragmentMaxV1 = 2 << 20

// Only the original native source can create this owner. It keeps the real
// source borrower, renderer/storage result handles and output loans through
// their actual consumers. It exposes descriptors, never bodies or a Grant.
type ApplicationPreSignArtifactsV1 struct {
	mu                                                              sync.Mutex
	activity                                                        applicationJoinedActivityV1
	closed                                                          atomic.Bool
	self                                                            *ApplicationPreSignArtifactsV1
	source                                                          *applicationHTMLSendSourceStateV1
	work                                                            *ApplicationHTMLSendWorkV1
	initial, reservationSession                                     *ApplicationSessionV1
	client                                                          *storage.Client
	renderer                                                        *render.Gotenberg
	coordinator                                                     *workguard.CoordinatorV1
	ctx                                                             context.Context
	org, document, preparation                                      uuid.UUID
	policy                                                          presign.Policy
	grant                                                           presign.Grant
	admission                                                       presignregistry.DataAdmission
	snapshot                                                        presign.DocumentSnapshot
	bindings                                                        sanitize.PDFProviderOverlayBindings
	overlay                                                         sanitize.PDFProviderOverlayManifest
	objects                                                         [8]storage.PresignTransientReservationV1
	stored                                                          [8]storage.StoredObject
	bodies                                                          [8][]byte
	grants                                                          []*workguard.GrantV1
	closes                                                          []func()
	releaseSource                                                   func()
	prepared, reserved, uploaded, prepareAttempted, uploadAttempted bool
}

func (w *ApplicationHTMLSendWorkV1) NewPreSignArtifactsV1(call context.Context, source *ApplicationHTMLSendSourceV1, client *storage.Client, renderer *render.Gotenberg, authority presignregistry.ExecutionAuthorityV1, admission presignregistry.DataAdmission, preparation uuid.UUID) (*ApplicationPreSignArtifactsV1, error) {
	if w == nil || w.self != w || source == nil || source.state == nil || client == nil || renderer == nil || preparation == uuid.Nil {
		return nil, ErrPreSignArtifactsV1
	}
	s := source.state
	if !s.lockV1() {
		return nil, ErrPreSignArtifactsV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || s.work != w || s.candidate || !s.currentAttempted || s.currentFailure != nil {
		return nil, ErrPreSignArtifactsV1
	}
	if err := s.owner.beginV1(); err != nil {
		return nil, err
	}
	defer s.owner.finishV1()
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && w.stage.operation != nil && w.sourceState == s && w.sourceDocument != nil && w.sourceRecipients != nil && w.sourceFields != nil
	stage := w.stage
	w.mu.Unlock()
	if !valid || presignregistry.ValidateDataAdmissionDocument(admission, s.owner.snapshot.document) != nil {
		return nil, ErrPreSignArtifactsV1
	}
	p, g := authority.Policy(), authority.Grant()
	// Both typed canonical constructors and the evaluated admission are checked
	// again. Public observation DTOs cannot manufacture these native source pins.
	checkedPolicy, err := presign.DecodePolicy(p.CanonicalJSON())
	if err != nil || checkedPolicy.Reference() != p.Reference() {
		return nil, ErrPreSignArtifactsV1
	}
	checkedGrant, err := presign.DecodeGrant(g.CanonicalJSON())
	if err != nil || checkedGrant.Reference() != g.Reference() || g.Snapshot().Policy != p.Reference() || p.Snapshot().OrgID != w.session.state.org ||
		g.Snapshot().Grantor.UserID != s.owner.snapshot.document.SenderID ||
		admission.Snapshot().PolicyID != p.Snapshot().ID || admission.Snapshot().WorkflowID != p.Snapshot().Workflow.ID ||
		admission.Snapshot().DefinitionSHA256 != p.Snapshot().Workflow.ContentSHA256 {
		return nil, ErrPreSignArtifactsV1
	}
	factory := stage.operation.factory.state
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, ErrPreSignArtifactsV1
	}
	// The complete app-controlled recipe/font/span bound is prepaid before
	// creating any recipe HTML or asset clones. Provider response/backing and
	// isolated PDF work acquire their separate actual bounded producer loans.
	fixed := int64(8<<20) + 8*int64(unsafe.Sizeof(ApplicationPreSignArtifactsV1{}))
	initialGrant, err := coordinator.TryAcquireV1(stage.operation.original, w.session.state.org, workguard.VectorV1{ParentBytes: fixed})
	if err != nil {
		return nil, err
	}
	if err = s.owner.beginV1(); err != nil {
		initialGrant.Close()
		return nil, err
	}
	var once sync.Once
	a := &ApplicationPreSignArtifactsV1{source: s, work: w, initial: w.session, client: client, renderer: renderer, coordinator: coordinator, ctx: stage.operation.original,
		org: w.session.state.org, document: w.logicalDocumentV1(), preparation: preparation, policy: p, grant: g, admission: admission, grants: []*workguard.GrantV1{initialGrant}, releaseSource: func() { once.Do(s.owner.finishV1) }}
	a.self = a
	w.mu.Lock()
	if !w.valid(call) || w.presignArtifacts != nil {
		w.mu.Unlock()
		a.CloseConsumerV1()
		return nil, ErrPreSignArtifactsV1
	}
	// This owner holds a source borrower. Close it before retiring source
	// resources, rather than placing its close behind that same borrower.
	w.presignArtifacts = a
	w.mu.Unlock()
	return a, nil
}

func (a *ApplicationPreSignArtifactsV1) lockV1() bool {
	if a == nil || a.self != a || !a.activity.enterV1() {
		return false
	}
	a.mu.Lock()
	return true
}
func (a *ApplicationPreSignArtifactsV1) unlockV1() {
	a.mu.Unlock()
	if a.activity.leaveV1() {
		a.retireV1()
	}
}
func (a *ApplicationPreSignArtifactsV1) retireV1() {
	for _, close := range a.closes {
		close()
	}
	a.closes = nil
	for i := range a.bodies {
		clear(a.bodies[i])
		a.bodies[i] = nil
	}
	for _, grant := range a.grants {
		grant.Close()
	}
	a.grants = nil
	if a.releaseSource != nil {
		a.releaseSource()
		a.releaseSource = nil
	}
	a.source = nil
	a.work = nil
	a.initial = nil
	a.reservationSession = nil
	a.client = nil
	a.renderer = nil
	a.coordinator = nil
}
func (a *ApplicationPreSignArtifactsV1) CloseConsumerV1() {
	if a == nil || a.self != a {
		return
	}
	a.closed.Store(true)
	if a.activity.closeV1() {
		a.retireV1()
	}
}
func preSignKnownCommitV1(h *ApplicationSessionV1) bool {
	if h == nil || h.state == nil || !h.RetiredV1() || h.CommitUnknownV1() {
		return false
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitAttempted && s.ended && !s.commitUnknown
}
func (a *ApplicationPreSignArtifactsV1) holdV1(n int64) error {
	if n < 1 || a.ctx == nil || a.ctx.Err() != nil || a.coordinator == nil {
		return ErrPreSignArtifactsV1
	}
	g, err := a.coordinator.TryAcquireV1(a.ctx, a.org, workguard.VectorV1{ParentBytes: n})
	if err != nil {
		return err
	}
	a.grants = append(a.grants, g)
	return nil
}

func (a *ApplicationPreSignArtifactsV1) PrepareV1() error {
	if !a.lockV1() {
		return ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || a.prepareAttempted || !preSignKnownCommitV1(a.initial) || a.ctx.Err() != nil {
		return ErrPreSignArtifactsV1
	}
	a.prepareAttempted = true
	d := a.source.owner.snapshot.document
	pagePolicy, _, err := a.source.owner.validation.SigningPageV1()
	if err != nil || pagePolicy == nil {
		return ErrPreSignArtifactsV1
	}
	copy := presignregistry.Disclosure()
	g := a.grant.Snapshot()
	if g.Disclosure.Version != copy.Version || g.Disclosure.SHA256 != copy.SHA256 {
		return ErrPreSignArtifactsV1
	}
	in := render.ProviderOverlayInput{Name: g.Grantor.Name, Font: g.Signature.Font, FontSHA256: g.Signature.FontSHA256, InterSHA256: pagePolicy.FontSHA256,
		TextColor: pagePolicy.Branding.SignatureColor, DisclosureColor: pagePolicy.Branding.MutedHex, DisclosureText: copy.Text, DisclosureVersion: copy.Version, DisclosureSHA256: copy.SHA256}
	recipe, err := render.ProviderOverlayRecipeForPolicy(render.ProviderOverlayRecipeV3, in)
	if err != nil {
		return err
	}
	a.bodies[0] = recipe.SignatureSpan
	a.bodies[1] = recipe.SignatureFont.Bytes
	a.bodies[2] = recipe.InterFont.Bytes
	a.bodies[3] = recipe.RecipeJSON
	observe, size, err := a.client.ObservePresignSourceLocalOwnedV1(a.ctx, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256, a.coordinator, a.org)
	if observe != nil {
		a.closes = append(a.closes, observe.CloseConsumerV1)
	}
	if err != nil {
		return err
	}
	a.snapshot, err = presignexecute.DocumentSnapshotFromModelsV1(d, a.work.sourceRecipients, a.work.sourceFields, a.admission, size)
	if err != nil {
		return err
	}
	for i, fragment := range []struct {
		html          string
		asset         render.FontAsset
		width, height float64
	}{
		{recipe.SignatureHTML, recipe.SignatureFont, render.ProviderOverlaySignatureWidth, render.ProviderOverlaySignatureHeight},
		{recipe.DisclosureHTML, recipe.InterFont, render.ProviderOverlayDisclosureWidth, render.ProviderOverlayDisclosureHeight},
	} {
		opts, e := render.ProviderOverlayOptionsForPolicy(render.ProviderOverlayRecipeV3, fragment.asset)
		if e != nil {
			return e
		}
		opts.MaxResponseBytes = preSignFragmentMaxV1
		opts.ExactPaperPoints = [2]float64{fragment.width, fragment.height}
		h, e := a.renderer.HTMLToPDFLocalOwnedV1(a.ctx, fragment.html, opts, a.coordinator, a.org)
		if h != nil {
			a.closes = append(a.closes, h.CloseConsumerV1)
		}
		if e != nil {
			return e
		}
		if h == nil {
			return ErrPreSignArtifactsV1
		}
		err = h.WithPDFV1(func(raw []byte) error {
			if len(raw) < 1 || len(raw) > preSignFragmentMaxV1 {
				return ErrPreSignArtifactsV1
			}
			if err := a.holdV1(4 * int64(len(raw))); err != nil {
				return err
			}
			a.bodies[4+i] = bytes.Clone(raw)
			return nil
		})
		if err != nil {
			return err
		}
	}
	base, _, err := a.client.ReadPackagePDFLocalOwnedV1(a.ctx, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256, size, a.coordinator, a.org)
	if base != nil {
		a.closes = append(a.closes, base.CloseConsumerV1)
	}
	if err != nil {
		return err
	}
	if base == nil {
		return ErrPreSignArtifactsV1
	}
	a.bindings = sanitize.PDFProviderOverlayBindings{SourceCommitment: a.snapshot.Materialization.SourceCommitment, SigningPlanSHA256: a.snapshot.SigningPlanSHA256,
		BrandingSHA256: a.snapshot.BrandingSHA256, PolicySHA256: a.policy.Commitment(), GrantSHA256: a.grant.Commitment(), Font: g.Signature.Font,
		SpanSHA256: preSignBodySHAV1(a.bodies[0]), SignatureFontSHA256: preSignBodySHAV1(a.bodies[1]), InterFontSHA256: preSignBodySHAV1(a.bodies[2]), DisclosureSHA256: copy.SHA256, RecipeSHA256: recipe.RecipeSHA256}
	err = base.WithPDFV1(func(raw []byte) error {
		total := int64(len(raw) + len(a.bodies[4]) + len(a.bodies[5]))
		if total > presign.MaxPDFBytes {
			return ErrPreSignArtifactsV1
		}
		// Worker input framing/copies and its bounded returned output are held
		// until all archive PUTs and immutable descriptor consumers finish.
		if err := a.holdV1(4*total + presign.MaxPDFBytes + 65536); err != nil {
			return err
		}
		// cmd/pdfworker/restrict_linux.go fixes RLIMIT_AS at exactly 2 GiB.
		// Own that concrete child address space and one worker position through
		// the original synchronous bounded runner's actual Wait return.
		worker, err := a.coordinator.TryAcquireV1(a.ctx, a.org, workguard.VectorV1{ChildAddressBytes: 2 << 30, PDFWorkers: 1})
		if err != nil {
			return err
		}
		defer worker.Close()
		result, err := sanitize.ApplyProviderOverlayWithContext(a.ctx, "presign-provider-visible", raw, a.bodies[4], a.bodies[5], a.bindings)
		if err != nil {
			return err
		}
		if sanitize.ValidatePDFProviderOverlayResult(result) != nil {
			return ErrPreSignArtifactsV1
		}
		if result.Overlay.BaseSHA256 != hex.EncodeToString(d.PdfSha256) || result.Overlay.BaseBytes != size || result.Overlay.Pages != a.snapshot.BasePDF.Pages {
			return ErrPreSignArtifactsV1
		}
		a.overlay = result.Overlay
		a.bodies[7] = result.Bytes
		a.bodies[6], err = json.Marshal(result.Overlay)
		return err
	})
	if err != nil {
		return err
	}
	for i, role := range [8]string{"signature_span", "signature_font", "inter_font", "overlay_recipe", "signature_fragment", "disclosure_fragment", "overlay_proof", "visible_pdf"} {
		a.objects[i] = storage.PresignTransientReservationV1{OrgID: a.org, DocumentID: a.document, PreparationID: a.preparation, Role: role, SHA256: sha256.Sum256(a.bodies[i]), Bytes: int64(len(a.bodies[i]))}
	}
	a.prepared = true
	return nil
}

func preSignBodySHAV1(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

func (a *ApplicationPreSignArtifactsV1) ReservationsV1() ([8]storage.PresignTransientReservationV1, error) {
	if !a.lockV1() {
		return [8]storage.PresignTransientReservationV1{}, ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.prepared {
		return [8]storage.PresignTransientReservationV1{}, ErrPreSignArtifactsV1
	}
	return a.objects, nil
}

func (a *ApplicationPreSignArtifactsV1) PreparedDocumentV1() (presign.DocumentSnapshot, error) {
	if !a.lockV1() {
		return presign.DocumentSnapshot{}, ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.prepared {
		return presign.DocumentSnapshot{}, ErrPreSignArtifactsV1
	}
	return a.snapshot, nil
}

// VerifyReservationsV1 reads the actual persisted rows under the SAME later
// native session/operation. Upload additionally requires this session's known
// successful COMMIT and actual retirement, so a dispatched error grants no PUT.
func (a *ApplicationPreSignArtifactsV1) VerifyReservationsV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if !a.lockV1() {
		return ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.prepared || a.reserved || w == nil || w.self != w {
		return ErrPreSignArtifactsV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && a.work.stage != nil && w.stage.operation == a.work.stage.operation && w.logicalDocumentV1() == a.document && w.session.state.org == a.org
	session := w.session
	w.mu.Unlock()
	if !valid {
		return ErrPreSignArtifactsV1
	}
	db := &applicationOwnedDBTXV1{session: session.state}
	for _, r := range a.objects {
		var exact bool
		err := db.QueryRow(call, `SELECT p.state='preparing' AND p.expires_at>clock_timestamp() AND o.upload_attempted AND o.version_id IS NULL
		 AND o.cleanup_started_at IS NULL AND o.object_key=$4 AND o.content_type=$5 AND o.object_sha256=$6 AND o.object_bytes=$7
		 FROM presign_preparations_v1 p JOIN presign_preparation_objects_v1 o ON o.org_id=p.org_id AND o.preparation_id=p.id
		 WHERE p.org_id=$1 AND p.id=$2 AND p.document_id=$8 AND o.role=$3`, a.org, a.preparation, r.Role, r.KeyV1(), r.ContentTypeV1(), r.SHA256[:], r.Bytes, a.document).Scan(&exact)
		if err != nil || !exact {
			return ErrPreSignArtifactsV1
		}
	}
	a.reservationSession = session
	a.reserved = true
	return nil
}

func (a *ApplicationPreSignArtifactsV1) UploadV1() error {
	if !a.lockV1() {
		return ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.prepared || !a.reserved || a.uploadAttempted || !preSignKnownCommitV1(a.reservationSession) || a.ctx.Err() != nil {
		return ErrPreSignArtifactsV1
	}
	a.uploadAttempted = true
	for i, r := range a.objects {
		h, err := a.client.PutPresignTransientLocalOwnedV1(a.ctx, r, a.bodies[i], a.coordinator, a.org)
		if h != nil {
			a.closes = append(a.closes, h.CloseConsumerV1)
		}
		if err != nil {
			return err
		}
		if h == nil {
			return ErrPreSignArtifactsV1
		}
		err = h.WithStoredV1(func(stored storage.StoredObject) error {
			if stored.SHA256 != r.SHA256 || stored.VersionID == "" {
				return ErrPreSignArtifactsV1
			}
			a.stored[i] = stored
			return nil
		})
		if err != nil {
			return err
		}
	}
	a.uploaded = true
	return nil
}

func (a *ApplicationPreSignArtifactsV1) StoredAssetsV1() ([8]presignexecute.AssetV1, error) {
	if !a.lockV1() {
		return [8]presignexecute.AssetV1{}, ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.uploaded {
		return [8]presignexecute.AssetV1{}, ErrPreSignArtifactsV1
	}
	return presignexecute.AssetsFromStoredV1(a.objects, a.stored)
}

// This constructor binds real prepared versions to the fresh exact source and
// actual epoch/use/clock. Authorization and the entire atomic record/audit are
// the caller's separately checked final transaction; this grants neither.
func (a *ApplicationPreSignArtifactsV1) NewExecutionV1(document presign.DocumentSnapshot, epoch, executed time.Time, use int64) (presign.Execution, presignexecute.AssetSetV1, error) {
	if !a.lockV1() {
		return presign.Execution{}, presignexecute.AssetSetV1{}, ErrPreSignArtifactsV1
	}
	defer a.unlockV1()
	if a.closed.Load() || !a.uploaded || document != a.snapshot {
		return presign.Execution{}, presignexecute.AssetSetV1{}, ErrPreSignArtifactsV1
	}
	objects, err := presignexecute.AssetsFromStoredV1(a.objects, a.stored)
	if err != nil {
		return presign.Execution{}, presignexecute.AssetSetV1{}, err
	}
	e, err := presign.NewExecution(presign.ExecutionSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: a.org, Policy: a.policy.Reference(), Grant: a.grant.Reference(), Executor: a.policy.Snapshot().Executor,
		Document: document, CeremonyEpoch: epoch, ExecutedAt: executed, UseNumber: use, Signature: presign.SignatureArtifact{ID: uuid.New(), RecipientID: document.Parties[1].ID, FieldID: document.Fields[1].ID,
			TypedName: a.grant.Snapshot().Grantor.Name, Style: a.grant.Snapshot().Signature, Image: objects[0].Object}, VisiblePDF: presign.PDFPin{Artifact: objects[7].Object, Pages: a.overlay.Pages}, VisibleStampProofSHA256: objects[6].Object.SHA256})
	if err != nil {
		return presign.Execution{}, presignexecute.AssetSetV1{}, err
	}
	assets, err := presignexecute.NewAssetSetV1(e, presignexecute.AssetSetSnapshotV1{SchemaVersion: 1, OrgID: a.org, DocumentID: a.document, ExecutionID: e.Snapshot().ID, ExecutionSHA256: e.Commitment(), Objects: objects, Bindings: a.bindings, Overlay: a.overlay})
	return e, assets, err
}
