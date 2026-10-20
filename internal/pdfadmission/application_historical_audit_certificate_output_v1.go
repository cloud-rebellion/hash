// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// This opaque independently funded output contains only actual native private
// row/claims/manifest formatting. Neither caller HTML/rows/digest/version nor
// an arbitrary signer callback can issue its original source provenance.
type ApplicationHistoricalAuditCertificateV1 struct {
	activityMutex      sync.Mutex
	activity           applicationJoinedActivityV1
	self               *ApplicationHistoricalAuditCertificateV1
	closeRequested     atomic.Bool
	grant              *workguard.GrantV1
	html               *ApplicationHistoricalFinalizationHTMLV1
	payload, signature string
	factory            *ApplicationSessionFactoryV1
	coordinator        *workguard.CoordinatorV1
	ctx                context.Context
	org, document      uuid.UUID
	retainUntil        time.Time
	local              *render.HTMLLocalPDFV1
	putError           *storage.EvidenceLocalPutV1
	keys               [3]string
	sums               [3][sha256.Size]byte
	versions           [3]string
	stored             bool
	metadataBorrowers  int
	report             participantReportCommitmentV1
	finalPDFSHA        [sha256.Size]byte
}

// Activity is admitted before waiting and remains owned through every actual
// callback/consumer completion. Closed admission never discards a prior finish.
func (c *ApplicationHistoricalAuditCertificateV1) lockV1() bool {
	if !c.activity.enterV1() {
		return false
	}
	c.activityMutex.Lock()
	return true
}
func (c *ApplicationHistoricalAuditCertificateV1) finishActivityV1() {
	if c.activity.leaveV1() {
		c.retireClosedV1()
	}
}
func (c *ApplicationHistoricalAuditCertificateV1) unlockV1() {
	c.activityMutex.Unlock()
	c.finishActivityV1()
}
func (c *ApplicationHistoricalAuditCertificateV1) clearClosedV1() []func() {
	if !c.closeRequested.Load() || c.metadataBorrowers != 0 {
		return nil
	}
	var closes []func()
	c.payload = ""
	c.signature = ""
	c.factory = nil
	c.coordinator = nil
	c.ctx = nil
	c.keys = [3]string{}
	c.versions = [3]string{}
	if c.html != nil {
		h := c.html
		c.html = nil
		closes = append(closes, h.CloseConsumerV1)
	}
	if c.local != nil {
		local := c.local
		c.local = nil
		closes = append(closes, local.CloseConsumerV1)
	}
	if c.putError != nil {
		put := c.putError
		c.putError = nil
		closes = append(closes, put.CloseConsumerV1)
	}
	if c.grant != nil {
		g := c.grant
		c.grant = nil
		closes = append(closes, g.Close)
	}
	return closes
}
func (c *ApplicationHistoricalAuditCertificateV1) retireClosedV1() {
	historicalFinalPDFClosesV1(c.clearClosedV1())
}
func (c *ApplicationHistoricalAuditCertificateV1) CloseConsumerV1() {
	if c == nil || c.self != c {
		return
	}
	c.closeRequested.Store(true)
	if c.activity.closeV1() {
		c.retireClosedV1()
	}
}

// Original signer-availability guard remains in the adapter before these
// recipient/signature reads; completion/prefix gates precede fields exactly.
func (w *ApplicationHTMLSendWorkV1) NewHistoricalAuditCertificateV1(call context.Context, source *ApplicationHistoricalFinalizationSourceEvidenceV1, snapshot *ApplicationHistoricalCertificateSnapshotV1, manifest *ApplicationHistoricalTerminalManifestV1, css *ApplicationHistoricalFinalizationCSSV1, private ed25519.PrivateKey, orgName, baseURL string) (result *ApplicationHistoricalAuditCertificateV1, failure error) {
	if w == nil || w.self != w || source == nil || snapshot == nil || snapshot.self != snapshot || css == nil || len(private) != ed25519.PrivateKeySize {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !snapshot.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer snapshot.unlockV1()
	if snapshot.closeRequested.Load() || snapshot.grant == nil || !snapshot.claimed {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !source.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer source.unlockV1()
	if !source.validV1() || !source.sourceChecked || source.document == nil || source.work.stage.operation.factory != snapshot.factory || source.document.ID != snapshot.document || source.document.OrgID != snapshot.org || source.document.UpdatedAt != snapshot.updated {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	valid := source.document.ParticipantReportSchema == snapshot.reportSchema && participantReportSchemaKnownV1(snapshot.reportSchema) && w.valid(call) && w.stage != nil && w.stage.purpose == HTMLHistoricalFinalizationSourceV1 && w.stage.operation == source.work.stage.operation && w.sourceDocument == source.document && w.sourceDocument.ID == snapshot.document && w.sourceDocument.OrgID == snapshot.org
	w.mu.Unlock()
	if !valid {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if _, err := w.ReadRecipientsV1(call); err != nil {
		return nil, err
	}
	if _, err := w.ReadHistoricalFinalizationSignaturesV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	doc := w.sourceDocument
	recs := w.sourceRecipients
	sigs := w.finalization.signatures
	w.mu.Unlock()
	// Prefix map/escaped recipients and private signature references are funded
	// before the original prefix formatter. Rows retain their own native loans.
	resource := 8*int64(len(snapshot.reportHTML)) + int64(65536) + 8*int64(unsafe.Sizeof(ApplicationHistoricalAuditCertificateV1{})) + 8*int64(unsafe.Sizeof(render.AuditCertificateKeyV1{})) + 4096
	if !htmlInputAddV1(&resource, int64(len(doc.Name)), 48) || !htmlInputAddV1(&resource, int64(len(recs)+len(sigs)), 4096) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	for _, r := range recs {
		if r == nil {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		for _, text := range []string{r.Role, r.Name, r.Email, r.Status} {
			if !htmlInputAddV1(&resource, int64(len(text)), 48) {
				return nil, ErrHistoricalFinalizationSourceV1
			}
		}
	}
	for _, s := range sigs {
		if s == nil {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		if !htmlInputAddV1(&resource, int64(len(s.Font)), 48) || !htmlInputAddV1(&resource, int64(len(s.ImageSha256)), 16) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	if snapshot.reportSchema == render.ParticipantReportSchemaV2 {
		if !participantReportParserQuoteV2(&resource, len(snapshot.reportHTML), snapshot.reportRows) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	output, err := w.newHistoricalHTMLV1(call, resource)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			output.CloseConsumerV1()
		}
	}()
	prefix, err := render.CertificatePrefixV1(doc, recs, sigs, snapshot.claims)
	if err != nil {
		return nil, err
	}
	if _, err = w.ReadFieldsV1(call); err != nil {
		return nil, fmt.Errorf("audit certificate: load filled fields: %w", err)
	}
	w.mu.Lock()
	fields := w.sourceFields
	w.mu.Unlock()
	extra := int64(65536)
	for _, field := range fields {
		if field == nil {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		if !htmlInputAddV1(&extra, 1, 4096) || !htmlInputAddV1(&extra, int64(len(field.Label.String)+len(field.Type)+len(field.Value.String)), 48) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	}
	// The closed report shape is RawMessage items + concrete sanitize.Report
	// strings/categories; at most one item report is decoded at a time. This
	// conservative bound covers typed slice/string/header scratch plus original
	// escaped fixed-row/unknown-row output, without a new accepted-wire cap.
	if (snapshot.reportSchema == render.ParticipantReportSchemaV1 && !htmlInputAddV1(&extra, int64(len(doc.MetadataRedactionReport)), 8192)) || !htmlInputAddV1(&extra, int64(len(orgName)+len(baseURL)), 96) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	var manifestHTML *string
	var finishManifest func()
	if doc.IsEnvelope {
		if manifest == nil {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		section, finish, err := manifest.borrowForCertificateV1(source)
		if err != nil {
			return nil, err
		}
		finishManifest = finish
		defer finishManifest()
		manifestHTML = &section
		if !htmlInputAddV1(&extra, int64(len(section)), 8) {
			return nil, ErrHistoricalFinalizationSourceV1
		}
	} else if manifest != nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	brand, finishCSS, err := css.BorrowCSSV1()
	if err != nil {
		return nil, err
	}
	defer finishCSS()
	if css.org != snapshot.org || css.document != snapshot.document {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !htmlInputAddV1(&extra, int64(len(brand)), 8) || !htmlInputAddV1(&extra, render.FinalDocumentHTMLFixedBytesV1(), 8) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if err = output.grant.TryGrowParentV1(w.stage.operation.original, extra); err != nil {
		return nil, err
	}
	key := render.NewAuditCertificateKeyV1(private)
	var cert, payload, signature string
	switch snapshot.reportSchema {
	case render.ParticipantReportSchemaV1:
		cert, payload, signature, err = render.CertificateFinishV1(prefix, doc, fields, snapshot.claims, manifestHTML, key, orgName, baseURL)
	case render.ParticipantReportSchemaV2:
		cert, payload, signature, err = render.CertificateFinishV2(prefix, doc, fields, snapshot.claims, manifestHTML, key, orgName, baseURL)
	default:
		return nil, ErrHistoricalFinalizationSourceV1
	}
	key = nil
	if err != nil {
		return nil, err
	}
	if payload == "" || signature == "" {
		return nil, errors.New("audit certificate: detached evidence is incomplete")
	}
	output.html = render.BuildHTMLDocumentV1(brand, "", cert)
	p := w.stage.operation.factory.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	control := int64(65536) + 8*int64(unsafe.Sizeof(ApplicationHistoricalAuditCertificateV1{}))
	grant, err := coordinator.TryAcquireV1(w.stage.operation.original, doc.OrgID, workguard.VectorV1{ParentBytes: control})
	if err != nil {
		return nil, err
	}
	result = &ApplicationHistoricalAuditCertificateV1{grant: grant, html: output, payload: payload, signature: signature, factory: w.stage.operation.factory, coordinator: coordinator, ctx: w.stage.operation.original, org: doc.OrgID, document: doc.ID, retainUntil: doc.FinalizationRetainUntil.Time.UTC()}
	result.finalPDFSHA, err = participantReportFinalPDFSHAFromV1(snapshot.claims.FinalPDFSHA256)
	if err != nil {
		grant.Close()
		return nil, err
	}
	result.report, err = participantReportCommitmentFromV1(snapshot.reportSchema, snapshot.reportCutoff, snapshot.reportRows, snapshot.reportSHA256)
	if err != nil {
		grant.Close()
		return nil, err
	}
	result.self = result
	keep = true
	return result, nil
}
func (c *ApplicationHistoricalAuditCertificateV1) storeArtifactLockedV1(client *storage.Client, index int, key, contentType string, raw []byte) error {
	sum := sha256.Sum256(raw)
	put, err := client.PutEvidenceVersionedLocalOwnedV1(c.ctx, key, contentType, raw, c.retainUntil, c.coordinator, c.org)
	if err != nil {
		c.putError = put
		return err
	}
	if put == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	err = put.WithStoredV1(func(stored storage.StoredObject) error {
		if stored.SHA256 != sum || strings.TrimSpace(stored.VersionID) == "" {
			return errors.New("storage digest mismatch")
		}
		c.keys[index] = key
		c.sums[index] = sum
		c.versions[index] = strings.Clone(stored.VersionID)
		return nil
	})
	if err != nil {
		c.putError = put
	} else {
		put.CloseConsumerV1()
	}
	return err
}
func (c *ApplicationHistoricalAuditCertificateV1) RenderAndStoreV1(renderer *render.Gotenberg, client *storage.Client) error {
	if c == nil || c.self != c || renderer == nil || client == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !c.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer c.unlockV1()
	if c.closeRequested.Load() || c.grant == nil || c.html == nil || c.stored || c.local != nil || c.putError != nil {
		return ErrHistoricalFinalizationSourceV1
	}
	local, err := c.html.RenderPDFV1(renderer, render.PDFOptions{})
	c.local = local
	if err != nil {
		return fmt.Errorf("gotenberg render cert: %w", err)
	}
	if local == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	dir := path.Join("org", c.org.String(), "documents", c.document.String())
	err = local.WithPDFV1(func(raw []byte) error {
		sum := sha256.Sum256(raw)
		key := path.Join(dir, "audit-"+hex.EncodeToString(sum[:])+".pdf")
		return c.storeArtifactLockedV1(client, 0, key, "application/pdf", raw)
	})
	if err != nil {
		return fmt.Errorf("store cert pdf: %w", err)
	}
	local.CloseConsumerV1()
	c.local = nil
	payload := []byte(c.payload)
	sum := sha256.Sum256(payload)
	key := path.Join(dir, "audit-payload-"+hex.EncodeToString(sum[:])+".txt")
	err = c.storeArtifactLockedV1(client, 1, key, "text/html; charset=utf-8", payload)
	clear(payload)
	payload = nil
	if err != nil {
		return fmt.Errorf("store cert payload: %w", err)
	}
	signature := []byte(c.signature)
	sum = sha256.Sum256(signature)
	key = path.Join(dir, "audit-signature-"+hex.EncodeToString(sum[:])+".txt")
	err = c.storeArtifactLockedV1(client, 2, key, "text/plain; charset=utf-8", signature)
	clear(signature)
	signature = nil
	if err != nil {
		return fmt.Errorf("store cert signature: %w", err)
	}
	c.payload = ""
	c.signature = ""
	c.html.CloseConsumerV1()
	c.html = nil
	c.stored = true
	return nil
}

// Only the actual Stage/intent callback may borrow stored metadata. Its
// borrower keeps fixed key/version control through copied Close, and ends
// before independent Resume work starts.
func (c *ApplicationHistoricalAuditCertificateV1) WithStoredV1(consume func([3]string, [3][sha256.Size]byte, [3]string) error) error {
	if c == nil || c.self != c || consume == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !c.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	if c.closeRequested.Load() || c.grant == nil || !c.stored {
		c.unlockV1()
		return ErrHistoricalFinalizationSourceV1
	}
	c.metadataBorrowers++
	keys, sums, versions := c.keys, c.sums, c.versions
	c.activityMutex.Unlock() // Retain this admitted metadata consumer through consume.
	defer func() { c.activityMutex.Lock(); c.metadataBorrowers--; c.unlockV1() }()
	return consume(keys, sums, versions)
}
