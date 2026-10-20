// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Real native renderer IO/result ownership only: these private source shells
// grant no SQL/preparation authority. The actual PostgreSQL recovery journey
// separately proves the preparation parent comes from the serialization owner
// and survives the metadata read operation's retirement.
func TestOrdinaryCertificateJoinedOutputSurvivesProviderChildCancellationV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 256 << 20, ProviderStreams: 1}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 65536})
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	bodyGrant, err := coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	defer bodyGrant.Close()
	p := &ApplicationHistoricalOrdinaryPreparationV1{grant: metadata, coordinator: coordinator, ctx: ctx}
	p.self = p
	p.header.OrgID = org
	body := &ApplicationHistoricalOrdinaryBodyV1{grant: bodyGrant, preparation: p, kind: ordinaryRenderHTMLV1, raw: []byte("<html>Exact frozen certificate</html>")}
	body.self = body
	defer body.CloseConsumerV1()
	defer p.CloseConsumerV1()
	pdf := []byte("%PDF-native ordinary certificate protocol peer\n")
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		_, _ = w.Write(pdf)
	}))
	defer peer.Close()
	rendered, err := body.RenderCertificateV1(render.NewGotenberg(peer.URL))
	if rendered != nil {
		defer rendered.CloseConsumerV1()
	}
	if err != nil || rendered == nil || rendered.local == nil {
		t.Fatal("actual native rendering failed", err)
	}
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.GlobalGrants != 3 {
		t.Fatal("returned renderer did not join provider IO while retaining output", got)
	}
	// RenderCertificateV1 has already cancelled its finite per-call child. An
	// independently owned joined PDF must still be usable and remain paid while
	// its actual consumer closes the wrapper and original source owners.
	err = rendered.local.WithPDFV1(func(actual []byte) error {
		if !bytes.Equal(actual, pdf) {
			t.Fatal("joined PDF changed after per-call cancellation")
		}
		rendered.CloseConsumerV1()
		body.CloseConsumerV1()
		p.CloseConsumerV1()
		if got := coordinator.SnapshotV1(org); got.Global.ParentBytes <= 0 || got.Global.ProviderStreams != 0 || got.GlobalGrants != 1 {
			t.Fatal("active PDF consumer lost its independent output grant", got)
		}
		if !bytes.Equal(actual, pdf) {
			t.Fatal("wrapper close erased an active PDF")
		}
		return nil
	})
	if err != nil {
		t.Fatal("joined result rejected after child cancellation", err)
	}
	if got := coordinator.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("actual joined result/source consumers did not drain", got)
	}
}

func TestOrdinaryPreparationSQLDiagnosticPreservesPrivateCauseV1(t *testing.T) {
	pg := &pgconn.PgError{Code: "23514", TableName: "document_ordinary_finalization_preparations_v1", ConstraintName: "bounded_constraint", Message: "private contract contents must remain hidden"}
	wrapped := applicationSessionErrorV1(context.Background(), nil, pg)
	if strings.Contains(wrapped.Error(), pg.Message) {
		t.Fatal("native session exposed database content")
	}
	err := ordinaryPreparationFailureV1("capture final PDF header", wrapped)
	if !strings.Contains(err.Error(), "capture final PDF header") || !strings.Contains(err.Error(), "SQLSTATE 23514") || !strings.Contains(err.Error(), pg.ConstraintName) || strings.Contains(err.Error(), pg.Message) {
		t.Fatal("bounded database diagnostic lost phase/state or exposed content", err)
	}
	var actual *pgconn.PgError
	if !errors.As(err, &actual) || actual != pg || !errors.Is(err, ErrApplicationSessionV1) {
		t.Fatal("diagnostic changed the original refusal authority")
	}
}

// The exported seam must not turn caller-created rows, a matching digest or a
// copied metadata handle into native SQL/provider/claims authority.
func TestOrdinaryPreparationRefusesUnissuedAndCopiedOwnersV1(t *testing.T) {
	ctx := context.Background()
	work := &ApplicationHTMLSendWorkV1{}
	if _, err := work.ReadHistoricalOrdinaryPreparationV1(ctx, &ApplicationHistoricalFinalizationStageReferenceV1{}); err == nil {
		t.Fatal("unissued Work acquired preparation")
	}
	if err := work.CaptureHistoricalOrdinaryFinalPDFV1(ctx, &ApplicationHistoricalFinalizationStageReferenceV1{}, &ApplicationHistoricalFinalizationPDFV1{}); err == nil {
		t.Fatal("caller final body adopted")
	}
	if err := work.FreezeHistoricalOrdinaryCertificateV1(ctx, &ApplicationHistoricalFinalizationStageReferenceV1{}, &ApplicationHistoricalAuditCertificateV1{}); err == nil {
		t.Fatal("caller certificate adopted")
	}
	p := &ApplicationHistoricalOrdinaryPreparationV1{}
	p.self = p
	p.header.CertificateInputFrozen = true
	copied := ApplicationHistoricalOrdinaryPreparationV1{self: p, header: p.header}
	if copied.HasCertificateInputV1() || copied.HasCertificatePDFV1() {
		t.Fatal("copied preparation became original")
	}
	if _, err := work.ReadHistoricalOrdinaryBodyV1(ctx, &ApplicationHistoricalFinalizationStageReferenceV1{}, &copied, "final_pdf"); err == nil {
		t.Fatal("copied preparation read bytes")
	}
	body := &ApplicationHistoricalOrdinaryBodyV1{preparation: p, kind: "final_pdf", raw: []byte("caller bytes")}
	body.self = body
	copiedBody := ApplicationHistoricalOrdinaryBodyV1{self: body, preparation: p, kind: body.kind, raw: body.raw}
	if _, err := copiedBody.StoreV1(&storage.Client{}); !errors.Is(err, ErrOrdinaryFinalizationPreparationV1) {
		t.Fatal("copied body reached provider", err)
	}
	if _, err := copiedBody.RenderCertificateV1(&render.Gotenberg{}); !errors.Is(err, ErrOrdinaryFinalizationPreparationV1) {
		t.Fatal("copied body reached renderer", err)
	}
	rendered := &ApplicationHistoricalOrdinaryRenderedV1{}
	rendered.self = rendered
	copyRendered := ApplicationHistoricalOrdinaryRenderedV1{self: rendered}
	if err := work.CaptureHistoricalOrdinaryCertificatePDFV1(ctx, &ApplicationHistoricalFinalizationStageReferenceV1{}, &copyRendered); err == nil {
		t.Fatal("copied render result adopted")
	}
	snapshot := &ApplicationHistoricalCertificateSnapshotV1{}
	if err := snapshot.PrepareOrdinaryClaimsV1(&ApplicationHistoricalFinalizationSourceEvidenceV1{}, &copied); err == nil {
		t.Fatal("caller preparation issued certificate claims")
	}
	copied.CloseConsumerV1()
	copiedBody.CloseConsumerV1()
	copyRendered.CloseConsumerV1()
}
