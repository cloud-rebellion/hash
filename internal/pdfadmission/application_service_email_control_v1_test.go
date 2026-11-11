// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"image"
	"image/png"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Exercise the existing bounded qualification profile. Production never creates
// a new coordinator or changes its configured limits for these operations.
func serviceEmailControlProfile760(t *testing.T) (*WorkAdmissionV1, *workguard.CoordinatorV1) {
	t.Helper()
	global := workguard.VectorV1{ParentBytes: 128 << 20, DBStagingBytes: 64 << 20}
	org := workguard.VectorV1{ParentBytes: 64 << 20, DBStagingBytes: 32 << 20}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: global, Organisation: org, MaxGrants: 64, MaxOrganisationGrants: 32})
	if err != nil {
		t.Fatal(err)
	}
	admission, err := NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	return admission, coordinator
}

// A valid PNG at both native limits, including a real bounded ancillary text
// chunk. This reaches 32768 compressed bytes without an oversized raster or
// unsupported codec, and is validated by the actual imageguard decoder below.
func serviceEmailMaxDesign760(t *testing.T) string {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewGray(image.Rect(0, 0, 512, 512))); err != nil {
		t.Fatal(err)
	}
	original := b.Bytes()
	padding := dispatch.ServiceEmailDesignLogoBytesV1 - len(original) - 12
	if padding < 8 {
		t.Fatal("PNG fixture exceeds logo limit")
	}
	chunk := make([]byte, padding+12)
	binary.BigEndian.PutUint32(chunk[:4], uint32(padding))
	copy(chunk[4:8], "tEXt")
	copy(chunk[8:], "Comment\x00"+strings.Repeat("a", padding-8))
	binary.BigEndian.PutUint32(chunk[len(chunk)-4:], crc32.ChecksumIEEE(chunk[4:len(chunk)-4]))
	raster := append([]byte{}, original[:len(original)-12]...)
	raster = append(raster, chunk...)
	raster = append(raster, original[len(original)-12:]...)
	if len(raster) != dispatch.ServiceEmailDesignLogoBytesV1 {
		t.Fatal("logo byte limit not reached")
	}
	sum := sha256.Sum256(raster)
	design := dispatch.DefaultServiceEmailDesignV1()
	design.Logo = &htmlmaster.Asset{Name: "logo", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(raster), SHA256: hex.EncodeToString(sum[:])}
	design.LogoAlt = strings.Repeat("a", 200)
	prefix, suffix := `<div>{{logo}}</div><div>{{native_content}}</div><p>`, `</p>`
	design.LayoutHTML = prefix + strings.Repeat("a", dispatch.ServiceEmailDesignLayoutBytesV1-len(prefix)-len(suffix)) + suffix
	raw, err := json.Marshal(design)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := dispatch.CanonicalServiceEmailDesignV1(string(raw))
	if err != nil {
		t.Fatal("maximum valid layout/logo rejected", err)
	}
	return canonical
}

func serviceEmailControlRows760(org uuid.UUID, kind, design string) (*generated.GetServiceEmailTemplateHeaderV1Row, *generated.GetServiceEmailTemplateV1Row) {
	stamp := pgtype.Timestamptz{Time: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Valid: true}
	row := &generated.GetServiceEmailTemplateV1Row{OrgID: org, Kind: kind, Revision: 1, SubjectTemplate: "{{document_name}}", HtmlTemplate: "<p>Hello {{recipient_name}}</p>", TextTemplate: "Hello {{recipient_name}}", DesignJson: design, DesignSha256: dispatch.ServiceEmailDesignDigestV1(design), UpdatedAt: stamp}
	header := &generated.GetServiceEmailTemplateHeaderV1Row{OrgID: org, Kind: kind, Revision: 1, SubjectBytes: int64(len(row.SubjectTemplate)), HtmlBytes: int64(len(row.HtmlTemplate)), TextBytes: int64(len(row.TextTemplate)), DesignBytes: int64(len(design)), DesignSha256: row.DesignSha256, UpdatedAt: stamp}
	return header, row
}

func TestServiceEmailDesign760MultiKindCatalogRetiresActualParserWork(t *testing.T) {
	admission, coordinator := serviceEmailControlProfile760(t)
	org := uuid.New()
	call, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx, owner, err := admission.NewServiceEmailControlV1(call, org)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.CloseConsumerV1()
	design := serviceEmailMaxDesign760(t)
	catalog := []dispatch.ServiceEmailTemplateV1{}
	for _, kind := range dispatch.ServiceEmailKindsV1() {
		if !dispatch.ServiceEmailTemplateEditableKindV1(kind) {
			catalog = append(catalog, dispatch.ServiceEmailTemplateV1{})
			continue
		}
		header, row := serviceEmailControlRows760(org, kind, design)
		if err := owner.AdmitSourceV1(ctx, header); err != nil {
			t.Fatal("catalog source denied", kind, err)
		}
		retained := coordinator.SnapshotV1(org)
		tpl := dispatch.ServiceEmailTemplateV1{Revision: row.Revision, SubjectTemplate: row.SubjectTemplate, HTMLTemplate: row.HtmlTemplate, TextTemplate: row.TextTemplate, DesignJSON: row.DesignJson}
		closeWork, err := owner.BeginTemplateWorkV1(ctx, tpl)
		if err != nil {
			t.Fatal("catalog parser denied", kind, err)
		}
		if coordinator.SnapshotV1(org).Global.ParentBytes < retained.Global.ParentBytes+dispatch.ServiceEmailDesignFixedWorkBytesV1 {
			t.Fatal("real raster/parser has no grant")
		}
		selected, err := applicationServiceEmailFromRowsV1(header, row, org, kind)
		if err != nil {
			t.Fatal("actual locked source validation failed", err)
		}
		closeWork()
		closeWork()
		if got := coordinator.SnapshotV1(org); got != retained {
			t.Fatal("one catalog edition retained synchronous parser work", kind, got, retained)
		}
		catalog = append(catalog, *selected)
	}
	if len(catalog) != 9 || owner.reads != 8 {
		t.Fatal("real nine-kind/eight-editable catalog changed")
	}
	// Serialize the entire retained catalog before closing its source owner.
	beforeJSON := coordinator.SnapshotV1(org)
	wire, err := json.Marshal(catalog)
	if err != nil || !bytes.Contains(wire, []byte("data_base64")) || coordinator.SnapshotV1(org) != beforeJSON {
		t.Fatal("retained source/JSON ownership lost", err)
	}
	owner.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got != (workguard.SnapshotV1{}) {
		t.Fatal("catalog ownership survived actual serialization close", got)
	}
}

func TestServiceEmailDesign760MaxInputPreviewAndConsumerRetirement(t *testing.T) {
	admission, coordinator := serviceEmailControlProfile760(t)
	org := uuid.New()
	call, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx, owner, err := admission.NewServiceEmailControlV1(call, org)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.CloseConsumerV1()
	canonical := serviceEmailMaxDesign760(t)
	input := dispatch.ServiceEmailTemplateV1{SubjectTemplate: strings.Repeat("a", dispatch.ServiceEmailSubjectSourceBytesV1), HTMLTemplate: "<p>" + strings.Repeat("a", dispatch.ServiceEmailHTMLSourceBytesV1-7) + "</p>", TextTemplate: strings.Repeat("a", dispatch.ServiceEmailTextSourceBytesV1), DesignJSON: canonical + strings.Repeat(" ", dispatch.ServiceEmailDesignSourceBytesV1-len(canonical))}
	if err := owner.AdmitInputV1(ctx, input.SubjectTemplate, input.HTMLTemplate, input.TextTemplate, input.DesignJSON); err != nil {
		t.Fatal(err)
	}
	retained := coordinator.SnapshotV1(org)
	closeValidate, err := owner.BeginTemplateWorkV1(ctx, input)
	if err != nil {
		t.Fatal("maximum input cannot be validated", err)
	}
	checked, err := dispatch.ValidateServiceEmailTemplateV1(dispatch.KindInvite, input)
	if err != nil {
		t.Fatal(err)
	}
	closeValidate()
	if coordinator.SnapshotV1(org) != retained || checked.DesignJSON != canonical {
		t.Fatal("canonicalization retained work or lost exact canonical source")
	}
	if err := owner.AdmitSyntheticPreviewV1(ctx); err != nil {
		t.Fatal(err)
	}
	retained = coordinator.SnapshotV1(org)
	closeRender, err := owner.BeginTemplateWorkV1(ctx, checked)
	if err != nil {
		t.Fatal("maximum valid preview cannot render", err)
	}
	_, body, text, err := dispatch.RenderServiceEmailV1(dispatch.KindInvite, dispatch.TemplateContext{DocumentName: "Contract", RecipientName: "Signer", SenderName: "Sender", OrgName: "Workspace", SignURL: "https://example.invalid/sign/test"}, &checked)
	if err != nil || !strings.Contains(body, "data-hash-logo=") || !strings.Contains(text, "https://example.invalid/sign/test") {
		t.Fatal("actual maximum render failed", err)
	}
	closeRender()
	if coordinator.SnapshotV1(org) != retained {
		t.Fatal("render workspace survived its actual return")
	}
	// A consumer close during actual outstanding parser work keeps its source
	// charged, denies further work and releases both grants at the last close.
	closeActive, err := owner.BeginTemplateWorkV1(ctx, checked)
	if err != nil {
		t.Fatal(err)
	}
	active := coordinator.SnapshotV1(org)
	owner.CloseConsumerV1()
	if coordinator.SnapshotV1(org) != active {
		t.Fatal("consumer close retired active parser's source")
	}
	if close, err := owner.BeginTemplateWorkV1(ctx, checked); err == nil || close != nil {
		t.Fatal("closing consumer issued more work")
	}
	closeActive()
	if got := coordinator.SnapshotV1(org); got != (workguard.SnapshotV1{}) {
		t.Fatal("last actual work close leaked retained output/source", got)
	}
}

func TestServiceEmailDesign760NativeMIMEUsesActualOrgMessageAndRetires(t *testing.T) {
	admission, coordinator := serviceEmailControlProfile760(t)
	org := uuid.New()
	msg := dispatch.Message{OrgID: org, To: "recipient@example.invalid", Subject: "Saved template", HTML: `<p>Frozen body</p>`, Text: "Frozen body"}
	work, err := dispatch.ServiceEmailMIMEWorkingBytesV1(msg)
	if err != nil {
		t.Fatal(err)
	}
	call, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	close, err := admission.ServiceEmailMIMEV1(call, msg)
	if err != nil {
		t.Fatal(err)
	}
	if got := coordinator.SnapshotV1(org); got.Organisation.ParentBytes != work || got.GlobalGrants != 1 || got.OrganisationGrants != 1 {
		t.Fatal("MIME did not use same process/actual message organization", got)
	}
	close()
	close()
	if got := coordinator.SnapshotV1(org); got != (workguard.SnapshotV1{}) {
		t.Fatal("MIME grant survived actual close", got)
	}
	msg.OrgID = uuid.Nil
	if close, err := admission.ServiceEmailMIMEV1(context.Background(), msg); err == nil || close != nil {
		t.Fatal("unscoped message acquired MIME work")
	}
}
