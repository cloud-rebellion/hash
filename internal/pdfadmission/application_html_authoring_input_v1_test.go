// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

func htmlInputFactoryTestV1(t *testing.T, parent int64) (*ApplicationSessionFactoryV1, *workguard.CoordinatorV1) {
	t.Helper()
	v := workguard.VectorV1{ParentBytes: parent}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWorkAdmissionV1(c)
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), w, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	return f, c
}

type htmlInputBlockedBodyV1 struct {
	started, finish chan struct{}
	once            sync.Once
}

func (b *htmlInputBlockedBodyV1) Read([]byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	<-b.finish
	return 0, io.EOF
}
func (b *htmlInputBlockedBodyV1) Close() error { return nil }
func TestHTMLInputActualBlockedReadCannotRefundOnCancelCloseOrFactoryShutdownV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 32<<20)
	org := uuid.New()
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1)
	if err != nil {
		t.Fatal(err)
	}
	copy := *h
	b := &htmlInputBlockedBodyV1{started: make(chan struct{}), finish: make(chan struct{})}
	var unblockOnce sync.Once
	unblock := func() { unblockOnce.Do(func() { close(b.finish) }) }
	done := make(chan struct{})
	var readErr error
	go func() { _, readErr = h.ReadBodyV1(ctx, b); close(done) }()
	// Failure paths must unblock and actually join the original reader before
	// finishing this source fixture. No timeout or fake fence credits its grant.
	t.Cleanup(func() {
		cancel()
		unblock()
		select {
		case <-done:
			h.CloseConsumerV1()
		case <-time.After(2 * time.Second):
			t.Error("original blocked Read did not join; producer remains charged")
		}
	})
	select {
	case <-b.started:
	case <-ctx.Done():
		t.Fatal("body never entered")
	}
	cancel()
	copy.CloseConsumerV1()
	h.CloseConsumerV1()
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.CloseV1(cleanup); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatalf("shutdown invented read retirement: %v", err)
	}
	p := f.PendingV1()
	s := c.SnapshotV1(org)
	if p.HTMLInputProducers != 1 || p.WorkSessions != 0 || p.ObserverSessions != 0 || s.GlobalGrants != 1 || s.Global.ParentBytes <= 0 || s.Global.SQLSessions != 0 {
		t.Fatalf("blocked actual work was refunded or opened SQL: %+v %+v", p, s)
	}
	unblock()
	select {
	case <-done:
		if readErr == nil {
			t.Fatal("canceled raw read accepted")
		}
	case <-cleanup.Done():
		t.Fatal("actual read did not join")
	}
	h.CloseConsumerV1()
	copy.CloseConsumerV1()
	if p := f.PendingV1(); p.HTMLInputProducers != 0 {
		t.Fatalf("finished source owner remained: %+v", p)
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 0 || s.Global != (workguard.VectorV1{}) {
		t.Fatalf("joined actual producer remained charged: %+v", s)
	}
	if err := f.CloseV1(cleanup); err != nil {
		t.Fatal(err)
	}
}
func TestHTMLInputRawGrantBeforeReadAndParseGrantBeforeConsumerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	rawCost, err := htmlAuthoringInputReadResourcesV1(2 << 10)
	if err != nil {
		t.Fatal(err)
	}
	f, c := htmlInputFactoryTestV1(t, rawCost-1)
	if h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1); err == nil || h != nil {
		t.Fatal("raw reservation bypassed actual capacity")
	}
	if p := f.PendingV1(); p.HTMLInputProducers != 0 {
		t.Fatal("empty refused registry retained")
	}
	f, c = htmlInputFactoryTestV1(t, rawCost)
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(`{"confirmed":true}`)))
	if raw != nil || !errors.Is(err, ErrHTMLAuthoringInputV1) {
		t.Fatalf("uncharged parser received raw bytes: %q %v", raw, err)
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 1 {
		t.Fatal("raw owner not retained on parse refusal")
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("closed refused input leaked")
	}
}

type htmlInputFaultBodyV1 struct{ err error }

func (b htmlInputFaultBodyV1) Read([]byte) (int, error) { return 0, b.err }
func (b htmlInputFaultBodyV1) Close() error             { return nil }
func TestHTMLInputPreservesReadFailureAndOriginalProfileCeilingsV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, c := htmlInputFactoryTestV1(t, 1<<30)
	org := uuid.New()
	for _, want := range []error{io.ErrUnexpectedEOF, io.ErrClosedPipe} {
		h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = h.ReadBodyV1(ctx, htmlInputFaultBodyV1{want}); !errors.Is(err, want) {
			t.Fatalf("real read error changed: %v", err)
		}
		h.CloseConsumerV1()
	}
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(strings.Repeat(" ", 2049))))
	var limit *http.MaxBytesError
	if !errors.As(err, &limit) || limit.Limit != 2048 {
		t.Fatalf("closure did not keep its actual2KiB ceiling: %v", err)
	}
	h.CloseConsumerV1()
	for _, tc := range []struct {
		p HTMLAuthoringInputProfileV1
		n int64
	}{{HTMLTemplateMasterInputV1, 14 << 20}, {HTMLTemplateApprovalInputV1, 1 << 20}, {HTMLTemplatePreviewInputV1, 1 << 20}, {HTMLDocumentCreationInputV1, 1 << 20}, {HTMLCRMTemplateSearchInputV1, 16 << 10}, {HTMLCRMTemplateObservationInputV1, 256 << 10}, {HTMLCreationClosureInputV1, 2 << 10}} {
		got, err := htmlAuthoringInputLimitV1(tc.p)
		if err != nil || got != tc.n {
			t.Fatalf("profile ceiling changed: %+v %d %v", tc, got, err)
		}
	}
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("profile/error consumers leaked")
	}
}
func TestHTMLInputFiniteSchemaPreservesArbitraryNamesEscapesAndTypedShapesV1(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		p   HTMLAuthoringInputProfileV1
		raw string
	}{
		{HTMLTemplateMasterInputV1, `{"name":"contract","html_master_json":{"schema_version":1,"html":"<p>ok</p>","values":[{"name":"a","required":true,"max_chars":1}]},"variables_json":{"arbitrary😃":"a\n","quote\"":"<>&"}}`},
		{HTMLTemplateApprovalInputV1, `{"expected_version":1e0,"expected_content_sha256":"x","preview_receipt":null,"expected_preview_pdf_sha256":"x"}`},
		{HTMLTemplatePreviewInputV1, `{"expected_version":1,"expected_content_sha256":"x","values":{"A.b":1},"sections":null}`},
		{HTMLDocumentCreationInputV1, `{"name":"x","expected_template_version":1,"expected_template_content_sha256":"x","values":{},"crm_population":{"expected_org_id":"x","mappings":[{"variable":"a","source_kind":"crm_deal","source_ref":"x","source_path":"name"}],"confirmed":true}}`},
		{HTMLCRMTemplateSearchInputV1, `{"kind":"deal","query":"Å \uD83D\uDE00","offset":0,"expected_connection_id":"x"}`},
		{HTMLCRMTemplateObservationInputV1, `{"candidate":{"name":"x","values":{"weird.key":"ok"},"sections":{},"expires_at":""},"mappings":[]}`},
		{HTMLCreationClosureInputV1, `{"expected_org_id":"x","expected_user_id":"y","confirmed":false}`},
		{HTMLTemplateMasterInputV1, `{"\u006eame":"x","html_master_json":{"schema_version":1,"html":"<p>ok</p>"},"variables_json":{}}`},
	} {
		if _, err := htmlAuthoringInputShapeForV1(ctx, tc.p, []byte(tc.raw)); err != nil {
			t.Fatalf("preflight narrowed finite schema: %s: %v", tc.raw, err)
		}
	}
	var defaults strings.Builder
	defaults.WriteString(`{"variables_json":{`)
	for i := 0; i < 64; i++ {
		if i != 0 {
			defaults.WriteByte(',')
		}
		key, _ := json.Marshal(strings.Repeat("a", i+1))
		defaults.Write(key)
		defaults.WriteString(`:"x"`)
	}
	defaults.WriteString("}}")
	if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLTemplateMasterInputV1, []byte(defaults.String())); err != nil {
		t.Fatal("64 arbitrary declared names refused", err)
	}
	raw := []byte(`{"name":"x","html_master_json":{"schema_version":1,"html":"<p>text</p>","assets":[]}}`)
	if n := testing.AllocsPerRun(100, func() {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLTemplateMasterInputV1, raw); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("shape preflight allocated before its parser grant: %f", n)
	}
	for _, raw := range []string{`{"html_master_json":{"metadata":{"arbitrary":{}}}}`, `{"unknown":"x"}`, `{"html_master_json":{"values":[[]]}}`} {
		if _, err := htmlAuthoringInputShapeForV1(ctx, HTMLTemplateMasterInputV1, []byte(raw)); err == nil {
			t.Fatalf("untyped allocation path accepted: %s", raw)
		}
	}
}
func TestHTMLInputCanonicalPreservesExactLegacyCommitmentAndConsumerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 8<<30)
	// Repeated known attribute names are accepted/deduplicated by the unchanged
	// tokenizer. They must not become a new raw occurrence ceiling.
	source := `{"name":"Contract","html_master_json":{"schema_version":1,"html":"<p CLASS=\"first\" class=\"second\">Å &amp; \u003c</p>","css":"p { color: #112233; }"},"variables_json":{}}`
	var original struct {
		Master   json.RawMessage `json:"html_master_json"`
		Defaults json.RawMessage `json:"variables_json"`
	}
	if err := json.Unmarshal([]byte(source), &original); err != nil {
		t.Fatal(err)
	}
	expected, err := htmlmaster.CanonicalTemplate(original.Master, original.Defaults)
	if err != nil {
		t.Fatal(err)
	}
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(source))); err != nil {
		t.Fatal(err)
	}
	actual, err := h.CanonicalTemplateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) || !bytes.Equal(actual.DefaultsJSON, expected.DefaultsJSON) {
		t.Fatal("native producer changed agreed canonical/SHA bytes")
	}
	if s := c.SnapshotV1(org); s.GlobalGrants != 7 || s.Global.SQLSessions != 0 {
		t.Fatalf("canonical/raw/parser/inspection/outputparser consumers not retained or SQL opened: %+v", s)
	}
	copy := *h
	h.CloseConsumerV1()
	copy.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("actual completed canonical consumer did not retire")
	}
}
func TestHTMLInputHTMLFilterKeepsTokenizerCompatibilityV1(t *testing.T) {
	ctx := context.Background()
	for _, source := range []string{`<p class=x CLASS=y class=z>ok</p>`, `<p title="<not-a-tag>" class=ok>ok</p>`, `<p/class=x>ok</p ignored=whatever>`, `<p title='a> b' id=x>2 < 3</p>`} {
		if err := htmlInputHTMLNamesV1(ctx, source); err != nil {
			t.Fatalf("known-name compatibility lost: %s %v", source, err)
		}
	}
	for _, source := range []string{`<p onclick="bad">x</p>`, `<script>bad</script>`, `<p unknown=x>bad</p>`} {
		if err := htmlInputHTMLNamesV1(ctx, source); err == nil {
			t.Fatalf("unbounded unknown-name map path accepted: %s", source)
		}
	}
	raw := `<p class="x" title="x">ok</p>`
	if n := testing.AllocsPerRun(100, func() {
		if err := htmlInputHTMLNamesV1(ctx, raw); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("attribute preflight allocated before tokenizer allowance: %f", n)
	}
}

func TestHTMLInputRealPNGInspectionGrantCannotAuthorizeCanonicalExpansionV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	var pngBytes bytes.Buffer
	if err := png.Encode(&pngBytes, image.NewNRGBA64(image.Rect(0, 0, 2, 3))); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pngBytes.Bytes())
	master := htmlmaster.Master{SchemaVersion: 1, HTML: "<p>Approved asset</p>", Assets: []htmlmaster.Asset{{Name: "logo", MediaType: "image/png", DataBase64: base64.StdEncoding.EncodeToString(pngBytes.Bytes()), SHA256: hex.EncodeToString(digest[:])}}}
	masterJSON, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Name     string          `json:"name"`
		Master   json.RawMessage `json:"html_master_json"`
		Defaults json.RawMessage `json:"variables_json"`
	}{"Asset", masterJSON, json.RawMessage("{}")})
	if err != nil {
		t.Fatal(err)
	}
	shape, err := htmlAuthoringInputShapeForV1(ctx, HTMLTemplateMasterInputV1, raw)
	if err != nil {
		t.Fatal(err)
	}
	rawCost, err := htmlAuthoringInputReadResourcesV1(14 << 20)
	if err != nil {
		t.Fatal(err)
	}
	parseCost, err := htmlAuthoringInputParseResourcesV1(HTMLTemplateMasterInputV1, shape)
	if err != nil {
		t.Fatal(err)
	}
	inspectCost, err := htmlInputCanonicalInspectionResourcesV1(master)
	if err != nil {
		t.Fatal(err)
	}
	// Exact real capacity admits raw+strict parser+header inspection and leaves
	// no canonical/pixel grant. This is a synthetic test profile, not production.
	f, c := htmlInputFactoryTestV1(t, rawCost+parseCost+inspectCost)
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	if got, err := h.CanonicalTemplateV1(ctx); !errors.Is(err, ErrHTMLAuthoringInputV1) || got.SHA256 != "" {
		t.Fatalf("header allowance became expansion authority: %+v %v", got, err)
	}
	if got := c.SnapshotV1(org); got.GlobalGrants != 3 || got.Global.ParentBytes != rawCost+parseCost+inspectCost {
		t.Fatalf("failed canonical source ownership wrong: %+v", got)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("failed expansion retained finished source")
	}
	// Real fixture source is otherwise accepted by the unchanged canonicalizer.
	expected, err := htmlmaster.CanonicalTemplate(masterJSON, []byte("{}"))
	if err != nil {
		t.Fatal("PNG fixture is not accepted", err)
	}
	f, c = htmlInputFactoryTestV1(t, 8<<30)
	h, err = f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	actual, err := h.CanonicalTemplateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) {
		t.Fatal("actual raster source changed canonical evidence")
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("PNG result final consumer leaked")
	}
}

func TestHTMLInputExpandedCanonicalSectionsNeedActualOutputParserGrantV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	master := htmlmaster.Master{SchemaVersion: 1}
	var markup strings.Builder
	for i := 0; i < 4; i++ {
		name := "s" + string(rune('a'+i))
		master.Sections = append(master.Sections, htmlmaster.Section{Name: name, DefaultText: strings.Repeat("&", 256), MaxChars: 256})
		markup.WriteString("<p data-hash-section=" + name + "></p>")
	}
	master.HTML = markup.String()
	// Keep legal authored literal '&' in the actual request. json.Marshal would
	// pre-escape it and accidentally erase the output-expansion regression.
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(master); err != nil {
		t.Fatal(err)
	}
	masterRaw := bytes.TrimSpace(encoded.Bytes())
	raw := append([]byte(`{"name":"Escaped sections","html_master_json":`), masterRaw...)
	raw = append(raw, []byte(`,"variables_json":{}}`)...)
	shape, err := htmlAuthoringInputShapeForV1(ctx, HTMLTemplateMasterInputV1, raw)
	if err != nil {
		t.Fatal(err)
	}
	rawCost, err := htmlAuthoringInputReadResourcesV1(14 << 20)
	if err != nil {
		t.Fatal(err)
	}
	parseCost, err := htmlAuthoringInputParseResourcesV1(HTMLTemplateMasterInputV1, shape)
	if err != nil {
		t.Fatal(err)
	}
	inspectCost, err := htmlInputCanonicalInspectionResourcesV1(master)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	canonicalCost, err := htmlInputCanonicalResourcesV1(masterRaw, []byte("{}"), master, stats)
	if err != nil {
		t.Fatal(err)
	}
	admitted := rawCost + parseCost + inspectCost + canonicalCost
	f, c := htmlInputFactoryTestV1(t, admitted)
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	if result, err := h.CanonicalTemplateV1(ctx); !errors.Is(err, ErrHTMLAuthoringInputV1) || result.SHA256 != "" {
		t.Fatalf("canonical result escaped without actual output parser credit: %+v %v", result, err)
	}
	if got := c.SnapshotV1(org); got.GlobalGrants != 4 || got.Global.ParentBytes != admitted {
		t.Fatalf("canonical producer credit was misclassified: %+v", got)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("postoutput refusal did not release completed consumers")
	}
	expected, err := htmlmaster.CanonicalTemplate(masterRaw, []byte("{}"))
	if err != nil {
		t.Fatal("accepted escaped-section fixture invalid", err)
	}
	if len(expected.MasterJSON) <= 2*len(masterRaw) {
		t.Fatal("fixture did not actually expand canonical escaped defaults")
	}
	f, c = htmlInputFactoryTestV1(t, 8<<30)
	h, err = f.NewHTMLAuthoringInputV1(ctx, org, HTMLTemplateMasterInputV1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.ReadBodyV1(ctx, io.NopCloser(bytes.NewReader(raw))); err != nil {
		t.Fatal(err)
	}
	actual, err := h.CanonicalTemplateV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if actual.SHA256 != expected.SHA256 || !bytes.Equal(actual.MasterJSON, expected.MasterJSON) {
		t.Fatal("escaped section canonical/provenance changed")
	}
	if c.SnapshotV1(org).GlobalGrants != 7 {
		t.Fatal("actual expanded-output parser consumer not retained")
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 {
		t.Fatal("escaped sections final consumer leaked")
	}
}

func TestHTMLInputFactoryShutdownCannotRetireReturnedRawConsumerV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	org := uuid.New()
	f, c := htmlInputFactoryTestV1(t, 32<<20)
	h, err := f.NewHTMLAuthoringInputV1(ctx, org, HTMLCreationClosureInputV1)
	if err != nil {
		t.Fatal(err)
	}
	defer h.CloseConsumerV1()
	raw, err := h.ReadBodyV1(ctx, io.NopCloser(strings.NewReader(`{"confirmed":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	before := c.SnapshotV1(org)
	if err := f.CloseV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("factory invented returned buffer retirement", err)
	}
	if after := c.SnapshotV1(org); after != before || after.GlobalGrants != 2 || f.PendingV1().HTMLInputProducers != 1 {
		t.Fatalf("shutdown refunded an executing route consumer: %+v before%+v", after, before)
	}
	var used struct {
		Confirmed bool `json:"confirmed"`
	}
	if err := json.Unmarshal(raw, &used); err != nil || !used.Confirmed {
		t.Fatal("actual returned bytes were not retained for consumer", err)
	}
	h.CloseConsumerV1()
	if c.SnapshotV1(org).GlobalGrants != 0 || f.PendingV1().HTMLInputProducers != 0 {
		t.Fatal("real final raw consumer did not retire")
	}
	if err := f.CloseV1(ctx); err != nil {
		t.Fatal("finished non-SQL factory remains unresolved", err)
	}
}
