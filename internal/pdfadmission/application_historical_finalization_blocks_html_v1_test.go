// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestHistoricalFinalHTMLActualGrantJoinsCopiedCloseAndBorrowersV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	org := uuid.New()
	v := workguard.VectorV1{ParentBytes: 64}
	c, err := workguard.NewV1(workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 4, MaxOrganisationGrants: 4})
	if err != nil {
		t.Fatal(err)
	}
	grant, err := c.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	h := &ApplicationHistoricalFinalizationHTMLV1{html: "exact immutable native formatter output", grant: grant}
	h.self = h
	first, finishFirst, err := h.BorrowHTMLV1()
	if err != nil {
		t.Fatal(err)
	}
	second, finishSecond, err := h.BorrowHTMLV1()
	if err != nil {
		t.Fatal(err)
	}
	copied := &ApplicationHistoricalFinalizationHTMLV1{self: h, html: h.html, grant: grant}
	copied.CloseConsumerV1()
	cancel()
	h.CloseConsumerV1()
	if first != second || first != "exact immutable native formatter output" {
		t.Fatal("close changed an active output")
	}
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
		t.Fatal("close/cancel credited live formatter result", got)
	}
	finishFirst()
	finishFirst()
	if got := c.SnapshotV1(org); got.Global.ParentBytes != 32 {
		t.Fatal("first borrower credited second", got)
	}
	finishSecond()
	if got := c.SnapshotV1(org); got.Global != (workguard.VectorV1{}) || got.GlobalGrants != 0 {
		t.Fatal("formatter result did not drain", got)
	}
	if h.html != "" || h.grant != nil {
		t.Fatal("retired output retains body")
	}
}
func TestHistoricalFinalHTMLBoundCoversOriginalSubstitutionsAndSanitizerV1(t *testing.T) {
	raw := []byte(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"{{buyer}} {{buyer}} {{buyer}}"},{"id":"table","type":"table","attrs":{"columns":["A","B"]},"rows":[["{{buyer}}","{{buyer}}"]]},{"id":"var","type":"dynamic_variable","attrs":{"name":"buyer"}},{"id":"html","type":"raw_html","text":"<a href='https://example.test'>safe</a><script>discard()</script>"}]}`)
	tree, err := blocks.ParseCanonicalTree(raw)
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"buyer": strings.Repeat("<&'\"", 2048)}
	values, _ := json.Marshal(vars)
	doc := &generated.Document{BlocksJson: raw, VariablesJson: values}
	resources, upper, err := historicalBlocksHTMLResourcesV1(doc, tree, vars, 0, "Pending")
	if err != nil || resources <= upper || upper <= 0 {
		t.Fatal("nonpositive formatter pricing", err)
	}
	body := blocks.RenderHTMLWithSignatures(tree, vars, nil, "Pending")
	if int64(len(body)) > upper {
		t.Fatalf("actual original formatter %d exceeds derived %d", len(body), upper)
	}
	if _, _, err = historicalBlocksHTMLResourcesV1(nil, tree, vars, 0, ""); err == nil {
		t.Fatal("missing actual source priced")
	}
}
