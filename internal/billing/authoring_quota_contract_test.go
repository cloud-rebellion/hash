// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package billing

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Follow the shared production owners rather than expecting SQL in each REST
// or MCP adapter. The callback must hold the org lock across counted writes
// and enforce quota before committing the same native transaction. PostgreSQL
// suites separately verify lock waits, rollback and original credentials.
func TestCountedAuthoringCallsitesUseAtomicQuotaProtocol(t *testing.T) {
	tests := []struct {
		file          string
		inserts       []string
		lock, enforce string
		native        bool
	}{
		{"internal/blockauthoring/create_v1.go", []string{".CreateBlocksDocument("}, ".LockDocumentQuotaMutation(", ".EnforceDocumentQuotaV1(", true},
		{"internal/blockauthoring/envelope_v1.go", []string{".CreateBlocksDocument("}, ".LockDocumentQuotaMutation(", ".EnforceDocumentQuotaV1(", true},
		{"internal/pdftemplateauthoring/create_v1.go", []string{".CreateDocumentV1(", ".NextRecipientV1("}, ".LockDocumentQuotaMutation(", ".EnforceDocumentQuotaV1(", true},
		{"internal/docintake/owned_pdf_v1.go", []string{"prepared.attach("}, ".LockDocumentQuotaMutation(", ".EnforceDocumentQuotaV1(", true},
		{"internal/pdflayout/materialize.go", []string{".CreateRecipient("}, ".LockDocumentQuotaMutation(", ".EnforceDocumentQuotaMutation(", false},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			source := quotaContractSource(t, test.file)
			var inserts []int
			for _, marker := range test.inserts {
				inserts = append(inserts, occurrenceIndexes(source, marker)...)
			}
			sort.Ints(inserts)
			locks, enforcements := occurrenceIndexes(source, test.lock), occurrenceIndexes(source, test.enforce)
			if len(inserts) != len(test.inserts) || len(locks) != len(inserts) || len(enforcements) != len(inserts) {
				t.Fatalf("counted inserts=%d locks=%d post-insert enforcements=%d; review the production owner", len(inserts), len(locks), len(enforcements))
			}
			for i := range inserts {
				if !(locks[i] < inserts[i] && inserts[i] < enforcements[i]) {
					t.Fatalf("counted insert %d is not bracketed by its lock and post-insert enforcement", i+1)
				}
			}
			if test.native {
				requireNativeQuotaCallback(t, source, locks[0], enforcements[len(enforcements)-1])
			}
		})
	}
	// The machine command locks once and enforces aggregate document+recipient
	// usage after its whole recipient loop, retaining its original atomic protocol.
	source := quotaContractSource(t, "internal/blockauthoring/automation_materialization_v1.go")
	markers := []string{".LockAutomationSignatureRequestQuota(", ".CreateBlocksDocument(", ".CreateNextV1(", ".EnforceDocumentQuotaV1("}
	positions := requireQuotaOrder(t, source, markers...)
	requireNativeQuotaCallback(t, source, positions[0], positions[len(positions)-1])
}

// Keep every previous transport in the contract: delegation must not silently
// become a direct insert that bypasses the quota owner.
func TestCountedAuthoringAdaptersDelegateToQuotaOwners(t *testing.T) {
	tests := []struct {
		file, marker string
		count        int
	}{
		{"internal/handler/documents.go", "blockauthoring.CreateV1(", 1},
		{"internal/handler/documents.go", "pdftemplateauthoring.CreateV1(", 1},
		{"internal/handler/documents_import.go", "docintake.CreateOwnedPDFSourceDocumentV1(", 1},
		{"internal/mcp/tools_authoring.go", "blockauthoring.CreateV1(", 1},
		{"internal/mcp/tools_authoring.go", "pdftemplateauthoring.CreateV1(", 1},
		{"internal/mcp/tools_authoring.go", "docintake.CreateOwnedPDFSourceDocumentV1(", 1},
		{"internal/mcp/tools_envelopes.go", "commitOwnedEnvelopeV1(", 5},
		{"internal/mcp/envelope_topology_owned_v1.go", "blockauthoring.EnvelopeV1(", 1},
	}
	for _, test := range tests {
		source := quotaContractSource(t, test.file)
		if got := strings.Count(source, test.marker); got != test.count {
			t.Fatalf("%s delegates %s %d times, want %d", test.file, test.marker, got, test.count)
		}
		for _, direct := range []string{".CreateBlocksDocument(", ".CreatePDFDocument(", ".CreateRecipient(", "docintake.CreatePDFSourceDocument("} {
			if strings.Contains(source, direct) {
				t.Fatalf("%s bypasses its quota owner with %s", test.file, direct)
			}
		}
	}
}

func TestImportedPDFQuotaRollbackCompensatesStoredObject(t *testing.T) {
	source := quotaContractSource(t, "internal/docintake/owned_pdf_v1.go")
	requireQuotaOrder(t, source, "owned = prepared.OwnedSource()", "prepared.attach(", ".EnforceDocumentQuotaV1(", "commitAttempted = true", "session.CommitV1(ctx)", "committed = true")
	start := strings.Index(source, "commitAttempted := false")
	end := strings.Index(source, "session.WithTxV1(")
	if start < 0 || end <= start {
		t.Fatal("owned intake rollback region missing")
	}
	requireQuotaOrder(t, source[start:end],
		"session.CloseV1(cleanup)",
		"admission.ReconcileCleanupV1(cleanup)",
		"!committed && !commitAttempted && owned.Key != \"\"",
		"deleteAfterFailedWrite(ctx, d.Store, owned.Key, storage.StoredObject{VersionID: owned.VersionID, SHA256: owned.SHA256})")
	if !strings.Contains(source[start:end], "context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)") {
		t.Fatal("rollback cleanup lost its detached bound")
	}
	cleanup := quotaContractSource(t, "internal/docintake/docintake.go")
	begin := strings.Index(cleanup, "func deleteAfterFailedWrite(")
	if begin < 0 {
		t.Fatal("exact-version cleanup helper missing")
	}
	requireQuotaOrder(t, cleanup[begin:], "context.WithTimeout(context.WithoutCancel(parent), orphanCleanupTimeout)", "st.DeleteVersion(cleanupCtx, key, stored.VersionID, stored.SHA256[:])")
}

func requireNativeQuotaCallback(t *testing.T, source string, lock, enforce int) {
	t.Helper()
	callbacks, commits := occurrenceIndexes(source, ".WithTxV1("), occurrenceIndexes(source, ".CommitV1(")
	if len(callbacks) != 1 || len(commits) != 1 || !(callbacks[0] < lock && enforce < commits[0]) {
		t.Fatal("quota mutation is not inside the single native transaction before commit")
	}
	body := source[callbacks[0]:commits[0]]
	if !strings.Contains(body, "db generated.DBTX") || !strings.Contains(body, "{DBTX: db}") || !strings.Contains(body, "generated.New(tx)") {
		t.Fatal("quota queries lost the native callback transaction")
	}
}

func requireQuotaOrder(t *testing.T, source string, markers ...string) []int {
	t.Helper()
	positions := make([]int, 0, len(markers))
	previous := -1
	for _, marker := range markers {
		matches := occurrenceIndexes(source, marker)
		if len(matches) != 1 || matches[0] <= previous {
			t.Fatalf("expected one ordered %q, positions=%v previous=%d", marker, matches, previous)
		}
		previous = matches[0]
		positions = append(positions, previous)
	}
	return positions
}

func quotaContractSource(t *testing.T, rel string) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "..", ".."))
	body, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(body)
}

func occurrenceIndexes(source, marker string) []int {
	var out []int
	for offset := 0; ; {
		i := strings.Index(source[offset:], marker)
		if i < 0 {
			return out
		}
		out = append(out, offset+i)
		offset += i + len(marker)
	}
}
