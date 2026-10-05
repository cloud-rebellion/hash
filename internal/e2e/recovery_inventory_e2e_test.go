//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type canonicalRecoveryInventoryRow struct {
	key                 string
	classes             string
	owners              string
	orgs                string
	hash                string
	hashConflict        bool
	legalEvidence       bool
	references          int64
	version             string
	versionConflict     bool
	legacyVersionLookup bool
}

func readCanonicalRecoveryInventory(t *testing.T, ctx context.Context, pool *pgxpool.Pool, inventorySQL []byte) map[string]canonicalRecoveryInventoryRow {
	t.Helper()
	// Execute the operator inventory file unchanged. Testing a copied/reduced
	// query would miss retention predicates or grouping drift in the real drill.
	rows, err := pool.Query(ctx, string(inventorySQL))
	must(t, err, "execute canonical recovery inventory")
	defer rows.Close()
	result := map[string]canonicalRecoveryInventoryRow{}
	for rows.Next() {
		var row canonicalRecoveryInventoryRow
		var keyB64, keyJSON string
		must(t, rows.Scan(&keyB64, &keyJSON, &row.classes, &row.owners, &row.orgs, &row.hash, &row.hashConflict,
			&row.legalEvidence, &row.references, &row.version, &row.versionConflict, &row.legacyVersionLookup), "scan canonical inventory row")
		decoded, err := base64.StdEncoding.DecodeString(keyB64)
		must(t, err, "decode inventory exact object key")
		must(t, json.Unmarshal([]byte(keyJSON), &row.key), "decode inventory display key")
		if string(decoded) != row.key || strings.ContainsAny(keyB64, "\r\n\t ") || strings.ContainsAny(keyJSON, "\r\n\t") {
			t.Fatalf("malformed inventory key encoding: base64=%q display=%q", keyB64, keyJSON)
		}
		if _, duplicate := result[row.key]; duplicate {
			t.Fatalf("object key was not grouped into one inventory row: %q", row.key)
		}
		if row.references <= 0 {
			t.Fatalf("inventory row lost its provenance count: %+v", row)
		}
		result[row.key] = row
	}
	must(t, rows.Err(), "finish canonical inventory query")
	return result
}

func assertCanonicalRecoveryInventoryRow(t *testing.T, rows map[string]canonicalRecoveryInventoryRow, expected canonicalRecoveryInventoryRow) {
	t.Helper()
	actual, ok := rows[expected.key]
	if !ok {
		t.Fatalf("retained object missing from canonical inventory: %q", expected.key)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("inventory identity/provenance mismatch for %q:\nactual=%+v\nexpected=%+v", expected.key, actual, expected)
	}
}

func TestCanonicalRecoveryInventoryRetainsSoftDeletedDraftObjectsE2E(t *testing.T) {
	ctx, pool, orgID, userID := setupCollabArchiveRetentionE2E(t)
	inventorySQL, err := os.ReadFile("../../ops/recovery-object-inventory.sql")
	must(t, err, "read operator canonical recovery inventory")
	inventoryDigest := sha256.Sum256(inventorySQL)
	docID, versionID, templateID := uuid.New(), uuid.New(), uuid.New()
	base := "org/" + orgID.String() + "/documents/" + docID.String() + "/"
	sourceKey := base + "source.pdf"
	renderedKey := base + "rendered.pdf"
	// Opaque image keys can contain whitespace and punctuation. Their exact
	// identity must survive the one-line inventory format and JSON display.
	imageKey := base + "assets/current diagram\nÅ.png"
	versionImageKey := base + "assets/historical\timage.png"
	sourceHash := sha256.Sum256([]byte("retained source PDF fixture"))
	renderedHash := sha256.Sum256([]byte("retained rendered PDF fixture"))
	sourcePin, renderedPin := "source-exact-version", "rendered-exact-version"
	blocks, err := json.Marshal(map[string]any{"version": 1, "blocks": []any{
		map[string]any{"id": "outer", "type": "callout", "content": []any{
			map[string]any{"id": "current-image", "type": "image", "attrs": map[string]any{"storage_key": imageKey}},
		}},
		map[string]any{"id": "repeated-image", "type": "image", "attrs": map[string]any{"storage_key": imageKey}},
	}})
	must(t, err, "encode retained block image tree")
	versionBlocks, err := json.Marshal(map[string]any{"version": 1, "blocks": []any{
		map[string]any{"id": "version-container", "type": "quote", "content": []any{
			map[string]any{"id": "version-image", "type": "image", "attrs": map[string]any{"storage_key": versionImageKey}},
		}},
	}})
	must(t, err, "encode retained version image tree")
	templateBlocks, err := json.Marshal(map[string]any{"version": 1, "blocks": []any{
		map[string]any{"id": "shared-image", "type": "image", "attrs": map[string]any{"storage_key": imageKey}},
	}})
	must(t, err, "encode shared template image tree")
	_, err = pool.Exec(ctx, `INSERT INTO documents(id,org_id,sender_id,name,source_kind,status,deleted_at,blocks_json,
pdf_storage_key,pdf_sha256,pdf_storage_version_id,rendered_pdf_key,rendered_pdf_sha,rendered_pdf_version_id,evidence_version_pins_required)
VALUES($1,$2,$3,'retained recovery inventory','blocks','draft',clock_timestamp(),$4,$5,$6,$7,$8,$9,$10,true)`,
		docID, orgID, userID, blocks, sourceKey, sourceHash[:], sourcePin, renderedKey, renderedHash[:], renderedPin)
	must(t, err, "seed soft-deleted retained draft")
	_, err = pool.Exec(ctx, `INSERT INTO document_versions(id,document_id,org_id,version_no,block_tree_json,name,source_kind,created_by)
VALUES($1,$2,$3,1,$4,'retained historical image','blocks',$5)`, versionID, docID, orgID, versionBlocks, userID)
	must(t, err, "seed retained historical block image")
	_, err = pool.Exec(ctx, `INSERT INTO templates(id,org_id,created_by,name,source_kind,blocks_json,pdf_storage_key,pdf_sha256,pdf_storage_version_id,evidence_version_pin_required)
VALUES($1,$2,$3,'shared recovery objects','blocks',$4,$5,$6,$7,true)`, templateID, orgID, userID, templateBlocks, sourceKey, sourceHash[:], sourcePin)
	must(t, err, "seed independent shared template references")
	owners := []string{"document:" + docID.String(), "template:" + templateID.String()}
	sharedOwners := strings.Join(owners, ",") // document sorts before template.
	source := canonicalRecoveryInventoryRow{key: sourceKey, classes: "document_source_pdf,template_source_pdf", owners: sharedOwners,
		orgs: orgID.String(), hash: hex.EncodeToString(sourceHash[:]), references: 2, version: sourcePin}
	rendered := canonicalRecoveryInventoryRow{key: renderedKey, classes: "document_rendered_pdf", owners: "document:" + docID.String(),
		orgs: orgID.String(), hash: hex.EncodeToString(renderedHash[:]), references: 1, version: renderedPin}
	image := canonicalRecoveryInventoryRow{key: imageKey, classes: "document_block_image,template_block_image", owners: sharedOwners,
		orgs: orgID.String(), hash: "-", references: 3, version: "-"}
	historicalImage := canonicalRecoveryInventoryRow{key: versionImageKey, classes: "document_version_block_image", owners: "document_version:" + versionID.String(),
		orgs: orgID.String(), hash: "-", references: 1, version: "-"}
	before := readCanonicalRecoveryInventory(t, ctx, pool, inventorySQL)
	if len(before) != 4 {
		t.Fatalf("retained draft inventory contains %d objects, want four", len(before))
	}
	for _, expected := range []canonicalRecoveryInventoryRow{source, rendered, image, historicalImage} {
		// Exact equality also verifies legal_evidence=false, no hash/version
		// conflicts, and no legacy lookup for the pinned modern PDF identities.
		assertCanonicalRecoveryInventoryRow(t, before, expected)
	}
	// Shared provenance must expose conflicting hash/version identities rather
	// than silently selecting one apparently valid recovery source.
	conflictingHash := sha256.Sum256([]byte("conflicting shared source fixture"))
	_, err = pool.Exec(ctx, `UPDATE templates SET pdf_sha256=$2,pdf_storage_version_id=$3 WHERE id=$1`, templateID, conflictingHash[:], "different-exact-version")
	must(t, err, "seed conflicting shared source identity")
	conflicted := readCanonicalRecoveryInventory(t, ctx, pool, inventorySQL)[sourceKey]
	if !conflicted.hashConflict || !conflicted.versionConflict || conflicted.legalEvidence || conflicted.references != 2 || conflicted.owners != sharedOwners {
		t.Fatalf("conflicting shared identity was hidden: %+v", conflicted)
	}
	_, err = pool.Exec(ctx, `UPDATE templates SET pdf_sha256=$2,pdf_storage_version_id=$3 WHERE id=$1`, templateID, sourceHash[:], sourcePin)
	must(t, err, "restore matching shared source identity")
	_, err = pool.Exec(ctx, `DELETE FROM documents WHERE id=$1`, docID)
	must(t, err, "retire fixture parent after retention review")
	after := readCanonicalRecoveryInventory(t, ctx, pool, inventorySQL)
	if len(after) != 2 {
		t.Fatalf("parent retirement inventory contains %d objects, want two independent template references", len(after))
	}
	source.classes, source.owners, source.references = "template_source_pdf", "template:"+templateID.String(), 1
	image.classes, image.owners, image.references = "template_block_image", "template:"+templateID.String(), 1
	assertCanonicalRecoveryInventoryRow(t, after, source)
	assertCanonicalRecoveryInventoryRow(t, after, image)
	if _, present := after[renderedKey]; present {
		t.Fatal("retired parent preview survived without a remaining owner")
	}
	if _, present := after[versionImageKey]; present {
		t.Fatal("retired parent version image survived without a remaining owner")
	}
	t.Logf("canonical inventory SHA256=%s; four soft-deleted draft objects/pins/provenance verified; shared conflicts visible; parent retirement preserves two template-owned objects", hex.EncodeToString(inventoryDigest[:]))
}
