// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package db

import (
	"fmt"
	"io/fs"
)

// LifecycleContractVersionV1 is the complete application/worker contract, not
// the storage encryption or physical database identity contract schema.
// Version7 owns M116 pre-sign archives, publication, recovery and V3 evidence.
// Version8 also owns M117 staff credentials and sealed recovery mail. Older
// workers do not decode that ciphertext and cannot safely consume its queue.
// M118 filing, M119 email content, M120 scoped SMTP, M121 finite automation
// M122 bounded email design and M123 retained brand profiles retain version 8:
// workers consume the same already-rendered durable message bodies.
// M125 is a trigger-only INSERT guard on template revisions and keeps version 9.
// M126 only backfills derived event size rows and keeps version 9.
// M127 adds pending_object_deletions_v1, a durable queue of object versions that a
// committed DSR erasure still owes the object store. It keeps version 9. A
// version-9 writer that predates M127 ignores the table: it neither reads nor
// writes rows that matter to it, and its own erasure keeps the old single
// post-commit attempt. Rows written by this version are only ever drained by this
// version's worker, and the Down refuses while any remain, so an older binary can
// neither misread nor lose them and there is no reason to lock it out.
// Version9 also owns M124 in-place draft edits: forward template moves and the
// append-only PDF revision/review history. An older writer would not honour the
// send-time review gate, so it must not resume a database that holds those rows.
// Version10 owns M128's frozen English/Swedish package-incorporation versions
// and response validation, as well as workspace email preferences and editions.
// An older writer does not understand Swedish package consent. The release must
// quiesce all old writers before migrating; this identity is an admission and
// rollback contract, not a database-session fence for already-running SQL.
const LifecycleContractVersionV1 = 10

func EmbeddedLifecycleIdentityV1() (version int, migrationsSHA256 string, err error) {
	digest, versions, err := EmbeddedMigrationsIdentity()
	if err != nil {
		return 0, "", err
	}
	reviewed, err := reviewedLifecycleContractVersionV1(embeddedMigrations, versions)
	if err != nil {
		return 0, "", err
	}
	if reviewed != LifecycleContractVersionV1 {
		return 0, "", fmt.Errorf("embedded lifecycle tree does not match this writer contract")
	}
	return LifecycleContractVersionV1, digest, nil
}

// Reviewed historical cohorts keep their original writer identity. They do not
// inherit the current binary's version when a later named migration is added.
func reviewedLifecycleContractVersionV1(migrations fs.FS, versions []int64) (int, error) {
	if err := requireReviewedLifecycleTreeV1(migrations, versions); err != nil {
		return 0, err
	}
	switch highest := versions[len(versions)-1]; {
	case highest >= 128:
		return 10, nil
	case highest >= 124:
		return 9, nil
	default:
		return 8, nil
	}
}

func requireReviewedLifecycleTreeV1(migrations fs.FS, versions []int64) error {
	unsupported := fmt.Errorf("embedded lifecycle contract requires the reviewed M117 or named M118/M119/M120/M121/M122/M123/M124/M125/M126/M127/M128 migration tree")
	if len(versions) == 0 || len(versions) > 128 {
		return unsupported
	}
	highest := versions[len(versions)-1]
	if highest != 117 && highest != 118 && highest != 119 && highest != 120 && highest != 121 && highest != 122 && highest != 123 && highest != 124 && highest != 125 && highest != 126 && highest != 127 && highest != 128 {
		return unsupported
	}
	seen := make(map[int64]bool, len(versions))
	for index, version := range versions {
		if version <= 0 || (index > 0 && versions[index-1] >= version) {
			return unsupported
		}
		seen[version] = true
	}
	names := []string{"00115_later_amendments.sql", "00116_presign_publication_v1.sql", "00117_staff_password_auth.sql"}
	if highest >= 118 {
		names = append(names, "00118_document_folders.sql")
	}
	if highest >= 119 {
		names = append(names, "00119_service_email_templates.sql")
	}
	if highest >= 120 {
		names = append(names, "00120_workspace_smtp.sql")
	}
	if highest >= 121 {
		names = append(names, "00121_reminder_sender_automation.sql")
	}
	if highest >= 122 {
		names = append(names, "00122_service_email_design.sql")
	}
	if highest >= 123 {
		names = append(names, "00123_org_brand_profiles.sql")
	}
	if highest >= 124 {
		names = append(names, "00124_draft_in_place_edit.sql")
	}
	if highest >= 125 {
		names = append(names, "00125_html_template_revision_insert_guard.sql")
	}
	if highest >= 126 {
		names = append(names, "00126_measure_html_document_events.sql")
	}
	if highest >= 127 {
		names = append(names, "00127_pending_object_deletions.sql")
	}
	if highest >= 128 {
		names = append(names, "00128_workspace_email_and_signing_languages.sql")
	}
	for index, name := range names {
		info, err := fs.Stat(migrations, "migrations/"+name)
		if !seen[int64(115+index)] || err != nil || !info.Mode().IsRegular() {
			return unsupported
		}
	}
	return nil
}
