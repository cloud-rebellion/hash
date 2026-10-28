#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
"""Mutation checks for the finite static/build-only dependency review."""

import copy
import datetime
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
REAL_DATETIME = datetime.datetime
spec = importlib.util.spec_from_file_location("frontend_audit", ROOT / "scripts/reconcile-frontend-audit.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="hash-frontend-review-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        files = [
            "frontend/package.json", "frontend/bun.lock", "frontend/vulnerability-review.json",
            "frontend/svelte.config.js", "Dockerfile", "cmd/server/frontend.go",
            "internal/handler/server.go", "cmd/server/main.go", *audit.BUILD_PINS,
            *["frontend/node_modules/" + name + "/package.json" for name in
              (audit.PACKAGE, "@sveltejs/adapter-static", "@sveltejs/vite-plugin-svelte", audit.BUILD_PACKAGE)],
        ]
        for relative in files:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / relative).read_bytes())
        source = self.root / "frontend/src/profile.ts"
        source.parent.mkdir(parents=True)
        source.write_text("export const staticProfile = true;\n")
        self.review = json.loads((self.root / "frontend/vulnerability-review.json").read_text())
        self.report = {
            audit.PACKAGE: [copy.deepcopy(entry["audit"]) for entry in self.review["advisories"]],
            audit.BUILD_PACKAGE: [copy.deepcopy(self.review["build_dependency"]["advisory"]["audit"])],
        }
        clock = patch.object(audit.datetime, "datetime", wraps=datetime.datetime)
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        self.clock.now.return_value = REAL_DATETIME(2026, 10, 29, tzinfo=datetime.timezone.utc)

    def check(self):
        approved, _expires = audit.validate_review(self.root, "1.3.9")
        audit.validate_report(self.report, approved)
        audit.source_profile(self.root)

    def change_json(self, relative, change):
        path = self.root / relative
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def refuse(self):
        with self.assertRaises((ValueError, OSError)):
            self.check()

    def test_exact_reviewed_report_and_build_profile(self):
        self.check()

    def test_new_package(self):
        self.report["unreviewed"] = []
        self.refuse()

    def test_new_advisory(self):
        self.report[audit.BUILD_PACKAGE][0]["id"] = 1249999
        self.refuse()

    def test_changed_native_metadata(self):
        self.report[audit.BUILD_PACKAGE][0]["cvss"]["score"] = 2.7
        self.refuse()

    def test_missing_build_advisory(self):
        del self.report[audit.BUILD_PACKAGE]
        self.refuse()

    def test_duplicate_advisory(self):
        self.report[audit.BUILD_PACKAGE].append(copy.deepcopy(self.report[audit.BUILD_PACKAGE][0]))
        self.refuse()

    def test_changed_severity(self):
        self.report[audit.BUILD_PACKAGE][0]["severity"] = "high"
        self.refuse()

    def test_changed_affected_range(self):
        self.report[audit.BUILD_PACKAGE][0]["vulnerable_versions"] = "<5.0.0"
        self.refuse()

    def test_changed_lock(self):
        with (self.root / "frontend/bun.lock").open("a") as stream:
            stream.write("\n")
        self.refuse()

    def test_changed_installed_deepmerge(self):
        self.change_json("frontend/node_modules/deepmerge/package.json", lambda value: value.update(version="4.3.2"))
        self.refuse()

    def test_changed_plugin_version(self):
        self.change_json("frontend/node_modules/@sveltejs/vite-plugin-svelte/package.json",
                         lambda value: value.update(version="5.1.2"))
        self.refuse()

    def test_changed_consumer(self):
        path = self.root / "frontend/node_modules/@sveltejs/vite-plugin-svelte/src/utils/options.js"
        path.write_text(path.read_text() + "\n// changed merge inputs\n")
        self.refuse()

    def test_untrusted_vite_config_input(self):
        (self.root / "frontend/vite.config.ts").write_text("export default JSON.parse(process.env.CONFIG);\n")
        self.refuse()

    def test_alternate_config(self):
        (self.root / "frontend/svelte.config.cjs").write_text("module.exports = {};\n")
        self.refuse()

    def test_runtime_import(self):
        (self.root / "frontend/src/profile.ts").write_text("import merge from 'deepmerge';\n")
        self.refuse()

    def test_runtime_build_consumer_import(self):
        (self.root / "frontend/src/profile.ts").write_text("import plugin from '@sveltejs/vite-plugin-svelte';\n")
        self.refuse()

    def test_alternate_build_command(self):
        self.change_json("frontend/package.json", lambda value: value["scripts"].update(build="vite build --config untrusted.ts"))
        self.refuse()

    def test_direct_runtime_dependency(self):
        self.change_json("frontend/package.json", lambda value: value["dependencies"].update(deepmerge="4.3.1"))
        self.refuse()

    def test_javascript_runtime_image(self):
        path = self.root / "Dockerfile"
        path.write_text(path.read_text() + "\nRUN apk add nodejs\n")
        self.refuse()

    def test_review_expired(self):
        self.clock.now.return_value = REAL_DATETIME(2026, 11, 8, tzinfo=datetime.timezone.utc)
        self.refuse()

    def test_review_cannot_be_extended(self):
        self.change_json("frontend/vulnerability-review.json",
                         lambda value: value["build_dependency"].update(review_expires_on="2026-11-08"))
        self.refuse()

    def test_existing_kit_guard_remains(self):
        (self.root / "frontend/src/profile.ts").write_text("import { enhance } from '$app/forms';\n")
        self.refuse()


if __name__ == "__main__":
    unittest.main()
