#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
"""Reconcile three exact static/build-only findings; never execute project code."""

import argparse
import datetime
import hashlib
from html.parser import HTMLParser
import json
import math
import os
from pathlib import Path
import re
import stat
import sys


PACKAGE = "@sveltejs/kit"
VERSION = "2.70.3"
INTEGRITY = "sha512-UDvEYuZqAMbfB/oXIoqKvbKcb7YczK5zYrzmsGV1zRJk03jntwp8dXiYoIJotxAndsKvcPFtx9H1GRSKFdSHgg=="
LOCK_SHA256 = "c1e7b5e13f679b3ee7341d6ae1e192e3c5beb4feb6e0a406ca3fe918494df3d3"
LOCK_BYTES = 55105
KNOWN = {1243067: "GHSA-pfhg-q3qv-9q6r", 1243076: "GHSA-27mw-82g8-phjj"}
BUILD_PACKAGE = "deepmerge"
BUILD_VERSION = "4.3.1"
BUILD_INTEGRITY = "sha512-3sUqbMEc77XqpdNO7FRyRog+eW3ph+GYCbj+rK+uYyRMuwsVy0rMiVtPn+QJlKFvWP/1PYpapqYn0Me2knFn+A=="
BUILD_KNOWN = {1243505: "GHSA-gcqx-w48m-w2h4"}
BUILD_PINS = {
    "frontend/vite.config.ts": (359, "29d90b8be4608102abf8e56f2e8178d9ab20cf7e91587626b76b0026159bc2e9"),
    "frontend/node_modules/@sveltejs/vite-plugin-svelte/src/utils/options.js":
        (22347, "d4b27fdc5d4580b2023a1a8c69aa9ad670375bcf6132d72b9fb73e36249e9447"),
    "frontend/node_modules/@sveltejs/vite-plugin-svelte/src/utils/load-svelte-config.js":
        (3650, "c70f865d8a634a308c8d2e73d69fb660a3144aab42294cc1c550ffe893ffed29"),
    "frontend/node_modules/deepmerge/dist/cjs.js":
        (4048, "2e5160f84a1141bd927264afe4d15766f1e6cf07daef182b37ff53fea121de7d"),
}
REVIEW_KEYS = {
    "schema", "package", "version", "integrity", "lock_sha256", "lock_bytes",
    "bun_version", "adapter", "adapter_version", "profile", "reviewed_on",
    "review_expires_on", "advisories", "build_dependency",
}
AUDIT_KEYS = {"id", "url", "title", "severity", "vulnerable_versions", "cwe", "cvss"}
STATIC_CONFIG = """import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      pages: 'build', assets: 'build', fallback: 'index.html',
      precompress: false, strict: false
    })
  }
};
export default config;
"""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_file(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                "input is not a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(limit + 1)
        after = os.fstat(descriptor)
        current = path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
        require(len(raw) <= limit and identity(before) == identity(after) == identity(current),
                "input changed while being read")
        return raw
    finally:
        os.close(descriptor)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON object key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite JSON number")


def read_json(path, limit=1 << 20):
    return json.loads(read_file(path, limit).decode("utf-8"),
                      object_pairs_hook=unique_object, parse_constant=reject_constant)


def audit_record(value, package=PACKAGE):
    require(type(value) is dict and set(value) == AUDIT_KEYS, "unreviewed audit record shape")
    identity = value["id"]
    known = {PACKAGE: KNOWN, BUILD_PACKAGE: BUILD_KNOWN}.get(package, {})
    require(type(identity) is int and identity in known, "unreviewed advisory ID")
    affected = "<3.0.0" if package == PACKAGE else ">=4.2.0 <=4.3.1"
    require(value["url"] == "https://github.com/advisories/" + known[identity]
            and type(value["title"]) is str and 0 < len(value["title"]) < 512
            and value["severity"] == "low" and value["vulnerable_versions"] == affected,
            "advisory identity, severity or affected range changed")
    require(type(value["cwe"]) is list and len(value["cwe"]) == 1
            and type(value["cwe"][0]) is str, "unreviewed CWE shape")
    cvss = value["cvss"]
    require(type(cvss) is dict and set(cvss) == {"score", "vectorString"}
            and type(cvss["score"]) in (int, float) and math.isfinite(cvss["score"])
            and type(cvss["vectorString"]) is str, "unreviewed CVSS shape")
    return identity


def validate_review(root, bun_version):
    review = read_json(root / "frontend/vulnerability-review.json")
    require(type(review) is dict and set(review) == REVIEW_KEYS, "review shape changed")
    expected = {
        "schema": 1, "package": PACKAGE, "version": VERSION, "integrity": INTEGRITY,
        "lock_sha256": LOCK_SHA256, "lock_bytes": LOCK_BYTES, "bun_version": "1.3.9",
        "adapter": "@sveltejs/adapter-static", "adapter_version": "3.0.10",
        "profile": "hash-go-embedded-static-v1", "reviewed_on": "2026-10-24",
        "review_expires_on": "2026-11-07",
    }
    require(all(review[key] == value for key, value in expected.items())
            and type(review["schema"]) is int and type(review["lock_bytes"]) is int
            and bun_version == review["bun_version"], "reviewed package, lock or tool identity changed")
    today = datetime.datetime.now(datetime.timezone.utc).date()
    reviewed = datetime.date.fromisoformat(review["reviewed_on"])
    expires = datetime.date.fromisoformat(review["review_expires_on"])
    require(reviewed <= today <= expires and (expires - reviewed).days <= 14,
            "review is future-dated or expired")
    require(type(review["advisories"]) is list and len(review["advisories"]) == 2,
            "review must contain exactly two advisories")
    approved = {}
    for entry in review["advisories"]:
        require(type(entry) is dict and set(entry) == {"audit", "primary_url", "status", "justification"},
                "review advisory shape changed")
        identity = audit_record(entry["audit"])
        require(identity not in approved and entry["status"] == "not_affected"
                and entry["primary_url"] == "https://github.com/sveltejs/kit/security/advisories/" + KNOWN[identity]
                and type(entry["justification"]) is str and len(entry["justification"]) >= 40,
                "review advisory disposition changed")
        approved[identity] = entry["audit"]
    require(set(approved) == set(KNOWN), "review advisory set changed")
    build = review["build_dependency"]
    require(type(build) is dict and set(build) == {
        "package", "version", "integrity", "dependency_path", "reviewed_on", "review_expires_on", "advisory"},
        "build dependency review shape changed")
    require(build["package"] == BUILD_PACKAGE and build["version"] == BUILD_VERSION
            and build["integrity"] == BUILD_INTEGRITY
            and build["dependency_path"] == ["@sveltejs/vite-plugin-svelte@5.1.1", "deepmerge@4.3.1"]
            and build["reviewed_on"] == "2026-10-28"
            and build["review_expires_on"] == "2026-11-07"
            and datetime.date.fromisoformat(build["reviewed_on"]) <= today <= expires,
            "reviewed build dependency identity changed")
    entry = build["advisory"]
    require(type(entry) is dict and set(entry) == {"audit", "primary_url", "status", "justification"},
            "build advisory review shape changed")
    identity = audit_record(entry["audit"], BUILD_PACKAGE)
    require(entry["status"] == "not_affected"
            and entry["primary_url"] == "https://github.com/advisories/" + BUILD_KNOWN[identity]
            and type(entry["justification"]) is str and len(entry["justification"]) >= 40,
            "build advisory disposition changed")
    lock = read_file(root / "frontend/bun.lock", 1 << 20)
    require(len(lock) == LOCK_BYTES and hashlib.sha256(lock).hexdigest() == LOCK_SHA256,
            "reviewed frozen lock changed")
    package = read_json(root / "frontend/package.json")
    require(type(package) is dict and type(package.get("devDependencies")) is dict
            and package["devDependencies"].get(PACKAGE) == "^2.70.3"
            and package["devDependencies"].get("@sveltejs/adapter-static") == "^3.0.10",
            "reviewed package or adapter requirement changed")
    for name, version in ((PACKAGE, VERSION), ("@sveltejs/adapter-static", "3.0.10")):
        installed = read_json(root / "frontend/node_modules" / name / "package.json")
        require(type(installed) is dict and installed.get("name") == name
                and installed.get("version") == version, "installed package or adapter version changed")
    return {PACKAGE: approved, BUILD_PACKAGE: {identity: entry["audit"]}}, expires


def build_dependency_profile(root):
    package = read_json(root / "frontend/package.json")
    require(package["devDependencies"].get("@sveltejs/vite-plugin-svelte") == "^5.1.1"
            and type(package.get("scripts")) is dict
            and package["scripts"].get("build") == "vite build"
            and all(type(package.get(kind, {})) is dict for kind in
                    ("dependencies", "optionalDependencies", "peerDependencies"))
            and all(BUILD_PACKAGE not in package.get(kind, {}) for kind in
                    ("dependencies", "optionalDependencies", "peerDependencies")),
            "deepmerge is no longer solely the reviewed build dependency")
    for name, version in (("@sveltejs/vite-plugin-svelte", "5.1.1"), (BUILD_PACKAGE, BUILD_VERSION)):
        installed = read_json(root / "frontend/node_modules" / name / "package.json")
        require(type(installed) is dict and installed.get("name") == name and installed.get("version") == version,
                "installed build dependency changed")
        if name == "@sveltejs/vite-plugin-svelte":
            require(installed.get("dependencies", {}).get(BUILD_PACKAGE) == "^4.3.1",
                    "reviewed build dependency path changed")
        else:
            require(installed.get("main") == "dist/cjs.js", "deepmerge entry point changed")
    for relative, (size, digest) in BUILD_PINS.items():
        raw = read_file(root / relative, 128 << 10)
        require(len(raw) == size and hashlib.sha256(raw).hexdigest() == digest,
                "reviewed build configuration or merge consumer changed: " + relative)
    for prefix, expected in (("vite.config.", "vite.config.ts"), ("svelte.config.", "svelte.config.js")):
        require({path.name for path in (root / "frontend").glob(prefix + "*")} == {expected},
                "alternate build configuration requires review")


def source_profile(root):
    config = read_file(root / "frontend/svelte.config.js", 64 << 10).decode("utf-8")
    config = "\n".join(line for line in config.splitlines()
                       if not line.startswith("// SPDX-License-Identifier:")
                       and not line.startswith("// Copyright (c) Bright Interaction"))
    compact = lambda value: re.sub(r"\s+", "", value)
    require(compact(config) == compact(STATIC_CONFIG), "reviewed static adapter profile changed")
    source_root = root / "frontend/src"
    require(source_root.is_dir() and not source_root.is_symlink(), "frontend source root changed")
    count, total = 0, 0
    for path in source_root.rglob("*"):
        require(not path.is_symlink(), "frontend source contains a symlink")
        if not path.is_file():
            continue
        count += 1
        require(count <= 4096, "frontend source inventory exceeds review bound")
        relative = path.relative_to(source_root)
        require(not any(re.search(r"\[\[?\.\.\.", part) for part in relative.parts),
                "SvelteKit catch-all route requires review")
        require(path.name not in {"hooks.ts", "hooks.js", "hooks.server.ts", "hooks.server.js"}
                and ".server." not in path.name,
                "SvelteKit server or universal hook requires review")
        require(not (relative.parts[0] == "routes" and path.name.startswith("+")
                    and path.suffix != ".svelte"), "SvelteKit server or universal route requires review")
        if path.suffix not in {".svelte", ".ts", ".js", ".html", ".mjs", ".cjs"}:
            continue
        raw = read_file(path, 2 << 20)
        total += len(raw)
        require(total <= 32 << 20, "frontend source exceeds review bound")
        text = raw.decode("utf-8")
        require(all(name not in text for name in
                    (BUILD_PACKAGE, "@sveltejs/vite-plugin-svelte", "@sveltejs/kit/vite")),
                "deepmerge or its build consumer runtime import requires review")
        require("$app/forms" not in text and "setHeaders" not in text
                and re.search(r"use\s*:\s*enhance\b", text) is None
                and re.search(r"\bexport\s+(?:const|let|var)\s+prerender\b", text) is None,
                "enhanced form, setHeaders or prerender feature requires review")
    require(count > 0, "frontend source inventory is empty")
    frontend = read_file(root / "cmd/server/frontend.go", 128 << 10).decode("utf-8")
    for snippet in ('//go:embed all:frontend/build', 'fs.Sub(frontendFS, "frontend/build")',
                    'http.FileServer(http.FS(sub))', 'sub.Open("index.html")', 'io.Copy(w, f)'):
        require(snippet in frontend, "Go embedded static delivery changed")
    policies = re.findall(r'\.Header\(\)\.Set\("Cache-Control",\s*([^\n]+)\)', frontend)
    require(sorted(policies) == sorted(['"public, max-age=31536000, immutable"',
            '"public, max-age=31536000, immutable"', '"public, max-age=300"', '"no-cache"']),
            "Go static cache policies changed")
    router = read_file(root / "internal/handler/server.go", 2 << 20).decode("utf-8")
    main = read_file(root / "cmd/server/main.go", 1 << 20).decode("utf-8")
    require('r.NotFound(s.Frontend.ServeHTTP)' in router
            and re.search(r'Frontend:\s+frontendHandler\(\)', main)
            and re.search(r'Handler:\s+srv\.Routes\(\)', main), "Go frontend router wiring changed")
    dockerfile = read_file(root / "Dockerfile", 128 << 10).decode("utf-8")
    lines = [line.strip() for line in dockerfile.splitlines() if not line.lstrip().startswith("#")]
    stages = [index for index, line in enumerate(lines) if line.startswith("FROM ")]
    require(len(stages) == 3 and lines.count('COPY --from=frontend /app/frontend/build ./cmd/server/frontend/build') == 1,
            "static frontend-to-Go image build changed")
    final = lines[stages[-1]:]
    require('ENTRYPOINT ["/usr/local/bin/hash-server"]' in final
            and all(re.fullmatch(r'COPY --from=backend /out/[a-z-]+ /usr/local/bin/hash-[a-z-]+', line)
                    for line in final if line.startswith("COPY "))
            and not re.search(r'\b(?:node|nodejs|bun|npm|npx|deno|svelte-kit|vite)\b', "\n".join(final)),
            "production image is no longer the reviewed Go-only frontend server")
    build_dependency_profile(root)


def validate_report(report, approved):
    require(type(report) is dict and set(report) == {PACKAGE, BUILD_PACKAGE},
            "audit contains unreviewed packages")
    for package, findings in report.items():
        require(type(findings) is list and len(findings) == len(approved[package]),
                "audit finding count changed")
        observed = set()
        for finding in findings:
            identity = audit_record(finding, package)
            require(identity not in observed and finding == approved[package][identity],
                    "audit finding is duplicated or its reviewed metadata changed")
            observed.add(identity)
        require(observed == set(approved[package]), "audit advisory set changed")


class StaticIndex(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.counts = {"html": 0, "head": 0, "body": 0}
        self.entries = set()
        self.in_script = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        require(len(attrs) == len({name for name, _value in attrs}), "built index has duplicate attributes")
        attributes = dict(attrs)
        if tag in self.counts:
            self.counts[tag] += 1
        require(not (tag == "meta" and "http-equiv" in attributes), "built index has unreviewed http-equiv metadata")
        if tag == "link" and attributes.get("rel") == "modulepreload":
            href = attributes.get("href", "")
            if re.fullmatch(r'/_app/immutable/entry/(?:start|app)\.[A-Za-z0-9_-]+\.js', href):
                self.entries.add(href)
        if tag == "script":
            self.in_script = True
            self.scripts.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1] += data


def built_index(root):
    raw = read_file(root / "frontend/build/index.html", 2 << 20)
    require(len(raw) >= 256, "actual built frontend index is missing or too small")
    text = raw.decode("utf-8")
    require("%sveltekit." not in text, "built index contains unresolved source placeholders")
    document = StaticIndex()
    document.feed(text)
    document.close()
    require(all(count == 1 for count in document.counts.values()) and len(document.entries) == 2
            and {entry.rsplit("/", 1)[-1].split(".", 1)[0] for entry in document.entries} == {"start", "app"}
            and any("kit.start(app, element)" in script and "Promise.all" in script
                    and all('import("' + entry + '")' in script for entry in document.entries)
                    for script in document.scripts), "actual built index is not the reviewed static fallback")
    for entry in document.entries:
        require(len(read_file(root / "frontend/build" / entry.lstrip("/"), 16 << 20)) > 0,
                "built index bootstrap entry is absent")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--audit-exit-code", required=True, type=int)
    parser.add_argument("--bun-version", required=True)
    args = parser.parse_args()
    try:
        require(args.audit_exit_code == 1, "only native Bun audit exit 1 can be reconciled")
        approved, expires = validate_review(args.root, args.bun_version)
        report = read_json(args.report)
        validate_report(report, approved)
        source_profile(args.root)
        built_index(args.root)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError) as error:
        print("frontend audit reconciliation REFUSED: " + str(error), file=sys.stderr)
        return 1
    print("frontend audit: native Bun audit exit=1; three low findings remain reported; "
          "exact Kit/static and deepmerge/build-only findings reviewed not_affected "
          "through " + expires.isoformat() + ": " + ", ".join([*KNOWN.values(), *BUILD_KNOWN.values()]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
