#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Cloud Rebellion
"""Resolve synthetic Compose inputs without a daemon, real env files or secrets.

Run from any directory with Docker Compose supporting --no-env-resolution.
This checks configuration projection only; it starts no containers and proves
neither private renderer execution nor a complete signing journey.
"""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
TOKEN = "synthetic-compose-route-token-not-a-runtime-secret"
NAME = "HASH_SIGNATURE_FIT_TOKEN"
CASES = [
    ("standalone-configured", "docker-compose.yml", TOKEN, True),
    ("standalone-unconfigured", "docker-compose.yml", None, True),
    ("production-configured", "docker-compose.prod.yml", TOKEN, True),
    ("production-missing-token", "docker-compose.prod.yml", None, False),
    ("production-empty-token", "docker-compose.prod.yml", "", False),
]


class ProjectionFailure(Exception):
    def __init__(self, case: str, classification: str):
        self.case, self.classification = case, classification


def compose_command(environment: dict[str, str], directory: Path) -> list[str]:
    # Docker Desktop may install its official plugin only through a user plugin
    # link. An empty DOCKER_CONFIG intentionally hides that link and credentials.
    # Try system plugin discovery, then the explicitly installed PATH executable;
    # never read/copy the user's config.json or inherit its plugin search settings.
    docker, standalone = shutil.which("docker"), shutil.which("docker-compose")
    candidates = []
    if docker is not None:
        candidates.append(("clean-cli-plugin", [docker, "compose"]))
    if standalone is not None:
        candidates.append(("installed-binary", [str(Path(standalone).resolve(strict=True))]))
    if not candidates:
        raise FileNotFoundError
    for mode, command in candidates:
        try:
            version = subprocess.run(command + ["version", "--short"], cwd=directory,
                                     env=environment, capture_output=True, text=True,
                                     timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        match = re.fullmatch(r"v?([0-9]+)\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version.stdout.strip())
        if version.returncode == 0 and match is not None and int(match[1]) >= 2:
            print(f"COMPOSE_TOOL mode={mode}")
            return command
    raise ProjectionFailure("tool-selection", "compose-v2-or-newer-unavailable")


def check(selected_case=None) -> None:
    base = ROOT / "docker-compose.yml"
    private = ROOT / "docker-compose.prod.yml"
    if not base.is_file() or base.is_symlink():
        raise ProjectionFailure("profile-selection", "development-profile-missing-or-invalid")
    private_present = private.is_file() and not private.is_symlink()
    if (private.exists() or private.is_symlink()) and not private_present:
        raise ProjectionFailure("profile-selection", "private-profile-invalid")
    cases = CASES if private_present else CASES[:2]
    if selected_case is not None and selected_case not in [case[0] for case in cases]:
        raise ProjectionFailure("profile-selection", "requested-profile-not-shipped")
    if not private_present:
        print("PROFILE_ABSENT name=private-production cases_not_run=3")
    with tempfile.TemporaryDirectory(prefix="hash-renderer-compose-") as temporary:
        directory = Path(temporary)
        (directory / "docker-config").mkdir()
        environment = {
            "PATH": os.environ.get("PATH", os.defpath),
            "DOCKER_CONFIG": str(directory / "docker-config"),
            "COMPOSE_DISABLE_ENV_FILE": "1",
        }
        command = compose_command(environment, directory)
        # No provider, cookie or key is read. Even app values are public fixtures.
        values = {
            "HASH_IMAGE": "sha256:" + "1" * 64,
            "HASH_GOTENBERG_IMAGE": "sha256:" + "2" * 64,
            "HASH_RELEASE": "3" * 40,
            "HASH_S3_ENDPOINT": "storage.invalid:9000",
            "HASH_S3_REGION": "synthetic",
            "HASH_S3_BUCKET": "synthetic-unused",
            "HASH_S3_ACCESS_KEY": "synthetic-storage-identity",
            "HASH_S3_SECRET_KEY": "synthetic-storage-key",
            "HASH_DEPLOY_S3_ENDPOINT": "storage.invalid:9000",
            "HASH_DEPLOY_S3_REGION": "synthetic",
            "HASH_DEPLOY_S3_BUCKET": "synthetic-unused",
            "HASH_DEPLOY_S3_USE_SSL": "true",
            "HASH_DEPLOY_S3_BUCKET_LOOKUP": "path",
            "HASH_DEPLOY_S3_SSE_MODE": "sse-s3",
            "HASH_DB_URL": "postgres://synthetic:fixture@db.invalid/hash",
            "HASH_SESSION_KEY": "synthetic-session-fixture",
            "HASH_AUDIT_PRIVATE_KEY": "synthetic-audit-fixture",
            "HASH_SMTP_PASSWORD": "synthetic-mail-fixture",
        }
        for index, (case, filename, token, expected_success) in enumerate(cases, 1):
            if selected_case is not None and case != selected_case:
                continue
            inputs = dict(values)
            if token is not None:
                inputs[NAME] = token
            env_file = directory / f"case-{index}.env"
            env_file.write_text("".join(f"{name}={value}\n" for name, value in inputs.items()))
            try:
                result = subprocess.run(
                    command + ["--project-directory", str(directory),
                               "--env-file", str(env_file), "-f", str(ROOT / filename),
                               "config", "--no-env-resolution", "--format", "json"],
                    cwd=directory, env=environment, capture_output=True,
                    text=True, timeout=20, check=False,
                )
            except subprocess.TimeoutExpired:
                raise ProjectionFailure(case, "config-process-timeout") from None
            except OSError:
                raise ProjectionFailure(case, "config-process-launch") from None
            if not expected_success:
                if result.returncode == 0 or NAME not in result.stderr:
                    raise ProjectionFailure(case, "missing-required-token-refusal")
            else:
                if result.returncode != 0:
                    classification = "unsupported-no-env-resolution" if "unknown flag: --no-env-resolution" in result.stderr else f"compose-exit-{result.returncode}"
                    raise ProjectionFailure(case, classification)
                try:
                    services = json.loads(result.stdout)["services"]
                except (KeyError, ValueError, TypeError):
                    raise ProjectionFailure(case, "invalid-compose-json") from None
                production = filename == "docker-compose.prod.yml"
                renderer = services["hash-gotenberg" if production else "gotenberg"]
                expected = token or ""
                if renderer.get("environment") != {NAME: expected} or renderer.get("env_file"):
                    raise ProjectionFailure(case, "renderer-environment-projection")
                for service in ["hash", "hash-worker" if production else "worker"]:
                    if services[service]["environment"].get(NAME) != expected:
                        raise ProjectionFailure(case, "app-worker-renderer-token-mismatch")
                for flag in ["--chromium-disable-javascript=true", "--chromium-deny-public-ips=true",
                             "--chromium-deny-private-ips=true", "--chromium-deny-list=^https?://.*"]:
                    if flag not in renderer["command"]:
                        raise ProjectionFailure(case, "renderer-isolation-control")
            print(f"PASS case={case}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[case[0] for case in CASES])
    arguments = parser.parse_args()
    try:
        check(arguments.case)
    except FileNotFoundError:
        print("NOT RUN case=tool-selection class=compose-tool-not-installed")
        raise SystemExit(99)
    except ProjectionFailure as failure:
        print(f"FAIL case={failure.case} class={failure.classification}")
        raise SystemExit(1)
    except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError):
        print("FAIL case=fixture class=unexpected-projection-shape-or-io")
        raise SystemExit(1)
