#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Cloud Rebellion
"""Resolve a public-only synthetic production profile; no daemon or real env.

Also compare critical security settings against the private compatibility profile
when it is present. Its absence in the public mirror must never require a fallback.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
HELPER = runpy.run_path(str(ROOT / "scripts/test-renderer-compose.py"))
FAILURE = HELPER["ProjectionFailure"]
TOKEN = HELPER["TOKEN"]
NAME = HELPER["NAME"]


def require(condition, case, classification):
    if not condition:
        raise FAILURE(case, classification)


def check(require_public=False):
    if require_public:
        for name in ["docker-compose.prod.yml", "PRODUCTION-CUTOVER.md", "PLAN.md", "docs/COMPLETION-STATUS.md",
                     "ops/INGRESS-RATE-LIMIT.md"]:
            require(not (ROOT / name).exists(), "actual-public-export", "private-artifact-present")
        for name in ["docker-compose.yml", "docker-compose.selfhost.yml", "DEPLOY.md", ".env.example", "README.md",
                     "docs/READINESS.md", "scripts/test-renderer-compose.py", "scripts/test-selfhost-compose.py"]:
            require((ROOT / name).is_file(), "actual-public-export", "missing-shipped-file")
        print("PASS case=actual-public-export-inventory")
    with tempfile.TemporaryDirectory(prefix="hash-selfhost-compose-") as temporary:
        directory = Path(temporary)
        docker_config = directory / "docker-config"
        docker_config.mkdir()
        environment = {"PATH": os.environ.get("PATH", os.defpath),
                       "DOCKER_CONFIG": str(docker_config), "COMPOSE_DISABLE_ENV_FILE": "1"}
        command = HELPER["compose_command"](environment, directory)
        public = directory / "public-only"
        public.mkdir()
        profile = public / "docker-compose.selfhost.yml"
        shutil.copyfile(ROOT / profile.name, profile)
        # Only the public production file is present. No private include exists.
        socket_dir = directory / "operator-scanner"
        socket_dir.mkdir()
        work = {
            "HASH_WORK_GLOBAL_PARENT_BYTES": "2147483648",
            "HASH_WORK_GLOBAL_DB_STAGING_BYTES": "402653184",
            "HASH_WORK_GLOBAL_CHILD_ADDRESS_BYTES": "2147483648",
            "HASH_WORK_GLOBAL_PDF_WORKERS": "1",
            "HASH_WORK_GLOBAL_SQL_SESSIONS": "8",
            "HASH_WORK_GLOBAL_PROVIDER_STREAMS": "1",
            "HASH_WORK_GLOBAL_RENDERER_REQUESTS": "1",
            "HASH_WORK_ORG_PARENT_BYTES": "2147483648",
            "HASH_WORK_ORG_DB_STAGING_BYTES": "402653184",
            "HASH_WORK_ORG_CHILD_ADDRESS_BYTES": "2147483648",
            "HASH_WORK_ORG_PDF_WORKERS": "1",
            "HASH_WORK_ORG_SQL_SESSIONS": "4",
            "HASH_WORK_ORG_PROVIDER_STREAMS": "1",
            "HASH_WORK_ORG_RENDERER_REQUESTS": "1",
            "HASH_WORK_MAX_GRANTS": "128", "HASH_WORK_MAX_ORG_GRANTS": "64",
            "HASH_WORK_DB_CONNECTION_ALLOCATION": "16",
        }
        work_paths = []
        for process in ["server", "worker"]:
            path = directory / f"{process}-work.env"
            path.write_text("".join(f"{k}={v}\n" for k, v in work.items()))
            work_paths.append(path)
        values = {
            "HASH_IMAGE": "sha256:" + "1" * 64,
            "HASH_GOTENBERG_IMAGE": "sha256:" + "2" * 64,
            "HASH_RELEASE": "3" * 40,
            "HASH_ENVIRONMENT": "development",  # Production must override this.
            "HASH_PUBLIC_URL": "https://contracts.customer.example",
            "HASH_PROXY_AUTH": "4d" * 32,
            "HASH_OPERATOR_NAME": "Synthetic independent operator",
            "HASH_PRIVACY_CONTACT": "privacy@customer.example",
            "HASH_SUPERVISORY_AUTHORITY": "Synthetic authority",
            "HASH_PRIVACY_POLICY_URL": "https://contracts.customer.example/privacy",
            "HASH_DB_URL": "postgres://synthetic:fixture@database.customer.example:5432/contracts?sslmode=verify-full&pool_max_conns=8",
            "HASH_S3_ENDPOINT": "objects.customer.example",
            "HASH_S3_REGION": "synthetic-region", "HASH_S3_BUCKET": "synthetic-contracts",
            "HASH_S3_ACCESS_KEY": "synthetic-scoped-storage",
            "HASH_S3_SECRET_KEY": "synthetic-storage-fixture",
            "HASH_S3_USE_SSL": "false",  # External TLS must remain forced.
            "HASH_S3_BUCKET_LOOKUP": "path", "HASH_S3_SSE_MODE": "sse-s3",
            "HASH_SMTP_HOST": "submission.customer.example", "HASH_SMTP_PORT": "587",
            "HASH_SMTP_FROM": "signing@customer.example", "HASH_SMTP_PASSWORD": "synthetic-mail-fixture",
            "HASH_SIGNER_TOKEN_KEY": "1a" * 32, "HASH_SESSION_KEY": "2b" * 32,
            "HASH_WEBHOOK_ENCRYPTION_KEY": "3c" * 32,
            "HASH_AUDIT_PRIVATE_KEY": base64.b64encode(bytes(range(32))).decode(),
            NAME: TOKEN,
            "HASH_BILLING_PROVIDER": "mock",  # No development billing fallback.
            "HASH_OPERATOR_ENTITLEMENTS": '[{"org_id":"11111111-1111-4111-8111-111111111111","plan_slug":"pro","review_ref":"synthetic-profile-test"}]',
            "HASH_SERVER_WORK_ENV_FILE": str(work_paths[0]),
            "HASH_WORKER_WORK_ENV_FILE": str(work_paths[1]),
            "HASH_MALWARE_SOCKET_DIR": str(socket_dir), "HASH_HTTP_PORT": "18443",
        }

        def resolve(case, path, inputs, missing=None, private=False):
            actual = dict(inputs)
            env_file = directory / f"{case}.env"
            actual["HASH_ENV_FILE"] = str(env_file)
            if missing is not None:
                actual.pop(missing, None)
            env_file.write_text("".join(f"{k}={v}\n" for k, v in actual.items()))
            argv = command + ["--project-directory", str(public), "--env-file", str(env_file),
                              "-f", str(path), "config", "--format", "json"]
            if private:
                argv.append("--no-env-resolution")
            try:
                result = subprocess.run(argv, cwd=public, env=environment,
                                        capture_output=True, text=True, timeout=20, check=False)
            except subprocess.TimeoutExpired:
                raise FAILURE(case, "config-timeout") from None
            if missing is not None:
                require(result.returncode != 0 and missing in result.stderr, case, "missing-input-not-refused")
                return None
            require(result.returncode == 0, case, f"compose-exit-{result.returncode}")
            return json.loads(result.stdout)

        resolved = resolve("public-only", profile, values)
        services = resolved["services"]
        require(set(services) == {"hash", "worker", "renderer"}, "public-only", "unexpected-services")
        require(not resolved.get("include"), "public-only", "private-include")
        require(set(resolved["networks"]) == {"hash-runtime", "hash-renderer"}, "public-only", "network-scope")
        require(resolved["networks"]["hash-renderer"].get("internal") is True, "public-only", "renderer-network-not-internal")
        for service in services.values():
            require("container_name" not in service, "public-only", "fixed-installation-container-name")
            require(service.get("read_only") is True and service.get("cap_drop") == ["ALL"] and
                    "no-new-privileges:true" in service.get("security_opt", []), "public-only", "process-hardening")
            require(service["environment"].get(NAME) == TOKEN, "public-only", "token-mismatch")
        renderer = services["renderer"]
        require(renderer["environment"] == {NAME: TOKEN} and not renderer.get("env_file") and
                not renderer.get("volumes") and not renderer.get("ports"), "public-only", "renderer-secret-or-exposure")
        require(set(renderer["networks"]) == {"hash-renderer"}, "public-only", "renderer-network-membership")
        for flag in ["--chromium-disable-javascript=true", "--api-disable-download-from=true",
                     "--pdfengines-disable-routes=true", "--chromium-deny-public-ips=true",
                     "--chromium-deny-private-ips=true", "--chromium-deny-list=^https?://.*"]:
            require(flag in renderer["command"], "public-only", "renderer-isolation-control")
        for name in ["hash", "worker"]:
            app = services[name]
            env = app["environment"]
            # Prove that deployment inputs come from the independent operator.
            # A company-name deny-list can itself be rewritten by publication
            # redaction and accidentally match unrelated values or file paths.
            for key in ["HASH_RELEASE", "HASH_OPERATOR_NAME", "HASH_PRIVACY_CONTACT",
                        "HASH_SUPERVISORY_AUTHORITY", "HASH_PRIVACY_POLICY_URL", "HASH_PROXY_AUTH",
                        "HASH_DB_URL", "HASH_S3_ENDPOINT", "HASH_S3_REGION", "HASH_S3_BUCKET",
                        "HASH_S3_ACCESS_KEY", "HASH_S3_SECRET_KEY", "HASH_SMTP_HOST",
                        "HASH_SMTP_PORT", "HASH_SMTP_FROM", "HASH_SIGNER_TOKEN_KEY",
                        "HASH_SESSION_KEY", "HASH_WEBHOOK_ENCRYPTION_KEY", "HASH_AUDIT_PRIVATE_KEY",
                        "HASH_OPERATOR_ENTITLEMENTS"]:
                require(env[key] == values[key], "public-only", "operator-input-not-forwarded-" + key)
            require(not any(key.startswith("HASH_DEPLOY_") for key in env),
                    "public-only", "installation-specific-environment-alias")
            require(env["HASH_ENVIRONMENT"] == "production" and env["HASH_BILLING_PROVIDER"] == "operator" and
                    env["HASH_S3_USE_SSL"] == "true" and env["HASH_S3_SSE_MODE"] == "sse-s3", "public-only", "production-safety-fallback")
            require(env["HASH_PUBLIC_URL"] == values["HASH_PUBLIC_URL"] and
                    env["HASH_GOTENBERG_URL"] == "http://renderer:3000" and
                    set(app["networks"]) == {"hash-runtime", "hash-renderer"}, "public-only", "operator-routing")
            require(all(env[k] == v for k, v in work.items()), "public-only", "work-profile-not-forwarded")
        ports = services["hash"]["ports"]
        require(len(ports) == 1 and ports[0]["host_ip"] == "127.0.0.1" and ports[0]["target"] == 8080,
                "public-only", "application-port-not-loopback")
        require(not services["worker"].get("ports"), "public-only", "worker-published")
        volume = services["hash"]["volumes"]
        require(len(volume) == 1 and volume[0]["source"] == str(socket_dir) and volume[0]["read_only"] is True and
                volume[0]["bind"].get("create_host_path") is False, "public-only", "scanner-bind-not-owned")
        print("PASS case=public-only-custom-domain-and-private-paths")

        private = ROOT / "docker-compose.prod.yml"
        if private.is_file():
            parity_inputs = dict(values)
            for suffix in ["ENDPOINT", "REGION", "BUCKET", "USE_SSL", "BUCKET_LOOKUP", "SSE_MODE"]:
                parity_inputs["HASH_DEPLOY_S3_" + suffix] = values["HASH_S3_" + suffix]
            parity = resolve("private-parity", private, parity_inputs, private=True)["services"]
            for public_name, private_name in [("hash", "hash"), ("worker", "hash-worker"), ("renderer", "hash-gotenberg")]:
                for key in ["read_only", "cap_drop", "security_opt", "tmpfs", "restart", "entrypoint", "healthcheck", "stop_grace_period"]:
                    require(services[public_name].get(key) == parity[private_name].get(key), "private-parity", "security-trait-drift-" + key)
            require(renderer["command"] == parity["hash-gotenberg"]["command"], "private-parity", "renderer-command-drift")
            print("PASS case=private-production-security-parity")
        else:
            print("PASS case=public-mirror-no-private-profile-required")

        for missing in [NAME, "HASH_PROXY_AUTH", "HASH_SIGNER_TOKEN_KEY", "HASH_SESSION_KEY",
                        "HASH_WEBHOOK_ENCRYPTION_KEY", "HASH_AUDIT_PRIVATE_KEY", "HASH_DB_URL",
                        "HASH_S3_SECRET_KEY", "HASH_OPERATOR_ENTITLEMENTS", "HASH_MALWARE_SOCKET_DIR"]:
            resolve("required-" + missing.lower(), profile, values, missing=missing)
            print("PASS case=required-" + missing.lower())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-public", action="store_true",
                        help="require an actual filtered public tree with no private artifacts")
    arguments = parser.parse_args()
    try:
        check(arguments.require_public)
    except FileNotFoundError:
        print("NOT RUN case=tool-selection class=compose-tool-or-source-not-installed")
        raise SystemExit(99)
    except FAILURE as error:
        print(f"FAIL case={error.case} class={error.classification}")
        raise SystemExit(1)
    except (KeyError, ValueError, TypeError, AttributeError, OSError, subprocess.SubprocessError):
        print("FAIL case=fixture class=unexpected-compose-shape-or-io")
        raise SystemExit(1)
