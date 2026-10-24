#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction
set -euo pipefail

# This path is the Hash module root in both the private hash/ import and mirror.
module_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to verify license provenance" >&2; exit 1; }
python3 - "$module_root" <<'PY'
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1])
HASH = "LicenseRef-Hash-Sustainable-Use-License"
MIXED = "MIT AND " + HASH
UPSTREAM_H1 = "h1:K4VDxqHRBIh/yKJbEStzQlaWOl286AnNjFwRFDtoKYc="
MIT_SHA = "24b9edd14f44d08af320e1d4fc63535636cb71f7c8e7d3827dc831692f27e1aa"
CHROMEDP_SHA = "a0420372ef7d3cf6d111994ee3ed30e606d5043ee9be12b270f6441b60e19bab"
# Closed reviewed source inventory: new files do not inherit a package-wide waiver.
EXPECTED = {
  "chromium": {
    "attrs_test.go": {
      "bytes": 2605,
      "sha256": "2c44d02dec07a075c70691b106940e68d5fedf6f7cf8fa0a102024afb1cd620e"
    },
    "browser.go": {
      "bytes": 22816,
      "sha256": "027fa8bf2238b8c0d726200801fc86c346d1e33023a83215e779708399fbf96a"
    },
    "browser_test.go": {
      "bytes": 1345,
      "sha256": "be154aa0c066e594f1d4608331cbea6fcae82966359774a347b1b9d1d06ae2ac"
    },
    "chromium.go": {
      "bytes": 38918,
      "sha256": "6072ada3ee5d237b3f990d34c149cbd3dfd195f1d3f6027fae555a6f33b87f11"
    },
    "debug.go": {
      "bytes": 632,
      "sha256": "85ef445fd58b5f482e3252ad4334b1cd19c4c992869271e54f78767a6413af2c"
    },
    "doc.go": {
      "bytes": 126,
      "sha256": "0a70c46a32612512ebfab098771729173016584ee97838413f259818122376a2"
    },
    "errortype_test.go": {
      "bytes": 1684,
      "sha256": "311239f8b35c4706e95178603943df07968cbb6ef357126c31c0960cfd4a7c50"
    },
    "events.go": {
      "bytes": 22601,
      "sha256": "9ad0635be615e188ea1fba6ea7f427ff2b297f5f3e2a9d3fa98c74723583f022"
    },
    "events_test.go": {
      "bytes": 3379,
      "sha256": "61672dbcf7e2fddf4f2f53da391413e0942b4aad72545155d8218e8cd3309d5b"
    },
    "mocks.go": {
      "bytes": 1739,
      "sha256": "652cee3617484688101249baf733fdd93354e9e1c9386a6214d57f265e02cd18"
    },
    "network_aggregate.go": {
      "bytes": 2980,
      "sha256": "15dadc1e66f91b46ba7d15adf541bc599f4ab4e34d8bd7393437551b4335f871"
    },
    "network_aggregate_test.go": {
      "bytes": 3020,
      "sha256": "6c8dfbfbb76e9b82ba32fc6a534641bcd63a2617839aabeb9ed0f6e95a7b8189"
    },
    "pinning_proxy.go": {
      "bytes": 14595,
      "sha256": "8687b4cba65f1271e889cfb369c7494b6192c56e32e927caebd8f9b89e35e37f"
    },
    "pinning_proxy_test.go": {
      "bytes": 28671,
      "sha256": "3164149fa9622175daea302f1a708592d6389735a56e55c2070d07c24c2159f1"
    },
    "pinning_proxy_upstream_test.go": {
      "bytes": 2478,
      "sha256": "2e963f75a9e16c1e79c552a3269dc214409e2fbaecdf88b946451dbdb9452cfd"
    },
    "routes.go": {
      "bytes": 35428,
      "sha256": "ab6e6fb3a2eec132951f96cd1bbb4a5b41f819004d5c6a6f5756c086be542f2f"
    },
    "scopebudget.go": {
      "bytes": 1529,
      "sha256": "e3d668141b8ed00cb07bded8c812f929d4c844872686590af4170c6f0fbac209"
    },
    "scopebudget_test.go": {
      "bytes": 3306,
      "sha256": "2757d4a26d3560c5021442165b8977733a701f79b1ab2d1ab16ea07b70cca904"
    },
    "stream.go": {
      "bytes": 2398,
      "sha256": "35b1902975884a2021956f989657e26baf6e7dbd5ff2ca199e4678dd96873128"
    },
    "tasks.go": {
      "bytes": 23573,
      "sha256": "b903cbdf126144847f87a4284ea720e109681c63ecac2c81dc6d1d534fbe5c9f"
    },
    "tasks_test.go": {
      "bytes": 1420,
      "sha256": "f6f226f239579e6cb4636ce8bed3f4e73854a3ce51155e2d6057ed7bec050aad"
    },
    "version_test.go": {
      "bytes": 1353,
      "sha256": "284ca49a32ac89473a63ff9e9f26dcd04dfaa075826e061ca10c5e7aa2b75273"
    }
  },
  "hashapi": {
    "api.go": {
      "bytes": 23902,
      "sha256": "506d936970a760c45e30be03970df0433ee6b8c59135662015b4e0a995e511ed"
    },
    "api_test.go": {
      "bytes": 1525,
      "sha256": "24ce81fe663031bb9d5f0f41f53bfd7685e4a5c883201bc042827e7af68e134d"
    },
    "context.go": {
      "bytes": 22737,
      "sha256": "c186d8958daaa4a0f6029b38ac9413db050d28ad9a7a55d6c461ecb623f78cf8"
    },
    "context_test.go": {
      "bytes": 7649,
      "sha256": "e3b23a91b4fc504c3ad700b9fa05bd7f17c211d862212b4cef33ad0025cc1993"
    },
    "doc.go": {
      "bytes": 159,
      "sha256": "60900f64bdca340563fead751ed8a89665c669628ba4cc3a783319612a7baaeb"
    },
    "errors.go": {
      "bytes": 2046,
      "sha256": "eb97696df39d4972076fd30a275c3682576b92f194c1101ce7c909bd0a3a341c"
    },
    "errors_test.go": {
      "bytes": 2344,
      "sha256": "a836163278dc5287e70b1f4cdf4e426416e7524d5fc612adc84d737e297872c1"
    },
    "formdata.go": {
      "bytes": 19394,
      "sha256": "47b522503432e887cc10734921f8a62293d353ad62e32ecbcb25f4d7be59e5dd"
    },
    "formdata_test.go": {
      "bytes": 38878,
      "sha256": "084af95ecc5166d0f5007354bceaa566775796e74287f118673433086a477904"
    },
    "middlewares.go": {
      "bytes": 18377,
      "sha256": "deb5fe4b07590d49684dc7a704ddae28e7390923251c401facdfd1e732397a13"
    },
    "middlewares_test.go": {
      "bytes": 7933,
      "sha256": "dd05cc94c223305e1d39faca10c21e6741180be12bdcf38cd369192606543217"
    },
    "mocks.go": {
      "bytes": 3514,
      "sha256": "5d2b7fab9a91a9eb97996ee74e510f9e700de1c0b25034b6caef3f255072dcde"
    }
  },
  "hashpdfengines": {
    "doc.go": {
      "bytes": 108,
      "sha256": "5f194c491786946ae20b97df73f7f81245d4a78fba95673d8aa005e5173135d9"
    },
    "fallback_test.go": {
      "bytes": 4958,
      "sha256": "0a5cef1d6ad95aff8434056e9641e2b9bfd0dabac52e07522084789888655c12"
    },
    "multi.go": {
      "bytes": 15270,
      "sha256": "5f6fdbe290a8c12e609f9051744f06d86b4a1c1aa6a355d0293d87dadda0a132"
    },
    "pdfengines.go": {
      "bytes": 14161,
      "sha256": "7cda89570eff24f09c542a1f76c2bab7e3bbbd46b700f03ed0985c0f3cfa33ca"
    },
    "routes.go": {
      "bytes": 56784,
      "sha256": "c3ab042a55ccda91b1cb62a6a80b3afdc46a60a9dcea4fe1297fb57b2fb2ffa1"
    },
    "stamp_test.go": {
      "bytes": 4825,
      "sha256": "ece6b93d8bd7b221f9884d759ea5f88fea79741aa34167dc13d5d3ad15fe08a5"
    }
  }
}
GOTENBERG_ADDITIONS = {
  "hash_supervisor.go": {
    "source": "pkg/gotenberg/supervisor.go",
    "bytes": 19456,
    "sha256": "7e966c132be9992f0680b7d34746e9bbed65fa1be0e9d6670d20812eb9cbde1d"
  },
  "hash_supervisor_upstream_test.go": {
    "source": "pkg/gotenberg/supervisor_test.go",
    "bytes": 29150,
    "sha256": "2862fd97e6021709cea3f2b9b0c9b485e1419054c0b23d64e01f130fe513359d"
  },
  "hash_supervisor_test.go": {
    "source": "pkg/gotenberg/cmd_test.go",
    "bytes": 3745,
    "sha256": "b9b2a900ffc8955f082e8d21b6650ec82e511bf952f19e4be63c6bf35626a0a9"
  },
  "hash_proxy_connect.go": {
    "source": "pkg/gotenberg/outbound.go",
    "bytes": 26116,
    "sha256": "c3927a9e8b18d1d6950e7e08dd288524fd12e146bc33da3b789a6c119f5c2f12"
  }
}
CHROMEDP_ADDITIONS = {
  "hash_cmd_linux.go": {
    "source": "allocate_linux.go",
    "bytes": 414,
    "sha256": "64a6b52b5cf64375e4695fb5cf2d05761751d1bdb1c3c469aa8d1b9fa6691b08"
  },
  "hash_cmd_other.go": {
    "source": "allocate_other.go",
    "bytes": 115,
    "sha256": "cf8efd953bae3eedb751d31f7729d3112563406589fd21c4025e7cee78e73217"
  }
}
MIXED_FILE = "gotenberg/internal/chromium/hash_supervisor_test.go"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def regular_bytes(path):
    require(path.is_file() and not path.is_symlink(), "missing or symlinked provenance: " + str(path))
    return path.read_bytes()


def license_file(path, expected, copyright_text):
    data = regular_bytes(path)
    require(hashlib.sha256(data).hexdigest() == expected, "license identity differs: " + str(path))
    require(data.startswith((b"MIT License\n", b"The MIT License (MIT)\n")) and copyright_text.encode() in data,
            "original MIT notice missing: " + str(path))


def same_record(row, expected, label):
    require(isinstance(row, dict) and all(row.get(k) == v for k, v in expected.items()),
            "original source provenance differs: " + label)


try:
    mit_files = set()
    for package, expected in EXPECTED.items():
        directory = root / "gotenberg/internal" / package
        metadata = json.loads(regular_bytes(directory / "UPSTREAM.json"))
        require(isinstance(metadata, dict), "invalid upstream provenance object: " + package)
        require(metadata.get("upstream_module") == "github.com/gotenberg/gotenberg/v8"
                and metadata.get("upstream_version") == "v8.36.0"
                and metadata.get("upstream_h1") == UPSTREAM_H1,
                "upstream module identity differs: " + package)
        require(metadata.get("license_sha256") == MIT_SHA, "upstream license pin differs: " + package)
        license_file(directory / "LICENSE", MIT_SHA, "Copyright (c) Julien Neuhart")
        records = metadata.get("files")
        require(isinstance(records, list), "upstream source inventory missing: " + package)
        actual = {}
        for row in records:
            require(isinstance(row, dict) and isinstance(row.get("file"), str), "invalid provenance entry: " + package)
            name = row["file"]
            if name.endswith(".go"):
                require(name not in actual, "duplicate upstream Go provenance: " + package + "/" + name)
                actual[name] = row
        require(set(actual) == set(expected), "reviewed upstream Go inventory differs: " + package)
        for name, original in expected.items():
            same_record(actual[name], original, package + "/" + name)
            mit_files.add("gotenberg/internal/" + package + "/" + name)
        additions = metadata.get("additional_owned_sources", [])
        expected_additions = GOTENBERG_ADDITIONS if package == "chromium" else {}
        require(isinstance(additions, list), "invalid additional upstream inventory: " + package)
        indexed = {}
        for row in additions:
            require(isinstance(row, dict) and isinstance(row.get("owned_file"), str), "invalid adapted source record")
            name = row["owned_file"]
            require(name not in indexed, "duplicate adapted source record: " + name)
            indexed[name] = row
        require(set(indexed) == set(expected_additions), "reviewed adapted source inventory differs: " + package)
        for name, original in expected_additions.items():
            same_record(indexed[name], original, name)
            mit_files.add("gotenberg/internal/" + package + "/" + name)
        dependencies = metadata.get("additional_owned_dependencies", [])
        require(isinstance(dependencies, list), "invalid retained dependency inventory")
        if package == "chromium":
            require(len(dependencies) == 1, "reviewed Chromium retained dependency inventory differs")
            dep = dependencies[0]
            require(isinstance(dep, dict), "invalid retained chromedp object")
            require(dep.get("module") == "github.com/chromedp/chromedp" and dep.get("version") == "v0.14.2"
                    and dep.get("license") == "MIT" and dep.get("license_file") == "LICENSE.chromedp"
                    and dep.get("license_sha256") == CHROMEDP_SHA, "retained chromedp identity differs")
            license_file(directory / "LICENSE.chromedp", CHROMEDP_SHA, "Copyright (c) 2016-2025 Kenneth Shaw")
            records = dep.get("sources")
            require(isinstance(records, list), "retained chromedp sources missing")
            indexed = {}
            for row in records:
                require(isinstance(row, dict) and isinstance(row.get("owned_file"), str), "invalid chromedp source record")
                name = row["owned_file"]
                require(name not in indexed, "duplicate chromedp source record: " + name)
                indexed[name] = row
            require(set(indexed) == set(CHROMEDP_ADDITIONS), "reviewed chromedp source inventory differs")
            for name, original in CHROMEDP_ADDITIONS.items():
                same_record(indexed[name], original, name)
                mit_files.add("gotenberg/internal/chromium/" + name)
        else:
            require(not dependencies, "unexpected retained dependency inventory: " + package)

    git_root = Path(subprocess.check_output(["git", "-C", str(root), "rev-parse", "--show-toplevel"], text=True).strip())
    tracked = subprocess.check_output(["git", "-C", str(root), "ls-files", "--full-name", "-z", "--", "*.go"])
    files = [name.decode("utf-8") for name in tracked.split(b"\0") if name]
    require(files, "no tracked Hash Go files were enumerated")
    problems = []
    seen = set()
    for name in files:
        path = git_root / name
        relative = path.relative_to(root).as_posix()
        require(relative not in seen, "duplicate tracked path: " + relative)
        seen.add(relative)
        content = regular_bytes(path).decode("utf-8")
        first = content.splitlines()[:5]
        spdx = [line.split("SPDX-License-Identifier:", 1)[1].strip()
                for line in first if line.startswith("// SPDX-License-Identifier:")]
        if relative == MIXED_FILE:
            if spdx != [MIXED] or not any("Copyright (c) Julien Neuhart" in line for line in first) or not any("Copyright (c) Bright Interaction" in line for line in first):
                problems.append(relative + ": expected both licenses and original/Hash attribution")
        elif relative in mit_files:
            # Original upstream files may have a package LICENSE instead of SPDX.
            # Their pinned original-source provenance and original license notices were checked above.
            if spdx not in ([], ["MIT"]):
                problems.append(relative + ": upstream MIT source must not be relabeled as Hash-only")
        elif spdx != [HASH]:
            problems.append(relative + ": missing Hash SPDX header in first five lines")
    require(mit_files <= seen, "reviewed upstream Go files are absent from tracked source: " + ", ".join(sorted(mit_files - seen)))
    if problems:
        raise ValueError("\n".join(problems))
except (OSError, UnicodeError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
    print("license provenance check failed: " + str(error), file=sys.stderr)
    sys.exit(1)
print("every tracked Hash Go file has its required Hash header or preserved exact upstream MIT provenance")
PY
