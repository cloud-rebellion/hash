#!/usr/bin/env python3
"""Validate the published contract and boundary examples, without network calls."""
import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate_spec

spec = json.loads((Path(__file__).resolve().parents[1] / "docs/openapi-automation.json").read_text())
validate_spec(spec)
base = {
    "template_id": "44bf21a1-26f8-4d85-a444-968649ba891d",
    "template_version": 1,
    "template_content_sha256": "ab" * 32,
    "name": "Agreement",
    "recipients": [{"email": "ada@example.com", "name": "Ada"}],
    "lawful_basis": "contract",
}
validator = Draft202012Validator(dict(spec, **{"$ref": "#/components/schemas/SignatureRequest"}))
cases = [
    ("minimal", {}, True),
    ("string variables", {"variables": {"customer.name": "Ada"}}, True),
    ("null variables", {"variables": None}, False),
    ("null variable value", {"variables": {"customer.name": None}}, False),
    ("unknown property", {"unexpected": "value"}, False),
    ("empty recipients", {"recipients": []}, False),
    ("recipient limit", {"recipients": base["recipients"] * 51}, False),
    ("unknown recipient field", {"recipients": [{**base["recipients"][0], "unexpected": True}]}, False),
    ("non-string variable", {"variables": {"amount": 123}}, False),
    ("bad variable name", {"variables": {"bad-key": "value"}}, False),
    ("nonpositive template version", {"template_version": 0}, False),
    ("template version overflow", {"template_version": 2147483648}, False),
    ("invalid template digest", {"template_content_sha256": "z" * 64}, False),
    ("noncanonical template digest", {"template_content_sha256": "AB" * 32}, False),
]
for name, changes, expected in cases:
    payload = copy.deepcopy(base)
    payload.update(changes)
    actual = not list(validator.iter_errors(payload))
    if actual != expected:
        raise SystemExit(f"contract fixture failed: {name}")
for field in ("template_version", "template_content_sha256"):
    payload = copy.deepcopy(base)
    del payload[field]
    if not list(validator.iter_errors(payload)):
        raise SystemExit(f"contract fixture failed: missing {field}")
print(f"OpenAPI valid; {len(cases) + 2} request boundary fixtures pass")
