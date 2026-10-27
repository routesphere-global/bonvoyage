#!/usr/bin/env python3
"""Validate strict native SPDX JSON against pinned official schema and semantic tools."""

import argparse
import hashlib
from importlib.metadata import version
import json
from pathlib import Path
import re
import sys

SCHEMA_SHA = "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b"
ROOT = Path(__file__).resolve().parent.parent


def strict_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def validate(document, schema):
    import jsonschema
    from spdx_tools.spdx.parser.parse_anything import parse_file
    from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document

    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("reviewed Python 3.12 runtime required")
    lock_path = ROOT / "security/tools/native-sbom-python.lock"
    lock = lock_path.read_text()
    expected = dict(re.findall(r"(?m)^([a-zA-Z0-9_.-]+)==([^\s\\]+)", lock))
    if not expected or expected.get("spdx-tools") != "0.8.5" or expected.get("jsonschema") != "4.26.0":
        raise RuntimeError("reviewed validator dependency lock required")
    installed = {name: version(name) for name in expected}
    if installed != expected:
        raise RuntimeError("validator dependency version differs from reviewed lock")
    schema_bytes = schema.read_bytes()
    if hashlib.sha256(schema_bytes).hexdigest() != SCHEMA_SHA:
        raise RuntimeError("official SPDX schema byte pin mismatch")
    raw = document.read_bytes()
    if not 0 < len(raw) <= 32 * 1024 * 1024:
        raise ValueError("bounded SPDX document required")
    decoded = json.loads(raw, object_pairs_hook=strict_pairs)
    specification = json.loads(schema_bytes, object_pairs_hook=strict_pairs)
    validator = jsonschema.validators.validator_for(specification)
    validator.check_schema(specification)
    validator(specification, format_checker=jsonschema.FormatChecker()).validate(decoded)
    parsed = parse_file(str(document), encoding="utf-8")
    errors = validate_full_spdx_document(parsed, spdx_version="SPDX-2.3")
    if errors:
        raise ValueError("\n".join(str(error) for error in errors))
    if raw != document.read_bytes() or schema_bytes != schema.read_bytes() or lock != lock_path.read_text():
        raise RuntimeError("validation input/schema/lock changed")
    return {"schema_sha256": SCHEMA_SHA, "spdx_tools": installed["spdx-tools"], "dependencies": installed,
            "python": sys.version, "interpreter": str(Path(sys.executable).resolve()),
            "lock_sha256": hashlib.sha256(lock.encode()).hexdigest(), "schema_passed": True, "semantic_passed": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.input, args.schema), indent=2))
    except (RuntimeError, ImportError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(2)
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
