#!/usr/bin/env python3
"""Capture the exact Ubuntu AMD64 package-builder environment for later review."""

import argparse
import importlib.util
import json
import os
from pathlib import Path


BUILDER_PATH = Path(__file__).with_name("build-oss-deb.py")
SPEC = importlib.util.spec_from_file_location("bonvoyage_oss_deb_builder", BUILDER_PATH)
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)


def capture(builder_image, output):
    BUILDER.require(not output.exists() and not output.is_symlink(), "new toolchain-lock output required")
    lock = BUILDER.capture_toolchain(builder_image)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    BUILDER.require(not temporary.exists() and not temporary.is_symlink(),
                    "new temporary toolchain-lock output required")
    temporary.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output)
    return lock


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--builder-image", required=True,
                        help="Externally observed immutable image reference ending in @sha256:<digest>.")
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        document = capture(arguments.builder_image, arguments.output.absolute())
    except (OSError, ValueError) as error:
        raise SystemExit("OSS Debian toolchain capture rejected: " + str(error)) from error
    print(json.dumps(document, indent=2, sort_keys=True))
