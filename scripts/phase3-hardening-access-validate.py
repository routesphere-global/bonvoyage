#!/usr/bin/env python3
"""Validate privacy and schema boundaries for soak-test access-log segments."""

from __future__ import annotations

import collections
import glob
import json
import shutil
import sys
from pathlib import Path


EXPECTED_FIELDS = {
    "action",
    "cluster",
    "completion",
    "duration_us",
    "listener",
    "method",
    "protocol",
    "request_body_bytes",
    "response_body_bytes",
    "route",
    "schema",
    "shard",
    "snapshot_generation",
    "status",
    "timestamp_unix_us",
}
FORBIDDEN_FIELDS = {
    "api_key",
    "authority",
    "client_ip",
    "cookie",
    "forwarded_for",
    "headers",
    "host",
    "jwt",
    "query",
    "request_body",
    "request_path",
    "response_body",
    "tenant_id",
    "user_id",
}


def main() -> None:
    if sys.flags.optimize != 0:
        raise RuntimeError("access-log validation requires Python assertions")
    paths = sorted(glob.glob("/access/*.jsonl"))
    assert paths, "access-log sink did not create a JSONL segment"
    records = 0
    invalid_records = 0
    actions: collections.Counter[str] = collections.Counter()
    protocols: collections.Counter[str] = collections.Counter()
    statuses: collections.Counter[str] = collections.Counter()
    forbidden_present: set[str] = set()
    for path in paths:
        with open(path, encoding="utf-8") as source:
            for line in source:
                value = json.loads(line)
                records += 1
                if set(value) != EXPECTED_FIELDS or value.get("schema") != "bonvoyage.access.v1":
                    invalid_records += 1
                forbidden_present.update(FORBIDDEN_FIELDS.intersection(value))
                actions[str(value.get("action"))] += 1
                protocols[str(value.get("protocol"))] += 1
                statuses[str(value.get("status"))] += 1
        shutil.copy2(path, "/evidence/" + Path(path).name)
    summary = {
        "actions": dict(sorted(actions.items())),
        "forbidden_fields_present": sorted(forbidden_present),
        "invalid_records": invalid_records,
        "protocols": dict(sorted(protocols.items())),
        "records": records,
        "retained_segments": [Path(path).name for path in paths],
        "segments": len(paths),
        "statuses": dict(sorted(statuses.items())),
    }
    destination = Path("/evidence/access-log-validation.json")
    destination.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
