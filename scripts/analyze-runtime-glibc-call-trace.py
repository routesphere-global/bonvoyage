#!/usr/bin/env python3
"""Validate bounded runtime observations of glibc-sensitive calls.

This analyzer accepts diagnostic traces only. A passing observation does not
close reachability, authorize VEX, suppress a scanner result, or approve a
release.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


PREFIX = b"BONVOYAGE_GLIBC_TRACE_V1\t"
FILE_LIMIT = 16 * 1024 * 1024
LINE_LIMIT = 8192
EVENT_LIMIT = 100_000
NAME = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
HEX = re.compile(r"(?:[0-9a-f]{2})*\Z")
FILE_FUNCTIONS = {"fopen", "fopen64", "freopen", "freopen64"}
RESOLVER_FUNCTIONS = {
    "getaddrinfo", "gethostbyname", "gethostbyname2", "getnameinfo"
}
PROCESS_FUNCTIONS = {"process_start", "process_stop"}
FUNCTIONS = FILE_FUNCTIONS | RESOLVER_FUNCTIONS | PROCESS_FUNCTIONS


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse_assignment(value, label):
    require("=" in value, f"{label} must be NAME=PATH")
    name, raw_path = value.split("=", 1)
    require(NAME.fullmatch(name) is not None and raw_path,
            f"invalid {label} assignment")
    return name, Path(raw_path)


def decode_field(value, label):
    if value == "-":
        return None
    require(len(value) <= 2 * 512 and HEX.fullmatch(value) is not None,
            f"invalid bounded hexadecimal {label}")
    return bytes.fromhex(value).decode("utf-8", errors="strict")


def parse_trace(path):
    require(path.is_file() and not path.is_symlink(),
            f"regular non-symlink trace required: {path}")
    size = path.stat().st_size
    require(0 < size <= FILE_LIMIT, f"bounded nonempty trace required: {path}")
    data = path.read_bytes()
    require(len(data) == size, f"trace changed while reading: {path}")
    events = []
    for line_number, raw_line in enumerate(data.splitlines(), start=1):
        offset = raw_line.find(PREFIX)
        if offset < 0:
            continue
        record = raw_line[offset:]
        require(len(record) <= LINE_LIMIT, f"trace line too long: {path}:{line_number}")
        try:
            text = record.decode("ascii")
        except UnicodeDecodeError as error:
            raise ValueError(f"non-ASCII trace line: {path}:{line_number}") from error
        fields = text.split("\t")
        require(fields[0] == PREFIX[:-1].decode("ascii") and len(fields) == 4,
                f"invalid trace field count: {path}:{line_number}")
        parsed = {}
        for field in fields[1:]:
            require("=" in field, f"invalid trace field: {path}:{line_number}")
            key, value = field.split("=", 1)
            require(key not in parsed, f"duplicate trace field: {path}:{line_number}")
            parsed[key] = value
        require(set(parsed) == {"function", "caller_hex", "argument_hex"},
                f"unexpected trace fields: {path}:{line_number}")
        function = parsed["function"]
        require(function in FUNCTIONS, f"unknown traced function: {function}")
        caller = decode_field(parsed["caller_hex"], "caller")
        argument = decode_field(parsed["argument_hex"], "argument")
        if function in FILE_FUNCTIONS:
            require(argument is not None, f"file mode missing: {path}:{line_number}")
        else:
            require(argument is None,
                    f"unexpected sensitive argument capture: {path}:{line_number}")
        events.append({
            "function": function,
            "caller": caller,
            "argument": argument,
            "line": line_number,
        })
        require(len(events) <= EVENT_LIMIT, f"trace event budget exceeded: {path}")
    require(events, f"no BonVoyage glibc trace events found: {path}")
    return data, events


def summarize(name, path):
    data, events = parse_trace(path)
    counts = {function: 0 for function in sorted(FUNCTIONS)}
    modes = {}
    callers = {}
    for event in events:
        counts[event["function"]] += 1
        if event["argument"] is not None:
            modes[event["argument"]] = modes.get(event["argument"], 0) + 1
        caller = ("process-boundary" if event["function"] in PROCESS_FUNCTIONS
                  else event["caller"] or "unknown")
        callers[caller] = callers.get(caller, 0) + 1
    resolver_calls = sum(counts[item] for item in RESOLVER_FUNCTIONS)
    file_calls = sum(counts[item] for item in FILE_FUNCTIONS)
    ccs_modes = sorted(mode for mode in modes if "ccs=" in mode.lower())
    lifecycle_complete = (
        counts["process_start"] == 1 and counts["process_stop"] == 1 and
        events[0]["function"] == "process_start" and
        events[-1]["function"] == "process_stop"
    )
    caller_attribution_complete = all(
        event["caller"] is not None
        for event in events
        if event["function"] not in PROCESS_FUNCTIONS
    )
    return {
        "name": name,
        "path": str(path),
        "bytes": len(data),
        "sha256": digest(data),
        "event_count": len(events),
        "function_counts": counts,
        "caller_counts": dict(sorted(callers.items())),
        "file_mode_counts": dict(sorted(modes.items())),
        "file_call_count": file_calls,
        "resolver_call_count": resolver_calls,
        "ccs_modes": ccs_modes,
        "process_start_count": counts["process_start"],
        "process_stop_count": counts["process_stop"],
        "lifecycle_complete": lifecycle_complete,
        "caller_attribution_complete": caller_attribution_complete,
    }


def analyze(controls, scenarios):
    require(controls and scenarios, "at least one control and gateway scenario required")
    require(set(controls).isdisjoint(scenarios), "control and scenario names must be unique")
    control_results = {name: summarize(name, path) for name, path in controls.items()}
    scenario_results = {name: summarize(name, path) for name, path in scenarios.items()}

    observer_control_passed = all(
        value["lifecycle_complete"] and value["caller_attribution_complete"] and
        value["file_call_count"] >= 1 and value["resolver_call_count"] >= 1
        for value in control_results.values()
    )
    scenarios_complete = all(
        value["lifecycle_complete"] and value["caller_attribution_complete"]
        for value in scenario_results.values()
    )
    resolver_calls = sum(value["resolver_call_count"] for value in scenario_results.values())
    ccs_modes = sorted({mode for value in scenario_results.values()
                        for mode in value["ccs_modes"]})
    observation_gate_passed = (
        observer_control_passed and scenarios_complete and resolver_calls == 0 and
        not ccs_modes
    )
    return {
        "schema_version": 1,
        "classification": "bounded-runtime-glibc-call-observation",
        "controls": control_results,
        "gateway_scenarios": scenario_results,
        "observations": {
            "observer_control_passed": observer_control_passed,
            "gateway_scenarios_complete": scenarios_complete,
            "gateway_caller_attribution_complete": all(
                value["caller_attribution_complete"]
                for value in scenario_results.values()
            ),
            "gateway_resolver_call_count": resolver_calls,
            "gateway_ccs_modes": ccs_modes,
            "observation_gate_passed": observation_gate_passed,
        },
        "finding_status": {
            "CVE-2026-8674": {
                "status": "under_review",
                "reason": "A bounded runtime trace cannot prove that every transitive resolver path is unreachable.",
            },
            "CVE-2026-18374": {
                "status": "under_review",
                "reason": "Observed fixed modes do not prove safe mode arguments across every future dependency path.",
            },
        },
        "reachability_closed": False,
        "coverage_qualified": False,
        "vex_authorized": False,
        "scanner_suppression_authorized": False,
        "release_authorized": False,
        "limitations": [
            "LD_PRELOAD observation covers only the recorded processes and exercised scenarios.",
            "Unexecuted branches, future modules, native-host services and changed dependencies remain outside this evidence.",
            "The observer records file modes but deliberately does not record file paths or resolver names.",
            "A complete caller-attributed trace is supporting evidence, not whole-program reachability proof.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", action="append", default=[])
    parser.add_argument("--scenario", action="append", default=[])
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        controls = dict(parse_assignment(item, "control") for item in args.control)
        scenarios = dict(parse_assignment(item, "scenario") for item in args.scenario)
        require(len(controls) == len(args.control), "duplicate control name")
        require(len(scenarios) == len(args.scenario), "duplicate scenario name")
        result = analyze(controls, scenarios)
        require(not args.output.exists() and not args.output.is_symlink(),
                "output must be new")
        os.umask(0o077)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(result, output, indent=2, sort_keys=True)
            output.write("\n")
        if not result["observations"]["observation_gate_passed"]:
            print("Runtime glibc observation completed with an open gate.")
            return 1
        print("Runtime glibc observation passed; both findings remain under review.")
    except (ValueError, OSError, UnicodeError) as error:
        print("Invalid runtime glibc call trace: " + str(error))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
