#!/usr/bin/env python3
"""Build the isolated candidate with bound upstream source and command evidence."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys

SOURCE = Path("/usr/src/seastar")
FIXTURE = Path("/fixture")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    # BuildKit RUN stages do not provide /.dockerenv. Require the explicit build
    # marker and installed fixture path; source hashes/commit are checked next.
    if (os.environ.get("BONVOYAGE_ISOLATED_LOGGING_BUILD") != "1"
            or Path(__file__).resolve() != FIXTURE / "build.py" or not SOURCE.is_dir()):
        raise SystemExit("refusing non-fixture execution")
    stage = sys.argv[1]
    commands = []

    def run(argv, cwd=SOURCE):
        print(json.dumps({"argv": argv, "cwd": str(cwd)}), flush=True)
        commands.append({"argv": argv, "cwd": str(cwd)})
        subprocess.run(argv, cwd=cwd, check=True)

    if stage == "library":
        metadata = json.loads((FIXTURE / "patch.json").read_text())
        patch = FIXTURE / "candidate.patch"
        expected_files = {"include/seastar/util/log.hh", "include/seastar/util/log-impl.hh", "src/util/log.cc"}
        if (metadata.get("schema_version") != 1 or metadata.get("classification") != "isolated-seastar-runtime-log-candidate"
                or any(set(metadata.get(phase, {})) != expected_files for phase in ["original", "patched"])):
            raise RuntimeError("complete pinned logger source inventory required")
        if metadata["production_selected"] is not False or sha(patch) != metadata["patch_sha256"]:
            raise RuntimeError("candidate patch identity mismatch")
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip()
        if commit != metadata["commit"]:
            raise RuntimeError("Seastar commit mismatch")
        for name, digest in metadata["original"].items():
            if sha(SOURCE / name) != digest:
                raise RuntimeError("original source mismatch: " + name)
        run(["git", "apply", "--check", str(patch)])
        run(["git", "apply", str(patch)])
        for name, digest in metadata["patched"].items():
            if sha(SOURCE / name) != digest:
                raise RuntimeError("patched source mismatch: " + name)
        # Rebuild the full release library against the new headers; never mix
        # old log_buf definitions into a purported newly built candidate library.
        run(["ninja", "-C", "build/release", "-j", "2", "install"])
        for name in ["log.hh", "log-impl.hh"]:
            if sha(Path("/opt/seastar/include/seastar/util") / name) != sha(SOURCE / "include/seastar/util" / name):
                raise RuntimeError("installed header mismatch")
        binding = {"commit": commit, "patch_sha256": sha(patch), "patched": metadata["patched"],
                   "release_library_sha256": sha(Path("/opt/seastar/lib/libseastar.a")), "commands": commands}
        (FIXTURE / "library-binding.json").write_text(json.dumps(binding, indent=2) + "\n")
    elif stage == "tests":
        flags = shlex.split(subprocess.check_output(
            ["pkg-config", "--cflags", "--libs", "--static", "seastar"], text=True,
            env={**os.environ, "PKG_CONFIG_PATH": "/opt/seastar/lib/pkgconfig"}))
        # CMake's installed pkg-config file may name the archive absolutely.
        # Require exactly one recognized archive input before substituting it.
        seastar_inputs = {"-lseastar", "/opt/seastar/lib/libseastar.a"}
        if sum(flag in seastar_inputs for flag in flags) != 1:
            raise RuntimeError("expected one explicit Seastar archive input")
        compile_commands = json.loads((SOURCE / "build/release/compile_commands.json").read_text())
        matches = [row for row in compile_commands if Path(row["file"]).resolve() == SOURCE / "src/util/log.cc"]
        if len(matches) != 1:
            raise RuntimeError("unique actual logger compile command required")
        original = matches[0]
        argv = shlex.split(original["command"])
        output_index = argv.index("-o") + 1
        sanitize = FIXTURE / "sanitize"
        sanitize.mkdir()
        argv[output_index] = str(sanitize / "log.cc.o")
        argv += ["-O1", "-g", "-fno-omit-frame-pointer", "-fno-sanitize-recover=undefined", "-fsanitize=address,undefined"]
        run(argv, Path(original["directory"]))
        library = sanitize / "libseastar.a"
        library.write_bytes(Path("/opt/seastar/lib/libseastar.a").read_bytes())
        # Only the changed logger TU is instrumented in this library. The rest
        # is the rebuilt release dependency, not a full Seastar sanitizer gate.
        run(["ar", "r", str(library), str(sanitize / "log.cc.o")])
        run(["ranlib", str(library)])
        sources = [str(FIXTURE / name) for name in ["runtime_log.cc", "runtime_log_binding.cc", "runtime_log_binding_test.cc"]]
        strict = ["g++", "-std=c++20", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wsign-conversion", "-Werror",
                  "-isystem", "/opt/seastar/include", "-I/fixture/include", "-pthread"]
        for variant in ["release", "sanitize"]:
            variant_flags = flags if variant == "release" else [str(library) if f in seastar_inputs else f for f in flags]
            optimization = ["-O3", "-DNDEBUG"] if variant == "release" else [
                "-O1", "-g", "-fno-omit-frame-pointer", "-fno-sanitize-recover=undefined", "-fsanitize=address,undefined"]
            run(strict + optimization + sources + variant_flags + ["-Werror=unused-result", "-o", str(FIXTURE / ("hook-" + variant))])
        run(strict + ["-O3", "-DNDEBUG"] + sources[:-1] + [str(FIXTURE / "runtime_log_binding_reactor_test.cc")]
            + flags + ["-Werror=unused-result", "-o", str(FIXTURE / "hook-reactor")])
        binding = {"sanitizer_scope": "logger-TU-binding-transport-test; remaining-Seastar-release",
                   "sanitizer_library_sha256": sha(library), "commands": commands,
                   "binary_sha256": {v: sha(FIXTURE / ("hook-" + v)) for v in ["release", "sanitize", "reactor"]}}
        (FIXTURE / "test-binding.json").write_text(json.dumps(binding, indent=2) + "\n")
    else:
        raise RuntimeError("unsupported stage")


if __name__ == "__main__":
    main()
