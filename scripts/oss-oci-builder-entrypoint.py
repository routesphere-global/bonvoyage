#!/usr/bin/env python3
"""Compile, test and assemble one BonVoyage OSS OCI technical candidate offline."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess


SOURCE_ROOT = Path("/workspace/source")
WORK_ROOT = Path("/workspace/work")
OUTPUT_ROOT = Path("/workspace/output")
PUBLIC_REPOSITORY = "https://github.com/routesphere-global/bonvoyage"
BUILDER_REPOSITORY = "ghcr.io/routesphere-global/bonvoyage-oci-builder"
CLASSIFICATION = "routesphere-bonvoyage-oss-oci-builder-execution"
SEMVER_TAG = re.compile(
    r"v(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)"
)
COMMIT = re.compile(r"[a-f0-9]{40}")
BUILDER_IMAGE = re.compile(
    r"ghcr[.]io/routesphere-global/bonvoyage-oci-builder@sha256:[a-f0-9]{64}"
)
BUILDER_ID = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
REQUIRED_TOOLS = (
    "cmake", "ctest", "dpkg", "dpkg-query", "g++-13", "git", "ldd",
    "ninja", "protoc", "python3",
)
REQUIRED_DEPENDENCIES = (
    "/opt/abseil/lib/cmake/absl/abslConfig.cmake",
    "/opt/c-ares/lib/libcares.a",
    "/opt/libjwt/lib/libjwt.a",
    "/opt/llhttp/lib/libllhttp.a",
    "/opt/nghttp2/lib/libnghttp2.a",
    "/opt/re2/lib/libre2.a",
    "/opt/seastar/lib/cmake/Seastar/SeastarConfig.cmake",
)
ASSEMBLER = Path("/usr/local/lib/bonvoyage/build-oss-oci.py")
PACKAGE_INDEX = Path("/usr/local/lib/bonvoyage/build-runtime-package-index.py")
CONTRACT = Path("/usr/local/share/bonvoyage/oss-oci-image-contract.json")
STATIC_ROOT = Path("/opt/bonvoyage-oci/rootfs-static")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def normalized_repository(value):
    value = value.strip()
    if value.endswith(".git"):
        value = value[:-4]
    return {
        "git@github.com:routesphere-global/bonvoyage": PUBLIC_REPOSITORY,
        "ssh://git@github.com/routesphere-global/bonvoyage": PUBLIC_REPOSITORY,
        PUBLIC_REPOSITORY: PUBLIC_REPOSITORY,
    }.get(value, value)


def git_bytes(root, *arguments):
    return subprocess.run(
        ["git", "-c", f"safe.directory={root}", "-C", str(root), *arguments],
        check=True, capture_output=True, timeout=30,
    ).stdout


def git_text(root, *arguments):
    return git_bytes(root, *arguments).decode("utf-8").strip()


def regular_directory(path, label, empty=False):
    require(path.is_dir() and not path.is_symlink(), f"regular {label} directory required")
    require(path.resolve() == path, f"{label} directory must not traverse symbolic links")
    if empty:
        require(not any(path.iterdir()), f"empty {label} directory required")


def environment_value(name, pattern):
    value = os.environ.get(name, "")
    require(pattern.fullmatch(value) is not None, f"invalid or missing {name}")
    return value


def source_identity(source_root, expected_commit, expected_tag):
    regular_directory(source_root, "source")
    require((source_root / ".git").exists(), "Git source checkout required")
    status = git_bytes(source_root, "status", "--porcelain=v1", "--untracked-files=all", "-z")
    commit = git_text(source_root, "rev-parse", "HEAD")
    origin = normalized_repository(git_text(source_root, "remote", "get-url", "origin"))
    tag_commit = git_text(
        source_root, "rev-parse", "--verify", f"refs/tags/{expected_tag}^{{commit}}",
    )
    source_date_epoch = int(git_text(source_root, "show", "-s", "--format=%ct", "HEAD"))
    require(not status, "clean source tree required")
    require(commit == expected_commit, "mounted source commit does not match hosted context")
    require(origin == PUBLIC_REPOSITORY, "mounted source origin is not the public repository")
    require(tag_commit == commit, "release tag does not resolve to the mounted commit")
    return {
        "repository": origin,
        "commit": commit,
        "tag": expected_tag,
        "source_date_epoch": source_date_epoch,
        "dirty": False,
        "status_sha256": digest(status),
    }


def regular_file(path, label):
    require(path.is_file() and not path.is_symlink(), f"regular {label} file required")


def self_check(builder_image):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Linux AMD64 OCI builder required")
    require(BUILDER_IMAGE.fullmatch(builder_image) is not None,
            "digest-pinned public OCI builder image required")
    tools = {}
    for name in REQUIRED_TOOLS:
        tool = shutil.which(name)
        require(tool is not None and Path(tool).is_file(), f"missing OCI builder tool: {name}")
        tools[name] = str(Path(tool).resolve())
    for name in REQUIRED_DEPENDENCIES:
        regular_file(Path(name), "pinned dependency")
    for path in (ASSEMBLER, PACKAGE_INDEX, CONTRACT):
        regular_file(path, "OCI builder component")
    regular_directory(STATIC_ROOT, "OCI static root")
    require(not Path("/usr/src/bonvoyage").exists() and
            not Path("/opt/bonvoyage/bin/bonvoyage-dataplane").exists(),
            "OCI builder image must not contain BonVoyage source or binary")
    os_release = Path("/etc/os-release").read_bytes()
    fields = dict(
        line.split("=", 1) for line in os_release.decode("utf-8").splitlines() if "=" in line
    )
    require(fields.get("ID", "").strip('"') == "ubuntu" and
            fields.get("VERSION_ID", "").strip('"') == "24.04",
            "Ubuntu 24.04 OCI builder required")
    return {
        "schema_version": 1,
        "classification": "routesphere-bonvoyage-oss-oci-builder-self-check",
        "outcome": "passed",
        "builder_image": builder_image,
        "platform": "linux/amd64",
        "os_release_sha256": digest(os_release),
        "tools": tools,
        "dependencies": list(REQUIRED_DEPENDENCIES),
        "release_admitted": False,
        "publishable": False,
    }


def run_logged(command, cwd, environment, log_path, timeout):
    with log_path.open("ab") as stream:
        stream.write(("$ " + " ".join(str(item) for item in command) + "\n").encode("utf-8"))
        result = subprocess.run(
            command, cwd=cwd, env=environment, stdout=stream,
            stderr=subprocess.STDOUT, timeout=timeout,
        )
    require(result.returncode == 0, f"command failed with exit code {result.returncode}")


def bounded_log(source, destination, maximum=1024 * 1024):
    if not source.is_file():
        return
    data = source.read_bytes()
    if len(data) > maximum:
        data = b"[earlier output omitted]\n" + data[-maximum:]
    destination.write_bytes(data)


def write_json(path, document):
    temporary = path.with_name(path.name + ".tmp")
    require(not path.exists() and not path.is_symlink() and
            not temporary.exists() and not temporary.is_symlink(),
            "new JSON output required")
    temporary.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def copy_regular(source, destination, executable=None):
    resolved = source.resolve(strict=True)
    require(resolved.is_file(), f"regular source file required: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.exists() and not destination.is_symlink(),
            f"new runtime path required: {destination}")
    shutil.copyfile(resolved, destination)
    if executable is None:
        executable = bool(stat.S_IMODE(resolved.stat().st_mode) & 0o111)
    destination.chmod(0o755 if executable else 0o644)


def copy_static_tree(source, destination):
    regular_directory(source, "OCI static input")
    for path in sorted(source.rglob("*")):
        require(not path.is_symlink(), "OCI static input links prohibited")
        relative = path.relative_to(source)
        target = destination / relative
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif path.is_file():
            copy_regular(path, target)
        else:
            raise ValueError("OCI static input special files prohibited")


def runtime_libraries(binary):
    result = subprocess.run(
        ["ldd", str(binary)], check=True, capture_output=True, text=True, timeout=30,
    )
    require("not found" not in result.stdout, "unresolved runtime library rejected")
    libraries = set()
    for line in result.stdout.splitlines():
        fields = line.strip().split()
        if not fields or fields[0].startswith("linux-vdso"):
            continue
        value = None
        if len(fields) >= 3 and fields[1] == "=>" and fields[2].startswith("/"):
            value = fields[2]
        elif fields[0].startswith("/"):
            value = fields[0]
        if value is not None:
            path = Path(value)
            require(str(path) == value and ".." not in path.parts,
                    "canonical runtime library path required")
            libraries.add(value)
    require(0 < len(libraries) <= 256, "bounded runtime library closure required")
    require(not any("libcares.so" in value for value in libraries),
            "unexpected shared c-ares dependency")
    return sorted(libraries)


def assemble_runtime_root(binary, rootfs, environment, log):
    rootfs.mkdir(mode=0o700)
    copy_regular(binary, rootfs / "usr/local/bin/bonvoyage-dataplane", executable=True)
    libraries = runtime_libraries(binary)
    library_list = WORK_ROOT / "runtime-libraries.txt"
    library_list.write_text("".join(value + "\n" for value in libraries), encoding="utf-8")
    for value in libraries:
        copy_regular(Path(value), rootfs / value.lstrip("/"))
    run_logged([
        "python3", "-B", str(PACKAGE_INDEX), "--root", str(rootfs),
        "--libraries", str(library_list),
    ], SOURCE_ROOT, environment, log, 120)
    copy_regular(Path("/etc/os-release"), rootfs / "etc/os-release")
    copy_regular(Path("/etc/ssl/certs/ca-certificates.crt"),
                 rootfs / "etc/ssl/certs/ca-certificates.crt")
    copy_static_tree(STATIC_ROOT, rootfs)
    copy_regular(SOURCE_ROOT / "LICENSE", rootfs / "usr/share/licenses/bonvoyage/LICENSE")
    copy_regular(SOURCE_ROOT / "third_party/opentelemetry-proto/LICENSE",
                 rootfs / "usr/share/licenses/opentelemetry-proto/LICENSE")
    (rootfs / "var/lib/bonvoyage").mkdir(parents=True, exist_ok=True)
    return libraries


def build():
    expected_commit = environment_value("BONVOYAGE_SOURCE_COMMIT", COMMIT)
    expected_tag = environment_value("BONVOYAGE_SOURCE_TAG", SEMVER_TAG)
    builder_image = environment_value("BONVOYAGE_BUILDER_IMAGE", BUILDER_IMAGE)
    builder_id = environment_value("BONVOYAGE_BUILDER_ID", BUILDER_ID)
    jobs_text = os.environ.get("BONVOYAGE_BUILD_JOBS", "2")
    require(re.fullmatch(r"[1-8]", jobs_text) is not None,
            "BONVOYAGE_BUILD_JOBS must be 1 through 8")
    jobs = int(jobs_text)
    self_check(builder_image)
    regular_directory(WORK_ROOT, "work", empty=True)
    regular_directory(OUTPUT_ROOT, "output", empty=True)
    source = source_identity(SOURCE_ROOT, expected_commit, expected_tag)
    version = SEMVER_TAG.fullmatch(expected_tag).group("version")
    license_path = SOURCE_ROOT / "LICENSE"
    regular_file(license_path, "reviewed public LICENSE")
    require(license_path.stat().st_size >= 64, "substantive reviewed public LICENSE required")

    build_root = WORK_ROOT / "build"
    install_root = WORK_ROOT / "install"
    rootfs = WORK_ROOT / "rootfs"
    home = WORK_ROOT / "home"
    home.mkdir(mode=0o700)
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": str(home),
        "SOURCE_DATE_EPOCH": str(source["source_date_epoch"]),
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
        "CC": "gcc-13",
        "CXX": "g++-13",
        "PKG_CONFIG_PATH": "/opt/c-ares/lib/pkgconfig",
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(SOURCE_ROOT),
    }
    configure = [
        "cmake", "-S", str(SOURCE_ROOT / "dataplane"), "-B", str(build_root), "-G", "Ninja",
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_PREFIX_PATH=/opt/seastar;/opt/c-ares;/opt/libjwt;/opt/nghttp2;/opt/llhttp;/opt/abseil;/opt/re2",
        "-DBONVOYAGE_ENABLE_SANITIZERS=OFF",
        "-DBONVOYAGE_BUILD_DOCUMENTATION=OFF",
        "-DBONVOYAGE_RUN_RUNTIME_TESTS=ON",
        "-DBONVOYAGE_UPSTREAM_HTTP1_CLIENT=seastar-reference",
        "-DBONVOYAGE_WARNINGS_AS_ERRORS=ON",
        "-DBUILD_TESTING=ON",
    ]
    compile_command = ["cmake", "--build", str(build_root), "--parallel", str(jobs)]
    test_command = ["ctest", "--test-dir", str(build_root), "--output-on-failure"]
    install_command = ["cmake", "--install", str(build_root), "--prefix", str(install_root)]
    archive_name = f"bonvoyage-gateway-{version}-linux-amd64.oci.tar"
    archive_path = OUTPUT_ROOT / archive_name
    execution = {
        "schema_version": 1,
        "classification": CLASSIFICATION,
        "outcome": "building",
        "builder_id": builder_id,
        "builder_image": builder_image,
        "source": source,
        "platform": {"architecture": "amd64", "os": "linux"},
        "version": version,
        "build_type": "RelWithDebInfo",
        "build_jobs": jobs,
        "compiled_tests_passed": False,
        "technical_candidate_built": False,
        "reproducibility_qualified": False,
        "sbom_qualified": False,
        "scan_qualified": False,
        "signature_qualified": False,
        "provenance_qualified": False,
        "lifecycle_qualified": False,
        "release_admitted": False,
        "publishable": False,
    }
    log = WORK_ROOT / "oci-builder.log"
    try:
        run_logged(configure, SOURCE_ROOT, environment, log, 600)
        run_logged(compile_command, SOURCE_ROOT, environment, log, 3600)
        run_logged(test_command, SOURCE_ROOT, environment, log, 900)
        execution["compiled_tests_passed"] = True
        run_logged(install_command, SOURCE_ROOT, environment, log, 300)
        dataplane = install_root / "bin/bonvoyage-dataplane"
        regular_file(dataplane, "compiled dataplane installation")
        libraries = assemble_runtime_root(dataplane, rootfs, environment, log)
        assemble = subprocess.run([
            "python3", "-B", str(ASSEMBLER), "build",
            "--rootfs", str(rootfs), "--archive", str(archive_path),
            "--contract", str(CONTRACT), "--source-commit", expected_commit,
            "--source-tag", expected_tag, "--version", version,
            "--source-date-epoch", str(source["source_date_epoch"]),
        ], check=True, capture_output=True, text=True, env=environment, timeout=1200)
        assembled = json.loads(assemble.stdout)
        execution.update({key: assembled[key] for key in (
            "archive", "manifest", "config", "layer", "rootfs_entries",
            "rootfs_payload_bytes",
        )})
        execution["archive"]["path"] = archive_name
        execution["runtime_library_count"] = len(libraries)
        execution["outcome"] = "built-tested-technical-candidate"
        execution["technical_candidate_built"] = True
        require(source_identity(SOURCE_ROOT, expected_commit, expected_tag) == source,
                "source identity changed during OCI build")
        write_json(OUTPUT_ROOT / "oci-builder-execution.json", execution)
        return execution
    except Exception as error:
        execution["outcome"] = "failed"
        execution["failure"] = {"type": type(error).__name__, "message": str(error)[:1000]}
        if not (OUTPUT_ROOT / "oci-builder-execution.json").exists():
            write_json(OUTPUT_ROOT / "oci-builder-execution.json", execution)
        bounded_log(log, OUTPUT_ROOT / "oci-builder-failure.log")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-check", action="store_true")
    arguments = parser.parse_args()
    os.umask(0o077)
    try:
        if arguments.self_check:
            result = self_check(environment_value("BONVOYAGE_BUILDER_IMAGE", BUILDER_IMAGE))
        else:
            result = build()
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        raise SystemExit("OSS OCI builder rejected: " + str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))
