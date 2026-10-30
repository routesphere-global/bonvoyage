#!/usr/bin/env python3
"""Compile and package one BonVoyage OSS Debian technical candidate offline."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess


SOURCE_ROOT = Path("/workspace/source")
WORK_ROOT = Path("/workspace/work")
OUTPUT_ROOT = Path("/workspace/output")
PUBLIC_REPOSITORY = "https://github.com/routesphere-global/bonvoyage"
BUILDER_REPOSITORY = "ghcr.io/routesphere-global/bonvoyage-debian-builder"
CLASSIFICATION = "routesphere-bonvoyage-oss-deb-builder-execution"
SEMVER_TAG = re.compile(
    r"v(?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?)"
)
COMMIT = re.compile(r"[a-f0-9]{40}")
BUILDER_IMAGE = re.compile(
    r"ghcr[.]io/routesphere-global/bonvoyage-debian-builder@sha256:[a-f0-9]{64}"
)
BUILDER_ID = re.compile(r"[A-Za-z0-9._:/-]{1,128}")
RUNTIME_IDENTITY = re.compile(
    r"RouteSphere BonVoyage dataplane "
    r"(?P<dataplane>[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?) "
    r"release=(?P<release>[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?) "
    r"upstream-http1-client=(?P<client>[A-Za-z0-9._-]{1,64})"
)
REQUIRED_TOOLS = (
    "cmake",
    "ctest",
    "dh",
    "dpkg-buildpackage",
    "dpkg-deb",
    "dpkg-query",
    "g++-13",
    "git",
    "ninja",
    "protoc",
    "python3",
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
INSTALLED_LICENSES = (
    ("abseil", Path("/opt/abseil/share/licenses/abseil/LICENSE")),
    ("c-ares", Path("/opt/c-ares/share/licenses/c-ares/LICENSE.md")),
    ("libjwt", Path("/opt/libjwt/share/licenses/libjwt/LICENSE")),
    ("llhttp", Path("/opt/llhttp/share/licenses/llhttp/LICENSE-MIT")),
    ("nghttp2", Path("/opt/nghttp2/share/licenses/nghttp2/COPYING")),
    ("re2", Path("/opt/re2/share/licenses/re2/LICENSE")),
    ("seastar", Path("/opt/seastar/share/licenses/seastar/LICENSE")),
)
MAINTAINER = "RouteSphere Release <release@routesphere.global>"


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
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout


def git_text(root, *arguments):
    return git_bytes(root, *arguments).decode("utf-8").strip()


def regular_directory(path, label, empty=False):
    require(path.is_dir() and not path.is_symlink(), f"regular {label} directory required")
    resolved = path.resolve()
    require(resolved == path, f"{label} directory must not traverse symbolic links")
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


def self_check(builder_image):
    require(platform.system() == "Linux" and platform.machine() == "x86_64",
            "Linux AMD64 builder required")
    require(BUILDER_IMAGE.fullmatch(builder_image) is not None,
            "digest-pinned public builder image required")
    tools = {}
    for name in REQUIRED_TOOLS:
        tool = shutil.which(name)
        require(tool is not None and Path(tool).is_file(), f"missing builder tool: {name}")
        tools[name] = str(Path(tool).resolve())
    for name in REQUIRED_DEPENDENCIES:
        path = Path(name)
        require(path.is_file() and not path.is_symlink(), f"missing pinned dependency: {name}")
    for name, path in INSTALLED_LICENSES:
        require(path.is_file() and not path.is_symlink(), f"missing {name} license text")
    os_release = Path("/etc/os-release").read_bytes()
    fields = dict(
        line.split("=", 1) for line in os_release.decode("utf-8").splitlines() if "=" in line
    )
    require(fields.get("ID", "").strip('"') == "ubuntu" and
            fields.get("VERSION_ID", "").strip('"') == "24.04",
            "Ubuntu 24.04 builder required")
    return {
        "schema_version": 1,
        "classification": "routesphere-bonvoyage-oss-deb-builder-self-check",
        "outcome": "passed",
        "builder_image": builder_image,
        "platform": "linux/amd64",
        "os_release_sha256": digest(os_release),
        "tools": tools,
        "dependencies": list(REQUIRED_DEPENDENCIES),
        "release_admitted": False,
        "publishable": False,
    }


def third_party_license_bundle(source_root):
    sources = list(INSTALLED_LICENSES)
    sources.append(("opentelemetry-proto", source_root / "third_party/opentelemetry-proto/LICENSE"))
    sections = ["BonVoyage bundled third-party license texts\n"]
    for name, path in sorted(sources, key=lambda item: item[0]):
        require(path.is_file() and not path.is_symlink(), f"missing {name} license text")
        data = path.read_bytes()
        require(0 < len(data) <= 2 * 1024 * 1024, f"invalid {name} license size")
        try:
            body = data.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise ValueError(f"{name} license text must be UTF-8") from error
        require(body, f"empty {name} license text")
        sections.append("=" * 80 + f"\n{name}\n" + "=" * 80 + f"\n{body}\n")
    return "\n".join(sections).encode("utf-8")


def command_record(command):
    return [str(item) for item in command]


def run_logged(command, cwd, environment, log_path, timeout):
    with log_path.open("ab") as stream:
        stream.write(("$ " + " ".join(str(item) for item in command) + "\n").encode("utf-8"))
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=stream,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
    require(result.returncode == 0, f"command failed with exit code {result.returncode}")


def runtime_identity(binary, expected_release, environment):
    require(binary.is_file() and not binary.is_symlink(),
            "compiled dataplane installation is missing")
    command = [str(binary), "--smp", "1", "--memory", "256M", "--version"]
    result = subprocess.run(
        command, cwd=SOURCE_ROOT, env=environment, capture_output=True,
        text=True, timeout=30,
    )
    require(result.returncode == 0, "compiled dataplane version command failed")
    output = result.stdout.strip()
    match = RUNTIME_IDENTITY.fullmatch(output)
    require(match is not None, "compiled dataplane version output is malformed")
    identity = match.groupdict()
    require(identity["release"] == expected_release,
            "compiled dataplane release identity does not match the source tag")
    return {
        "command": command,
        "dataplane_version": identity["dataplane"],
        "release_version": identity["release"],
        "upstream_http1_client": identity["client"],
        "stdout_sha256": digest(result.stdout.encode("utf-8")),
        "stderr_sha256": digest(result.stderr.encode("utf-8")),
    }


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


def build():
    expected_commit = environment_value("BONVOYAGE_SOURCE_COMMIT", COMMIT)
    expected_tag = environment_value("BONVOYAGE_SOURCE_TAG", SEMVER_TAG)
    builder_image = environment_value("BONVOYAGE_BUILDER_IMAGE", BUILDER_IMAGE)
    builder_id = environment_value("BONVOYAGE_BUILDER_ID", BUILDER_ID)
    jobs_text = os.environ.get("BONVOYAGE_BUILD_JOBS", "2")
    require(re.fullmatch(r"[1-8]", jobs_text) is not None, "BONVOYAGE_BUILD_JOBS must be 1 through 8")
    jobs = int(jobs_text)

    self_check(builder_image)
    regular_directory(WORK_ROOT, "work", empty=True)
    regular_directory(OUTPUT_ROOT, "output", empty=True)
    source = source_identity(SOURCE_ROOT, expected_commit, expected_tag)
    version = SEMVER_TAG.fullmatch(expected_tag).group("version")
    license_path = SOURCE_ROOT / "LICENSE"
    require(license_path.is_file() and not license_path.is_symlink(),
            "reviewed public LICENSE file required")
    third_party_notices = SOURCE_ROOT / "packaging/release/licenses/THIRD_PARTY_NOTICES.md"
    third_party_source = SOURCE_ROOT / "packaging/release/licenses/THIRD_PARTY_SOURCE.md"
    for label, path in (("third-party notices", third_party_notices),
                        ("third-party source instructions", third_party_source)):
        require(path.is_file() and not path.is_symlink(), f"reviewed {label} required")

    build_root = WORK_ROOT / "build"
    install_root = WORK_ROOT / "install"
    inputs_root = WORK_ROOT / "inputs"
    package_root = WORK_ROOT / "package"
    home = WORK_ROOT / "home"
    for directory in (build_root, inputs_root, home):
        directory.mkdir(mode=0o700)

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
        f"-DBONVOYAGE_RELEASE_VERSION={version}",
        "-DBUILD_TESTING=ON",
    ]
    compile_command = ["cmake", "--build", str(build_root), "--parallel", str(jobs)]
    test_command = ["ctest", "--test-dir", str(build_root), "--output-on-failure"]
    install_command = ["cmake", "--install", str(build_root), "--prefix", str(install_root)]
    execution = {
        "schema_version": 1,
        "classification": CLASSIFICATION,
        "outcome": "building",
        "builder_id": builder_id,
        "builder_image": builder_image,
        "source": source,
        "platform": "linux/amd64",
        "build_type": "RelWithDebInfo",
        "build_jobs": jobs,
        "commands": {
            "configure": command_record(configure),
            "compile": command_record(compile_command),
            "test": command_record(test_command),
            "install": command_record(install_command),
        },
        "compiled_tests_passed": False,
        "technical_candidate_built": False,
        "release_admitted": False,
        "publishable": False,
    }
    log = WORK_ROOT / "builder.log"
    try:
        run_logged(configure, SOURCE_ROOT, environment, log, 600)
        run_logged(compile_command, SOURCE_ROOT, environment, log, 3600)
        run_logged(test_command, SOURCE_ROOT, environment, log, 900)
        execution["compiled_tests_passed"] = True
        run_logged(install_command, SOURCE_ROOT, environment, log, 300)
        dataplane = install_root / "bin/bonvoyage-dataplane"
        execution["runtime_identity"] = runtime_identity(dataplane, version, environment)

        toolchain = inputs_root / "toolchain-lock.json"
        run_logged([
            "python3", "-B", str(SOURCE_ROOT / "scripts/capture-oss-deb-toolchain.py"),
            "--builder-image", builder_image, "--output", str(toolchain),
        ], SOURCE_ROOT, environment, log, 60)
        shutil.copyfile(dataplane, inputs_root / "bonvoyage-dataplane")
        (inputs_root / "bonvoyage-dataplane").chmod(0o700)
        shutil.copyfile(license_path, inputs_root / "LICENSE")
        shutil.copyfile(third_party_notices, inputs_root / "THIRD_PARTY_NOTICES.md")
        shutil.copyfile(third_party_source, inputs_root / "THIRD_PARTY_SOURCE.md")
        (inputs_root / "THIRD_PARTY_LICENSES.txt").write_bytes(
            third_party_license_bundle(SOURCE_ROOT))
        manifest = inputs_root / "inputs.json"
        input_result = subprocess.run([
            "python3", "-B", str(SOURCE_ROOT / "scripts/create-oss-deb-input.py"),
            "--source-root", str(SOURCE_ROOT),
            "--release-version", version,
            "--package-revision", "1",
            "--maintainer", MAINTAINER,
            "--dataplane", str(inputs_root / "bonvoyage-dataplane"),
            "--copyright", str(inputs_root / "LICENSE"),
            "--third-party-notices", str(inputs_root / "THIRD_PARTY_NOTICES.md"),
            "--third-party-source", str(inputs_root / "THIRD_PARTY_SOURCE.md"),
            "--third-party-licenses", str(inputs_root / "THIRD_PARTY_LICENSES.txt"),
            "--toolchain-lock", str(toolchain),
            "--output", str(manifest),
        ], check=True, capture_output=True, text=True, env=environment, timeout=60)
        manifest_result = json.loads(input_result.stdout)
        run_logged([
            "python3", "-B", str(SOURCE_ROOT / "scripts/build-oss-deb.py"),
            "--inputs", str(manifest),
            "--manifest-sha256", manifest_result["manifest_sha256"],
            "--output", str(package_root),
            "--builder-id", builder_id,
        ], SOURCE_ROOT, environment, log, 1200)
        packages = list(package_root.glob("bonvoyage-gateway_*_amd64.deb"))
        require(len(packages) == 1, "exactly one Debian package output required")
        for source_path in (packages[0], package_root / "build-receipt.json"):
            require(source_path.is_file() and not source_path.is_symlink(),
                    "regular bounded package output required")
            shutil.copyfile(source_path, OUTPUT_ROOT / source_path.name)
        execution["outcome"] = "built-tested-technical-candidate"
        execution["technical_candidate_built"] = True
        execution["package"] = {
            "path": packages[0].name,
            "bytes": packages[0].stat().st_size,
            "sha256": digest(packages[0].read_bytes()),
        }
        require(source_identity(SOURCE_ROOT, expected_commit, expected_tag) == source,
                "source identity changed during hosted build")
        write_json(OUTPUT_ROOT / "builder-execution.json", execution)
        return execution
    except Exception as error:
        execution["outcome"] = "failed"
        execution["failure"] = {"type": type(error).__name__, "message": str(error)[:1000]}
        if not (OUTPUT_ROOT / "builder-execution.json").exists():
            write_json(OUTPUT_ROOT / "builder-execution.json", execution)
        bounded_log(log, OUTPUT_ROOT / "builder-failure.log")
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
        raise SystemExit("OSS Debian builder rejected: " + str(error)) from error
    print(json.dumps(result, indent=2, sort_keys=True))
