"""Bounded controlled-receiver tests; never bind a host's logging socket."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import statistics
import subprocess
import time

MODES = ("disabled", "syslog", "stdout")
COST_COUNT = 1024
PAYLOAD_BYTES = 256
REPETITIONS = 5
HOLD_SECONDS = 0.25


def require(value, message):
    if not value:
        raise RuntimeError(message)


def validate_case(case):
    """Do not equate returned logger calls with delivered records."""
    require(case["mode"] in MODES, "unknown sink")
    require(type(case["count"]) is int and 1 <= case["count"] <= 4096, "invalid call count")
    require(type(case["payload_bytes"]) is int and 1 <= case["payload_bytes"] <= 1024, "invalid payload")
    require(case["exit_code"] == 0, "emitter failed")
    complete = [event for event in case["events"] if event.get("event") == "complete"]
    begin = [event for event in case["events"] if event.get("event") == "begin"]
    require(len(begin) == len(complete) == 1, "missing or duplicate emitter receipt")
    summary = complete[0]
    require(begin[0]["pid"] == summary["pid"] == case["pid"], "process identity changed")
    require(summary["calls_returned"] == case["count"], "incomplete call execution")
    require(all(type(summary[key]) is int and summary[key] >= 0 for key in ("cpu_us", "wall_ns", "max_call_ns")), "invalid timing")
    require(0 < summary["max_call_ns"] <= summary["wall_ns"], "invalid call duration")
    raw = "".join(case["received"])
    matches = re.findall(r"BVLOG_PRESSURE seq=(\d+) payload=(x+)", raw)
    expected = [] if case["mode"] == "disabled" or case["missing_receiver"] else list(range(case["count"]))
    require(raw.count("BVLOG_PRESSURE") == len(expected), "unparsed or unexpected delivery record")
    require(bool(expected) or not raw, "unexpected output from unavailable or disabled sink")
    require([int(seq) for seq, _ in matches] == expected, "missing, duplicate or reordered delivery")
    require(all(len(payload) == case["payload_bytes"] for _, payload in matches), "payload truncated")
    if case["paused"]:
        expected_wait = "unix_wait_for_peer" if case["mode"] == "syslog" else "pipe_write"
        require(case["filled_units"] > 0 and case["saturation_errno"] == "EAGAIN", "receiver not proven full")
        require(case["blocked_wait_channel"] == expected_wait, "sender not observed waiting in sink")
        require(case["alive_before_resume"] is True and case["completed_before_resume"] < case["count"], "sender completed while receiver paused")
        require(case["held_seconds"] >= HOLD_SECONDS and summary["max_call_ns"] >= int(HOLD_SECONDS * 0.8e9), "pressure interval not observed")
    return summary


def validate_result(result):
    require(result["classification"] == "isolated-logging-backpressure-cost", "wrong fixture type")
    cases = result["cases"]
    require([case["name"] for case in cases] == ["syslog-paused", "stdout-paused", "syslog-missing"], "incomplete pressure matrix")
    for case in cases + result["warmups"] + result["cost_samples"]:
        validate_case(case)
    require([(c["mode"], c["paused"], c["missing_receiver"]) for c in cases] ==
            [("syslog", True, False), ("stdout", True, False), ("syslog", False, True)], "wrong pressure matrix")
    require([c["mode"] for c in result["warmups"]] == list(MODES), "incomplete warmups")
    samples = result["cost_samples"]
    require(len(samples) == REPETITIONS * len(MODES), "wrong cost sample count")
    for repetition in range(1, REPETITIONS + 1):
        group = [c for c in samples if c["repetition"] == repetition]
        order = list(MODES[repetition % 3:] + MODES[:repetition % 3])
        require([c["mode"] for c in group] == order, "missing, duplicate or unordered repetition")
        require(all(c["count"] == COST_COUNT and c["payload_bytes"] == PAYLOAD_BYTES and
                    c["paused"] is False and c["missing_receiver"] is False for c in group), "noncomparable cost sample")
    return {mode: {"median_sender_cpu_ns_per_call": statistics.median(
        validate_case(c)["cpu_us"] * 1000 / c["count"] for c in samples if c["mode"] == mode),
        "median_sender_wall_ns_per_call": statistics.median(
        validate_case(c)["wall_ns"] / c["count"] for c in samples if c["mode"] == mode)} for mode in MODES}


def run_case(mode, count, *, paused=False, missing=False, name, repetition=None):
    case = dict(name=name, mode=mode, count=count, payload_bytes=PAYLOAD_BYTES,
                paused=paused, missing_receiver=missing, repetition=repetition, received=[], events=[])
    receiver = filler = process = None
    read_fd = write_fd = None
    socket_identity = None
    stream_data = bytearray()
    stderr_data = bytearray()
    selector = selectors.DefaultSelector()
    socket_path = Path("/dev/log")
    try:
        require(not socket_path.exists() and not socket_path.is_symlink(), "foreign logging socket exists")
        case.update(filled_units=0, saturation_errno=None)
        if mode == "syslog" and not missing:
            receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            receiver.bind(str(socket_path))
            socket_identity = socket_path.lstat().st_ino
            receiver.setblocking(False)
            if paused:
                filler = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                filler.setblocking(False)
                filler.connect(str(socket_path))
                for _ in range(4096):
                    try:
                        filler.send(b"BVLOG_FILLER")
                        case["filled_units"] += 1
                    except BlockingIOError:
                        case["saturation_errno"] = "EAGAIN"
                        break
                require(case["saturation_errno"] == "EAGAIN", "syslog queue not bounded")
        if mode in ("stdout", "disabled"):
            read_fd, write_fd = os.pipe()
            os.set_blocking(read_fd, False)
            if paused:
                os.set_blocking(write_fd, False)
                for _ in range(4096):
                    try:
                        case["filled_units"] += os.write(write_fd, b"\0" * 4096)
                    except BlockingIOError:
                        case["saturation_errno"] = "EAGAIN"
                        break
                os.set_blocking(write_fd, True)
                require(case["saturation_errno"] == "EAGAIN", "stdout pipe not bounded")
        argv = ["/fixture/pressure-emitter", "--count", str(count), "--payload-bytes", str(PAYLOAD_BYTES),
                "--log-to-syslog", "1" if mode == "syslog" else "0", "--log-to-stdout",
                "1" if mode == "stdout" else "0", "--logger-ostream-type", "stdout", "--log-with-color", "0"]
        if mode == "disabled":
            argv.append("--disabled")
        if paused:
            argv.append("--progress")
        case["argv"] = argv
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=write_fd if write_fd is not None else subprocess.DEVNULL,
                                   stderr=subprocess.PIPE)
        case["pid"] = process.pid
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
        os.set_blocking(process.stderr.fileno(), False)
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        draining = not paused
        receive_fd = receiver if receiver else read_fd
        if draining and receive_fd is not None:
            selector.register(receive_fd, selectors.EVENT_READ, "receiver")
        stderr_open = True
        started = time.monotonic()
        blocked_at = None
        channels = []

        def drain():
            for _ in range(256):
                try:
                    chunk = receiver.recv(16384) if receiver else os.read(read_fd, 65536) if read_fd is not None else b""
                except BlockingIOError:
                    return
                if not chunk:
                    return
                if receiver:
                    case["received"].append(chunk.decode("utf-8"))
                else:
                    stream_data.extend(chunk)

        while True:
            require(time.monotonic() - started < 12, "emitter watchdog expired")
            for key, _ in selector.select(0.005):
                if key.data == "receiver":
                    drain()
                    continue
                chunk = os.read(key.fd, 65536)
                if chunk:
                    stderr_data.extend(chunk)
                else:
                    selector.unregister(key.fileobj)
                    stderr_open = False
            events = [json.loads(line) for line in stderr_data.splitlines() if line.endswith(b"}")]
            if paused and not draining:
                require(process.poll() is None, "emitter exited before receiver resume")
                channel = Path(f"/proc/{process.pid}/wchan").read_text().strip()
                if not channels or channels[-1] != channel:
                    channels.append(channel)
                expected = "unix_wait_for_peer" if mode == "syslog" else "pipe_write"
                if channel == expected and any(e.get("event") == "begin" for e in events):
                    if blocked_at is None:
                        blocked_at = time.monotonic()
                    if time.monotonic() - blocked_at >= HOLD_SECONDS:
                        case.update(blocked_wait_channel=channel, wait_channels=channels,
                                    held_seconds=time.monotonic() - blocked_at,
                                    alive_before_resume=process.poll() is None,
                                    completed_before_resume=max([e["returned"] for e in events if e.get("event") == "progress"] or [0]))
                        draining = True
                        selector.register(receive_fd, selectors.EVENT_READ, "receiver")
            if draining:
                drain()
            if process.poll() is not None and not stderr_open:
                drain()
                break
        if read_fd is not None:
            case["received"].append(stream_data.decode("utf-8"))
        case.update(exit_code=process.returncode, events=[json.loads(line) for line in stderr_data.splitlines()],
                    elapsed_seconds=time.monotonic() - started)
        validate_case(case)
        return case
    except BaseException as error:
        case.update(error=str(error), stderr_partial=stderr_data.decode("utf-8", "replace"))
        error.fixture_case = case
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5)
            process.stderr.close()
        selector.close()
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        for sock in (filler, receiver):
            if sock is not None:
                sock.close()
        if socket_identity is not None:
            require(socket_path.lstat().st_ino == socket_identity, "logging socket ownership changed")
            socket_path.unlink()


def main():
    if not Path("/.dockerenv").is_file() or os.environ.get("BONVOYAGE_ISOLATED_LOGGING_FIXTURE") != "1":
        raise SystemExit("refusing non-fixture execution")
    result = dict(classification="isolated-logging-backpressure-cost", status="failed", cases=[], warmups=[], cost_samples=[],
                  unit_sha256=hashlib.sha256(Path("/fixture/bonvoyage.service").read_bytes()).hexdigest(),
                  seastar_binding=Path("/fixture/pressure-binding.txt").read_text(),
                  compiler=Path("/fixture/pressure-compiler.txt").read_text(),
                  emitter_optimization=["-O3", "-DNDEBUG"],
                  kernel_release=os.uname().release,
                  max_dgram_qlen=Path("/proc/sys/net/unix/max_dgram_qlen").read_text().strip(),
                  limitations=["synchronous emitter without reactor, gateway or HTTP workload",
                               "controlled receiver, not journald/rsyslog policy or durable retention",
                               "sender CPU excludes collector CPU; wall includes scheduling and receiver delay",
                               "per-call clocks add overhead; not allocation accounting or a zero-cost claim",
                               "no performance pass threshold; local directional samples only"])
    try:
        result["cases"].append(run_case("syslog", 32, paused=True, name="syslog-paused"))
        result["cases"].append(run_case("stdout", 32, paused=True, name="stdout-paused"))
        result["cases"].append(run_case("syslog", 32, missing=True, name="syslog-missing"))
        for mode in MODES:
            result["warmups"].append(run_case(mode, 64, name="warmup-" + mode))
        for repetition in range(1, REPETITIONS + 1):
            for mode in MODES[repetition % 3:] + MODES[:repetition % 3]:
                result["cost_samples"].append(run_case(mode, COST_COUNT, name=f"cost-{repetition}-{mode}", repetition=repetition))
        result["cost_summary"] = validate_result(result)
        result["status"] = "passed"
    except BaseException as error:
        result.update(error=str(error), failed_case=getattr(error, "fixture_case", None))
        raise
    finally:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
