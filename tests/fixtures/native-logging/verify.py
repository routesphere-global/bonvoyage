"""Real local journald/syslog fixture; never run on the host or the AWS VM."""
import configparser
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import time


def run(argv):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    if result.returncode:
        raise RuntimeError(f"{argv}: {result.returncode}: {result.stderr}")
    return result.stdout


def wait_for(check):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise AssertionError("logging fixture deadline exceeded")


def journal():
    return [json.loads(line) for line in run(
        ["journalctl", "--no-pager", "--output=json", "--all"]).splitlines()]


def message(record):
    value = record.get("MESSAGE", "")
    # journalctl JSON represents control-containing fields as byte arrays.
    # Decode only for assertions; retain the original records as evidence.
    return bytes(value).decode("utf-8") if isinstance(value, list) else value


def marked(records, marker):
    return [record for record in records if marker in message(record)]


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise AssertionError("logging daemon required forced termination")


def main():
    if not Path("/.dockerenv").is_file() or os.environ.get("BONVOYAGE_ISOLATED_LOGGING_FIXTURE") != "1":
        raise SystemExit("refusing non-fixture execution")
    service = configparser.ConfigParser(interpolation=None)
    service.read("/fixture/bonvoyage.service")
    unit = service["Service"]
    policy_document = configparser.ConfigParser(interpolation=None)
    policy_document.read("/fixture/no-wall.conf")
    assert dict(policy_document["Journal"]) == {"forwardtowall": "no"}
    assert unit["StandardOutput"] == unit["StandardError"] == "journal"
    assert unit["SyslogLevelPrefix"] == "no" and unit["SyslogLevel"] == "info"
    argv = shlex.split(unit["ExecStart"])
    flags = []
    for key, value in {"--log-to-syslog": "1", "--log-to-stdout": "0", "--log-with-color": "0"}.items():
        assert argv.count(key) == 1 and argv[argv.index(key) + 1] == value
        flags.extend([key, value])
    run(["systemd-machine-id-setup"])
    run(["systemd-analyze", "verify", "/fixture/bonvoyage.service"])
    for path in ("/run/systemd/journal", "/run/log/journal", "/etc/systemd/journald.conf.d"):
        Path(path).mkdir(parents=True, exist_ok=True)
    Path("/dev/log").symlink_to("/run/systemd/journal/dev-log")
    # Only container paths are modified. No host sockets, journals or terminals
    # are mounted. Finite local retention, no kernel collection or network sink.
    Path("/etc/systemd/journald.conf").write_text(
        "[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\nReadKMsg=no\n"
        "ForwardToSyslog=yes\nForwardToWall=yes\nRateLimitIntervalSec=0\n")
    policy = Path("/etc/systemd/journald.conf.d/90-bonvoyage-no-wall.conf")
    rsyslog_config = Path("/fixture/rsyslog.conf")
    common = '''module(load="imuxsock" SysSock.Use="off")
input(type="imuxsock" Socket="/run/systemd/journal/syslog" CreatePath="on")
$EscapeControlCharactersOnReceive on
template(name="FixtureJSON" type="string" string="{\\"priority\\":%syslogseverity%,\\"message\\":\\"%msg:::json%\\"}\\n")
*.* action(type="omfile" file="/fixture/forwarded.jsonl" template="FixtureJSON")
'''
    wall = "*.emerg :omusrmsg:*\n"
    original = common + wall
    journald = rsyslog = None
    journal_log = open("/fixture/journald.log", "w")
    rsyslog_log = open("/fixture/rsyslog.log", "w")
    result = {"classification": "isolated-local-logging-fixture", "phases": [],
              "unit_sha256": hashlib.sha256(Path("/fixture/bonvoyage.service").read_bytes()).hexdigest(),
              "packages": run(["dpkg-query", "-W", "systemd", "rsyslog"]),
              "seastar_binding": Path("/fixture/seastar-binding.txt").read_text(),
              "limitations": ["not a systemd PID-1 service installation", "no logged-in terminal broadcast assertion",
                              "not AMD64 package acceptance or throughput qualification"]}
    try:
        for phase in ("baseline", "no-wall", "rollback"):
            stop(journald)
            stop(rsyslog)
            if phase == "no-wall":
                policy.write_bytes(Path("/fixture/no-wall.conf").read_bytes())
                rsyslog_config.write_text(common + "# Operator disabled terminal broadcast: " + wall)
            else:
                policy.unlink(missing_ok=True)
                rsyslog_config.write_text(original)
            if phase == "rollback":
                assert rsyslog_config.read_text() == original and not policy.exists()
            run(["rsyslogd", "-N1", "-f", str(rsyslog_config)])
            rsyslog = subprocess.Popen(["rsyslogd", "-n", "-i", "/run/fixture-rsyslog.pid", "-f", str(rsyslog_config)],
                                       stdout=rsyslog_log, stderr=rsyslog_log)
            wait_for(lambda: Path("/run/systemd/journal/syslog").is_socket())
            journald = subprocess.Popen(["/usr/lib/systemd/systemd-journald"], stdout=journal_log, stderr=journal_log)
            wait_for(lambda: Path("/run/systemd/journal/stdout").is_socket())
            # systemd-cat configures the real journald stream protocol with the
            # same priority-prefix setting as the unit, without host PID 1.
            before = len(marked(journal(), "BVLOG-"))
            run(["systemd-cat", "--identifier=bonvoyage-fixture", "--priority=info",
                 "--stderr-priority=info", "--level-prefix=false", "/fixture/emitter", *flags])
            def new_records():
                records = marked(journal(), "BVLOG-")[before:]
                return records if len(records) >= 7 else []
            records = wait_for(new_records)
            expected = {"trace": 7, "debug": 7, "info": 6, "warn": 4, "error": 3,
                        "raw-stdout": 6, "raw-stderr": 6}
            assert len(records) == 7, records
            for name, priority in expected.items():
                matches = marked(records, "BVLOG-" + name)
                assert len(matches) == 1 and int(matches[0]["PRIORITY"]) == priority, matches
            warning = marked(records, "BVLOG-warn")[0]
            assert "\n<0>untrusted-priority" in message(warning) and "literal %s" in message(warning)
            assert not any(record["PRIORITY"] == "0" for record in records)
            def forwarded():
                path = Path("/fixture/forwarded.jsonl")
                return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
            # Forwarding stays available when terminal broadcasting is disabled.
            count = len(result["phases"]) + 1
            for name, priority in expected.items():
                matches = wait_for(lambda: [record for record in forwarded() if "BVLOG-" + name in record["message"]]
                                   if sum("BVLOG-" + name in record["message"] for record in forwarded()) >= count else [])
                assert len(matches) == count and all(record["priority"] == priority for record in matches)
            combined = run(["systemd-analyze", "cat-config", "systemd/journald.conf"])
            effective = configparser.ConfigParser(interpolation=None, strict=False)
            effective.read_string(combined)
            assert effective["Journal"]["ForwardToWall"] == ("no" if phase == "no-wall" else "yes")
            assert effective["Journal"]["ForwardToSyslog"] == "yes"
            result["phases"].append({"name": phase, "records": records, "forwarding_verified": True,
                                     "journald_config": combined,
                                     "rsyslog_config": rsyslog_config.read_text()})
        # Positive control: prefix interpretation really changes journal
        # priority when enabled. Only benign text in a terminal-free container.
        run(["systemd-cat", "--identifier=bonvoyage-control", "--priority=info", "--level-prefix=true",
             "printf", "<0>BVLOG-positive-control\n"])
        control = wait_for(lambda: marked(journal(), "BVLOG-positive-control"))
        assert len(control) == 1 and control[0]["PRIORITY"] == "0", control
        result["positive_control"] = control
        assert len(marked(journal(), "BVLOG-")) == 22
        result["status"] = "passed"
    finally:
        result["journal_raw"] = journal()
        stop(journald)
        stop(rsyslog)
        journal_log.close()
        rsyslog_log.close()
        result["journald_log"] = Path("/fixture/journald.log").read_text()
        result["rsyslog_log"] = Path("/fixture/rsyslog.log").read_text()
        result["forwarded_log"] = Path("/fixture/forwarded.jsonl").read_text() if Path("/fixture/forwarded.jsonl").exists() else ""
        print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    main()
