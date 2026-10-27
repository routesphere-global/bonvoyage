#!/usr/bin/env python3
"""Private Unix log receiver with acknowledged pause/resume for local fixtures."""

import argparse
import collections
import json
import os
import re
import select
import signal
import socket


EVENT = re.compile(r"(?:^| )event=([a-z_]+)(?: |$)")


def serve(directory):
    log_path = os.path.join(directory, "logger.sock")
    control_path = os.path.join(directory, "control.sock")
    for path in (log_path, control_path):
        if os.path.lexists(path):
            raise FileExistsError("fixture socket already exists: " + path)

    receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    controller = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    received = 0
    invalid = 0
    paused = False
    running = True
    events = collections.Counter()

    def stop_signal(_number, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop_signal)
    try:
        receiver.bind(log_path)
        os.chmod(log_path, 0o777)
        receiver.setblocking(False)
        controller.bind(control_path)
        os.chmod(control_path, 0o600)
        controller.listen(4)

        with open(os.path.join(directory, "records.jsonl"), "w", encoding="utf-8") as output:
            while running:
                ready, _, _ = select.select(
                    [controller] + ([] if paused else [receiver]), [], [], 0.2
                )
                if controller in ready:
                    connection, _ = controller.accept()
                    with connection:
                        connection.settimeout(2)
                        command = connection.recv(32).decode("ascii")
                        if command == "pause":
                            paused = True
                        elif command == "resume":
                            paused = False
                        elif command == "stop":
                            running = False
                        elif command != "status":
                            raise ValueError("unsupported fixture receiver command")
                        result = {"command": command, "paused": paused,
                                  "received": received, "invalid": invalid,
                                  "events": dict(events)}
                        connection.sendall(json.dumps(result, sort_keys=True).encode())
                if not paused and receiver in ready:
                    for _ in range(1024):
                        try:
                            raw = receiver.recv(4096)
                        except BlockingIOError:
                            break
                        text = raw.decode("utf-8", errors="replace")
                        if not (0 < len(raw) <= 2048 and text.startswith("<")):
                            invalid += 1
                        match = EVENT.search(text)
                        if match:
                            events[match[1]] += 1
                        received += 1
                        output.write(json.dumps({"record": text}, sort_keys=True) + "\n")
                    output.flush()
    finally:
        receiver.close()
        controller.close()
        for path in (log_path, control_path):
            if os.path.lexists(path):
                os.unlink(path)


def control(directory, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(2)
        connection.connect(os.path.join(directory, "control.sock"))
        connection.sendall(command.encode("ascii"))
        response = bytearray()
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    result = json.loads(response)
    if result["command"] != command or result["invalid"] != 0:
        raise AssertionError("receiver control or record validation failed")
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", default="/runtime-log")
    commands = parser.add_subparsers(dest="action", required=True)
    commands.add_parser("serve")
    controls = commands.add_parser("control")
    controls.add_argument("command", choices=("status", "pause", "resume", "stop"))
    args = parser.parse_args()
    if args.action == "serve":
        serve(args.directory)
    else:
        control(args.directory, args.command)


if __name__ == "__main__":
    main()
