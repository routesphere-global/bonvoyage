"""Exercise the exact embedded Python without Docker or host ownership changes."""

import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


HELPER = Path(__file__).with_name("test-fixture-secrets.sh").read_text()


def embedded(marker):
    return HELPER.split("<<'" + marker + "'", 1)[1].split("\n", 1)[1].split("\n" + marker, 1)[0]


COPY = compile(embedded("BV_FIXTURE_COPY_PY"), "fixture-copy", "exec")
PROBE = embedded("BV_GATEWAY_PROBE_PY")


class CopyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="bv-copy-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.destination = self.root / "destination"
        self.source.mkdir()
        self.destination.mkdir()
        self.names = ["server-chain.pem", "server-key.pem"]
        for name in self.names + ["ca-key.pem"]:
            (self.source / name).write_bytes((name + "\0fixture\n").encode())
        (self.source / "server-key.pem").chmod(0o600)

    def copy(self, names=None, source=None, destination=None):
        argv = ["fixture-copy", str(source or self.source), str(destination or self.destination),
                *(self.names if names is None else names)]
        # Do not chown host temp files. Record intended ownership while executing
        # real descriptor opens, copying, replacement, chmod and rejection logic.
        with mock.patch.object(sys, "argv", argv), mock.patch.object(os, "fchown") as chown:
            exec(COPY, {"__name__": "__main__"})
        return chown

    def test_only_allowlisted_files_modes_and_ownership_requests(self):
        before = {p.name: (p.read_bytes(), p.stat()) for p in self.source.iterdir()}
        chown = self.copy()
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), sorted(self.names))
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        for name in self.names:
            target = self.destination / name
            self.assertEqual(target.read_bytes(), before[name][0])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(chown.call_count, 3)
        for call in chown.call_args_list:
            self.assertEqual(call.args[1:], (65532, 65532))
        for p in self.source.iterdir():
            self.assertEqual(p.read_bytes(), before[p.name][0])
            self.assertEqual(p.stat().st_mode, before[p.name][1].st_mode)
            self.assertEqual(p.stat().st_uid, before[p.name][1].st_uid)
            self.assertEqual(p.stat().st_gid, before[p.name][1].st_gid)
            self.assertEqual(p.stat().st_mtime_ns, before[p.name][1].st_mtime_ns)

    def test_intentional_invalid_certificate_refresh_same_directory(self):
        self.copy()
        inode = self.destination.stat().st_ino
        (self.source / self.names[0]).write_text("not a certificate")
        self.copy()
        self.assertEqual(self.destination.stat().st_ino, inode)
        self.assertEqual((self.destination / self.names[0]).read_text(), "not a certificate")

    def test_bad_missing_and_duplicate_allowlist_validated_before_write(self):
        for names in [[], [self.names[0]] * 2, ["../escape"], ["/absolute"], ["."], [".."],
                      ["-option"], ["bad\nname"], ["bad/name"], ["bad name"], [""],
                      [self.names[0], "missing.pem"]]:
            with self.subTest(names=names), self.assertRaises((ValueError, OSError)):
                self.copy(names)
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_source_symlink_dangling_symlink_directory_and_fifo_rejected(self):
        candidate = self.source / "bad.pem"
        for kind in ["symlink", "dangling", "directory", "fifo"]:
            if kind == "symlink":
                candidate.symlink_to(self.source / self.names[0])
            elif kind == "dangling":
                candidate.symlink_to(self.source / "missing")
            elif kind == "directory":
                candidate.mkdir()
            else:
                os.mkfifo(candidate)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                self.copy([self.names[0], candidate.name])
            self.assertEqual(list(self.destination.iterdir()), [])
            if kind == "directory":
                candidate.rmdir()
            else:
                candidate.unlink()

    def test_destination_symlink_directory_fifo_and_unlisted_entry_rejected(self):
        target = self.destination / self.names[0]
        original = (self.source / self.names[0]).read_bytes()
        for kind in ["symlink", "dangling", "directory", "fifo", "unlisted"]:
            candidate = self.destination / "unlisted.pem" if kind == "unlisted" else target
            if kind in ("symlink", "unlisted"):
                candidate.symlink_to(self.source / self.names[0])
            elif kind == "dangling":
                candidate.symlink_to(self.root / "missing")
            elif kind == "directory":
                candidate.mkdir()
            else:
                os.mkfifo(candidate)
            with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                self.copy()
            self.assertEqual((self.source / self.names[0]).read_bytes(), original)
            self.assertFalse((self.destination / self.names[1]).exists())
            if kind == "directory":
                candidate.rmdir()
            else:
                candidate.unlink()

    def test_directory_roots_cannot_be_symlinks(self):
        for key, target in [("source", self.source), ("destination", self.destination)]:
            link = self.root / (key + "-link")
            link.symlink_to(target, target_is_directory=True)
            with self.subTest(root=key), self.assertRaises(OSError):
                self.copy(**{key: link})

    def test_hardlinked_destination_replaced_without_mutating_other_file(self):
        outside = self.root / "untouched"
        outside.write_bytes(b"untouched")
        os.link(outside, self.destination / self.names[0])
        self.copy()
        self.assertEqual(outside.read_bytes(), b"untouched")
        self.assertEqual((self.destination / self.names[0]).stat().st_nlink, 1)

    def test_copy_error_removes_partial_temporary_file(self):
        with mock.patch("shutil.copyfileobj", side_effect=OSError("copy failed")):
            with self.assertRaisesRegex(OSError, "copy failed"):
                self.copy()
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_raced_source_fifo_does_not_block(self):
        real_open = os.open
        switched = False

        def raced_open(name, flags, *args, **kwargs):
            nonlocal switched
            if name == self.names[0] and not switched:
                switched = True
                (self.source / name).unlink()
                os.mkfifo(self.source / name)
                self.assertTrue(flags & os.O_NONBLOCK)
            return real_open(name, flags, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=raced_open):
            with self.assertRaisesRegex(ValueError, "changed to a non-regular"):
                self.copy()


class ProbeTests(unittest.TestCase):
    def test_http_status_and_url_argument(self):
        url = 'http://gateway:9901/health/ready?quote=";not-code'
        for status in [200, 503]:
            response = mock.MagicMock()
            response.__enter__.return_value.status = status
            with mock.patch.object(sys, "argv", ["probe", url]), \
                    mock.patch("urllib.request.urlopen", return_value=response) as urlopen, \
                    mock.patch("signal.signal") as handler, mock.patch("signal.alarm") as alarm:
                if status == 200:
                    exec(PROBE, {})
                else:
                    with self.assertRaises(SystemExit):
                        exec(PROBE, {})
                urlopen.assert_called_once_with(url, timeout=1)
                handler.assert_called_once_with(signal.SIGALRM, signal.SIG_DFL)
                self.assertEqual(alarm.call_args_list, [mock.call(1), mock.call(0)])

    @unittest.skipUnless(hasattr(signal, "SIGALRM"), "requires POSIX signals")
    def test_alarm_interrupts_blocked_dns(self):
        # Actual urllib resolution reaches this simulated stuck DNS call. Run in
        # a subprocess so a broken alarm fails the test instead of hanging it.
        prefix = """
import socket
import time
import urllib.request
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
def blocked_dns(*args, **kwargs):
    print('entered DNS', flush=True)
    time.sleep(60)
socket.getaddrinfo = blocked_dns
"""
        started = time.monotonic()
        result = subprocess.run([sys.executable, "-c", prefix + PROBE,
                                 "http://fixture-dns.invalid:9901/health/ready"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, -signal.SIGALRM)
        self.assertIn("entered DNS", result.stdout)
        self.assertLess(time.monotonic() - started, 4)


if __name__ == "__main__":
    unittest.main()
