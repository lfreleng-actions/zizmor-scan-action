# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for scripts/zizmor_fetch.py.

The script runs as the action runs it: ``python3 -I`` in a subprocess,
configured through the environment. These tests import it as a module
so they can substitute the network, the attestation check and the clock;
nothing here touches the network or sleeps. Run with
``python3 -m unittest discover -s tests``.
"""

import __future__

import contextlib
import email.message
import hashlib
import http.client
import http.server
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
SCRIPT = SCRIPTS / "zizmor_fetch.py"

VERSION = "1.31.1"
TAG = f"v{VERSION}"
PRIMARY_BINARY = b"#!/bin/sh\necho primary\n"
FALLBACK_BINARY = b"#!/bin/sh\necho fallback\n"


def load_module(name: str) -> ModuleType:
    """Import a script module once, failing the calling test if absent."""
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # The scripts import each other by name, as they do when run directly.
    if str(SCRIPTS) not in sys.path:
        sys.path.insert(0, str(SCRIPTS))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def load() -> ModuleType:
    """The sourcing module: platform assets, wheels and the fetch order."""
    return load_module("zizmor_fetch")


def transfer() -> ModuleType:
    """The transport module: retries, downloads and verification."""
    return load_module("zizmor_transfer")


class FakeTime:
    """A clock that only advances when the code under test sleeps."""

    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds

    def schedule(self, lowest: bool = False) -> Any:
        """Build a deterministic schedule: full-length delays unless asked."""
        return transfer().RetrySchedule(
            sleep=self.sleep,
            clock=self.clock,
            rand=(lambda lo, hi: lo) if lowest else (lambda lo, hi: hi),
        )


def make_tarball(content: bytes = PRIMARY_BINARY) -> bytes:
    """Build a release tarball holding a ``zizmor`` file under a directory."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo("zizmor-release/zizmor")
        info.size = len(content)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def make_wheel(content: bytes = FALLBACK_BINARY, version: str = VERSION) -> bytes:
    """Build a PyPI wheel carrying the binary under ``.data/scripts``.

    The archive is byte-for-byte reproducible: a fixed timestamp keeps
    two builds of the same content from differing across a clock tick.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as wheel:
        for name, data in (
            (f"zizmor-{version}.data/scripts/zizmor", content),
            (f"zizmor-{version}.dist-info/METADATA", b"Name: zizmor\n"),
        ):
            wheel.writestr(zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0)), data)
    return buffer.getvalue()


def lock_text(wheel: bytes, version: str = VERSION) -> str:
    """Render a uv.lock pinning zizmor with wheels for every platform."""
    digest = hashlib.sha256(wheel).hexdigest()
    base = "https://files.pythonhosted.org/packages/aa/bb"
    tags = [
        "macosx_10_12_x86_64",
        "macosx_11_0_arm64",
        "manylinux_2_24_aarch64",
        "manylinux_2_28_x86_64",
        "musllinux_1_2_aarch64",
        "musllinux_1_2_x86_64",
        "win_amd64",
    ]
    wheels = ",\n".join(
        f'    {{ url = "{base}/zizmor-{version}-py3-none-{tag}.whl", '
        f'hash = "sha256:{digest}" }}'
        for tag in tags
    )
    return (
        "version = 1\n\n"
        "[[package]]\n"
        'name = "other"\n'
        'version = "9.9.9"\n\n'
        "[[package]]\n"
        'name = "zizmor"\n'
        f'version = "{version}"\n'
        f"wheels = [\n{wheels},\n]\n"
    )


def http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://example.invalid/x", code, "status", email.message.Message(), None
    )


def is_github(url: str) -> bool:
    """Whether the URL's host is github.com, not merely mentions it."""
    return urllib.parse.urlparse(url).hostname == "github.com"


class RetryTests(unittest.TestCase):
    def setUp(self) -> None:
        # Keep the retry notices out of the test run's output.
        quiet = contextlib.redirect_stderr(io.StringIO())
        quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def test_default_schedule_is_four_retries_in_180_seconds(self) -> None:
        schedule = transfer().RetrySchedule()
        self.assertEqual(schedule.retries, 4)
        self.assertEqual(schedule.base_delay, 10.0)
        self.assertEqual(schedule.budget, 180.0)

    def test_backoff_doubles_between_attempts(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        outcomes = [mod.TransientError("boom")] * 4
        calls: list[int] = []

        def operation(remaining: float) -> str:
            calls.append(1)
            if outcomes:
                raise outcomes.pop()
            return "done"

        result = mod.retry_call(
            operation,
            label="test",
            schedule=schedule,
            deadline=fake.clock() + schedule.budget,
        )
        self.assertEqual(result, "done")
        self.assertEqual(len(calls), 5)
        self.assertEqual(fake.sleeps, [10, 20, 40, 80])

    def test_gives_up_after_four_retries(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        calls: list[int] = []

        def operation(remaining: float) -> None:
            calls.append(1)
            raise mod.TransientError("still down")

        with self.assertRaises(mod.TransientError):
            mod.retry_call(
                operation,
                label="test",
                schedule=schedule,
                deadline=fake.clock() + schedule.budget,
            )
        self.assertEqual(len(calls), 5)
        self.assertEqual(len(fake.sleeps), 4)

    def test_budget_stops_retries_early(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        calls: list[int] = []

        def operation(remaining: float) -> None:
            calls.append(1)
            fake.now += 60
            raise mod.TransientError("slow failure")

        with self.assertRaises(mod.TransientError):
            mod.retry_call(
                operation,
                label="test",
                schedule=schedule,
                deadline=fake.clock() + schedule.budget,
            )
        # 60 s + 10 s wait, 60 s + 20 s wait, 60 s: the next 40 s wait
        # would pass the 180 s budget, so the third failure is final.
        self.assertEqual(len(calls), 3)
        self.assertEqual(fake.sleeps, [10, 20])

    def test_permanent_errors_are_not_retried(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        calls: list[int] = []

        def operation(remaining: float) -> None:
            calls.append(1)
            raise mod.IntegrityError("hash mismatch")

        with self.assertRaises(mod.IntegrityError):
            mod.retry_call(
                operation,
                label="test",
                schedule=schedule,
                deadline=fake.clock() + schedule.budget,
            )
        self.assertEqual(len(calls), 1)
        self.assertEqual(fake.sleeps, [])

    def test_jitter_only_ever_shortens_the_wait(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule(lowest=True)
        outcomes = [mod.TransientError("boom")] * 4

        def operation(remaining: float) -> str:
            if outcomes:
                raise outcomes.pop()
            return "done"

        mod.retry_call(
            operation,
            label="test",
            schedule=schedule,
            deadline=fake.clock() + schedule.budget,
        )
        self.assertEqual(fake.sleeps, [7.5, 15, 30, 60])

    def test_each_attempt_is_told_how_much_budget_remains(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        seen: list[float] = []

        def operation(remaining: float) -> None:
            seen.append(remaining)
            fake.now += 30
            raise mod.TransientError("slow failure")

        with self.assertRaises(mod.TransientError):
            mod.retry_call(
                operation,
                label="test",
                schedule=schedule,
                deadline=fake.clock() + schedule.budget,
            )
        # 180; then 180 - 30 - 10; then 180 - 30 - 10 - 30 - 20; and so on.
        self.assertEqual(seen, [180, 140, 90, 20])

    def test_no_attempt_starts_once_the_budget_is_spent(self) -> None:
        mod, fake = transfer(), FakeTime()
        schedule = fake.schedule()
        calls: list[int] = []

        def operation(remaining: float) -> None:
            calls.append(1)
            raise mod.TransientError("down")

        # A real sleep can overshoot; model one that lands past the deadline.
        def overshooting_sleep(seconds: float) -> None:
            fake.now += seconds + 500

        schedule = mod.RetrySchedule(
            sleep=overshooting_sleep, clock=fake.clock, rand=lambda lo, hi: hi
        )
        with self.assertRaises(mod.TransientError) as caught:
            mod.retry_call(
                operation,
                label="test",
                schedule=schedule,
                deadline=fake.clock() + schedule.budget,
            )
        self.assertEqual(len(calls), 1)
        self.assertIn("down", str(caught.exception))


class FakeResponse:
    """A response double: ``read`` hands out the chunks, then EOF."""

    def __init__(self, chunks: list[bytes], length: int | None = None) -> None:
        self.chunks = list(chunks)
        self.headers = {} if length is None else {"Content-Length": str(length)}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def read(self, size: int = -1) -> bytes:
        return self.chunks.pop(0) if self.chunks else b""


@contextlib.contextmanager
def stalling_server(script: Any) -> Any:
    """Serve one scripted response on localhost; yield its URL.

    ``script`` receives the request handler and may sleep, which stands
    in for a CDN that accepts a connection and then goes quiet.
    """

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            script(self)

        def log_message(self, *args: object) -> None:
            return None

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/asset"
    finally:
        server.shutdown()
        server.server_close()


class DownloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dest = Path(self.tmp.name) / "download"

    def serve(self, mod: ModuleType, response: Any) -> Any:
        return mock.patch.object(mod.urllib.request, "urlopen", return_value=response)

    def test_writes_the_response_body(self) -> None:
        mod = transfer()
        with self.serve(mod, FakeResponse([b"pay", b"load"], length=7)):
            mod.download_file("https://example.invalid/a", self.dest)
        self.assertEqual(self.dest.read_bytes(), b"payload")

    def test_a_body_without_a_declared_length_is_accepted(self) -> None:
        mod = transfer()
        with self.serve(mod, FakeResponse([b"payload"])):
            mod.download_file("https://example.invalid/a", self.dest)
        self.assertEqual(self.dest.read_bytes(), b"payload")

    def test_a_truncated_body_is_transient(self) -> None:
        # http.client hands back what arrived and reports a clean EOF when
        # the connection drops early, so the length must be checked.
        mod = transfer()
        with self.serve(mod, FakeResponse([b"pay"], length=7)):
            with self.assertRaises(mod.TransientError) as caught:
                mod.download_file("https://example.invalid/a", self.dest)
        self.assertIn("3 of 7", str(caught.exception))

    def test_an_incomplete_chunked_body_is_transient(self) -> None:
        mod = transfer()

        class Broken(FakeResponse):
            def read(self, size: int = -1) -> bytes:
                raise http.client.IncompleteRead(b"pay", 4)

        with self.serve(mod, Broken([])):
            with self.assertRaises(mod.TransientError):
                mod.download_file("https://example.invalid/a", self.dest)

    def test_the_deadline_holds_while_the_server_says_nothing(self) -> None:
        # The server sends headers, then goes quiet for 6 s; the 1 s
        # limit, not the 30 s socket default, must end the attempt.
        mod = transfer()

        def script(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "100")
            handler.end_headers()
            handler.wfile.flush()
            time.sleep(6)

        with stalling_server(script) as url:
            started = time.monotonic()
            with self.assertRaises(mod.TransientError):
                mod.download_file(url, self.dest, timeout=1)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 4)

    def test_the_deadline_holds_against_a_slow_drip(self) -> None:
        # One byte every 0.2 s never trips a per-read timeout, but the
        # whole transfer must still end at the deadline.
        mod = transfer()

        def script(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "1000")
            handler.end_headers()
            for _ in range(1000):
                handler.wfile.write(b"x")
                handler.wfile.flush()
                time.sleep(0.2)

        with stalling_server(script) as url:
            started = time.monotonic()
            with self.assertRaises(mod.TransientError):
                mod.download_file(url, self.dest, timeout=1)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 4)

    def test_a_server_that_closes_early_is_transient(self) -> None:
        mod = transfer()

        def script(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "100")
            handler.end_headers()
            handler.wfile.write(b"only a little")
            handler.wfile.flush()
            handler.close_connection = True

        with stalling_server(script) as url:
            with self.assertRaises(mod.TransientError) as caught:
                mod.download_file(url, self.dest, timeout=10)
        self.assertIn("13 of 100", str(caught.exception))

    def test_a_complete_download_from_a_real_server_succeeds(self) -> None:
        mod = transfer()

        def script(handler: http.server.BaseHTTPRequestHandler) -> None:
            handler.send_response(200)
            handler.send_header("Content-Length", "7")
            handler.end_headers()
            handler.wfile.write(b"payload")

        with stalling_server(script) as url:
            mod.download_file(url, self.dest, timeout=10)
        self.assertEqual(self.dest.read_bytes(), b"payload")

    def test_the_socket_timeout_never_exceeds_the_remaining_budget(self) -> None:
        mod = transfer()
        with mock.patch.object(
            mod.urllib.request, "urlopen", return_value=FakeResponse([b"x"], length=1)
        ) as urlopen:
            mod.download_file("https://example.invalid/a", self.dest, timeout=12)
        self.assertEqual(urlopen.call_args.kwargs["timeout"], 12)

    def test_gateway_errors_are_transient(self) -> None:
        mod = transfer()
        for code in (408, 425, 429, 500, 502, 503, 504, 507, 520, 524, 599):
            with self.subTest(code=code):
                with mock.patch.object(
                    mod.urllib.request, "urlopen", side_effect=http_error(code)
                ):
                    with self.assertRaises(mod.TransientError):
                        mod.download_file("https://example.invalid/a", self.dest)

    def test_client_errors_are_permanent(self) -> None:
        mod = transfer()
        for code in (400, 401, 403, 404, 410, 451):
            with self.subTest(code=code):
                with mock.patch.object(
                    mod.urllib.request, "urlopen", side_effect=http_error(code)
                ):
                    with self.assertRaises(mod.FetchError) as caught:
                        mod.download_file("https://example.invalid/a", self.dest)
                self.assertNotIsInstance(caught.exception, mod.TransientError)

    def test_connection_failures_are_transient(self) -> None:
        mod = transfer()
        for failure in (
            urllib.error.URLError("connection reset"),
            TimeoutError("timed out"),
            ConnectionResetError("reset by peer"),
        ):
            with self.subTest(failure=type(failure).__name__):
                with mock.patch.object(
                    mod.urllib.request, "urlopen", side_effect=failure
                ):
                    with self.assertRaises(mod.TransientError):
                        mod.download_file("https://example.invalid/a", self.dest)


class VerifyTests(unittest.TestCase):
    def test_success_returns_quietly(self) -> None:
        mod = transfer()
        done = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with mock.patch.object(mod.subprocess, "run", return_value=done) as run:
            mod.verify_attestation(Path("/tmp/archive.tar.gz"))
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["gh", "attestation", "verify"])
        self.assertIn("zizmorcore/zizmor", command)

    def test_the_check_is_bounded_by_the_remaining_budget(self) -> None:
        mod = transfer()
        done = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
        with mock.patch.object(mod.subprocess, "run", return_value=done) as run:
            mod.verify_attestation(Path("/tmp/archive.tar.gz"), timeout=25)
            mod.verify_attestation(Path("/tmp/archive.tar.gz"), timeout=9999)
        timeouts = [call.kwargs["timeout"] for call in run.call_args_list]
        self.assertEqual(timeouts, [25, mod.ATTESTATION_TIMEOUT])

    def test_failure_is_transient_so_it_is_retried(self) -> None:
        mod = transfer()
        failed = subprocess.CompletedProcess([], 1, stdout="", stderr="HTTP 502")
        with mock.patch.object(mod.subprocess, "run", return_value=failed):
            with self.assertRaises(mod.TransientError) as caught:
                mod.verify_attestation(Path("/tmp/archive.tar.gz"))
        self.assertIn("HTTP 502", str(caught.exception))

    def test_timeout_is_transient(self) -> None:
        mod = transfer()
        with mock.patch.object(
            mod.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("gh", 120),
        ):
            with self.assertRaises(mod.TransientError):
                mod.verify_attestation(Path("/tmp/archive.tar.gz"))

    def test_missing_gh_is_permanent(self) -> None:
        mod = transfer()
        with mock.patch.object(mod.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaises(mod.FetchError) as caught:
                mod.verify_attestation(Path("/tmp/archive.tar.gz"))
        self.assertNotIsInstance(caught.exception, mod.TransientError)


class AssetTests(unittest.TestCase):
    def test_release_asset_for_each_supported_platform(self) -> None:
        mod = load()
        expected = {
            ("Linux", "X64"): "zizmor-x86_64-unknown-linux-gnu.tar.gz",
            ("Linux", "ARM64"): "zizmor-aarch64-unknown-linux-gnu.tar.gz",
            ("macOS", "X64"): "zizmor-x86_64-apple-darwin.tar.gz",
            ("macOS", "ARM64"): "zizmor-aarch64-apple-darwin.tar.gz",
        }
        for (system, arch), asset in expected.items():
            with self.subTest(system=system, arch=arch):
                self.assertEqual(mod.release_asset(system, arch), asset)

    def test_unsupported_platform_is_rejected(self) -> None:
        mod = load()
        with self.assertRaises(mod.FetchError) as caught:
            mod.release_asset("Windows", "X64")
        self.assertIn("unsupported runner Windows/X64", str(caught.exception))


class WheelSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = lock_text(make_wheel())

    def test_picks_the_manylinux_wheel_for_linux(self) -> None:
        mod = load()
        url, digest = mod.select_wheel(self.lock, VERSION, "Linux", "X64")
        self.assertTrue(url.endswith("manylinux_2_28_x86_64.whl"))
        self.assertEqual(len(digest), 64)

    def test_picks_the_wheel_for_each_supported_platform(self) -> None:
        mod = load()
        expected = {
            ("Linux", "ARM64"): "manylinux_2_24_aarch64.whl",
            ("macOS", "X64"): "macosx_10_12_x86_64.whl",
            ("macOS", "ARM64"): "macosx_11_0_arm64.whl",
        }
        for (system, arch), suffix in expected.items():
            with self.subTest(system=system, arch=arch):
                url, _ = mod.select_wheel(self.lock, VERSION, system, arch)
                self.assertTrue(url.endswith(suffix))

    def test_falls_back_to_musllinux_when_no_manylinux_wheel(self) -> None:
        mod = load()
        lock = "\n".join(
            line for line in self.lock.splitlines() if "manylinux" not in line
        )
        url, _ = mod.select_wheel(lock, VERSION, "Linux", "X64")
        self.assertTrue(url.endswith("musllinux_1_2_x86_64.whl"))

    def test_names_the_python_requirement_when_tomllib_is_missing(self) -> None:
        mod = load()
        with mock.patch.dict(sys.modules, {"tomllib": None}):
            with self.assertRaises(mod.FetchError) as caught:
                mod.select_wheel(self.lock, VERSION, "Linux", "X64")
        self.assertIn("Python 3.11", str(caught.exception))

    def test_refuses_a_version_the_lock_does_not_pin(self) -> None:
        mod = load()
        with self.assertRaises(mod.FetchError) as caught:
            mod.select_wheel(self.lock, "1.99.0", "Linux", "X64")
        message = str(caught.exception)
        self.assertIn(VERSION, message)
        self.assertIn("1.99.0", message)

    def test_refuses_a_platform_with_no_wheel(self) -> None:
        mod = load()
        with self.assertRaises(mod.FetchError):
            mod.select_wheel(self.lock, VERSION, "Windows", "X64")

    def test_refuses_a_url_outside_the_pypi_file_host(self) -> None:
        mod = load()
        lock = self.lock.replace(
            "https://files.pythonhosted.org", "https://evil.example.invalid"
        )
        with self.assertRaises(mod.FetchError):
            mod.select_wheel(lock, VERSION, "Linux", "X64")

    def test_refuses_plain_http(self) -> None:
        mod = load()
        lock = self.lock.replace("https://files", "http://files")
        with self.assertRaises(mod.FetchError):
            mod.select_wheel(lock, VERSION, "Linux", "X64")


class ExtractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bindir = self.root / "bin"
        self.bindir.mkdir()

    def test_extracts_an_executable_from_a_tarball(self) -> None:
        mod = load()
        archive = self.root / "release.tar.gz"
        archive.write_bytes(make_tarball())
        binary = mod.extract_from_tarball(archive, self.bindir)
        self.assertEqual(binary, self.bindir / "zizmor")
        self.assertEqual(binary.read_bytes(), PRIMARY_BINARY)
        self.assertTrue(os.access(binary, os.X_OK))

    def test_tarball_without_the_binary_is_rejected(self) -> None:
        mod = load()
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            info = tarfile.TarInfo("README")
            info.size = 0
            tar.addfile(info, io.BytesIO(b""))
        archive = self.root / "release.tar.gz"
        archive.write_bytes(buffer.getvalue())
        with self.assertRaises(mod.FetchError):
            mod.extract_from_tarball(archive, self.bindir)

    def test_extracts_an_executable_from_a_wheel(self) -> None:
        mod = load()
        wheel = self.root / "zizmor.whl"
        wheel.write_bytes(make_wheel())
        binary = mod.extract_from_wheel(wheel, VERSION, self.bindir)
        self.assertEqual(binary, self.bindir / "zizmor")
        self.assertEqual(binary.read_bytes(), FALLBACK_BINARY)
        self.assertTrue(os.access(binary, os.X_OK))

    def test_wheel_without_the_binary_is_rejected(self) -> None:
        mod = load()
        wheel = self.root / "zizmor.whl"
        wheel.write_bytes(make_wheel(version="0.0.1"))
        with self.assertRaises(mod.FetchError):
            mod.extract_from_wheel(wheel, VERSION, self.bindir)


class FetchTests(unittest.TestCase):
    """The primary source, the fallback, and the choice between them."""

    @property
    def mod(self) -> ModuleType:
        # Imported on first use, inside the test, so a missing script
        # fails the test rather than its fixture.
        return load()

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.work = self.root / "work"
        self.work.mkdir()
        # One wheel, so the digest in the lock is the digest of the file
        # the fake downloader serves.
        self.wheel = make_wheel()
        self.lock = self.root / "uv.lock"
        self.lock.write_text(lock_text(self.wheel))
        self.fake = FakeTime()
        self.urls: list[str] = []
        self.tarball = make_tarball()
        # Failures to raise for each host; None means the host answers.
        self.github_error: Exception | None = None
        self.pypi_error: Exception | None = None
        self.verify_error: Exception | None = None
        self.stderr = io.StringIO()

    def download(self, url: str, dest: Path, **_: Any) -> None:
        self.urls.append(url)
        github = is_github(url)
        error = self.github_error if github else self.pypi_error
        if error is not None:
            raise error
        dest.write_bytes(self.tarball if github else self.wheel)

    def verify(self, archive: Path, **_: Any) -> None:
        if self.verify_error is not None:
            raise self.verify_error

    def run_fetch(self, tag: str = TAG) -> Any:
        schedule = self.fake.schedule()
        with (
            mock.patch.object(self.mod, "download_file", self.download),
            mock.patch.object(self.mod, "verify_attestation", self.verify),
            contextlib.redirect_stderr(self.stderr),
        ):
            return self.mod.fetch(
                tag=tag,
                system="Linux",
                arch="X64",
                workdir=self.work,
                lock_path=self.lock,
                schedule=schedule,
            )

    def test_uses_the_attested_github_release_when_it_is_reachable(self) -> None:
        result = self.run_fetch()
        self.assertEqual(result.source, "github")
        self.assertEqual(result.binary.read_bytes(), PRIMARY_BINARY)
        self.assertEqual(
            self.urls,
            [
                "https://github.com/zizmorcore/zizmor/releases/download/"
                f"{TAG}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
            ],
        )
        self.assertEqual(self.fake.sleeps, [])

    def test_falls_back_to_pypi_after_the_github_retries_are_spent(self) -> None:
        self.github_error = transfer().TransientError("HTTP 504")
        result = self.run_fetch()
        self.assertEqual(result.source, "pypi")
        self.assertEqual(result.binary.read_bytes(), FALLBACK_BINARY)
        self.assertEqual(self.fake.sleeps, [10, 20, 40, 80])
        self.assertTrue(self.urls[-1].startswith("https://files.pythonhosted.org/"))
        self.assertIn("::warning::", self.stderr.getvalue())

    def test_falls_back_when_the_attestation_cannot_be_checked(self) -> None:
        self.verify_error = transfer().TransientError("api.github.com unreachable")
        result = self.run_fetch()
        self.assertEqual(result.source, "pypi")
        self.assertEqual(result.binary.read_bytes(), FALLBACK_BINARY)
        # The unverified tarball must not be left behind to be used.
        self.assertEqual(list(self.work.rglob("*.tar.gz")), [])

    def test_a_missing_release_falls_back_without_retrying(self) -> None:
        self.github_error = transfer().FetchError("HTTP 404")
        result = self.run_fetch()
        self.assertEqual(result.source, "pypi")
        self.assertEqual(self.fake.sleeps, [])

    def test_a_wheel_that_fails_its_hash_is_never_used(self) -> None:
        self.github_error = transfer().TransientError("HTTP 504")
        self.wheel = make_wheel(b"tampered")
        with self.assertRaises(transfer().FetchError):
            self.run_fetch()
        self.assertEqual(list(self.work.rglob("zizmor")), [])
        # A hash mismatch is permanent, so the wheel was fetched once.
        pypi = [u for u in self.urls if "pythonhosted" in u]
        self.assertEqual(len(pypi), 1)

    def test_reports_both_failures_when_neither_source_works(self) -> None:
        self.github_error = transfer().TransientError("HTTP 504")
        self.wheel = make_wheel(b"tampered")
        with self.assertRaises(transfer().FetchError) as caught:
            self.run_fetch()
        message = str(caught.exception).lower()
        self.assertIn("github", message)
        self.assertIn("pypi", message)
        self.assertIn("http 504", message)

    def test_no_fallback_for_a_version_the_lock_does_not_pin(self) -> None:
        self.github_error = transfer().TransientError("HTTP 504")
        with self.assertRaises(transfer().FetchError) as caught:
            self.run_fetch(tag="v1.99.0")
        self.assertIn("uv.lock", str(caught.exception))

    def test_a_pypi_outage_after_a_github_outage_fails_loudly(self) -> None:
        self.github_error = transfer().TransientError("HTTP 504")
        self.pypi_error = transfer().TransientError("HTTP 503")
        with self.assertRaises(transfer().FetchError):
            self.run_fetch()
        # Five attempts at each source, four waits at each.
        self.assertEqual(len(self.urls), 10)
        self.assertEqual(self.fake.sleeps, [10, 20, 40, 80] * 2)

    def test_a_slow_github_source_cannot_delay_the_fallback_past_its_budget(
        self,
    ) -> None:
        # Every GitHub attempt burns 100 s before failing: the first waits
        # 10 s and the second starts with 70 s left; neither may outlast
        # the 180 s budget, so the fallback starts at 180 s at the latest.
        seen: list[float] = []

        def slow(url: str, dest: Path, timeout: float = 0, **_: Any) -> None:
            if is_github(url):
                seen.append(timeout)
                self.fake.now += min(100, timeout)
                raise transfer().TransientError("HTTP 504")
            dest.write_bytes(self.wheel)

        with (
            mock.patch.object(self.mod, "download_file", slow),
            mock.patch.object(self.mod, "verify_attestation", self.verify),
            contextlib.redirect_stderr(self.stderr),
        ):
            result = self.mod.fetch(
                tag=TAG,
                system="Linux",
                arch="X64",
                workdir=self.work,
                lock_path=self.lock,
                schedule=self.fake.schedule(),
            )
        self.assertEqual(result.source, "pypi")
        self.assertLessEqual(self.fake.now, 180)
        self.assertTrue(all(0 < t <= 180 for t in seen), seen)

    def test_the_attestation_check_shares_the_source_retry_budget(self) -> None:
        self.verify_error = transfer().TransientError("HTTP 502")
        self.run_fetch()
        # One download, then four retried verifications, then the fallback.
        github = [u for u in self.urls if is_github(u)]
        self.assertEqual(len(github), 1)
        self.assertEqual(self.fake.sleeps, [10, 20, 40, 80])


def python39() -> str | None:
    """Find a Python 3.9 interpreter, or None when the host has none."""
    return os.environ.get("ZIZMOR_TEST_PYTHON39") or shutil.which("python3.9")


class OldPythonTests(unittest.TestCase):
    """The GitHub source is documented to work on Python 3.9 and newer."""

    def test_annotations_are_never_evaluated_at_import(self) -> None:
        # ``X | None`` in an annotation raises TypeError on Python 3.9 when
        # evaluated. ``from __future__ import annotations`` stores the
        # annotations as text, so the module imports on any version. This
        # check runs on every Python, not just 3.9, so CI catches it.
        for module in (load(), transfer()):
            with self.subTest(module=module.__name__):
                self.assertIs(
                    getattr(module, "annotations", None), __future__.annotations
                )

    def test_imports_on_a_real_python_39(self) -> None:
        interpreter = python39()
        if interpreter is None:
            self.skipTest("no python3.9 on this host (set ZIZMOR_TEST_PYTHON39)")
        code = (
            f"import sys; sys.path.insert(0, {str(SCRIPTS)!r}); "
            "import zizmor_fetch; print(sys.version_info[:2])"
        )
        proc = subprocess.run(  # noqa: S603
            [interpreter, "-E", "-s", "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "(3, 9)")


class CommandLineTests(unittest.TestCase):
    def run_script(self, **env: str) -> subprocess.CompletedProcess[str]:
        clean = {k: v for k, v in os.environ.items() if not k.startswith("ZIZMOR_")}
        clean.update(env)
        return subprocess.run(  # noqa: S603
            [sys.executable, "-E", "-s", str(SCRIPT)],
            capture_output=True,
            text=True,
            env=clean,
            check=False,
        )

    def test_unsupported_runner_exits_non_zero_with_a_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_script(
                ZIZMOR_TAG=TAG,
                ZIZMOR_WORKDIR=tmp,
                ZIZMOR_LOCK=str(Path(tmp) / "uv.lock"),
                RUNNER_OS="Windows",
                RUNNER_ARCH="X64",
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("unsupported runner Windows/X64", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_ignores_modules_planted_in_the_workspace(self) -> None:
        # The audited workspace is untrusted. Plant modules the script
        # imports in the working directory and on PYTHONPATH; running
        # with -E -s must not import any of them.
        with tempfile.TemporaryDirectory() as tmp:
            planted = "import sys\nsys.exit(97)\n"
            for name in ("tomllib", "re", "hashlib", "zizmor_transfer"):
                (Path(tmp) / f"{name}.py").write_text(planted)
            proc = subprocess.run(  # noqa: S603
                [sys.executable, "-E", "-s", str(SCRIPT)],
                capture_output=True,
                text=True,
                cwd=tmp,
                env={"PATH": os.environ["PATH"], "PYTHONPATH": tmp},
                check=False,
            )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("ZIZMOR_TAG", proc.stderr)

    def test_imports_without_tomllib_so_python_310_can_use_github(self) -> None:
        # tomllib arrived in Python 3.11. Only the PyPI fallback reads the
        # lock, so a runner without it must still reach the GitHub path.
        code = (
            "import sys; sys.modules['tomllib'] = None; "
            f"sys.path.insert(0, {str(SCRIPTS)!r}); import zizmor_fetch"
        )
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-E", "-s", "-c", code],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_missing_configuration_exits_non_zero(self) -> None:
        proc = self.run_script()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("ZIZMOR_TAG", proc.stderr)


if __name__ == "__main__":
    unittest.main()
