# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for scripts/zizmor_audit.py.

A small Python stub stands in for zizmor: it counts its calls in a
file, writes partial output and the marker for the first failures, and
then exits with a chosen code. Run with
``python3 -m unittest discover -s tests``.
"""

import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "zizmor_audit.py"

_spec = importlib.util.spec_from_file_location("zizmor_audit", SCRIPT)
assert _spec is not None and _spec.loader is not None
zizmor_audit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(zizmor_audit)

MARKER = "    1: request error while accessing GitHub API"

STUB = """
import sys
from pathlib import Path

counter, fails, fail_rc, stderr, final_rc = sys.argv[1:6]
calls = int(Path(counter).read_text() or "0") + 1 if Path(counter).exists() else 1
Path(counter).write_text(str(calls))
if calls <= int(fails):
    sys.stdout.write("partial output from attempt %d" % calls)
    sys.stderr.write(stderr + "\\n")
    sys.exit(int(fail_rc))
sys.stdout.write('{"runs": []}')
sys.stderr.write("attempt %d done\\n" % calls)
sys.exit(int(final_rc))
"""


class RunTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.counter = self.dir / "calls"
        self.sarif = self.dir / "out.sarif"
        self.sleeps: list[float] = []
        stdout = mock.patch("sys.stdout", new_callable=io.StringIO)
        self.stdout = stdout.start()
        self.addCleanup(stdout.stop)
        stderr = mock.patch("sys.stderr", new=io.TextIOWrapper(io.BytesIO()))
        self.stderr = stderr.start()
        self.addCleanup(stderr.stop)

    def audit(self, fails: int, fail_rc: int, stderr: str, final_rc: int = 0) -> int:
        cmd = [
            sys.executable,
            "-c",
            STUB,
            str(self.counter),
            str(fails),
            str(fail_rc),
            stderr,
            str(final_rc),
        ]
        return zizmor_audit.run(
            cmd, str(self.sarif), delays=(15, 30), sleep=self.sleeps.append
        )

    def calls(self) -> int:
        return int(self.counter.read_text())

    def logged_stderr(self) -> str:
        buffer = self.stderr.buffer
        assert isinstance(buffer, io.BytesIO)
        return buffer.getvalue().decode()

    def test_transient_failure_retried_until_success(self) -> None:
        rc = self.audit(fails=2, fail_rc=1, stderr=MARKER)
        self.assertEqual(rc, 0)
        self.assertEqual(self.calls(), 3)
        self.assertEqual(self.sleeps, [15, 30])
        self.assertEqual(self.sarif.read_text(), '{"runs": []}')
        self.assertIn("zizmor attempt 1 failed", self.stdout.getvalue())
        self.assertIn("zizmor attempt 2 failed", self.stdout.getvalue())
        log = self.logged_stderr()
        self.assertEqual(log.count("request error"), 2)
        self.assertIn("attempt 3 done", log)

    def test_retries_exhausted_returns_last_code(self) -> None:
        rc = self.audit(fails=5, fail_rc=1, stderr=MARKER)
        self.assertEqual(rc, 1)
        self.assertEqual(self.calls(), 3)
        self.assertEqual(self.sleeps, [15, 30])
        self.assertEqual(self.sarif.read_text(), "partial output from attempt 3")

    def test_internal_error_without_marker_not_retried(self) -> None:
        rc = self.audit(fails=1, fail_rc=1, stderr="fatal: something broke")
        self.assertEqual(rc, 1)
        self.assertEqual(self.calls(), 1)
        self.assertEqual(self.sleeps, [])
        self.assertNotIn("::warning::", self.stdout.getvalue())

    def test_other_exit_codes_not_retried(self) -> None:
        for code in (0, 2, 3):
            with self.subTest(code=code):
                self.counter.unlink(missing_ok=True)
                rc = self.audit(fails=0, fail_rc=1, stderr=MARKER, final_rc=code)
                self.assertEqual(rc, code)
                self.assertEqual(self.calls(), 1)
                rc = self.audit(fails=9, fail_rc=code, stderr=MARKER)
                self.assertEqual(rc, code)
                self.assertEqual(self.calls(), 2)
        self.assertEqual(self.sleeps, [])

    def test_runs_as_the_action_runs_it(self) -> None:
        # A failure without the marker, so no real backoff delay runs
        self.sarif.write_text("stale SARIF from an earlier run")
        stub = [sys.executable, "-c", STUB, str(self.counter), "1", "1"]
        result = subprocess.run(
            [sys.executable, "-I", str(SCRIPT), str(self.sarif), *stub, "boom", "0"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("boom", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(self.calls(), 1)
        self.assertEqual(self.sarif.read_text(), "partial output from attempt 1")


if __name__ == "__main__":
    unittest.main()
