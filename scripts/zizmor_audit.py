# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Run zizmor, retrying a failure caused by a transient GitHub API error.

zizmor's online audits query the GitHub API. A single dropped request
makes zizmor exit 1 with ``request error while accessing GitHub API``
on stderr, which says nothing about the audited workflows. Retry that
case alone, after a short backoff; return every other outcome from the
first attempt unchanged, so bad arguments (2), no inputs (3) and real
internal errors fail or pass exactly as before.

Usage::

    zizmor_audit.py SARIF_PATH ZIZMOR [ARGS...]

zizmor's stdout goes to ``SARIF_PATH``, which each attempt truncates
first so a failed attempt's output never survives. Its stderr streams
through to this process's stderr and is scanned for the marker. The
exit status is zizmor's own from the last attempt.
"""

import subprocess
import sys
import time
from collections.abc import Callable, Sequence

# zizmor's wording for a failed GitHub API request (a transport error)
TRANSIENT_MARKER = b"request error while accessing GitHub API"
# Seconds to wait before each retry; the length is the retry budget
RETRY_DELAYS = (15, 30)


def run_once(cmd: Sequence[str], sarif_path: str) -> tuple[int, bool]:
    """Run ``cmd`` once; return its exit code and whether it hit the marker."""
    transient = False
    with open(sarif_path, "wb") as out:
        proc = subprocess.Popen(cmd, stdout=out, stderr=subprocess.PIPE)
        assert proc.stderr is not None
        for line in proc.stderr:
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()
            if TRANSIENT_MARKER in line:
                transient = True
        rc = proc.wait()
    return rc, transient


def run(
    cmd: Sequence[str],
    sarif_path: str,
    delays: Sequence[float] = RETRY_DELAYS,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Run ``cmd``, retrying only exit 1 with the transient marker."""
    attempt = 1
    while True:
        rc, transient = run_once(cmd, sarif_path)
        if rc != 1 or not transient or attempt > len(delays):
            return rc
        delay = delays[attempt - 1]
        print(
            f"::warning::zizmor attempt {attempt} failed on a transient "
            f"GitHub API error; retrying in {delay} seconds",
            flush=True,
        )
        sleep(delay)
        attempt += 1


def main(argv: Sequence[str]) -> int:
    if len(argv) < 3:
        print(f"usage: {argv[0]} SARIF_PATH ZIZMOR [ARGS...]", file=sys.stderr)
        return 2
    return run(argv[2:], argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
