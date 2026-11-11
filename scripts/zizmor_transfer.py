# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Network and verification helpers for ``zizmor_fetch.py``.

This module holds the parts of fetching zizmor that deal with an unreliable
network: a bounded retry schedule, a download that classifies its failures,
the Sigstore attestation check and the digest check.

Each helper raises one of four errors so a caller can decide whether to
try again, or to try another source:

* :class:`TransientError`     a later attempt may succeed (HTTP 408, 425,
  429 and every 5xx, connection resets, timeouts, a body cut short, and
  an attestation check that matches a known outage signature, or that
  could not load a Sigstore trust root while no trust root mirror
  answers)
* :class:`IntegrityError`     content did not match its pinned digest
* :class:`VerificationError`  the GitHub artifact could not be trusted or
  used: its attestation is missing or rejected, ``gh`` is not installed,
  or the archive is unusable
* :class:`FetchError`         anything else, such as an HTTP 404

The retry budget is a hard limit. ``retry_call`` tells each attempt how
much of the budget remains, and the download and the attestation check
bound themselves by it, so a slow attempt cannot run past the deadline.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import random
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

ATTESTATION_REPO = "zizmorcore/zizmor"
USER_AGENT = "zizmor-scan-action"

# HTTP statuses worth retrying besides the 5xx range: request timeout, too
# early and throttling. Every 5xx counts, including codes a CDN adds, such
# as Cloudflare's 520 to 524.
RETRYABLE_STATUSES = frozenset({408, 425, 429})

# Output of a failed ``gh attestation verify`` that means GitHub or the
# Sigstore trust root could not be reached or could not answer, matched
# case-insensitively alongside the retryable HTTP statuses. This is an
# allow-list on purpose: ``gh`` exits 1 for every failure, and any output
# not listed here is a verdict on the archive that fails the run. A
# misread outage then stops the run loudly; a misread rejection would
# skip the check. Add a new outage wording from ``gh`` here.
ATTESTATION_OUTAGE_SIGNATURES = (
    "i/o timeout",
    "connection refused",
    "connection reset",
    "no such host",
    "tls handshake timeout",
    "dial tcp",
)
HTTP_STATUS = re.compile(r"\bhttp (\d{3})\b", re.IGNORECASE)

# Go's "unexpected EOF" on its own is no outage: a decoder reading
# truncated or malformed verification material says the same after a
# transfer that succeeded. It names an outage only in the form Go's HTTP
# client gives a request whose connection dropped, quoting the method
# and URL, as in ``Get "https://api.github.com/...": unexpected EOF``.
TRANSPORT_EOF = re.compile(
    r'\b(?:get|head|post|put|patch|delete|options) "https?://[^"\s]+": '
    r"unexpected eof\b",
    re.IGNORECASE,
)

# What ``gh`` prints, without the cause, when neither of its Sigstore
# verifiers could load its trust root. An unreachable trust root does
# that, but so does invalid trust metadata, so this message alone is not
# an outage. It counts as one only when no mirror below answers; a
# mirror that answers means the failure was not the network, and one
# whose TLS certificate fails validation means something untrusted
# answered in its place, which is no outage either.
UNVERIFIED_TRUST_ROOT = "no valid sigstore verifiers could be initialized"
TRUST_ROOT_MIRRORS = (
    "https://tuf-repo-cdn.sigstore.dev/",
    "https://tuf-repo.github.com/",
)

# Seconds the transport waits on one socket operation, the cap on a whole
# transfer, and the cap on the attestation check. A caller passes a
# smaller limit when less of its retry budget remains. Exceeding a limit
# counts as a transient failure.
SOCKET_TIMEOUT = 30
TRANSFER_TIMEOUT = 120
ATTESTATION_TIMEOUT = 120
PROBE_TIMEOUT = 10

T = TypeVar("T")


class FetchError(Exception):
    """A source could not supply a verified binary."""


class TransientError(FetchError):
    """A failure that a later attempt may not repeat."""


class IntegrityError(FetchError):
    """Downloaded content did not match its pinned digest."""


class VerificationError(FetchError):
    """The GitHub artifact could not be trusted or used.

    A verdict, not an outage: retrying cannot cure it, and the caller
    must not route around it by switching source.
    """


def is_retryable_status(code: int) -> bool:
    """Whether an HTTP status is worth another attempt."""
    return code in RETRYABLE_STATUSES or 500 <= code <= 599


def is_attestation_outage(output: str) -> bool:
    """Whether failed ``gh attestation verify`` output names an outage."""
    lowered = output.lower()
    if any(signature in lowered for signature in ATTESTATION_OUTAGE_SIGNATURES):
        return True
    if TRANSPORT_EOF.search(output):
        return True
    return any(is_retryable_status(int(code)) for code in HTTP_STATUS.findall(output))


def is_certificate_failure(exc: BaseException) -> bool:
    """Whether ``exc`` is a TLS certificate validation failure.

    ``urlopen`` wraps one raised while connecting in a ``URLError``.
    """
    if isinstance(exc, urllib.error.URLError) and not isinstance(
        exc, urllib.error.HTTPError
    ):
        exc = exc.reason if isinstance(exc.reason, BaseException) else exc
    return isinstance(exc, ssl.SSLCertVerificationError)


def trust_root_answers(url: str, timeout: float) -> bool:
    """Whether a trust root mirror answers within ``timeout`` seconds.

    Any HTTP response counts, a 404 included, except a retryable status:
    the question is whether the network reaches the mirror, not what it
    serves. A certificate that fails validation is not an outage but an
    untrusted answer, and raises :class:`VerificationError`.
    """
    request = urllib.request.Request(
        url, method="HEAD", headers={"User-Agent": USER_AGENT}
    )
    try:
        with wall_clock_limit(timeout):
            with urllib.request.urlopen(request, timeout=timeout):  # noqa: S310
                return True
    except _DeadlineExceeded:
        return False
    except urllib.error.HTTPError as exc:
        return not is_retryable_status(exc.code)
    except (OSError, http.client.HTTPException) as exc:
        if is_certificate_failure(exc):
            raise VerificationError(
                f"trust root mirror {url} failed TLS certificate validation"
            ) from exc
        return False


def trust_root_outage_doubt(timeout: float) -> str | None:
    """Why a trust root outage cannot be established, or ``None``.

    ``None`` means every mirror in :data:`TRUST_ROOT_MIRRORS` was asked and
    none answered: an outage. Otherwise the reason names what stopped
    the probe: a mirror that answered, or too little time left to ask
    one. The mirrors share ``timeout`` seconds, and a mirror whose
    certificate fails validation raises :class:`VerificationError`.
    """
    deadline = time.monotonic() + timeout
    for url in TRUST_ROOT_MIRRORS:
        remaining = min(PROBE_TIMEOUT, deadline - time.monotonic())
        if remaining < 1:
            return (
                f"too little time remained to ask trust root mirror {url}, "
                "so an outage could not be established"
            )
        if trust_root_answers(url, remaining):
            return f"trust root mirror {url} answered, so this is not an outage"
    return None


@dataclass(frozen=True)
class RetrySchedule:
    """How often, how long and how patiently to retry.

    The wait before retry ``n`` is ``base_delay * 2 ** (n - 1)``, cut by
    up to a quarter at random. ``sleep``, ``clock`` and ``rand`` are
    parameters so tests can run the schedule without waiting.
    """

    retries: int = 4
    base_delay: float = 10.0
    budget: float = 180.0
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], float] = time.monotonic
    rand: Callable[[float, float], float] = random.uniform


def log(message: str) -> None:
    """Write a progress line to stderr, keeping stdout for the outputs."""
    print(message, file=sys.stderr, flush=True)


def retry_call(
    operation: Callable[[float], T],
    *,
    label: str,
    schedule: RetrySchedule,
    deadline: float,
) -> T:
    """Run ``operation``, retrying transient failures within the budget.

    ``operation`` receives the seconds left before ``deadline`` and must
    finish within them. No attempt starts once the deadline has passed.
    Raise the last failure once the retries or the time run out. Any
    other error propagates immediately.
    """
    attempt = 0
    while True:
        attempt += 1
        try:
            return operation(deadline - schedule.clock())
        except TransientError as exc:
            if attempt > schedule.retries:
                raise
            nominal = schedule.base_delay * 2 ** (attempt - 1)
            delay = schedule.rand(0.75 * nominal, nominal)
            if schedule.clock() + delay > deadline:
                raise
            log(
                f"{label}: {exc}; retry {attempt} of {schedule.retries} in {delay:.0f}s"
            )
            schedule.sleep(delay)
            if schedule.clock() >= deadline:
                # A sleep can overshoot; do not start an attempt past
                # the budget.
                raise


class _DeadlineExceeded(BaseException):
    """Raised by the alarm handler; a BaseException so nothing swallows it."""


@contextlib.contextmanager
def wall_clock_limit(seconds: float) -> Iterator[None]:
    """Interrupt the block with :class:`_DeadlineExceeded` after ``seconds``.

    A socket timeout restarts on every read, so a server that sends a byte
    now and then never trips it. An interval timer ends the whole block at
    an absolute time, even inside a blocked read. It needs ``SIGALRM`` and
    the main thread; elsewhere the block runs unbounded and the socket
    timeout is the only limit.
    """
    usable = (
        hasattr(signal, "SIGALRM")
        and threading.current_thread() is threading.main_thread()
    )
    if not usable:
        yield
        return

    def interrupt(signum: int, frame: object) -> None:
        raise _DeadlineExceeded

    previous = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.001))
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def download_file(
    url: str, destination: Path, timeout: float = TRANSFER_TIMEOUT
) -> None:
    """Download ``url`` to ``destination``, redirects included.

    The whole transfer, connection included, must finish within
    ``timeout`` seconds (at most :data:`TRANSFER_TIMEOUT`). A body that
    ends before its declared length is a transient failure, not a file:
    ``http.client`` reports a connection dropped early as a clean end.
    """
    limit = min(timeout, TRANSFER_TIMEOUT)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with wall_clock_limit(limit):
            with urllib.request.urlopen(  # noqa: S310
                request, timeout=min(SOCKET_TIMEOUT, limit)
            ) as response:
                declared = response.headers.get("Content-Length")
                received = 0
                with destination.open("wb") as out:
                    while chunk := response.read(1 << 20):
                        out.write(chunk)
                        received += len(chunk)
                if declared is not None and received != int(declared):
                    raise TransientError(
                        f"incomplete download of {url}: "
                        f"received {received} of {declared} bytes"
                    )
    except _DeadlineExceeded:
        raise TransientError(f"download of {url} exceeded {limit:.0f}s") from None
    except urllib.error.HTTPError as exc:
        message = f"HTTP {exc.code} from {url}"
        if is_retryable_status(exc.code):
            raise TransientError(message) from exc
        raise FetchError(message) from exc
    except (OSError, http.client.HTTPException) as exc:
        # URLError, timeouts and connection resets are all OSErrors.
        raise TransientError(f"{type(exc).__name__} fetching {url}: {exc}") from exc


def verify_attestation(archive: Path, timeout: float = ATTESTATION_TIMEOUT) -> None:
    """Check the archive's Sigstore provenance with the GitHub CLI.

    The check needs ``api.github.com`` and the TUF trust root, so a
    failure may be the network rather than the archive. Report it as
    transient, for the caller to retry, only when the output matches
    :data:`ATTESTATION_OUTAGE_SIGNATURES`, :data:`TRANSPORT_EOF` or a
    retryable HTTP status, when it says :data:`UNVERIFIED_TRUST_ROOT` and
    no trust root mirror answers, or when the check runs out of time. A
    mirror whose TLS certificate fails validation is not an outage, and
    neither is a probe the remaining time cut short. Any other failure,
    and a missing ``gh``, raises :class:`VerificationError`. It must finish
    within ``timeout`` seconds (at most :data:`ATTESTATION_TIMEOUT`).
    """
    limit = min(timeout, ATTESTATION_TIMEOUT)
    started = time.monotonic()
    command = [
        "gh",
        "attestation",
        "verify",
        str(archive),
        "--repo",
        ATTESTATION_REPO,
    ]
    try:
        proc = subprocess.run(  # noqa: S603
            command,
            capture_output=True,
            text=True,
            timeout=limit,
            check=False,
        )
    except FileNotFoundError as exc:
        raise VerificationError(
            f"cannot verify the attestation for {archive.name}: "
            "the GitHub CLI (gh) is not installed"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise TransientError(f"attestation check exceeded {limit:.0f}s") from exc
    if proc.returncode != 0:
        output = f"{proc.stderr or ''}\n{proc.stdout or ''}"
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        last = detail[-1] if detail else "no output"
        if is_attestation_outage(output):
            raise TransientError(f"attestation check failed: {last}")
        if UNVERIFIED_TRUST_ROOT in output.lower():
            try:
                doubt = trust_root_outage_doubt(limit - (time.monotonic() - started))
            except VerificationError as untrusted:
                raise VerificationError(
                    f"attestation verification failed for {archive.name}: "
                    f"{last}; {untrusted}, so this is not an outage"
                ) from untrusted
            if doubt is None:
                raise TransientError(
                    f"attestation check failed: {last}; "
                    "no Sigstore trust root mirror answered"
                )
            raise VerificationError(
                f"attestation verification failed for {archive.name}: {last}; {doubt}"
            )
        raise VerificationError(
            f"attestation verification failed for {archive.name}: {last}"
        )


def verify_sha256(path: Path, expected: str) -> None:
    """Raise :class:`IntegrityError` unless the file matches the digest."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1 << 20):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise IntegrityError(
            f"{path.name} does not match its pinned sha256 digest "
            f"(expected {expected}, got {digest.hexdigest()})"
        )
