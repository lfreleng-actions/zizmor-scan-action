# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Fetch the pinned zizmor binary, with bounded retries and a second source.

The action runs this script instead of a bare ``curl`` so that one flaky
CDN no longer fails a whole organisation-wide scan. It has two sources:

1. The attested GitHub release tarball. The script verifies its Sigstore
   provenance with ``gh attestation verify`` before it extracts anything.
2. The matching wheel on PyPI, which carries the same binary. The bundled
   ``uv.lock`` pins the wheel URL and its SHA-256 digest, so the script
   refuses a wheel that does not match the pin. This is a hash pin, not
   Sigstore provenance, so the script reports when it was used.

The script uses the PyPI wheel only when GitHub is unavailable: the
release download or the attestation check keeps failing with an outage,
or the release asset is not there to download. A verdict on the GitHub
artifact fails the run instead, without trying PyPI: a missing or
rejected attestation, a runner without ``gh``, or a tarball that is not
readable or lacks the binary. Routing around a verdict would skip the
provenance check that the GitHub source exists to make.

Each network operation retries transient failures up to four times,
waiting 10, 20, 40 and 80 seconds with each wait cut by up to a quarter
at random so that parallel jobs do not retry in step. Each source also
has a hard 180 second budget: every attempt gets only the time that
remains, so a slow GitHub cannot delay the PyPI fallback past it.
``zizmor_transfer.py`` implements the retries.

Configuration is read from the environment:

* ``ZIZMOR_TAG``      release tag to fetch, for example ``v1.31.1``
* ``ZIZMOR_WORKDIR``  existing directory to work in; the binary lands in
  its ``bin`` subdirectory
* ``ZIZMOR_LOCK``     path to the ``uv.lock`` that pins the PyPI wheels
* ``RUNNER_OS``      ``Linux`` or ``macOS`` (set by the runner)
* ``RUNNER_ARCH``    ``X64`` or ``ARM64`` (set by the runner)

On success the script prints ``zizmor=<path>`` and ``source=<github|pypi>``
to stdout, ready to append to ``$GITHUB_OUTPUT``. Everything else goes to
stderr.

The GitHub source needs only the standard library of Python 3.9 or
newer. The PyPI fallback reads ``uv.lock`` with ``tomllib``, which needs
3.11, and reports that when it is missing.

Run it as ``python3 -E -s zizmor_fetch.py``: ``-I`` would also drop the
script's own directory from ``sys.path`` and hide its sibling module,
while ``-E -s`` still ignores ``PYTHONPATH`` and the user site, and never
puts the audited workspace on the path.
"""

from __future__ import annotations

import gzip
import os
import re
import sys
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

from zizmor_transfer import (
    FetchError,
    RetrySchedule,
    VerificationError,
    download_file,
    log,
    retry_call,
    verify_attestation,
    verify_sha256,
)

RELEASE_BASE = "https://github.com/zizmorcore/zizmor/releases/download"
PYPI_FILE_HOST = "https://files.pythonhosted.org/"
BINARY_NAME = "zizmor"

RELEASE_ASSETS = {
    ("Linux", "X64"): "zizmor-x86_64-unknown-linux-gnu.tar.gz",
    ("Linux", "ARM64"): "zizmor-aarch64-unknown-linux-gnu.tar.gz",
    ("macOS", "X64"): "zizmor-x86_64-apple-darwin.tar.gz",
    ("macOS", "ARM64"): "zizmor-aarch64-apple-darwin.tar.gz",
}

# Wheel platform tags per runner, most preferred first. A glibc runner
# takes the manylinux wheel; musllinux is the fallback for the rest.
WHEEL_PLATFORMS = {
    ("Linux", "X64"): (
        re.compile(r"-manylinux[0-9a-z_]*_x86_64\.whl$"),
        re.compile(r"-musllinux[0-9a-z_]*_x86_64\.whl$"),
    ),
    ("Linux", "ARM64"): (
        re.compile(r"-manylinux[0-9a-z_]*_aarch64\.whl$"),
        re.compile(r"-musllinux[0-9a-z_]*_aarch64\.whl$"),
    ),
    ("macOS", "X64"): (re.compile(r"-macosx_[0-9]+_[0-9]+_x86_64\.whl$"),),
    ("macOS", "ARM64"): (re.compile(r"-macosx_[0-9]+_[0-9]+_arm64\.whl$"),),
}

SHA256_DIGEST = re.compile(r"^sha256:([0-9a-f]{64})$")


@dataclass(frozen=True)
class FetchResult:
    """Where the binary landed and which source supplied it."""

    binary: Path
    source: str


@dataclass(frozen=True)
class FetchRequest:
    """What to fetch, for which runner, and where to put it."""

    tag: str
    system: str
    arch: str
    workdir: Path
    lock_path: Path

    @property
    def version(self) -> str:
        return self.tag.removeprefix("v")

    @property
    def bindir(self) -> Path:
        return self.workdir / "bin"


def release_asset(system: str, arch: str) -> str:
    """Name the release tarball for a runner platform."""
    try:
        return RELEASE_ASSETS[(system, arch)]
    except KeyError:
        raise FetchError(
            f"unsupported runner {system}/{arch}; "
            "supports Linux and macOS on x86_64 or arm64"
        ) from None


def select_wheel(
    lock_text: str, version: str, system: str, arch: str
) -> tuple[str, str]:
    """Return the pinned wheel URL and SHA-256 digest for a platform."""
    # tomllib arrived in Python 3.11. Import it here, not at module level,
    # so a runner with an older python3 can still use the GitHub source;
    # only this fallback needs it.
    try:
        import tomllib
    except ImportError as exc:
        raise FetchError(
            "the PyPI fallback needs Python 3.11 or newer (tomllib)"
        ) from exc
    try:
        packages = tomllib.loads(lock_text).get("package", [])
    except tomllib.TOMLDecodeError as exc:
        raise FetchError(f"uv.lock is not valid TOML: {exc}") from exc
    pinned = next((p for p in packages if p.get("name") == "zizmor"), None)
    if pinned is None:
        raise FetchError("uv.lock does not pin zizmor")
    if pinned.get("version") != version:
        raise FetchError(
            f"uv.lock pins zizmor {pinned.get('version')}, not {version}; "
            "the PyPI fallback needs a pinned digest"
        )
    patterns = WHEEL_PLATFORMS.get((system, arch))
    if patterns is None:
        raise FetchError(f"no PyPI wheel for {system}/{arch}")
    wheels = [w for w in pinned.get("wheels", []) if isinstance(w.get("url"), str)]
    for pattern in patterns:
        for wheel in wheels:
            if not pattern.search(wheel["url"]):
                continue
            url = wheel["url"]
            if not url.startswith(PYPI_FILE_HOST):
                raise FetchError(f"uv.lock wheel is not on {PYPI_FILE_HOST}: {url}")
            match = SHA256_DIGEST.match(str(wheel.get("hash", "")))
            if match is None:
                raise FetchError(f"uv.lock wheel has no sha256 digest: {url}")
            return url, match.group(1)
    raise FetchError(f"uv.lock has no zizmor {version} wheel for {system}/{arch}")


def install(content: bytes, bindir: Path) -> Path:
    """Write the binary into ``bindir`` and make it executable."""
    binary = bindir / BINARY_NAME
    binary.write_bytes(content)
    binary.chmod(0o755)
    return binary


def extract_from_tarball(archive: Path, bindir: Path) -> Path:
    """Extract the ``zizmor`` file from a release tarball.

    Read the member's bytes and write them under a fixed name rather
    than extracting by path, so an archive cannot place a file elsewhere.
    """
    # gzip reports a damaged stream with errors tarfile does not wrap:
    # EOFError when truncated, BadGzipFile on a bad checksum, zlib.error
    # on an invalid deflate block inside a member.
    try:
        with tarfile.open(archive, "r:gz") as tar:
            for member in tar:
                if member.isfile() and Path(member.name).name == BINARY_NAME:
                    handle = tar.extractfile(member)
                    if handle is not None:
                        return install(handle.read(), bindir)
    except (tarfile.TarError, EOFError, gzip.BadGzipFile, zlib.error) as exc:
        raise VerificationError(
            f"{archive.name} is not a readable tarball: {exc}"
        ) from exc
    raise VerificationError(f"{BINARY_NAME} binary not found in {archive.name}")


def extract_from_wheel(wheel: Path, version: str, bindir: Path) -> Path:
    """Extract the ``zizmor`` script from a PyPI wheel."""
    member = f"{BINARY_NAME}-{version}.data/scripts/{BINARY_NAME}"
    try:
        with zipfile.ZipFile(wheel) as archive:
            return install(archive.read(member), bindir)
    except KeyError:
        raise FetchError(f"{BINARY_NAME} binary not found in {wheel.name}") from None
    except zipfile.BadZipFile as exc:
        raise FetchError(f"{wheel.name} is not a readable wheel: {exc}") from exc


def fetch_from_github(request: FetchRequest, schedule: RetrySchedule) -> Path:
    """Download the release tarball, verify its attestation, extract it."""
    asset = release_asset(request.system, request.arch)
    url = f"{RELEASE_BASE}/{request.tag}/{asset}"
    archive = request.workdir / asset
    # The download and the attestation check share one budget: both
    # depend on GitHub, so a long outage spends it once, not twice.
    deadline = schedule.clock() + schedule.budget
    try:
        retry_call(
            lambda remaining: download_file(url, archive, timeout=remaining),
            label=f"download {asset}",
            schedule=schedule,
            deadline=deadline,
        )
        retry_call(
            lambda remaining: verify_attestation(archive, timeout=remaining),
            label="attestation check",
            schedule=schedule,
            deadline=deadline,
        )
        return extract_from_tarball(archive, request.bindir)
    finally:
        archive.unlink(missing_ok=True)


def fetch_from_pypi(request: FetchRequest, schedule: RetrySchedule) -> Path:
    """Download the pinned wheel, check its digest, extract the binary."""
    try:
        lock_text = request.lock_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FetchError(f"cannot read {request.lock_path}: {exc}") from exc
    url, digest = select_wheel(lock_text, request.version, request.system, request.arch)
    wheel = request.workdir / url.rsplit("/", 1)[1]

    def download_and_check(remaining: float) -> None:
        download_file(url, wheel, timeout=remaining)
        verify_sha256(wheel, digest)

    try:
        retry_call(
            download_and_check,
            label=f"download {wheel.name}",
            schedule=schedule,
            deadline=schedule.clock() + schedule.budget,
        )
        return extract_from_wheel(wheel, request.version, request.bindir)
    finally:
        wheel.unlink(missing_ok=True)


def fetch(
    *,
    tag: str,
    system: str,
    arch: str,
    workdir: Path,
    lock_path: Path,
    schedule: RetrySchedule | None = None,
) -> FetchResult:
    """Fetch zizmor from GitHub, or from PyPI when GitHub is unavailable."""
    schedule = schedule or RetrySchedule()
    request = FetchRequest(tag, system, arch, workdir, lock_path)
    # Reject an unsupported runner before any network traffic.
    release_asset(system, arch)
    request.bindir.mkdir(parents=True, exist_ok=True)
    try:
        return FetchResult(fetch_from_github(request, schedule), "github")
    except VerificationError as rejected:
        raise VerificationError(
            f"{rejected}; not falling back to the PyPI wheel"
        ) from rejected
    except FetchError as github_failure:
        log(
            "::warning::GitHub could not supply the attested release "
            f"({github_failure}); falling back to the PyPI wheel pinned "
            "in uv.lock. Its SHA-256 digest is checked, but its Sigstore "
            "attestation is not."
        )
        try:
            return FetchResult(fetch_from_pypi(request, schedule), "pypi")
        except FetchError as pypi_failure:
            raise FetchError(
                f"could not fetch zizmor {request.version}: "
                f"github release: {github_failure}; pypi wheel: {pypi_failure}"
            ) from pypi_failure


def main() -> int:
    """Fetch the binary as configured by the environment."""
    try:
        tag = os.environ["ZIZMOR_TAG"]
        workdir = Path(os.environ["ZIZMOR_WORKDIR"])
        lock_path = Path(os.environ["ZIZMOR_LOCK"])
    except KeyError as exc:
        print(f"::error::{exc.args[0]} is not set", file=sys.stderr)
        return 2
    try:
        result = fetch(
            tag=tag,
            system=os.environ.get("RUNNER_OS", ""),
            arch=os.environ.get("RUNNER_ARCH", ""),
            workdir=workdir,
            lock_path=lock_path,
        )
    except FetchError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    log(f"zizmor {tag} ready from {result.source}")
    print(f"zizmor={result.binary}")
    print(f"source={result.source}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
