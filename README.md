<!--
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
-->

# 🌈 Zizmor Security Audit Action

<!-- prettier-ignore-start -->
<!-- markdownlint-disable-next-line MD013 -->
[![Linux Foundation](https://img.shields.io/badge/Linux-Foundation-blue)](https://linuxfoundation.org/) [![Source Code](https://img.shields.io/badge/GitHub-100000?logo=github&logoColor=white&color=blue)](https://github.com/lfreleng-actions/zizmor-scan-action) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
<!-- prettier-ignore-end -->

A composite GitHub Action that runs the
[zizmor](https://github.com/zizmorcore/zizmor) static security auditor
against a repository's GitHub Actions workflows. It downloads a verified,
attested zizmor binary, audits the workspace in SARIF mode, writes a
findings summary, and publishes the SARIF to code scanning on request.

SARIF mode makes zizmor exit zero, so the audit stays advisory and does
not block merges. A code scanning ruleset can promote findings to
merge-blocking later.

Deploy it across an estate from one place — an organisation required
workflow — or opt in per repository with a short caller workflow.

The action runs on Linux and macOS runners, on x86_64 or arm64. On
other platforms it fails fast with a clear error.

## Usage

### Run the action

Check out the repository, then run the action as a step:

<!-- markdownlint-disable MD013 MD046 -->

```yaml
jobs:
  zizmor:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      # yamllint disable-line rule:line-length
      - uses: actions/checkout@<commit-sha>  # v6
      # yamllint disable-line rule:line-length
      - uses: lfreleng-actions/zizmor-scan-action@<commit-sha>  # vX.Y.Z
        with:
          upload-sarif: 'true'
```

<!-- markdownlint-enable MD013 MD046 -->

Grant `security-events: write` and set `upload-sarif` to `'true'` to
publish results to code scanning. Drop both to keep the run advisory.
Pin the action to a commit SHA (the organisation standard) and record
the version in a trailing comment.

### Deploy across an organisation

Copy [`examples/required-workflow.yaml`](examples/required-workflow.yaml)
into your organisation's `.github` repository and reference it from an
organisation ruleset as a required workflow. GitHub then runs it across
every selected repository with no per-repository file. The audit job
holds `contents: read`; a separate job uploads the SARIF under
`security-events: write` on default-branch pushes.

### Opt in per repository

Copy [`examples/caller-workflow.yaml`](examples/caller-workflow.yaml)
into a repository's `.github/workflows/` directory. The single job audits
the repository on pull requests and uploads the SARIF on default-branch
pushes.

## How it works

1. The runner checks the action out at the ref a consumer pins. The
   action reads its pinned zizmor version from its bundled
   `pyproject.toml` through `${{ github.action_path }}`, so that ref
   fixes the zizmor version: the ref is the pin.
2. The action sets up Python 3.13 with a commit-pinned
   `actions/setup-python` and runs its own scripts on that interpreter,
   not on whichever `python3` comes first on the caller's `PATH`. It
   passes `update-environment: false`, so the caller's `PATH` and
   environment stay as they were.
3. The action downloads the matching zizmor release binary from the
   [zizmorcore/zizmor releases](https://github.com/zizmorcore/zizmor/releases)
   and verifies its Sigstore provenance with `gh attestation verify`
   before it runs. The action retries transient failures (see
   [Download resilience](#download-resilience)). It never runs a binary
   that fails verification.
4. zizmor audits the workspace in SARIF mode.
5. The action writes a findings summary to the job summary and, unless
   `annotate` is `'false'`, emits inline annotations.
6. When `upload-sarif` is `'true'`, the action publishes the SARIF to
   code scanning. The example workflows set this for default-branch
   pushes and keep pull request runs advisory.

## Inputs

<!-- markdownlint-disable MD013 -->

| Name                 | Default         | Description                                                                                   |
| -------------------- | --------------- | --------------------------------------------------------------------------------------------- |
| `persona`            | `auditor`       | zizmor persona controlling finding breadth: `regular`, `pedantic`, or `auditor`.              |
| `min-severity`       | `informational` | Lowest severity reported: `unknown`, `informational`, `low`, `medium`, `high`.                |
| `min-confidence`     | `""`            | Lowest confidence reported: `low`, `medium`, or `high`. Empty audits all confidences.         |
| `working-directory`  | `.`             | Path within the workspace to audit.                                                           |
| `zizmor-version`     | `""`            | Override the bundled pin with an explicit tag (for example `v1.25.2`).                        |
| `extra-args`         | `""`            | Extra raw arguments appended to the zizmor call.                                              |
| `upload-sarif`       | `'false'`       | Publish SARIF to code scanning from the action: `'true'` or `'false'`.                        |
| `annotate`           | `'true'`        | Emit inline annotations for the top findings: `'true'` or `'false'`.                          |
| `summary-repository` | `""`            | owner/repo label for step-summary links; takes effect when paired with a valid `summary-sha`. |
| `summary-sha`        | `""`            | Commit SHA (7–40 hex digits) for step-summary links; pairs with `summary-repository`.         |

<!-- markdownlint-enable MD013 -->

Set `annotate` to `'false'` for a scan whose findings do not belong to
the current run. A gate that scans both the pull request head and its
merge base, so that it fails on the findings the pull request adds and
not on older ones, turns annotations off for the base scan. Otherwise
the base scan's annotations attach to the run, and findings the pull
request has already fixed still show as warnings or errors on it. The
job summary, the SARIF file, the outputs and the exit status stay the
same either way.

<!-- markdownlint-disable MD013 MD046 -->

```yaml
      # yamllint disable-line rule:line-length
      - uses: lfreleng-actions/zizmor-scan-action@<commit-sha>  # vX.Y.Z
        with:
          working-directory: base
          annotate: 'false'
```

<!-- markdownlint-enable MD013 MD046 -->

## Outputs

<!-- markdownlint-disable MD013 -->

| Name         | Description                                  |
| ------------ | -------------------------------------------- |
| `sarif-file` | Absolute path to the generated SARIF file.   |

<!-- markdownlint-enable MD013 -->

## Permissions

Grant these to the calling job:

<!-- markdownlint-disable MD013 -->

| Permission               | Why                                                                      |
| ------------------------ | ------------------------------------------------------------------------ |
| `contents: read`         | Check out the repository under audit.                                    |
| `security-events: write` | Publish SARIF to code scanning when `upload-sarif` is `true`.            |
| `actions: read`          | Lets `upload-sarif` read run info on private repos (harmless on public). |

<!-- markdownlint-enable MD013 -->

The action uses the automatically provided `GITHUB_TOKEN` and needs no
extra secrets.

## Version management

`pyproject.toml` pins the zizmor version and `uv.lock` locks it.
Dependabot's `uv` ecosystem watches these files and opens a pull request
when a new zizmor release ships. The lock file gives Dependabot the
resolution context it needs, so version and security updates resolve
cleanly.

The update flow:

1. zizmor publishes a new release.
2. Dependabot opens a pull request bumping `pyproject.toml` and `uv.lock`
   (weekly, with a cooldown so fresh releases settle first).
3. A maintainer reviews and merges the bump.
4. A maintainer pushes a signed semver tag; the release-drafter and
   tag-push workflows draft and promote the GitHub release.
5. Consuming repositories bump their pinned ref (through their own
   Dependabot `github-actions` updates) to adopt the new zizmor version.

## Download resilience

A scheduled scan of an entire organisation downloads zizmor once per
repository, so the download must survive a flaky release CDN. `scripts/zizmor_fetch.py`
fetches the binary from two sources:

1. **The attested GitHub release.** The script downloads the tarball and
   checks its attestation with `gh attestation verify`.
2. **The PyPI wheel pinned in `uv.lock`.** The wheel carries the same
   binary. The script takes the wheel's URL and SHA-256 digest from the
   bundled `uv.lock` and refuses a file that does not match. The script
   turns to it when GitHub is unavailable, and never otherwise.

Each network operation, the download and the attestation check included,
retries transient failures: HTTP 408, 425, 429 and 5xx responses,
connection resets, timeouts and a response body cut short. It makes at
most four retries, waiting about 10, 20, 40 and 80 seconds (each wait cut
by up to a quarter at random, so parallel jobs do not retry in step).
Each source also has a hard 180 second budget: every attempt receives
the time that remains, so a stalled connection cannot delay the
fallback past it. Failures retrying cannot fix, such as HTTP 404 or a
digest mismatch, fail at once.

GitHub counts as unavailable when the release download fails with one of
those transient errors until the retries run out, when the release asset
answers HTTP 404 or another client error, or when the attestation check
fails with output that names an outage: a retryable HTTP status, or a
network failure such as a timeout, a refused or reset connection, an
unknown host, or a request whose connection dropped. Go's `unexpected
EOF` names an outage when it follows the request's method and URL, and
a verdict otherwise, because a decoder reading malformed attestation
data says the same. When `gh` reports no cause beyond a Sigstore
verifier that could not load its trust root, which invalid trust
metadata causes as well as a blocked network, the script asks the
Sigstore and GitHub trust root mirrors, and counts an outage when
neither answers. A mirror whose TLS certificate fails validation is not
an outage, and nor is a check with too little time left to ask both
mirrors. Anything else is a verdict on the release, and the run fails
without trying PyPI: a missing or rejected attestation, a runner without
`gh`, or a tarball that is not readable or lacks the binary. The outage
list is an allow-list, so an unrecognised `gh` message fails the run
rather than skipping the check.

The action logs a `::warning::` when it uses the PyPI wheel. That
fallback checks a pinned digest but not the Sigstore attestation, so it
proves the file matches what this action's `uv.lock` pinned, not who
built it. The fallback needs `uv.lock` to pin the requested version: it
does not apply when `zizmor-version` overrides the bundled pin. It also
needs Python 3.11 or newer, for `tomllib`; the Python 3.13 the action
sets up meets that.

`uv.lock` is the same file Dependabot already keeps current alongside
`pyproject.toml`, so the fallback needs no extra maintenance.

## Security model

- **Provenance verification.** Every run downloads the zizmor release
  binary and verifies its Sigstore attestation with
  `gh attestation verify --repo zizmorcore/zizmor` before it runs. When
  GitHub stays unavailable the action instead uses the PyPI wheel pinned
  by digest in `uv.lock`, and logs a warning. A missing or rejected
  attestation fails the run instead of falling back. It never runs a
  binary that matches neither check.
- **Pinned and reviewable.** The ref a consumer pins fixes the installed
  zizmor version. Upgrades arrive as reviewable pull requests rather than
  tracking the latest release automatically.
- **SHA pinning.** Consumers pin this action, and the action pins
  everything it uses, to commit SHAs.
- **Least privilege.** The example workflows audit under `contents: read`
  and upload the SARIF from a job that holds `security-events: write`.

## License

Apache-2.0. See [LICENSE](LICENSE).
