# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Summarise a zizmor SARIF report for the GitHub Actions step summary.

Read the SARIF file at ``$ZIZMOR_SARIF`` and write a human-readable
markdown summary to ``$GITHUB_STEP_SUMMARY``. Also emit a compact
listing to stdout and ``::warning``/``::error``/``::notice`` workflow
commands for the top findings so they surface as inline PR annotations.

Configuration is read from the environment:

* ``ZIZMOR_SARIF``        path to the SARIF report (required)
* ``ZIZMOR_TOP_N``        max findings to detail and annotate (default 10)
* ``ZIZMOR_PERSONA``      persona label shown in the summary header
* ``ZIZMOR_MIN_SEVERITY`` minimum severity label shown in the header
* ``ZIZMOR_REPOSITORY``   owner/repo label override for summary links
* ``ZIZMOR_SHA``          commit SHA override for summary links
"""

import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from posixpath import basename
from typing import Any
from urllib.parse import quote

LEVEL_LABEL = {
    "error": "\u26d4 High",
    "warning": "\u26a0\ufe0f Medium",
    "note": "\U0001f4dd Low",
    "none": "\u2139\ufe0f Info",
}
LEVEL_ORDER = ["error", "warning", "note", "none"]
WARN_CMD = {
    "error": "error",
    "warning": "warning",
    "note": "notice",
    "none": "notice",
}
MAX_MSG_LEN = 200

Finding = dict[str, Any]


def strip_rule_prefix(rid: str) -> str:
    """Drop the ``zizmor/`` prefix from a rule id for tighter tables."""
    if rid.startswith("zizmor/"):
        return rid[len("zizmor/") :]
    return rid


def _escape_wf_data(value: object) -> str:
    """Escape the message body of a GitHub workflow command.

    Per GitHub's workflow-command rules, ``%``, ``CR`` and ``LF`` must
    be percent-encoded in the data (post-``::``) portion.
    """
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_wf_property(value: object) -> str:
    """Escape a property value of a GitHub workflow command.

    Properties live in the comma-separated ``key=value`` list before
    ``::``. In addition to the data-escapes, ``,`` and ``:`` must be
    encoded so they cannot terminate the property list or the command
    prefix.
    """
    return _escape_wf_data(value).replace(":", "%3A").replace(",", "%2C")


def _render_link(file: str, line: int | None, repo: str, sha: str, server: str) -> str:
    """Render a path:line link with the basename as visible text."""
    if not file:
        return ""
    short = basename(file) or file
    label = short + (f":{line}" if line else "")
    if not repo or not sha:
        return f"`{label}`"
    anchor = f"#L{line}" if line else ""
    url = f"{server}/{repo}/blob/{sha}/{quote(file)}{anchor}"
    return f"[`{label}`]({url})"


def _result_level(result: dict[str, Any], meta: dict[str, Any]) -> str:
    """Resolve a result's level, falling back to the rule default."""
    level = result.get("level")
    if level:
        return str(level)
    default_cfg = meta.get("defaultConfiguration") or {}
    return str(default_cfg.get("level", "warning"))


def _result_location(
    result: dict[str, Any],
) -> tuple[str, int | None, int | None]:
    """Extract (file, line, endline) from a SARIF result."""
    locations = result.get("locations") or [{}]
    ploc = locations[0].get("physicalLocation") or {}
    artifact = ploc.get("artifactLocation") or {}
    region = ploc.get("region") or {}
    line = region.get("startLine")
    endline = region.get("endLine") or line
    return artifact.get("uri", ""), line, endline


def _load_findings(
    sarif_path: Path,
) -> tuple[list[Finding], Counter[str], Counter[str]]:
    """Parse SARIF and return (findings, level_counts, rule_counts)."""
    with sarif_path.open() as fh:
        data = json.load(fh)

    findings: list[Finding] = []
    rule_meta: dict[str, Any] = {}
    for run in data.get("runs", []):
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        for rule in driver.get("rules", []):
            rule_meta[rule.get("id", "")] = rule
        for result in run.get("results", []):
            rid = result.get("ruleId", "?")
            level = _result_level(result, rule_meta.get(rid) or {})
            message = result.get("message") or {}
            file, line, endline = _result_location(result)
            findings.append(
                {
                    "rule": rid,
                    "level": level,
                    "msg": str(message.get("text", "")).strip(),
                    "file": file,
                    "line": line,
                    "endline": endline,
                }
            )

    def sort_key(f: Finding) -> tuple[int, str, str, int]:
        try:
            idx = LEVEL_ORDER.index(f["level"])
        except ValueError:
            idx = 99
        return (idx, f["rule"], f["file"], f["line"] or 0)

    findings.sort(key=sort_key)
    level_counts: Counter[str] = Counter(f["level"] for f in findings)
    rule_counts: Counter[str] = Counter(f["rule"] for f in findings)
    return findings, level_counts, rule_counts


# Owner: alphanumeric with inner hyphens/underscores (underscores
# appear in Enterprise Managed User logins); no dots, no leading or
# trailing separator. Repo: must not be all dots ("." / "..") so a
# "valid" override can never URL-normalise into a different
# blob-link path.
_REPO_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?"
    r"/(?!\.+$)[A-Za-z0-9._-]+$"
)
_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def _label_overrides() -> tuple[str, str]:
    """Read and validate the summary label override pair.

    ``ZIZMOR_REPOSITORY`` and ``ZIZMOR_SHA`` override the ambient
    GitHub values so summaries can label a checkout of a different
    repository (for example in an organisation-wide scan matrix).
    The pair applies atomically and each value must be well formed
    (``owner/repo``; 7-40 hex-digit SHA): a partial or malformed
    override would mislabel the summary or break its links, so it is
    ignored with a warning.
    """
    repo = os.environ.get("ZIZMOR_REPOSITORY", "").strip()
    sha = os.environ.get("ZIZMOR_SHA", "").strip()
    if not repo and not sha:
        return "", ""
    if not (_REPO_RE.match(repo) and _SHA_RE.match(sha)):
        print(
            "::warning::ZIZMOR_REPOSITORY and ZIZMOR_SHA must be set"
            " together as owner/repo and a 7-40 hex-digit commit SHA;"
            " ignoring the override"
        )
        return "", ""
    return repo, sha


def _read_context() -> dict[str, Any]:
    """Collect configuration and repository context from the env."""
    repo_override, sha_override = _label_overrides()
    sha = sha_override or os.environ.get("GITHUB_SHA", "")
    return {
        "sarif_path": Path(os.environ["ZIZMOR_SARIF"]),
        "top_n": int(os.environ.get("ZIZMOR_TOP_N", "10")),
        "summary_path": os.environ.get("GITHUB_STEP_SUMMARY"),
        "server": os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        "repo": repo_override or os.environ.get("GITHUB_REPOSITORY", ""),
        "sha": sha,
        "short_sha": sha[:7] if sha else "?",
        "persona": os.environ.get("ZIZMOR_PERSONA", "auditor"),
        "min_severity": os.environ.get("ZIZMOR_MIN_SEVERITY", "informational"),
    }


def _render_header(total: int, ctx: dict[str, Any]) -> list[str]:
    """Render the title, finding total, and scan context lines."""
    title = "# \U0001f308 Zizmor Scan"
    if ctx["repo"]:
        title += f": {ctx['repo']}"
    out = [title, ""]
    if total == 0:
        out.append(f"No findings at or above `{ctx['min_severity']}` \u2705")
    else:
        out.append(
            f"{total} finding(s) at or above `{ctx['min_severity']}` \u26a0\ufe0f"
        )
    out.extend(
        [
            "",
            f"`{ctx['repo']}@{ctx['short_sha']}`",
            f"persona: `{ctx['persona']}`",
            f"min-severity: `{ctx['min_severity']}`",
            "",
        ]
    )
    return out


def _render_breakdowns(
    level_counts: Counter[str], rule_counts: Counter[str]
) -> list[str]:
    """Render the counts-by-severity and counts-by-rule tables."""
    out = ["## Counts by severity", "", "| Severity | Count |"]
    out.append("| --- | ---: |")
    for lvl in LEVEL_ORDER:
        if lvl in level_counts:
            out.append(f"| {LEVEL_LABEL.get(lvl, lvl)} | {level_counts[lvl]} |")
    out.extend(["", "## Counts by rule", "", "| Rule | Count |"])
    out.append("| --- | ---: |")
    for rid, n in rule_counts.most_common():
        out.append(f"| `{strip_rule_prefix(rid)}` | {n} |")
    out.append("")
    return out


def _render_findings_table(findings: list[Finding], ctx: dict[str, Any]) -> list[str]:
    """Render the detail table for the top findings."""
    total = len(findings)
    shown = findings[: ctx["top_n"]]
    extra = total - len(shown)
    heading = f"## Top {len(shown)} findings"
    if extra > 0:
        heading += f" (of {total}; {extra} more in SARIF)"
    out = [heading, ""]
    out.append("| Severity | Rule | Location | Message |")
    out.append("| --- | --- | --- | --- |")
    for f in shown:
        label = LEVEL_LABEL.get(f["level"], f["level"])
        msg = f["msg"].replace("|", "\\|").replace("\n", " ")
        if len(msg) > MAX_MSG_LEN:
            msg = msg[: MAX_MSG_LEN - 3] + "..."
        rule_short = strip_rule_prefix(f["rule"])
        loc = _render_link(f["file"], f["line"], ctx["repo"], ctx["sha"], ctx["server"])
        out.append(f"| {label} | `{rule_short}` | {loc} | {msg} |")
    return out


def _print_console(
    findings: list[Finding],
    level_counts: Counter[str],
    rule_counts: Counter[str],
    top_n: int,
) -> None:
    """Print a compact grouped listing to the job log."""
    total = sum(level_counts.values())
    print("::group::zizmor summary")
    by_level = {LEVEL_LABEL.get(k, k): v for k, v in level_counts.items()}
    print(f"Total: {total}  by-level: {by_level}  rules: {len(rule_counts)}")
    for f in findings[:top_n]:
        label = LEVEL_LABEL.get(f["level"], f["level"])
        loc_str = f["file"] + (f":{f['line']}" if f["line"] else "")
        rule_short = strip_rule_prefix(f["rule"])
        print(f"  {label}  {rule_short:<28}  {loc_str}")
    print("::endgroup::")


def _emit_annotations(findings: list[Finding], top_n: int) -> None:
    """Emit workflow-command annotations for the top findings.

    The commands keep the full rule id in the title since GitHub shows
    them out of context (e.g. in PR file annotations). Property values
    are escaped per GitHub's workflow-command rules so ``,`` and ``:``
    in titles or paths cannot break the format.
    """
    for f in findings[:top_n]:
        cmd = WARN_CMD.get(f["level"], "warning")
        parts = []
        if f["file"]:
            parts.append(f"file={_escape_wf_property(f['file'])}")
        if f["line"]:
            parts.append(f"line={f['line']}")
        if f["endline"] and f["endline"] != f["line"]:
            parts.append(f"endLine={f['endline']}")
        ann_title = f"zizmor: {f['rule']}"
        parts.append(f"title={_escape_wf_property(ann_title)}")
        msg = f["msg"].replace("\n", " ").strip() or f["rule"]
        print(f"::{cmd} {','.join(parts)}::{_escape_wf_data(msg)}")


def _write(lines: list[str], summary_path: str | None) -> None:
    """Append the rendered markdown lines to the step summary file."""
    if not summary_path:
        return
    with open(summary_path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def summarise() -> int:
    """Read SARIF and write summary; return process exit code."""
    ctx = _read_context()
    findings, level_counts, rule_counts = _load_findings(ctx["sarif_path"])
    total = sum(level_counts.values())

    out = _render_header(total, ctx)
    if total > 0:
        out.extend(_render_breakdowns(level_counts, rule_counts))
        out.extend(_render_findings_table(findings, ctx))
    _write(out, ctx["summary_path"])

    _print_console(findings, level_counts, rule_counts, ctx["top_n"])
    _emit_annotations(findings, ctx["top_n"])
    return 0


if __name__ == "__main__":
    sys.exit(summarise())
