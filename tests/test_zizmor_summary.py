# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation
"""Tests for scripts/zizmor_summary.py.

The script runs as the action runs it: ``python3 -I`` in a subprocess,
configured through the environment. Run with
``python3 -m unittest discover -s tests``.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "zizmor_summary.py"

SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "zizmor",
                    "rules": [
                        {"id": "zizmor/artipacked"},
                        {"id": "zizmor/unpinned-uses"},
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "zizmor/unpinned-uses",
                    "level": "error",
                    "message": {"text": "unpinned action reference"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ".github/workflows/ci.yaml"
                                },
                                "region": {"startLine": 12, "endLine": 12},
                            }
                        }
                    ],
                },
                {
                    "ruleId": "zizmor/artipacked",
                    "level": "warning",
                    "message": {"text": "credential persistence"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": ".github/workflows/ci.yaml"
                                },
                                "region": {"startLine": 20, "endLine": 22},
                            }
                        }
                    ],
                },
            ],
        }
    ],
}

ANNOTATION_PREFIXES = ("::warning", "::error", "::notice")


class AnnotateTest(unittest.TestCase):
    """Check that ZIZMOR_ANNOTATE gates the finding annotations only."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.sarif = self.tmp / "zizmor.sarif"
        self.sarif.write_text(json.dumps(SARIF), encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def run_summary(self, annotate: str | None) -> tuple[list[str], str, int]:
        """Run the script; return (stdout lines, step summary, exit code)."""
        summary = self.tmp / f"summary-{annotate}.md"
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("ZIZMOR_", "GITHUB_"))
        }
        env.update(
            {
                "ZIZMOR_SARIF": str(self.sarif),
                "GITHUB_STEP_SUMMARY": str(summary),
                "GITHUB_REPOSITORY": "example/repo",
                "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
            }
        )
        if annotate is not None:
            env["ZIZMOR_ANNOTATE"] = annotate
        proc = subprocess.run(
            [sys.executable, "-I", str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        return (
            proc.stdout.splitlines(),
            summary.read_text(encoding="utf-8"),
            proc.returncode,
        )

    @staticmethod
    def annotations(lines: list[str]) -> list[str]:
        """Return the workflow-command annotation lines."""
        return [line for line in lines if line.startswith(ANNOTATION_PREFIXES)]

    def test_true_annotates_top_findings(self) -> None:
        lines, _, rc = self.run_summary("true")
        self.assertEqual(rc, 0)
        found = self.annotations(lines)
        self.assertEqual(len(found), 2)
        self.assertTrue(found[0].startswith("::error "))
        self.assertIn("title=zizmor%3A zizmor/unpinned-uses", found[0])
        self.assertTrue(found[1].startswith("::warning "))
        self.assertIn("endLine=22", found[1])

    def test_unset_emits_no_annotations(self) -> None:
        """Unset behaves as aislop_summary.py does: annotations off."""
        unset_lines, unset_summary, unset_rc = self.run_summary(None)
        false_lines, false_summary, false_rc = self.run_summary("false")
        self.assertEqual(unset_rc, false_rc)
        self.assertEqual(self.annotations(unset_lines), [])
        self.assertEqual(unset_lines, false_lines)
        self.assertEqual(unset_summary, false_summary)

    def test_false_emits_no_annotations(self) -> None:
        lines, _, rc = self.run_summary("false")
        self.assertEqual(rc, 0)
        self.assertEqual(self.annotations(lines), [])

    def test_false_keeps_summary_and_listing(self) -> None:
        false_lines, false_summary, false_rc = self.run_summary("false")
        true_lines, true_summary, true_rc = self.run_summary("true")
        self.assertEqual(false_rc, true_rc)
        self.assertEqual(false_summary, true_summary)
        self.assertIn("2 finding(s)", false_summary)
        self.assertEqual(
            false_lines,
            [line for line in true_lines if not line.startswith(ANNOTATION_PREFIXES)],
        )


if __name__ == "__main__":
    unittest.main()
