"""Regression tests for preflight JSON stdout."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "hyops.cli", *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


class PreflightJsonStdoutTests(unittest.TestCase):
    def test_passing_json_stdout_is_one_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("preflight", "--root", tmp, "--json")
            payload = self._assert_json_document(result)

        self.assertEqual(result.returncode, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["code"], 0)

    def test_failing_json_stdout_is_one_document(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("preflight", "--root", tmp, "--target", "gcp", "--json")
            payload = self._assert_json_document(result)

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["code"], result.returncode)
        names = [item["name"] for item in payload["results"]]
        self.assertIn("readiness:gcp", names)

    def test_text_mode_still_announces_the_run_record_on_stdout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = _run("preflight", "--root", tmp, "--target", "gcp")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("readiness:gcp", result.stdout)
            self.assertIn("run record:", result.stdout)
            self.assertNotIn("run record:", result.stderr)
            record = result.stdout.split("run record:", 1)[1].strip()
            log = Path(record) / "output.log"
            self.assertTrue(log.is_file(), result.stdout)
            self.assertIn("readiness:gcp", log.read_text(encoding="utf-8"))

    def _assert_json_document(self, result: subprocess.CompletedProcess[str]) -> dict:
        self.assertNotIn("run record:", result.stdout, result.stdout)
        payload = json.loads(result.stdout)
        self.assertIsInstance(payload, dict)
        self.assertIn("run record:", result.stderr, result.stderr)
        record = result.stderr.split("run record:", 1)[1].strip()
        log = Path(record) / "output.log"
        self.assertTrue(log.is_file(), result.stderr)
        self.assertIn('"results"', log.read_text(encoding="utf-8"))
        return payload


if __name__ == "__main__":
    unittest.main()
