"""命令行入口测试。"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CliTests(unittest.TestCase):
    def test_cli_writes_output_json_with_contract_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "audit.sqlite3"
            output = Path(directory) / "release.json"
            script = (
                "import sys; sys.path.insert(0, %r);"
                "from screening_kpi_auditor.safe_release.__main__ import main;"
                "sys.exit(main(['--input', %r, '--database', %r, '--output', %r]))"
                % (
                    str(ROOT),
                    str(ROOT / "fixtures/analysis/input.json"),
                    str(database),
                    str(output),
                )
            )
            completed = subprocess.run(
                [sys.executable, "-I", "-c", script],
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            result = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                set(result),
                {"release_id", "status", "as_of", "public_cells", "suppressed", "certificate"}
                | ({"rejection_reasons"} if result["status"] == "rejected" else set()),
            )
            self.assertIn("certificate_fingerprint", result["certificate"])
            self.assertTrue(database.is_file())


if __name__ == "__main__":
    unittest.main()
