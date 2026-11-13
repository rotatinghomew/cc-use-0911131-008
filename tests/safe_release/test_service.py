"""端到端测试：服务编排、外部脱敏输出、只增持久化与台账关联。"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from screening_kpi_auditor.safe_release.service import SafeReleasePlanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures/analysis/input.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ServiceContractTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / "audit.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_response_contains_required_top_level_fields(self):
        result = SafeReleasePlanner(self.database).plan(load_fixture())
        for field_name in ("release_id", "status", "public_cells", "suppressed", "certificate"):
            self.assertIn(field_name, result)
        self.assertIn(result["status"], ("published", "rejected"))
        self.assertTrue(result["release_id"].startswith("rel-"))

    def test_public_cells_carry_cell_id_numerator_denominator_rate(self):
        result = SafeReleasePlanner(self.database).plan(load_fixture())
        if result["status"] == "rejected":
            # 无法证明安全时整单拒绝，不发布任何单元数值。
            self.assertEqual(result["public_cells"], [])
            return
        self.assertTrue(result["public_cells"])
        for cell in result["public_cells"]:
            self.assertEqual(
                set(cell),
                {"cell_id", "view_id", "level", "members", "numerator", "denominator", "rate"},
            )
            if cell["numerator"] is not None:
                self.assertEqual(cell["rate"], round(cell["numerator"] / cell["denominator"], 6))
            else:
                # 隐藏值三项必须全部为 null。
                self.assertIsNone(cell["denominator"])
                self.assertIsNone(cell["rate"])

    def test_external_result_never_carries_hidden_true_values(self):
        result = SafeReleasePlanner(self.database).plan(load_fixture())
        external = json.dumps(result, ensure_ascii=False)
        # small 镇真值：分母 2、分子 1。这些数字不得出现在任何被抑制单元上。
        for entry in result["public_cells"]:
            if entry["numerator"] is None:
                self.assertNotIn("true", json.dumps(entry))
                self.assertNotIn("interval", json.dumps(entry))
        # 证书只含方法与口径说明，不含单元真值。
        cert = result["certificate"]
        self.assertNotIn("true_numerator", external)
        self.assertNotIn("true_denominator", external)
        self.assertIn("scope_and_limitations", cert)
        self.assertIn("protection_condition", cert)

    def test_persisted_internal_workpaper_keeps_true_values(self):
        planner = SafeReleasePlanner(self.database)
        result = planner.plan(load_fixture())
        with sqlite3.connect(self.database) as connection:
            rows = connection.execute(
                "SELECT visibility, true_numerator, true_denominator, disclosed_numerator "
                "FROM safe_release_cells WHERE release_id=?",
                (result["release_id"],),
            ).fetchall()
        self.assertTrue(rows)
        for visibility, true_n, true_d, disclosed_n in rows:
            self.assertIsNotNone(true_n)
            self.assertIsNotNone(true_d)
            if visibility == "suppressed":
                self.assertIsNone(disclosed_n)

    def test_release_evidence_is_append_only(self):
        planner = SafeReleasePlanner(self.database)
        result = planner.plan(load_fixture())
        with sqlite3.connect(self.database) as connection:
            # SQLite 触发器 RAISE(ABORT) 报 IntegrityError。
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "DELETE FROM safe_release_cells WHERE release_id=?",
                    (result["release_id"],),
                )
            with self.assertRaises(sqlite3.DatabaseError):
                connection.execute(
                    "UPDATE safe_releases SET status='published' WHERE release_id=?",
                    (result["release_id"],),
                )

    def test_evidence_links_to_existing_audit_ledger(self):
        result = SafeReleasePlanner(self.database).plan(load_fixture())
        with sqlite3.connect(self.database) as connection:
            link = connection.execute(
                "SELECT run_id FROM safe_release_links WHERE release_id=?",
                (result["release_id"],),
            ).fetchone()
            run = connection.execute(
                "SELECT run_id FROM runs WHERE run_id=?", (link[0],)
            ).fetchone()
            events = connection.execute(
                "SELECT stage FROM events WHERE run_id=? LIMIT 3", (link[0],)
            ).fetchall()
        self.assertIsNotNone(link)
        self.assertIsNotNone(run)
        self.assertIn(("safe_release",), events)

    def test_idempotent_same_input_returns_same_release(self):
        planner = SafeReleasePlanner(self.database)
        first = planner.plan(load_fixture())
        second = planner.plan(load_fixture())
        self.assertEqual(first["release_id"], second["release_id"])
        self.assertTrue(second.get("replayed"))

    def test_record_dispositions_are_persisted(self):
        result = SafeReleasePlanner(self.database).plan(load_fixture())
        with sqlite3.connect(self.database) as connection:
            count = connection.execute(
                "SELECT count(*) FROM safe_release_record_dispositions WHERE release_id=?",
                (result["release_id"],),
            ).fetchone()[0]
        # fixture 有 65 条记录，每条都应有处置留痕。
        self.assertEqual(count, len(load_fixture()["records"]))

    def test_publishable_all_safe_dataset_publishes_everything(self):
        # 构造一个所有单元都远超阈值的数据集，应全部发布、零抑制。
        request = load_fixture()
        request = json.loads(json.dumps(request))
        big_records = []
        rid = 0
        for town in ("t1", "t2", "t3", "t4"):
            for age in ("young", "old"):
                for channel in ("clinic", "mobile"):
                    for _ in range(8):
                        big_records.append(
                            {
                                "record_id": f"r{rid}",
                                "person_id": f"p{rid}",
                                "period": "2026-Q2",
                                "town": town,
                                "age_band": age,
                                "channel": channel,
                                "eligible": True,
                                "screened": rid % 2 == 0,
                                "effective_at": "2026-06-01",
                                "known_at": "2026-06-20",
                                "revision": 1,
                            }
                        )
                        rid += 1
        request["records"] = big_records
        result = SafeReleasePlanner(self.database).plan(request)
        self.assertEqual(result["status"], "published")
        self.assertEqual(result["suppressed"], [])
        self.assertTrue(all(c["numerator"] is not None for c in result["public_cells"]))


if __name__ == "__main__":
    unittest.main()
