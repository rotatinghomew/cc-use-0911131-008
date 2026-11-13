"""口径重建测试：去重、口径生效日、迟到补录、未知维度与零分母留痕。"""
from __future__ import annotations

import copy
import unittest

from screening_kpi_auditor.runtime import DomainError
from screening_kpi_auditor.safe_release.rebuild import (
    DISPOSITION_DUPLICATE,
    DISPOSITION_INCLUDED,
    DISPOSITION_INELIGIBLE,
    DISPOSITION_LATE,
    DISPOSITION_PRECALIBER,
    UNKNOWN_DIMENSION,
    rebuild_indicators,
)


def base_record(record_id: str, **overrides) -> dict:
    record = {
        "record_id": record_id,
        "person_id": record_id.replace("r", "p"),
        "period": "2026-Q2",
        "town": "east",
        "age_band": "young",
        "channel": "clinic",
        "eligible": True,
        "screened": False,
        "effective_at": "2026-06-01",
        "known_at": "2026-06-20",
        "revision": 1,
    }
    record.update(overrides)
    return record


def base_request(records: list[dict]) -> dict:
    return {
        "as_of": "2026-07-01",
        "records": records,
        "indicator": {
            "version": "v1",
            "effective_at": "2026-01-01",
            "dedup_keys": ["person_id", "period"],
        },
        "minimum_cell_count": 5,
        "views": [
            {"view_id": "ta", "dimensions": ["town", "age_band"], "margins": True},
        ],
        "historical_cells": [],
        "required_totals": ["all"],
    }


class RebuildTests(unittest.TestCase):
    def test_dedup_keeps_highest_revision_for_same_person_period(self):
        request = base_request(
            [
                base_record("r1", person_id="p1", revision=1, screened=False),
                base_record("r2", person_id="p1", revision=3, screened=True),
                base_record("r3", person_id="p2", revision=1, screened=True),
            ]
        )
        result = rebuild_indicators(request)
        self.assertEqual(len(result.observations), 2)
        winner = next(o for o in result.observations if o.person_key == "p1")
        self.assertTrue(winner.screened)  # 采用 revision=3
        self.assertEqual(winner.source_record_ids, ("r1", "r2"))
        codes = {d["record_id"]: d["disposition"] for d in result.dispositions}
        self.assertEqual(codes["r2"], DISPOSITION_INCLUDED)
        self.assertEqual(codes["r1"], DISPOSITION_DUPLICATE)

    def test_pre_caliber_records_excluded_and_traced(self):
        request = base_request(
            [
                base_record("r1", effective_at="2025-12-31"),
                base_record("r2", effective_at="2026-01-01"),
            ]
        )
        result = rebuild_indicators(request)
        codes = {d["record_id"]: d["disposition"] for d in result.dispositions}
        self.assertEqual(codes["r1"], DISPOSITION_PRECALIBER)
        self.assertEqual(codes["r2"], DISPOSITION_INCLUDED)
        self.assertEqual(len(result.observations), 1)

    def test_late_backfill_excluded_against_as_of(self):
        request = base_request(
            [
                base_record("r1", known_at="2026-07-02"),  # 晚于 as_of
                base_record("r2", known_at="2026-07-01"),  # 恰好等于，纳入
            ]
        )
        result = rebuild_indicators(request)
        codes = {d["record_id"]: d["disposition"] for d in result.dispositions}
        self.assertEqual(codes["r1"], DISPOSITION_LATE)
        self.assertEqual(codes["r2"], DISPOSITION_INCLUDED)

    def test_ineligible_records_do_not_enter_denominator(self):
        request = base_request(
            [
                base_record("r1", eligible=False, screened=True),
                base_record("r2", eligible=True, screened=True),
            ]
        )
        result = rebuild_indicators(request)
        self.assertEqual(len(result.denominator_persons), 1)
        codes = {d["record_id"]: d["disposition"] for d in result.dispositions}
        self.assertEqual(codes["r1"], DISPOSITION_INELIGIBLE)

    def test_missing_dimension_goes_to_unknown_bucket(self):
        request = base_request(
            [base_record("r1", age_band=None), base_record("r2", age_band="  ")]
        )
        result = rebuild_indicators(request)
        self.assertTrue(all(o.age_band == UNKNOWN_DIMENSION for o in result.observations))

    def test_numerator_and_denominator_built_from_same_person_set(self):
        request = base_request(
            [
                base_record("r1", screened=True),
                base_record("r2", screened=False),
                base_record("r3", eligible=False, screened=True),
            ]
        )
        result = rebuild_indicators(request)
        self.assertEqual(len(result.denominator_persons), 2)
        self.assertEqual(sum(1 for o in result.observations if o.screened), 1)

    def test_invalid_request_raises_domain_error(self):
        with self.assertRaises(DomainError):
            rebuild_indicators({})
        bad = base_request([base_record("r1")])
        bad["indicator"]["dedup_keys"] = []
        with self.assertRaises(DomainError):
            rebuild_indicators(bad)
        bad2 = base_request([base_record("r1")])
        bad2["minimum_cell_count"] = 0
        with self.assertRaises(DomainError):
            rebuild_indicators(bad2)

    def test_disposition_counts_are_complete_and_traceable(self):
        request = base_request(
            [
                base_record("r1", known_at="2026-08-01"),
                base_record("r2", eligible=False),
                base_record("r3", screened=True),
                base_record("r4", person_id="p3", revision=1),
                base_record("r5", person_id="p3", revision=2),
            ]
        )
        result = rebuild_indicators(request)
        record_ids = {d["record_id"] for d in result.dispositions}
        self.assertEqual(record_ids, {"r1", "r2", "r3", "r4", "r5"})
        self.assertGreaterEqual(sum(result.counts.values()), 5)


if __name__ == "__main__":
    unittest.main()
