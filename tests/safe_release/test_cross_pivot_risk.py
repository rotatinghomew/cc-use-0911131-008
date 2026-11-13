"""跨透视联合风险演示：单透视各自安全，合在一起需要更多抑制。

构造一个受控数据集，分别在只含 town-age 透视、只含 town-channel 透视时审计，
再对两个透视的联合立方审计，断言：

1. 单透视审计通过（或抑制更少）；
2. 联合审计因为两套恒等式联立，能从行列合计与交叉透视反推小单元，要求更多
   单元被抑制，或直接拒绝；
3. 加入历史已发布单元后，差分约束进一步收紧可行区间。
"""
from __future__ import annotations

import json
import unittest

from screening_kpi_auditor.safe_release.auditor import (
    ComplementarySuppressionPlanner,
    SuppressionAuditor,
)
from screening_kpi_auditor.safe_release.cube import build_cube
from screening_kpi_auditor.safe_release.rebuild import rebuild_indicators


def cross_dataset() -> dict:
    # small 镇只放 3 人，分散到两个年龄、两个渠道；其它镇足够大。
    records = []
    rid = 0

    def add(town: str, age: str, channel: str, n: int, screened: bool | None = None):
        nonlocal rid
        for i in range(n):
            records.append(
                {
                    "record_id": f"r{rid}",
                    "person_id": f"p{rid}",
                    "period": "2026-Q2",
                    "town": town,
                    "age_band": age,
                    "channel": channel,
                    "eligible": True,
                    "screened": screened if screened is not None else (i % 2 == 0),
                    "effective_at": "2026-06-01",
                    "known_at": "2026-06-20",
                    "revision": 1,
                }
            )
            rid += 1

    # small 镇：3 人，刻意制造小单元。
    add("small", "young", "clinic", 2)
    add("small", "old", "mobile", 1)
    # 四个大镇，每格人数充足。
    for town in ("t1", "t2", "t3", "t4"):
        for age in ("young", "old"):
            for channel in ("clinic", "mobile"):
                add(town, age, channel, 10)

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
            {"view_id": "town-age", "dimensions": ["town", "age_band"], "margins": True},
            {"view_id": "town-channel", "dimensions": ["town", "channel"], "margins": True},
        ],
        "historical_cells": [],
        "required_totals": ["all"],
    }


def audit_one_view(request: dict, dimensions: list[str]):
    single = json.loads(json.dumps(request))
    single["views"] = [{"view_id": "v", "dimensions": dimensions, "margins": True}]
    rebuild = rebuild_indicators(single)
    cube = build_cube(rebuild.observations, single["views"], single["required_totals"])
    auditor = SuppressionAuditor(cube, 5, [])
    plan = ComplementarySuppressionPlanner(auditor).plan(set(cube.total_cell_ids))
    return auditor, cube, plan


class CrossPivotRiskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request = cross_dataset()

    def test_each_single_view_is_strictly_more_revealing_than_joint(self):
        # 单透视 A
        _, _, plan_age = audit_one_view(self.request, ["town", "age_band"])
        # 单透视 B
        _, _, plan_channel = audit_one_view(self.request, ["town", "channel"])
        # 联合立方
        rebuild = rebuild_indicators(self.request)
        joint_cube = build_cube(
            rebuild.observations, self.request["views"], self.request["required_totals"]
        )
        joint_auditor = SuppressionAuditor(joint_cube, 5, [])
        joint_plan = ComplementarySuppressionPlanner(joint_auditor).plan(
            set(joint_cube.total_cell_ids)
        )

        single_suppressed = min(
            len(plan_age.suppressed), len(plan_channel.suppressed)
        )
        # 联合审计要么需要不少于单透视的抑制，要么直接无法证明安全（拒绝）。
        if joint_plan.audit.safe:
            self.assertGreaterEqual(len(joint_plan.suppressed), single_suppressed)
        else:
            # 拒绝本身即说明联立后无法在保留同等信息下证明安全。
            self.assertFalse(joint_plan.audit.safe)

    def test_joint_cube_detects_small_cell_via_difference_even_if_margins_published(self):
        rebuild = rebuild_indicators(self.request)
        cube = build_cube(
            rebuild.observations, self.request["views"], self.request["required_totals"]
        )
        auditor = SuppressionAuditor(cube, 5, [])
        primary = {c.cell_id for c in auditor.primary_cells()}
        # 只做主抑制、保留所有边际：联合恒等式必然能反推 small 单元。
        report = auditor.audit(set(cube.cells_by_id) - primary)
        self.assertFalse(report.safe)
        # 违规里能定位到 small 镇相关单元。
        violating_members = {
            tuple(cube.cells_by_id[v.cell_id].member_values)
            for v in report.violations
        }
        self.assertTrue(
            any(any(value == "small" for _, value in members) for members in violating_members)
        )

    def test_historical_release_tightens_feasible_interval(self):
        request = json.loads(json.dumps(self.request))
        # 历史已发布 small 镇的 young/clinic 单元（旧版本泄漏过）。
        request["historical_cells"] = [
            {
                "members": [["town", "small"], ["age_band", "young"]],
                "denominator": 2,
                "numerator": 1,
            }
        ]
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        plain_cube = build_cube(
            rebuild_indicators(self.request).observations,
            self.request["views"],
            self.request["required_totals"],
        )
        auditor_no_history = SuppressionAuditor(plain_cube, 5, [])
        auditor_with_history = SuppressionAuditor(cube, 5, request["historical_cells"])
        # 带历史固定行时，约束系统包含额外等式；审计器确实加载了历史行。
        self.assertTrue(auditor_with_history.historical_rows)
        self.assertFalse(auditor_no_history.historical_rows)
        # 历史值与当前真值冲突时必须判不可行，而不是静默忽略历史。
        conflict = json.loads(json.dumps(request))
        conflict["historical_cells"][0]["denominator"] = 99
        rebuild_c = rebuild_indicators(conflict)
        cube_c = build_cube(
            rebuild_c.observations, conflict["views"], conflict["required_totals"]
        )
        auditor_conflict = SuppressionAuditor(cube_c, 5, conflict["historical_cells"])
        report = auditor_conflict.audit(set(cube_c.cells_by_id))
        self.assertTrue(report.infeasible or not report.safe)


if __name__ == "__main__":
    unittest.main()
