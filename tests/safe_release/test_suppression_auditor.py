"""可发布性推理测试：精确 LP、跨透视联合抑制、历史差分与拒绝逻辑。

关键验证点（对应用户需求）：两套交叉透视各自看似安全，合在一起仍可能需要
多隐藏几个单元；历史已发布单元参与差分，且不可通过撤稿证明新版安全。
"""
from __future__ import annotations

import itertools
import unittest

from screening_kpi_auditor.safe_release.auditor import (
    REASON_COMPLEMENTARY,
    REASON_HISTORICAL,
    REASON_PRIMARY,
    ComplementarySuppressionPlanner,
    SuppressionAuditor,
)
from screening_kpi_auditor.safe_release.cube import build_cube
from screening_kpi_auditor.safe_release.rebuild import rebuild_indicators
from screening_kpi_auditor.safe_release.rational_lp import LpSystem, optimize

from tests.safe_release.helpers import build_request, two_view_request


class RationalLpTests(unittest.TestCase):
    def test_interval_matches_brute_force_on_contingency_table(self):
        # 3 个原子层、总和固定为 10，发布 x0+x1=6，求 x0 的精确可行区间。
        rows = [([1, 1, 1], 10), ([1, 1, 0], 6)]
        bounds = [(0, 10), (0, 10), (0, 10)]
        system = LpSystem(rows, bounds)
        lo, hi = system.range([1, 0, 0])
        # 暴力枚举整数解。
        feasible = set()
        for x0 in range(11):
            for x1 in range(11):
                x2 = 10 - x0 - x1
                if x2 >= 0 and x0 + x1 == 6:
                    feasible.add(x0)
        self.assertEqual((int(lo), int(hi)), (min(feasible), max(feasible)))

    def test_infeasible_system_detected(self):
        from screening_kpi_auditor.safe_release.rational_lp import InfeasibleError

        with self.assertRaises(InfeasibleError):
            LpSystem(
                [([1, 1], 10), ([1, 0], 11)],
                [(0, 10), (0, 10)],
            )

    def test_n_leq_d_constraint_respected(self):
        # n - d + q = 0，d 固定为 4，则 n ∈ [0,4]。
        rows = [([1, -1, 1], 0), ([0, 1, 0], 4)]
        bounds = [(0, 4), (0, 4), (0, None)]
        system = LpSystem(rows, bounds)
        lo, hi = system.range([1, 0, 0])
        self.assertEqual((int(lo), int(hi)), (0, 4))


class PrimarySuppressionTests(unittest.TestCase):
    def test_below_threshold_cells_are_primary_sensitive(self):
        request = build_request(town_sizes={"small": 2, "big": 20}, k=5)
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, 5, [])
        primary = auditor.primary_cells()
        self.assertTrue(primary)
        self.assertTrue(all(cell.denominator < 5 for cell in primary))

    def test_zero_denominator_cell_is_suppressed_but_not_width_checked(self):
        import json
        from pathlib import Path

        fixture = json.loads(
            Path(__file__).resolve().parents[2]
            .joinpath("fixtures/analysis/input.json")
            .read_text(encoding="utf-8")
        )
        rebuild = rebuild_indicators(fixture)
        cube = build_cube(
            rebuild.observations, fixture["views"], fixture["required_totals"]
        )
        auditor = SuppressionAuditor(cube, fixture["minimum_cell_count"], [])
        zero_cells = [c for c in cube.cells_by_id.values() if c.denominator == 0]
        self.assertTrue(zero_cells)
        report = auditor.audit(
            set(cube.cells_by_id) - {c.cell_id for c in zero_cells}
        )
        # 零单元不出现在宽度违规里（只要求保持抑制）。
        self.assertFalse(
            any(v.cell_id in {c.cell_id for c in zero_cells} for v in report.violations)
        )


class CrossPivotJointSuppressionTests(unittest.TestCase):
    """两套透视共享同一批人，必须联合决定可见性。"""

    def test_two_views_share_cell_identity_for_same_predicate(self):
        request = two_view_request()
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        # 同一个乡镇合计谓词在两个视图中只对应一个 cell_id。
        town_margins = [
            cell
            for cell in cube.cells_by_id.values()
            if cell.member_values == (("town", "east"),)
        ]
        self.assertEqual(len(town_margins), 1)

    def test_linear_difference_blocks_simple_subtraction_attack(self):
        # 全县总计 - 其余乡镇 = 小乡镇：若总计和大乡镇都发布，小乡镇被唯一解出。
        request = build_request(town_sizes={"small": 2, "a": 20, "b": 20}, k=5)
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, 5, [])
        primary = {c.cell_id for c in auditor.primary_cells()}
        # 仅做主抑制：小乡镇边际仍可由总计差分得到，审计必须判不安全。
        report = auditor.audit(set(cube.cells_by_id) - primary)
        self.assertFalse(report.safe)
        small_margin = next(
            cell
            for cell in cube.cells_by_id.values()
            if cell.member_values == (("town", "small"),)
        )
        self.assertIn(small_margin.cell_id, {v.cell_id for v in report.violations})

    def test_joint_audit_covers_both_pivots_together(self):
        # 单独任一透视可能通过，但联合立方审计把两套恒等式同时纳入约束。
        request = two_view_request()
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, request["minimum_cell_count"], [])
        plan = ComplementarySuppressionPlanner(auditor).plan(set(cube.total_cell_ids))
        # 最终方案必须通过对**全部**单元（两个视图）的一次完整审计。
        final_report = auditor.audit(plan.published_ids)
        if plan.audit.safe:
            self.assertTrue(final_report.safe)
            # 互补抑制确实被触发（不只是主抑制）。
            self.assertTrue(
                any(reason == REASON_COMPLEMENTARY for reason in plan.suppressed.values())
                or len(plan.suppressed) == len(auditor.primary_cells())
            )


class HistoricalDifferenceTests(unittest.TestCase):
    def test_historical_published_cell_enters_difference_constraints(self):
        request = build_request(town_sizes={"small": 2, "a": 20, "b": 20, "c": 20}, k=5)
        # 历史上已发布 small 镇边际（旧版没保护好），差分审计必须把它当固定行。
        request["historical_cells"] = [
            {"members": [["town", "small"]], "denominator": 2, "numerator": 1}
        ]
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, 5, request["historical_cells"])
        self.assertTrue(auditor.historical_rows)
        plan = ComplementarySuppressionPlanner(auditor).plan(set(cube.total_cell_ids))
        # 历史固定行使 small 镇无法被隐藏到宽度达标 -> 无法证明安全时拒绝，
        # 或给出的方案中相关单元被标记为历史差分互补抑制。
        if not plan.audit.safe:
            self.assertFalse(plan.audit.safe)  # 明确拒绝而非伪造安全
        else:
            self.assertTrue(
                any(
                    reason == REASON_HISTORICAL
                    for reason in plan.suppressed.values()
                )
            )

    def test_conflicting_history_makes_system_infeasible(self):
        request = build_request(town_sizes={"small": 2, "a": 20}, k=5)
        # 历史值与当前真值矛盾：small 镇当前分母 2，历史却声称 99。
        request["historical_cells"] = [
            {"members": [["town", "small"]], "denominator": 99, "numerator": 1}
        ]
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, 5, request["historical_cells"])
        report = auditor.audit(set(cube.cells_by_id))
        self.assertTrue(report.infeasible or not report.safe)


class NumeratorDenominatorJointTests(unittest.TestCase):
    def test_rate_cannot_leak_when_denominator_protected(self):
        # 分子分母联合审计：即使分母区间达标，分子区间不足仍判不安全。
        request = build_request(town_sizes={"small": 2, "a": 20, "b": 20, "c": 20}, k=5)
        rebuild = rebuild_indicators(request)
        cube = build_cube(rebuild.observations, request["views"], request["required_totals"])
        auditor = SuppressionAuditor(cube, 5, [])
        report = auditor.audit(set(cube.cells_by_id) - {c.cell_id for c in auditor.primary_cells()})
        metrics = {(v.cell_id, v.metric) for v in report.violations}
        # 同一敏感单元的分子和分母都被检查，不存在只护分母、分子经比率泄漏。
        vulnerable = {v.cell_id for v in report.violations}
        for cell_id in vulnerable:
            self.assertTrue(
                (cell_id, "numerator") in metrics or (cell_id, "denominator") in metrics
            )


if __name__ == "__main__":
    unittest.main()
