"""可发布性推理：主抑制、互补抑制与精确 LP 审计。

防护模型（写入发布证书的 scope 内可证明安全）
---------------------------------------------
攻击者掌握的信息被建模为：

1. 本次所有**已发布单元**给出的线性等式（每个单元 = 若干原子层人数之和，
   即请求里各视图的明细、行列边际与要求保留的全部线性加减关系）；
2. 原子层取值边界 ``0 <= n_s <= d_s <= D_total``（总人数是发布的已知上
   界，不引入任何外部数据）；
3. **历史已发布单元**：已发布内容不可撤回，作为额外固定等式参与差分。

对每个主敏感单元（真值分母 < ``minimum_cell_count``，含零分母单元）的
分母表达式 D_t 与分子表达式 N_t，在上述约束下用精确有理数 LP 求最小/
最大可行值。约束矩阵是多向列联表的边际关联矩阵叠加盒子与
``n_s - d_s <= 0`` 约束，全幺模且右端为整数，故多面体顶点全为整数，LP
区间就是整数可行取值区间。当且仅当 ``max - min >= k`` 同时对 D_t、N_t
成立时，攻击者无法把真值缩到少于 k 种整数可能，单元通过防护。

证书只对该线性模型负责；任意外部知识（其它系统的登记表、访谈信息等）
不在建模范围内，证书会显式声明这一边界。无法证明安全时整单拒绝，不会
输出部分结果冒充安全。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from screening_kpi_auditor.runtime import DomainError, stable_json
from screening_kpi_auditor.safe_release.cube import Cube, Cell
from screening_kpi_auditor.safe_release.rational_lp import (
    InfeasibleError,
    LpSystem,
)

# 抑制原因（对外只暴露类别，不含任何真值数字）。
REASON_PRIMARY = "primary:below_minimum_cell_count"
REASON_ZERO_DENOMINATOR = "primary:zero_denominator"
REASON_COMPLEMENTARY = "complementary:linear_or_difference_attack"
REASON_HISTORICAL = "complementary:historical_difference"

REASON_EXPLANATIONS = {
    REASON_PRIMARY: "单元分母人数低于最低单元人数阈值，直接识别可识别小群体，做主抑制。",
    REASON_ZERO_DENOMINATOR: "单元分母为零，比率无定义且零/非零本身即披露，做主抑制。",
    REASON_COMPLEMENTARY: "发布该单元会使某个已抑制单元可经行列合计、跨透视或历史差分被唯一解出，做互补抑制。",
    REASON_HISTORICAL: "与历史已发布单元联立后可反推已抑制单元，按历史差分防护做互补抑制。",
}


@dataclass(slots=True)
class AuditViolation:
    cell_id: str
    metric: str  # denominator / numerator
    true_value: int
    feasible_min: int
    feasible_max: int
    width: int
    required_width: int


@dataclass(slots=True)
class AuditReport:
    safe: bool
    violations: list[AuditViolation] = field(default_factory=list)
    # 每个主敏感单元的精确披露区间（内部工作底稿使用，不进入外部文件）。
    intervals: dict[str, dict[str, tuple[int, int]]] = field(default_factory=dict)
    # 显式枚举并核验过的线性加减关系组（视图内边际恒等式）。
    relation_checks: list[dict[str, Any]] = field(default_factory=list)
    infeasible: bool = False


class SuppressionAuditor:
    """基于统一立方的 LP 审计器。"""

    def __init__(
        self,
        cube: Cube,
        minimum_cell_count: int,
        historical_cells: Sequence[Mapping[str, Any]] | None = None,
    ) -> None:
        self.cube = cube
        self.k = minimum_cell_count
        self.historical_cells = list(historical_cells or [])
        self.strata_count = len(cube.strata)
        # 变量排布：[d_0..d_{S-1}, n_0..n_{S-1}]。
        self.total_upper = cube.total_denominator
        self.bounds = self._build_bounds()
        self._validate_historical()
        # 历史固定行（cell_id 或维度谓词 → 等式），在每次审计时并入。
        self.historical_rows = self._build_historical_rows()
        # published 集合（冻结）→ 审计报告，避免试抑制时重复求解同一系统。
        self._audit_cache: dict[frozenset[str], AuditReport] = {}

    # ------------------------------------------------------------------
    # 约束系统
    # ------------------------------------------------------------------
    def _build_bounds(self) -> list[tuple[int, int | None]]:
        upper = self.total_upper
        bounds: list[tuple[int, int | None]] = []
        for _ in range(self.strata_count):
            bounds.append((0, upper))  # d_s
        for _ in range(self.strata_count):
            bounds.append((0, upper))  # n_s
        return bounds

    def _validate_historical(self) -> None:
        for item in self.historical_cells:
            if not isinstance(item, Mapping):
                raise DomainError("historical_cells 条目必须是对象")
            members = item.get("members")
            if not isinstance(members, list):
                raise DomainError("historical_cells.members 必须是 [维度, 取值] 数组")
            denominator = item.get("denominator")
            numerator = item.get("numerator")
            if not isinstance(denominator, int) or isinstance(denominator, bool) or denominator < 0:
                raise DomainError("historical_cells.denominator 必须是非负整数")
            if not isinstance(numerator, int) or isinstance(numerator, bool) or not 0 <= numerator <= denominator:
                raise DomainError("historical_cells.numerator 必须满足 0 <= 分子 <= 分母")

    def _members_to_cell(self, members: Sequence[Sequence[str]]) -> Cell | None:
        key = stable_json(sorted(tuple(pair) for pair in members))
        cell_id = self.cube.predicate_to_cell.get(key)
        return None if cell_id is None else self.cube.cells_by_id[cell_id]

    def _build_historical_rows(self) -> list[tuple[list[int], int, str]]:
        rows: list[tuple[list[int], int, str]] = []
        for item in self.historical_cells:
            cell = self._members_to_cell(item["members"])
            if cell is None:
                # 历史单元在当前立方无对应原子层：其分母为 0 才自洽。
                if item["denominator"] != 0 or item["numerator"] != 0:
                    raise DomainError("历史单元与当前立方不可比，无法纳入差分审计")
                continue
            incidence = self.cube.incidence(cell)
            rows.append(
                (list(incidence) + [0] * self.strata_count, int(item["denominator"]), cell.cell_id)
            )
            rows.append(
                ([0] * self.strata_count + list(incidence), int(item["numerator"]), cell.cell_id)
            )
        return rows

    def _published_rows(self, published_ids: set[str]) -> list[tuple[list[int], int]]:
        rows: list[tuple[list[int], int]] = []
        # 盒子约束 n_s <= d_s 写成等式 n_s - d_s + slack_s = 0；LP 内部通过
        # 变量上界松弛表达盒子，这里额外补 n_s - d_s <= 0：转为等式并新增
        # 松弛变量。为保持变量数稳定，改用直接扩展 tableau 行的方式：
        # feasible_range 仅支持等式，故把不等式拆成 n_s - d_s + q_s = 0，
        # q_s >= 0 且无上界。
        for cell_id in sorted(published_ids):
            cell = self.cube.cells_by_id[cell_id]
            incidence = self.cube.incidence(cell)
            rows.append((list(incidence) + [0] * self.strata_count, cell.denominator))
            rows.append(([0] * self.strata_count + list(incidence), cell.numerator))
        rows.extend((row, rhs) for row, rhs, _ in self.historical_rows)
        return rows

    def _system(
        self, published_ids: set[str]
    ) -> tuple[list[tuple[list[int], int]], list[tuple[int, int | None]], int]:
        """构造带 n_s <= d_s 松弛变量的完整约束系统。"""
        base_rows = self._published_rows(published_ids)
        slack_count = self.strata_count  # q_s for n_s - d_s + q_s = 0
        extended_rows: list[tuple[list[int], int]] = []
        width = 2 * self.strata_count
        for row, rhs in base_rows:
            extended_rows.append((row + [0] * slack_count, rhs))
        for s in range(self.strata_count):
            row = [0] * (width + slack_count)
            row[self.strata_count + s] = 1   # n_s
            row[s] = -1                      # -d_s
            row[width + s] = 1               # q_s
            extended_rows.append((row, 0))
        extended_bounds: list[tuple[int, int | None]] = list(self.bounds) + [
            (0, None) for _ in range(slack_count)
        ]
        return extended_rows, extended_bounds, width

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------
    def primary_cells(self) -> list[Cell]:
        return [
            cell
            for cell in self.cube.cells_by_id.values()
            if cell.denominator < self.k
        ]

    def audit(self, published_ids: set[str]) -> AuditReport:
        cache_key = frozenset(published_ids)
        cached = self._audit_cache.get(cache_key)
        if cached is not None:
            return cached
        extended_rows, extended_bounds, width = self._system(published_ids)
        report = AuditReport(safe=True)

        # 规则 0：已发布单元自身不得是主敏感单元（直接披露）。
        for cell_id in sorted(published_ids):
            cell = self.cube.cells_by_id[cell_id]
            if cell.denominator < self.k:
                report.safe = False
                report.violations.append(
                    AuditViolation(
                        cell_id=cell_id,
                        metric="denominator",
                        true_value=cell.denominator,
                        feasible_min=cell.denominator,
                        feasible_max=cell.denominator,
                        width=0,
                        required_width=self.k,
                    )
                )

        # 同一约束系统只建一次可行基，所有敏感单元的分子/分母区间热启动求解。
        try:
            system = LpSystem(extended_rows, extended_bounds)
            system.assert_feasible()
        except InfeasibleError:
            report.safe = False
            report.infeasible = True
            self._audit_cache[cache_key] = report
            return report

        # 规则 1：每个**正分母**主敏感单元的 D_t、N_t 披露区间宽度都 >= k。
        # 零分母单元是结构性空单元（不含任何真实个人，无小群体可识别），只
        # 要求保持抑制、绝不发布；其取值被盒子约束恒为 0，不适用宽度规则。
        for target in self.primary_cells():
            d_vector = self._metric_vector(target, "denominator", width)
            n_vector = self._metric_vector(target, "numerator", width)
            intervals: dict[str, tuple[int, int]] = {}
            if target.denominator == 0:
                intervals["denominator"] = (0, 0)
                intervals["numerator"] = (0, 0)
                report.intervals[target.cell_id] = intervals
                continue
            for metric, vector in (("denominator", d_vector), ("numerator", n_vector)):
                try:
                    lower, upper = system.range(vector)
                except InfeasibleError:
                    report.safe = False
                    report.infeasible = True
                    self._audit_cache[cache_key] = report
                    return report
                intervals[metric] = (int(lower), int(upper))
                true_value = target.denominator if metric == "denominator" else target.numerator
                if upper - lower < self.k:
                    report.safe = False
                    report.violations.append(
                        AuditViolation(
                            cell_id=target.cell_id,
                            metric=metric,
                            true_value=true_value,
                            feasible_min=int(lower),
                            feasible_max=int(upper),
                            width=int(upper - lower),
                            required_width=self.k,
                        )
                    )
            report.intervals[target.cell_id] = intervals

        report.relation_checks = self._enumerate_relation_checks(published_ids)
        self._audit_cache[cache_key] = report
        return report

    def _metric_vector(self, cell: Cell, metric: str, width: int) -> list[int]:
        incidence = self.cube.incidence(cell)
        vector = [0] * (width + self.strata_count)
        if metric == "denominator":
            for index in cell.stratum_indices:
                vector[index] = 1
        else:
            for index in cell.stratum_indices:
                vector[self.strata_count + index] = 1
        return vector

    def _enumerate_relation_checks(self, published_ids: set[str]) -> list[dict[str, Any]]:
        """显式核验请求内的线性加减关系：每个视图的边际分组恒等式。

        对每个视图、每个边际维度取值，明细单元之和必须等于边际单元；
        全部边际之和等于总计。记录每组中被抑制的单元数，证明差分检测确实
        逐组执行而不是只看单格阈值。
        """
        checks: list[dict[str, Any]] = []
        for view_id, cell_ids in self.cube.view_cell_ids.items():
            view_cells = [self.cube.cells_by_id[cid] for cid in cell_ids]
            detail_cells = [cell for cell in view_cells if cell.level == "detail"]
            margin_cells = [cell for cell in view_cells if cell.level == "margin"]
            for margin in margin_cells:
                fixed_dim = margin.member_values[0][0]
                fixed_value = margin.member_values[0][1]
                children = [
                    cell
                    for cell in detail_cells
                    if dict(cell.member_values).get(fixed_dim) == fixed_value
                ]
                if not children:
                    continue
                suppressed_children = [cell.cell_id for cell in children if cell.cell_id not in published_ids]
                checks.append(
                    {
                        "view_id": view_id,
                        "relation": "detail_sum_equals_margin",
                        "margin_cell_id": margin.cell_id,
                        "child_cell_ids": [cell.cell_id for cell in children],
                        "suppressed_in_group": len(suppressed_children),
                        "margin_published": margin.cell_id in published_ids,
                    }
                )
        return checks


@dataclass(slots=True)
class SuppressionPlan:
    published_ids: set[str]
    suppressed: dict[str, str]  # cell_id -> reason code
    audit: AuditReport
    iterations: int


class ComplementarySuppressionPlanner:
    """LP 引导的互补抑制贪心 + 独立完整 LP 审计兜底。

    从主抑制集合出发，每轮对当前仍被解出（披露区间宽度不足）的敏感单元，
    在由分区恒等式兄弟/父单元与共享原子层单元构成的候选池上逐个试抑制，
    用真实精确 LP 审计挑选「违规下降最多 → 层级更高 → 分母更小 → id」的
    单元，确定性地最小化信息损失。审计结果带缓存，同一发布集合不重复求解。

    不保证全局最优，但返回的方案最后再经一次完整 LP 审计：覆盖请求内全
    部线性加减关系、跨透视联立与历史差分；无法通过则整单拒绝，绝不用
    「看似合理」的启发式结论冒充可证明安全。
    """

    def __init__(self, auditor: SuppressionAuditor) -> None:
        self.auditor = auditor
        self.cube = auditor.cube
        self.k = auditor.k
        self.partitions = self._enumerate_partitions()

    def _enumerate_partitions(self) -> list[tuple[str, list[str]]]:
        """返回 (父单元 id, 互不相交且覆盖父单元的子单元 id 列表)。

        按视图枚举线性恒等式：每个视图的明细单元互不相交并覆盖该视图的
        全部边际与总计；同一父单元在不同视图里的切分都登记，跨透视的联立
        攻击由最终 LP 审计兜底。基于 ``view_cell_ids`` 而非盲目集合包含，
        避免两个交错透视（age × channel）互相破坏不交性。
        """
        unique: dict[tuple[str, tuple[str, ...]], None] = {}
        for view_id, cell_ids in self.cube.view_cell_ids.items():
            view_cells = [self.cube.cells_by_id[cid] for cid in cell_ids]
            detail = [cell for cell in view_cells if cell.level == "detail"]
            margins = [cell for cell in view_cells if cell.level == "margin"]
            detail_sets = {cell.cell_id: set(cell.stratum_indices) for cell in detail}
            if detail:
                union = set().union(*detail_sets.values())
                for total_id in self.cube.total_cell_ids:
                    if set(self.cube.cells_by_id[total_id].stratum_indices) == union:
                        unique[(total_id, tuple(sorted(detail_sets)))] = None
            for margin in margins:
                margin_set = set(margin.stratum_indices)
                children = sorted(
                    cell_id
                    for cell_id, member_set in detail_sets.items()
                    if member_set.issubset(margin_set)
                )
                if children and set().union(*(detail_sets[cid] for cid in children)) == margin_set:
                    unique[(margin.cell_id, tuple(children))] = None
        return [(parent_id, list(child_ids)) for (parent_id, child_ids) in unique]

    # 单轮规划的审计节点预算，防止试抑制组合爆炸。
    NODE_BUDGET = 250

    def plan(self, required_total_ids: set[str]) -> SuppressionPlan:
        all_ids = set(self.cube.cells_by_id)
        primary = {cell.cell_id for cell in self.auditor.primary_cells()}
        suppressed: dict[str, str] = {}
        for cell_id in sorted(primary):
            cell = self.cube.cells_by_id[cell_id]
            suppressed[cell_id] = (
                REASON_ZERO_DENOMINATOR if cell.denominator == 0 else REASON_PRIMARY
            )
        historical_ids = {cell_id for _, _, cell_id in self.auditor.historical_rows}

        # 不可行性早判：连「只发必须保留总计」都无法保护主敏感单元，则任何
        # 抑制方案都不可证明安全，直接拒绝，仅保留主抑制清单。
        limit_report = self.auditor.audit(required_total_ids)
        if not limit_report.safe and any(
            violation.cell_id in primary for violation in limit_report.violations
        ):
            base_published = all_ids - set(suppressed)
            return SuppressionPlan(
                published_ids=base_published,
                suppressed=suppressed,
                audit=self.auditor.audit(base_published),
                iterations=0,
            )

        published = all_ids - set(suppressed)
        report = self.auditor.audit(published)
        level_rank = {"grand_total": 0, "margin": 1, "detail": 2}
        iterations = 0
        while not report.safe:
            iterations += 1
            if iterations > self.NODE_BUDGET:
                break
            offending = {violation.cell_id for violation in report.violations}
            candidate = self._best_next_suppression(
                offending, published, required_total_ids, level_rank
            )
            if candidate is None:
                break
            suppressed[candidate] = (
                REASON_HISTORICAL if candidate in historical_ids else REASON_COMPLEMENTARY
            )
            published.discard(candidate)
            report = self.auditor.audit(published)

        return SuppressionPlan(published, suppressed, report, iterations)

    def _best_next_suppression(
        self,
        offending: set[str],
        published: set[str],
        required_total_ids: set[str],
        level_rank: Mapping[str, int],
    ) -> str | None:
        """选下一个互补抑制单元。

        评分依据是试抑制后所有违规单元的**最坏情况披露区间宽度之和**：该值
        越大说明攻击者的不确定性越高、越接近满足最低宽度。相比「违规计数」
        在达标前恒正、无法区分进展，区间宽度能在仍违规时给出连续的改善信号，
        从而避免停滞和盲目连锁。同分时按层级（边际优先）、分母、id 决策。
        """
        pool = self._relevant_candidates(offending, published, required_total_ids)
        if not pool:
            return None
        best_id: str | None = None
        best_key: tuple[int, int, int, str] | None = None
        for candidate in pool:
            trial = self.auditor.audit(published - {candidate})
            if trial.infeasible:
                continue
            # 违规单元在试抑制后的区间宽度总和（越大越好，取负用于最小化）。
            width_sum = 0
            for cell_id in offending:
                intervals = trial.intervals.get(cell_id)
                if not intervals:
                    continue
                for lower, upper in intervals.values():
                    width_sum += upper - lower
            cell = self.cube.cells_by_id[candidate]
            key = (
                -width_sum,
                level_rank.get(cell.level, 3),
                cell.denominator,
                candidate,
            )
            if best_key is None or key < best_key:
                best_key = key
                best_id = candidate
        return best_id

    def _relevant_candidates(
        self,
        offending: set[str],
        published: set[str],
        required_total_ids: set[str],
    ) -> list[str]:
        """与违规单元共享原子层、或处于同一分区恒等式的已发布候选。"""
        pool: set[str] = set()
        strata: set[int] = set()
        for cell_id in offending:
            strata.update(self.cube.cells_by_id[cell_id].stratum_indices)
        for offending_id in offending:
            for parent_id, child_ids in self.partitions:
                if offending_id not in child_ids or parent_id not in published:
                    continue
                if parent_id not in required_total_ids:
                    pool.add(parent_id)
                pool.update(
                    cid
                    for cid in child_ids
                    if cid in published and cid not in required_total_ids
                )
        for cell_id in published:
            if cell_id in required_total_ids:
                continue
            if strata.intersection(self.cube.cells_by_id[cell_id].stratum_indices):
                pool.add(cell_id)
        return sorted(pool)
