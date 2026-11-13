"""精确有理数线性规划（两阶段单纯形，Bland 规则，标准 tableau）。

用途：发布安全审计需要对每个敏感单元的分母/分子，在「攻击者已知的全部
线性等式与取值边界」下求可行区间。浮点求解可能因舍入把边界外的取值误
判为可行，因此这里全部使用 :class:`fractions.Fraction`，得到的最优值是
精确值。

整数可靠性（与业务背景绑定的可证明性质）：
    变量是多向列联表原子层的人数，约束矩阵是边际/单元等式的 0/±1 关联
    矩阵，全幺模（TU）；再叠加盒子约束 0 <= x <= U 与 0 <= n_s <= d_s
    （后者写成 n_s - d_s + q_s = 0，仍是 TU 增广），右端项均为整数，因此
    多面体的每个顶点都是整数点。于是精确 LP 的最小/最大值恰好等于整数
    可行域的最小/最大值，无需整数规划即可给出无误差的披露区间。

实现为带目标行的稠密 tableau，规模面向本项目的单元数量级（数十变量、数
十约束）；不可行抛出 :class:`InfeasibleError`。
"""
from __future__ import annotations

from fractions import Fraction
from typing import Sequence


class InfeasibleError(ValueError):
    """约束系统无可行解。"""


def _as_fraction(value: int | Fraction) -> Fraction:
    return value if isinstance(value, Fraction) else Fraction(value)


def optimize(
    objective: Sequence[int | Fraction],
    rows: Sequence[Sequence[int | Fraction]],
    bounds: Sequence[tuple[int | Fraction, int | Fraction | None]],
    *,
    minimize: bool,
) -> Fraction:
    """在 ``A x = b`` 与 ``lo_j <= x_j <= hi_j`` 下最小化/最大化目标函数。

    返回精确最优值；无可行解时抛出 :class:`InfeasibleError`，无界时抛出
    :class:`ArithmeticError`（本项目的模型恒有界，无界属于建模错误）。
    """
    n = len(objective)
    if len(bounds) != n:
        raise ValueError("bounds 长度必须与变量数一致")

    # 1) 平移到非负变量 y_j = x_j - lo_j；有限上界转盒子等式 y_j + s_j = w。
    lower = [_as_fraction(lo) for lo, _ in bounds]
    widths: list[Fraction | None] = []
    for lo, hi in bounds:
        widths.append(None if hi is None else _as_fraction(hi) - _as_fraction(lo))

    slack_index: dict[int, int] = {}
    structural_count = n
    for j, width in enumerate(widths):
        if width is not None:
            slack_index[j] = structural_count
            structural_count += 1

    eq_rows: list[tuple[list[Fraction], Fraction]] = []
    for coefficients, rhs in rows:
        if len(coefficients) != n:
            raise ValueError("约束系数宽度与变量数不一致")
        shifted_rhs = _as_fraction(rhs) - sum(
            _as_fraction(a) * lower[j] for j, a in enumerate(coefficients)
        )
        eq_rows.append(([_as_fraction(a) for a in coefficients], shifted_rhs))
    for j, width in enumerate(widths):
        if width is not None:
            coeffs = [Fraction(0)] * n
            coeffs[j] = Fraction(1)
            eq_rows.append((coeffs, width))

    m = len(eq_rows)
    first_artificial = structural_count
    total_cols = structural_count + m
    rhs_col = total_cols
    # tableau：m 个约束行 + 1 个目标行；列 = 结构变量 + 人工变量 + 右端项。
    tableau: list[list[Fraction]] = [
        [Fraction(0) for _ in range(total_cols + 1)] for _ in range(m + 1)
    ]
    basis: list[int] = []
    box_row_to_slack: dict[int, int] = {}
    box_order = 0
    for j, width in enumerate(widths):
        if width is not None:
            box_row_to_slack[len(rows) + box_order] = slack_index[j]
            box_order += 1
    for i, (coeffs, rhs) in enumerate(eq_rows):
        for j, a in enumerate(coeffs):
            tableau[i][j] = a
        # 盒子行的松弛变量系数（行号 -> 对应松弛列）。
        if i in box_row_to_slack:
            tableau[i][box_row_to_slack[i]] = Fraction(1)
        artificial = first_artificial + i
        tableau[i][artificial] = Fraction(1)
        tableau[i][rhs_col] = rhs
        basis.append(artificial)

    def pivot(row: int, col: int) -> None:
        # 原地修改（不重新绑定 tableau 的行），保证外部持有的目标行引用
        # objective_row = tableau[m] 在转轴后仍指向被更新的同一对象。
        pivot_value = tableau[row][col]
        normalized = [value / pivot_value for value in tableau[row]]
        for r in range(m + 1):
            if r == row:
                tableau[row][:] = normalized
                continue
            factor = tableau[r][col]
            if factor == 0:
                continue
            target = tableau[r]
            for j in range(len(target)):
                target[j] = target[j] - factor * normalized[j]
        basis[row] = col

    def leaving_row(entering: int) -> int | None:
        # Bland 最小比率测试，平局取行号最小者。
        best_row: int | None = None
        best_ratio: Fraction | None = None
        for i in range(m):
            coefficient = tableau[i][entering]
            if coefficient <= 0:
                continue
            ratio = tableau[i][rhs_col] / coefficient
            if best_ratio is None or ratio < best_ratio:
                best_ratio = ratio
                best_row = i
        return best_row

    # 2) 第一阶段目标行：w = 人工变量之和。用约束行之和构造规范目标行。
    objective_row = tableau[m]
    for j in range(structural_count):
        objective_row[j] = -sum(tableau[i][j] for i in range(m))
    for i in range(m):
        objective_row[first_artificial + i] = Fraction(0)
    objective_row[rhs_col] = -sum(tableau[i][rhs_col] for i in range(m))

    while True:
        # 第一阶段只允许结构变量（含盒子松弛）进基；人工变量一旦离基永不
        # 再进，否则可能重新进基造成循环。
        entering = next(
            (j for j in range(structural_count) if objective_row[j] < 0), None
        )
        if entering is None:
            break
        leaving = leaving_row(entering)
        if leaving is None:
            raise ArithmeticError("第一阶段无界，属于建模错误")
        pivot(leaving, entering)

    # 最小化约定下目标值 = -objective_row[rhs_col]。
    if -objective_row[rhs_col] != 0:
        raise InfeasibleError("约束系统无可行解")

    # 人工变量仍在基中（取值 0）：用一次退化旋转换出，无法换出则是冗余行。
    for i, base_var in enumerate(basis):
        if base_var >= first_artificial:
            candidate = next(
                (j for j in range(structural_count) if tableau[i][j] != 0), None
            )
            if candidate is not None:
                pivot(i, candidate)

    # 3) 第二阶段：真实目标（最大化通过 sign=-1 转最小化）。
    sign = 1 if minimize else -1
    cost = [Fraction(0)] * total_cols
    for j, c in enumerate(objective):
        cost[j] = sign * _as_fraction(c)
    # 由当前基重建规范目标行：row0 = c - c_B·B^-1 A。
    for j in range(total_cols):
        objective_row[j] = cost[j]
    objective_row[rhs_col] = Fraction(0)
    for i, base_var in enumerate(basis):
        if base_var >= first_artificial:
            continue
        coefficient = cost[base_var]
        if coefficient == 0:
            continue
        for j in range(total_cols + 1):
            objective_row[j] -= coefficient * tableau[i][j]

    while True:
        # Bland：编号最小的负检验数变量进基。
        entering = next(
            (j for j in range(structural_count) if objective_row[j] < 0), None
        )
        if entering is None:
            break
        leaving = leaving_row(entering)
        if leaving is None:
            raise ArithmeticError("目标无界，属于建模错误")
        pivot(leaving, entering)

    optimum_shifted = -objective_row[rhs_col]
    shift_constant = sum(
        _as_fraction(c) * lower[j] for j, c in enumerate(objective)
    )
    return sign * optimum_shifted + shift_constant


def feasible_range(
    incidence: Sequence[int],
    rows: Sequence[Sequence[int | Fraction]],
    bounds: Sequence[tuple[int, Fraction | None]],
) -> tuple[Fraction, Fraction]:
    """求线性表达式 ``incidence · x`` 在约束系统下的精确可行区间。"""
    lower = optimize(incidence, rows, bounds, minimize=True)
    upper = optimize(incidence, rows, bounds, minimize=False)
    if lower > upper:  # pragma: no cover - 两次求解一致性由 LP 保证
        raise InfeasibleError("可行区间反转")
    return lower, upper


class LpSystem:
    """同一约束系统、多个目标的可复用单纯形求解器。

    安全审计要对许多目标（每个敏感单元的分子/分母）在**完全相同**的等式
    与盒子约束下求最小/最大值。逐目标重建第一阶段基会造成大量重复转轴。
    本类只做一次第一阶段得到一个可行基，之后每个目标从该可行基出发重建
    规范目标行并仅做第二阶段转轴（热启动），把每目标成本压到最低。

    用法::

        system = LpSystem(rows, bounds)
        system.assert_feasible()
        lo, hi = system.range(objective_vector)
    """

    def __init__(
        self,
        rows: Sequence[Sequence[int | Fraction]],
        bounds: Sequence[tuple[int | Fraction, int | Fraction | None]],
    ) -> None:
        self.rows = rows
        self.bounds = bounds
        self.n = len(bounds)
        self._feasible_basis: tuple[list[list[Fraction]], list[int]] | None = None
        self._build_phase_one()

    def _build_phase_one(self) -> None:
        n = self.n
        lower = [_as_fraction(lo) for lo, _ in self.bounds]
        widths: list[Fraction | None] = [
            None if hi is None else _as_fraction(hi) - lo for lo, hi in self.bounds
        ]
        self.lower = lower
        slack_index: dict[int, int] = {}
        structural_count = n
        for j, width in enumerate(widths):
            if width is not None:
                slack_index[j] = structural_count
                structural_count += 1
        self.structural_count = structural_count

        eq_rows: list[tuple[list[Fraction], Fraction]] = []
        for coefficients, rhs in self.rows:
            shifted_rhs = _as_fraction(rhs) - sum(
                _as_fraction(a) * lower[j] for j, a in enumerate(coefficients)
            )
            eq_rows.append(([_as_fraction(a) for a in coefficients], shifted_rhs))
        for j, width in enumerate(widths):
            if width is not None:
                coeffs = [Fraction(0)] * n
                coeffs[j] = Fraction(1)
                eq_rows.append((coeffs, width))

        m = len(eq_rows)
        self.m = m
        first_artificial = structural_count
        self.first_artificial = first_artificial
        total_cols = structural_count + m
        self.total_cols = total_cols
        rhs_col = total_cols
        self.rhs_col = rhs_col
        tableau: list[list[Fraction]] = [
            [Fraction(0) for _ in range(total_cols + 1)] for _ in range(m + 1)
        ]
        basis: list[int] = []
        box_row_to_slack: dict[int, int] = {}
        box_order = 0
        for j, width in enumerate(widths):
            if width is not None:
                box_row_to_slack[len(self.rows) + box_order] = slack_index[j]
                box_order += 1
        for i, (coeffs, rhs) in enumerate(eq_rows):
            for j, a in enumerate(coeffs):
                tableau[i][j] = a
            if i in box_row_to_slack:
                tableau[i][box_row_to_slack[i]] = Fraction(1)
            artificial = first_artificial + i
            tableau[i][artificial] = Fraction(1)
            tableau[i][rhs_col] = rhs
            basis.append(artificial)

        def pivot(row: int, col: int) -> None:
            pivot_value = tableau[row][col]
            normalized = [value / pivot_value for value in tableau[row]]
            for r in range(m + 1):
                if r == row:
                    tableau[row][:] = normalized
                    continue
                factor = tableau[r][col]
                if factor == 0:
                    continue
                target = tableau[r]
                for j in range(len(target)):
                    target[j] = target[j] - factor * normalized[j]
            basis[row] = col

        def leaving_row(entering: int) -> int | None:
            best_row: int | None = None
            best_ratio: Fraction | None = None
            for i in range(m):
                coefficient = tableau[i][entering]
                if coefficient <= 0:
                    continue
                ratio = tableau[i][rhs_col] / coefficient
                if best_ratio is None or ratio < best_ratio:
                    best_ratio = ratio
                    best_row = i
            return best_row

        objective_row = tableau[m]
        for j in range(structural_count):
            objective_row[j] = -sum(tableau[i][j] for i in range(m))
        objective_row[rhs_col] = -sum(tableau[i][rhs_col] for i in range(m))
        while True:
            entering = next(
                (j for j in range(structural_count) if objective_row[j] < 0), None
            )
            if entering is None:
                break
            leaving = leaving_row(entering)
            if leaving is None:
                raise ArithmeticError("第一阶段无界，属于建模错误")
            pivot(leaving, entering)
        if -objective_row[rhs_col] != 0:
            raise InfeasibleError("约束系统无可行解")
        for i, base_var in enumerate(basis):
            if base_var >= first_artificial:
                candidate = next(
                    (j for j in range(structural_count) if tableau[i][j] != 0), None
                )
                if candidate is not None:
                    pivot(i, candidate)
        self._tableau = tableau
        self._basis = basis
        self._pivot = pivot
        self._leaving_row = leaving_row

    def assert_feasible(self) -> None:
        """第一阶段已在构造时完成；不可行会直接抛出。"""
        if self._feasible_basis is None:
            self._feasible_basis = (
                [row[:] for row in self._tableau],
                list(self._basis),
            )

    def _optimize_from_feasible(
        self, objective: Sequence[int | Fraction], minimize: bool
    ) -> Fraction:
        self.assert_feasible()
        # 每个目标从同一个可行基的副本出发，避免目标之间互相污染基。
        tableau = [row[:] for row in self._feasible_basis[0]]
        basis = list(self._feasible_basis[1])
        m = self.m
        structural_count = self.structural_count
        first_artificial = self.first_artificial
        total_cols = self.total_cols
        rhs_col = self.rhs_col

        def pivot(row: int, col: int) -> None:
            pivot_value = tableau[row][col]
            normalized = [value / pivot_value for value in tableau[row]]
            for r in range(m + 1):
                if r == row:
                    tableau[row][:] = normalized
                    continue
                factor = tableau[r][col]
                if factor == 0:
                    continue
                target = tableau[r]
                for j in range(len(target)):
                    target[j] = target[j] - factor * normalized[j]
            basis[row] = col

        def leaving_row(entering: int) -> int | None:
            best_row: int | None = None
            best_ratio: Fraction | None = None
            for i in range(m):
                coefficient = tableau[i][entering]
                if coefficient <= 0:
                    continue
                ratio = tableau[i][rhs_col] / coefficient
                if best_ratio is None or ratio < best_ratio:
                    best_ratio = ratio
                    best_row = i
            return best_row

        sign = 1 if minimize else -1
        cost = [Fraction(0)] * total_cols
        for j, c in enumerate(objective):
            cost[j] = sign * _as_fraction(c)
        objective_row = tableau[m]
        for j in range(total_cols):
            objective_row[j] = cost[j]
        objective_row[rhs_col] = Fraction(0)
        for i, base_var in enumerate(basis):
            if base_var >= first_artificial:
                continue
            coefficient = cost[base_var]
            if coefficient == 0:
                continue
            for j in range(total_cols + 1):
                objective_row[j] -= coefficient * tableau[i][j]
        while True:
            entering = next(
                (j for j in range(structural_count) if objective_row[j] < 0), None
            )
            if entering is None:
                break
            leaving = leaving_row(entering)
            if leaving is None:
                raise ArithmeticError("目标无界，属于建模错误")
            pivot(leaving, entering)
        optimum_shifted = -objective_row[rhs_col]
        shift_constant = sum(
            _as_fraction(c) * self.lower[j] for j, c in enumerate(objective)
        )
        return sign * optimum_shifted + shift_constant

    def range(
        self, objective: Sequence[int | Fraction]
    ) -> tuple[Fraction, Fraction]:
        lower = self._optimize_from_feasible(objective, True)
        upper = self._optimize_from_feasible(objective, False)
        if lower > upper:  # pragma: no cover - 一致性由 LP 保证
            raise InfeasibleError("可行区间反转")
        return lower, upper
