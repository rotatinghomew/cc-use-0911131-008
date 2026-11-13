"""多维列联立方与发布单元聚合。

所有透视（views）共享同一批原子层（strata）：每个人落在一个
``(town, age_band, channel)`` 组合上。透视单元是对原子层的谓词选择，因
此两个透视里业务含义相同的单元（例如同一个乡镇合计）得到同一个
``cell_id``、同一组分子/分母真值，抑制决策天然全局共享，不可能出现
「A 透视隐藏、B 透视却换个名字发布」的旁路。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from screening_kpi_auditor.runtime import DomainError, fingerprint, stable_json
from screening_kpi_auditor.safe_release.rebuild import PersonObservation

DIMENSIONS = ("town", "age_band", "channel")
TOTAL_MARKER = "all"


@dataclass(frozen=True, slots=True)
class Stratum:
    """原子层：维度的一个完整取值组合。"""

    index: int
    coordinates: tuple[str, ...]

    @property
    def key(self) -> tuple[str, ...]:
        return self.coordinates


@dataclass(slots=True)
class Cell:
    """一个可发布单元：对若干原子层的谓词选择及其真值。"""

    cell_id: str
    view_id: str
    dimensions: tuple[str, ...]
    member_values: tuple[tuple[str, str], ...]
    level: str
    is_total: bool
    stratum_indices: tuple[int, ...]
    numerator: int
    denominator: int

    @property
    def predicate_key(self) -> str:
        """跨透视的业务身份：维度→取值的规范表示。"""
        return stable_json(sorted(self.member_values))

    @property
    def rate(self) -> float | None:
        if self.denominator == 0:
            return None
        return round(self.numerator / self.denominator, 6)


@dataclass(slots=True)
class Cube:
    strata: list[Stratum]
    # 每个原子层两个计数：分母人数与分子（已筛查）人数。
    denominator: list[int]
    numerator: list[int]
    cells_by_id: dict[str, Cell] = field(default_factory=dict)
    # 业务谓词 → 规范 cell_id，用于跨透视去重。
    predicate_to_cell: dict[str, str] = field(default_factory=dict)
    view_cell_ids: dict[str, list[str]] = field(default_factory=dict)
    total_cell_ids: list[str] = field(default_factory=list)

    @property
    def total_denominator(self) -> int:
        return sum(self.denominator)

    @property
    def total_numerator(self) -> int:
        return sum(self.numerator)

    def incidence(self, cell: Cell) -> list[int]:
        """单元对原子层分母变量的 0/1 关联向量（分子同构）。"""
        vector = [0] * len(self.strata)
        for index in cell.stratum_indices:
            vector[index] = 1
        return vector


def _domains(observations: Sequence[PersonObservation]) -> dict[str, list[str]]:
    domains: dict[str, set[str]] = {name: set() for name in DIMENSIONS}
    for observation in observations:
        values = (observation.town, observation.age_band, observation.channel)
        for name, value in zip(DIMENSIONS, values):
            domains[name].add(value)
    return {name: sorted(values) for name, values in domains.items()}


def _make_cell_id(dimensions: Sequence[str], member_values: Sequence[tuple[str, str]]) -> str:
    digest = fingerprint({"dims": list(dimensions), "members": sorted(member_values)})[:16]
    return f"cell-{digest}"


def _level_name(dimensions: Sequence[str], member_values: Sequence[tuple[str, str]]) -> str:
    if not member_values:
        return "grand_total"
    if len(member_values) == len(dimensions):
        return "detail"
    return "margin"


def build_cube(
    observations: Sequence[PersonObservation],
    views: Sequence[Mapping[str, Any]],
    required_totals: Sequence[str],
) -> Cube:
    domains = _domains(observations)
    # 原子层取观察中出现过的维度组合（未出现组合人数恒为 0，不建变量，
    # 避免无意义地扩大 LP；边界 0 由盒子约束表达）。
    coordinate_set: dict[tuple[str, ...], int] = {}
    for observation in observations:
        key = (observation.town, observation.age_band, observation.channel)
        if key not in coordinate_set:
            coordinate_set[key] = len(coordinate_set)
    strata = [Stratum(index=index, coordinates=key) for key, index in sorted(coordinate_set.items(), key=lambda item: item[1])]
    denominator = [0] * len(strata)
    numerator = [0] * len(strata)
    for observation in observations:
        index = coordinate_set[(observation.town, observation.age_band, observation.channel)]
        denominator[index] += 1
        if observation.screened:
            numerator[index] += 1

    cube = Cube(strata=strata, denominator=denominator, numerator=numerator)

    def select_strata(member_values: Sequence[tuple[str, str]]) -> tuple[int, ...]:
        wanted = dict(member_values)
        matched: list[int] = []
        for stratum in strata:
            coords = dict(zip(DIMENSIONS, stratum.coordinates))
            if all(coords.get(dim) == value for dim, value in wanted.items()):
                matched.append(stratum.index)
        return tuple(sorted(matched))

    def register_cell(
        view_id: str,
        dimensions: Sequence[str],
        member_values: Sequence[tuple[str, str]],
        is_total: bool,
    ) -> str:
        member_values = tuple(sorted(member_values))
        predicate_key = stable_json(sorted(member_values))
        existing = cube.predicate_to_cell.get(predicate_key)
        if existing is not None:
            return existing
        indices = select_strata(member_values)
        cell_denominator = sum(denominator[i] for i in indices)
        cell_numerator = sum(numerator[i] for i in indices)
        cell = Cell(
            cell_id=_make_cell_id(dimensions, member_values),
            view_id=view_id,
            dimensions=tuple(dimensions),
            member_values=member_values,
            level=_level_name(dimensions, member_values),
            is_total=is_total,
            stratum_indices=indices,
            numerator=cell_numerator,
            denominator=cell_denominator,
        )
        cube.cells_by_id[cell.cell_id] = cell
        cube.predicate_to_cell[predicate_key] = cell.cell_id
        if is_total:
            cube.total_cell_ids.append(cell.cell_id)
        return cell.cell_id

    for view in views:
        view_id = str(view.get("view_id", "")).strip()
        if not view_id:
            raise DomainError("view_id 缺失")
        dimensions = view.get("dimensions")
        if not isinstance(dimensions, list) or not dimensions:
            raise DomainError(f"视图 {view_id} 的 dimensions 必须是非空数组")
        for dimension in dimensions:
            if dimension not in DIMENSIONS:
                raise DomainError(f"视图 {view_id} 使用了未知维度 {dimension}")
        margins = bool(view.get("margins", False))
        cell_ids: list[str] = []

        # 明细单元：视图维度域的完整笛卡尔积。未出现的取值组合生成零分母
        # 单元（结构性零单元，参与主抑制），但不新增 LP 原子层变量。
        def walk(dim_index: int, chosen: list[tuple[str, str]]) -> None:
            if dim_index == len(dimensions):
                cell_ids.append(register_cell(view_id, dimensions, chosen, False))
                return
            dimension = dimensions[dim_index]
            for value in domains[dimension]:
                walk(dim_index + 1, chosen + [(dimension, value)])

        walk(0, [])

        if margins:
            # 单维边际：固定一个视图维度，其余放开。
            for dimension in dimensions:
                for value in domains[dimension]:
                    cell_ids.append(
                        register_cell(view_id, dimensions, [(dimension, value)], False)
                    )
        cube.view_cell_ids[view_id] = cell_ids

    # 要求保留的汇总层级：目前支持 grand total（"all"）。
    for required in required_totals:
        token = str(required).strip()
        if token != TOTAL_MARKER:
            raise DomainError(f"不支持的 required_totals 层级: {token}")
    if TOTAL_MARKER in {str(item).strip() for item in required_totals}:
        grand_id = register_cell(TOTAL_MARKER, (), (), True)
        if grand_id not in cube.total_cell_ids:
            cube.total_cell_ids.append(grand_id)

    return cube
