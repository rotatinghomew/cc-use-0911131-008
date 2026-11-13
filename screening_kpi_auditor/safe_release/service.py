"""安全发布规划的编排服务与对外结果构造。

输出文件的脱敏原则：外部 JSON 只包含允许发布的数值；被抑制单元以
``null`` 占位，工作底稿里的真值、披露区间、记录级处置一律只写内部数据
库。外部结构由白名单字段重新构造，不直接序列化内部对象，避免调试字段
或可反推小计被夹带出去。
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Mapping, Sequence

from screening_kpi_auditor.runtime import (
    DomainError,
    ProcessingContext,
    fingerprint,
    stable_json,
    utc_now,
)
from screening_kpi_auditor.safe_release.auditor import (
    ComplementarySuppressionPlanner,
    SuppressionAuditor,
)
from screening_kpi_auditor.safe_release.cube import build_cube
from screening_kpi_auditor.safe_release.rebuild import rebuild_indicators
from screening_kpi_auditor.safe_release.storage import SafeReleaseStore

METHOD_NAME = "exact-rational-lp-complementary-suppression"
CERTIFICATE_SCOPE = (
    "仅覆盖请求中各视图明细、行列边际、required_totals 的全部线性加减关系，"
    "以及 historical_cells 中登记的历史已发布单元差分；不覆盖任意外部知识、"
    "未登记的历史发布或侧信道信息。"
)
PROTECTION_STATEMENT = (
    "对每个真值分母低于 minimum_cell_count 的主敏感单元，其分母与分子在攻击者"
    "已知线性等式和取值边界下的整数可行区间宽度均不小于 minimum_cell_count；"
    "约束矩阵为多向列联表边际关联矩阵叠加盒子与 n_s<=d_s 约束，全幺模且右端为"
    "整数，精确有理数 LP 最优值即整数可行域边界。比率不单独发布，分子分母同时"
    "抑制，rate 同步置 null，不存在比率旁路。"
)


class SafeReleasePlanner:
    def __init__(self, database: str | Path) -> None:
        self.store = SafeReleaseStore(database)

    def plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        self._validate_request_shape(request)
        # 幂等：同一份输入指纹只对应一次发布结论。
        recalled = self.store.find_by_input_fingerprint(request)
        if recalled is not None:
            return self._rehydrate(recalled)

        release_id = f"rel-{uuid.uuid4().hex}"
        ctx = ProcessingContext(
            run_id=uuid.uuid4().hex,
            case_id=release_id,
            payload={"release_id": release_id, "stage": "safe_release"},
        )
        ctx.emit("safe_release", "run_started", release_id=release_id)

        # 1) 口径重建。
        rebuild = rebuild_indicators(request)
        ctx.emit(
            "safe_release",
            "indicators_rebuilt",
            observations=len(rebuild.observations),
            dispositions=rebuild.counts,
            indicator_version=rebuild.indicator_version,
        )
        ctx.add_evidence(
            "safe_release",
            "indicator_rebuild",
            "request.records",
            "observations",
            [o.person_key for o in rebuild.observations],
        )
        periods = {observation.period for observation in rebuild.observations}
        if len(periods) > 1:
            raise DomainError(f"单次发布仅支持同一期间，收到多个期间: {sorted(periods)}")

        # 2) 统一立方与跨透视单元。
        cube = build_cube(
            rebuild.observations,
            request["views"],
            request.get("required_totals", []),
        )
        ctx.emit(
            "safe_release",
            "cube_built",
            strata=len(cube.strata),
            cells=len(cube.cells_by_id),
            total_denominator=cube.total_denominator,
        )

        # 3) LP 审计 + 互补抑制规划。
        auditor = SuppressionAuditor(
            cube,
            minimum_cell_count=int(request["minimum_cell_count"]),
            historical_cells=request.get("historical_cells", []),
        )
        required_total_ids = set(cube.total_cell_ids)
        planner = ComplementarySuppressionPlanner(auditor)
        plan = planner.plan(required_total_ids)
        ctx.emit(
            "safe_release",
            "suppression_planned",
            iterations=plan.iterations,
            suppressed=len(plan.suppressed),
            safe=plan.audit.safe,
            violations=len(plan.audit.violations),
        )

        required_total_suppressed = required_total_ids.intersection(plan.suppressed)
        rejection_reasons = [
            f"cell:{violation.cell_id}:metric:{violation.metric}:feasible_width_{violation.width}_below_{violation.required_width}"
            for violation in plan.audit.violations
        ]
        if plan.audit.infeasible:
            rejection_reasons.append("constraint_system_infeasible:historical_or_published_equations_conflict")
        if required_total_suppressed:
            rejection_reasons.append(
                "required_total_cannot_be_protected:"
                + ",".join(sorted(required_total_suppressed))
            )
        status = "published" if plan.audit.safe and not required_total_suppressed else "rejected"

        certificate = self._build_certificate(
            release_id, request, cube, rebuild, plan, status, rejection_reasons
        )
        ctx.emit("safe_release", "certificate_issued", status=status, method=METHOD_NAME)

        # 4) 内部工作底稿行（含真值与披露区间，仅入库）。
        cell_rows = self._build_internal_cell_rows(release_id, cube, plan, auditor)
        self.store.save(
            release_id=release_id,
            ctx=ctx,
            status=status,
            request=request,
            certificate=certificate,
            cell_rows=cell_rows,
            dispositions=rebuild.dispositions,
            rejection_reasons=rejection_reasons,
        )

        # 5) 外部脱敏结果。
        return self._build_external_result(
            release_id, status, cube, plan, certificate, rejection_reasons
        )

    # ------------------------------------------------------------------
    def _validate_request_shape(self, request: Mapping[str, Any]) -> None:
        if not isinstance(request, Mapping):
            raise DomainError("发布请求必须是 JSON 对象")
        for field_name in ("as_of", "records", "indicator", "views", "minimum_cell_count"):
            if field_name not in request:
                raise DomainError(f"发布请求缺少必填字段: {field_name}")
        if not isinstance(request["views"], list) or not request["views"]:
            raise DomainError("views 必须是非空数组")
        if request.get("required_totals") is not None and not isinstance(
            request.get("required_totals"), list
        ):
            raise DomainError("required_totals 必须是数组")
        if not isinstance(request.get("historical_cells", []), list):
            raise DomainError("historical_cells 必须是数组")

    def _build_certificate(
        self,
        release_id: str,
        request: Mapping[str, Any],
        cube: Any,
        rebuild: Any,
        plan: Any,
        status: str,
        rejection_reasons: Sequence[str],
    ) -> dict[str, Any]:
        certificate = {
            "release_id": release_id,
            "status": status,
            "as_of": request["as_of"],
            "generated_at": utc_now(),
            "method": METHOD_NAME,
            "indicator": {
                "version": rebuild.indicator_version,
                "effective_at": rebuild.indicator_effective_at,
                "dedup_keys": list(rebuild.dedup_keys),
            },
            "minimum_cell_count": int(request["minimum_cell_count"]),
            "views": [
                {
                    "view_id": view.get("view_id"),
                    "dimensions": list(view.get("dimensions", [])),
                    "margins": bool(view.get("margins", False)),
                }
                for view in request["views"]
            ],
            "required_totals": list(request.get("required_totals", [])),
            "historical_cell_count": len(request.get("historical_cells", [])),
            "record_disposition_counts": dict(rebuild.counts),
            "strata_count": len(cube.strata),
            "cell_count": len(cube.cells_by_id),
            "suppressed_count": len(plan.suppressed),
            "linear_relation_groups_checked": len(plan.audit.relation_checks),
            "protection_condition": PROTECTION_STATEMENT,
            "scope_and_limitations": CERTIFICATE_SCOPE,
            "rejection_reasons": list(rejection_reasons),
            "input_fingerprint": rebuild.input_fingerprint,
        }
        certificate["certificate_fingerprint"] = fingerprint(certificate)
        return certificate

    def _build_internal_cell_rows(
        self,
        release_id: str,
        cube: Any,
        plan: Any,
        auditor: SuppressionAuditor,
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for cell_id in sorted(cube.cells_by_id):
            cell = cube.cells_by_id[cell_id]
            is_published = cell_id in plan.published_ids
            interval = plan.audit.intervals.get(cell_id)
            rows.append(
                {
                    "cell_id": cell_id,
                    "view_id": cell.view_id,
                    "level": cell.level,
                    "is_total": cell.is_total,
                    "members": list(cell.member_values),
                    "visibility": "published" if is_published else "suppressed",
                    "suppression_reason": None if is_published else plan.suppressed.get(cell_id),
                    "true_numerator": cell.numerator,
                    "true_denominator": cell.denominator,
                    "disclosed_numerator": cell.numerator if is_published else None,
                    "disclosed_denominator": cell.denominator if is_published else None,
                    "disclosure_interval": interval,
                }
            )
        return rows

    def _build_external_result(
        self,
        release_id: str,
        status: str,
        cube: Any,
        plan: Any,
        certificate: Mapping[str, Any],
        rejection_reasons: Sequence[str],
    ) -> dict[str, Any]:
        if status == "rejected":
            # 拒绝时不发布任何单元数值；仅保留类别级抑制清单（无数字）。
            public_cells: list[dict[str, Any]] = []
            suppressed = [
                {
                    "cell_id": cell_id,
                    "reason_code": plan.suppressed[cell_id],
                    "members": list(cube.cells_by_id[cell_id].member_values),
                    "level": cube.cells_by_id[cell_id].level,
                }
                for cell_id in sorted(plan.suppressed)
            ]
        else:
            public_cells = []
            suppressed = []
            for cell_id in sorted(cube.cells_by_id):
                cell = cube.cells_by_id[cell_id]
                if cell_id in plan.published_ids:
                    public_cells.append(
                        {
                            "cell_id": cell_id,
                            "view_id": cell.view_id,
                            "level": cell.level,
                            "members": [list(pair) for pair in cell.member_values],
                            "numerator": cell.numerator,
                            "denominator": cell.denominator,
                            "rate": cell.rate,
                        }
                    )
                else:
                    public_cells.append(
                        {
                            "cell_id": cell_id,
                            "view_id": cell.view_id,
                            "level": cell.level,
                            "members": [list(pair) for pair in cell.member_values],
                            "numerator": None,
                            "denominator": None,
                            "rate": None,
                        }
                    )
                    suppressed.append(
                        {
                            "cell_id": cell_id,
                            "reason_code": plan.suppressed[cell_id],
                            "members": list(cell.member_values),
                            "level": cell.level,
                        }
                    )
        result = {
            "release_id": release_id,
            "status": status,
            "as_of": certificate["as_of"],
            "public_cells": public_cells,
            "suppressed": suppressed,
            "certificate": certificate,
        }
        if status == "rejected":
            result["rejection_reasons"] = list(rejection_reasons)
        return result

    def _rehydrate(self, stored: Mapping[str, Any]) -> dict[str, Any]:
        """从只增证据表重建对外结果（历史发布不可改、不可删）。"""
        certificate = json.loads(stored["certificate_json"])
        release_id = stored["release_id"]
        with self.store.connect() as connection:
            cell_rows = connection.execute(
                "SELECT * FROM safe_release_cells WHERE release_id=? ORDER BY cell_id",
                (release_id,),
            ).fetchall()
        public_cells: list[dict[str, Any]] = []
        suppressed: list[dict[str, Any]] = []
        if stored["status"] == "published":
            for row in cell_rows:
                members = json.loads(row["members_json"])
                entry = {
                    "cell_id": row["cell_id"],
                    "view_id": row["view_id"],
                    "level": row["level"],
                    "members": members,
                    "numerator": row["disclosed_numerator"],
                    "denominator": row["disclosed_denominator"],
                    "rate": (
                        round(row["disclosed_numerator"] / row["disclosed_denominator"], 6)
                        if row["disclosed_denominator"]
                        else None
                    ),
                }
                public_cells.append(entry)
                if row["visibility"] == "suppressed":
                    suppressed.append(
                        {
                            "cell_id": row["cell_id"],
                            "reason_code": row["suppression_reason"],
                            "members": members,
                            "level": row["level"],
                        }
                    )
        result = {
            "release_id": release_id,
            "status": stored["status"],
            "as_of": stored["as_of"],
            "public_cells": public_cells,
            "suppressed": suppressed,
            "certificate": certificate,
            "replayed": True,
        }
        if stored["status"] == "rejected":
            result["rejection_reasons"] = json.loads(stored["rejection_reasons_json"])
            result["suppressed"] = suppressed
        return result


def plan_safe_release(
    request: Mapping[str, Any], database: str | Path
) -> dict[str, Any]:
    return SafeReleasePlanner(database).plan(request)
