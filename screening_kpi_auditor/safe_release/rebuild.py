"""按同一人、同一期间的业务口径重建分子与分母。

处理规则（每条原始记录都在工作底稿留下处置痕迹，保证可追溯）：

* ``dedup_keys`` 去重：同一业务键只保留 ``revision`` 最大的一条；并列时
  以 ``record_id`` 字典序确定，保证结果确定。
* 口径生效日 ``indicator.effective_at``：业务日期 ``effective_at`` 早于
  口径生效日的记录不属于当前口径，排除并留痕。
* 迟到补录：``known_at`` 晚于发布快照日 ``as_of`` 的记录，发布时点尚不可
  知，排除并留痕；其人数不进入本次发布，避免把未来信息夹带出去。
* 资格：``eligible`` 为真才进入分母；分子要求同时满足 ``eligible`` 与
  ``screened``。
* 维度缺省与数值零含义不同：维度字段缺失/为空/空字符串归入 ``unknown``
  桶；分母为零的单元没有比率（rate 为 null），但仍参与抑制推理。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Any, Mapping

from screening_kpi_auditor.runtime import DomainError, fingerprint

UNKNOWN_DIMENSION = "unknown"

# 处置原因代码。
DISPOSITION_INCLUDED = "included"
DISPOSITION_INELIGIBLE = "excluded:ineligibility"
DISPOSITION_LATE = "excluded:late_backfill"
DISPOSITION_PRECALIBER = "excluded:pre_caliber"
DISPOSITION_DUPLICATE = "excluded:superseded_revision"


@dataclass(frozen=True, slots=True)
class PersonObservation:
    """去重后、口径内的一个（人, 期间）业务观察。"""

    person_key: str
    period: str
    town: str
    age_band: str
    channel: str
    eligible: bool
    screened: bool
    source_record_ids: tuple[str, ...]
    revision: int


@dataclass(slots=True)
class RebuildResult:
    observations: list[PersonObservation]
    dispositions: list[dict[str, Any]] = field(default_factory=list)
    included_record_ids: set[str] = field(default_factory=set)
    indicator_version: str = ""
    indicator_effective_at: str = ""
    dedup_keys: tuple[str, ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    input_fingerprint: str = ""

    @property
    def denominator_persons(self) -> list[PersonObservation]:
        return [observation for observation in self.observations if observation.eligible]


def _parse_iso_date(value: Any, field_name: str) -> date:
    if not isinstance(value, str) or not value.strip():
        raise DomainError(f"{field_name} 必须是 ISO 日期字符串")
    text = value.strip()
    try:
        return date.fromisoformat(text[:10])
    except ValueError as exc:
        raise DomainError(f"{field_name} 日期格式非法: {text!r}") from exc


def _dimension_value(record: Mapping[str, Any], name: str) -> str:
    value = record.get(name)
    if value is None:
        return UNKNOWN_DIMENSION
    if isinstance(value, str):
        text = value.strip()
        return text if text else UNKNOWN_DIMENSION
    text = str(value).strip()
    return text if text else UNKNOWN_DIMENSION


def _as_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().casefold()
        if text in {"true", "1", "yes", "y"}:
            return True
        if text in {"false", "0", "no", "n"}:
            return False
    raise DomainError(f"{field_name} 必须是布尔值")


def rebuild_indicators(request: Mapping[str, Any]) -> RebuildResult:
    """依据发布请求中的口径定义，从本地个体记录重建观察集合。"""
    if not isinstance(request, Mapping):
        raise DomainError("发布请求必须是 JSON 对象")
    as_of = _parse_iso_date(request.get("as_of"), "as_of")
    indicator = request.get("indicator")
    if not isinstance(indicator, Mapping):
        raise DomainError("indicator 口径定义缺失")
    version = str(indicator.get("version", "")).strip()
    if not version:
        raise DomainError("indicator.version 缺失")
    effective_date = _parse_iso_date(indicator.get("effective_at"), "indicator.effective_at")
    dedup_keys = tuple(str(key).strip() for key in indicator.get("dedup_keys", []) if str(key).strip())
    if not dedup_keys:
        raise DomainError("indicator.dedup_keys 至少包含一个字段")

    raw_records = request.get("records")
    if not isinstance(raw_records, list):
        raise DomainError("records 必须是数组")

    minimum_cell_count = request.get("minimum_cell_count")
    if not isinstance(minimum_cell_count, int) or isinstance(minimum_cell_count, bool) or minimum_cell_count < 1:
        raise DomainError("minimum_cell_count 必须是正整数")

    dispositions: list[dict[str, Any]] = []
    # 第一遍：口径生效日与迟到补录过滤。
    admitted: list[Mapping[str, Any]] = []
    for index, record in enumerate(raw_records):
        if not isinstance(record, Mapping):
            raise DomainError(f"records[{index}] 必须是对象")
        record_id = str(record.get("record_id") or f"row-{index}")
        effective_at = _parse_iso_date(record.get("effective_at"), f"records[{index}].effective_at")
        known_at = _parse_iso_date(record.get("known_at"), f"records[{index}].known_at")
        if effective_at < effective_date:
            dispositions.append(
                {
                    "record_id": record_id,
                    "disposition": DISPOSITION_PRECALIBER,
                    "reason": "effective_at 早于口径生效日",
                    "effective_at": record.get("effective_at"),
                    "indicator_effective_at": indicator.get("effective_at"),
                }
            )
            continue
        if known_at > as_of:
            dispositions.append(
                {
                    "record_id": record_id,
                    "disposition": DISPOSITION_LATE,
                    "reason": "known_at 晚于发布快照日 as_of，发布时点数据尚未到达",
                    "known_at": record.get("known_at"),
                    "as_of": request.get("as_of"),
                }
            )
            continue
        admitted.append(record)

    # 第二遍：按业务键去重，保留最高 revision。
    winners: dict[tuple[Any, ...], Mapping[str, Any]] = {}
    members: dict[tuple[Any, ...], list[str]] = {}
    for record in admitted:
        key = tuple(record.get(field_name) for field_name in dedup_keys)
        members.setdefault(key, []).append(str(record.get("record_id", "")))
        incumbent = winners.get(key)
        revision = record.get("revision", 0)
        if not isinstance(revision, int) or isinstance(revision, bool):
            raise DomainError("revision 必须是整数")
        if incumbent is None or (revision, str(record.get("record_id", ""))) > (
            incumbent.get("revision", 0),
            str(incumbent.get("record_id", "")),
        ):
            winners[key] = record

    winner_ids = {str(record.get("record_id", "")) for record in winners.values()}
    for record in admitted:
        record_id = str(record.get("record_id", ""))
        if record_id not in winner_ids:
            dispositions.append(
                {
                    "record_id": record_id,
                    "disposition": DISPOSITION_DUPLICATE,
                    "reason": "同一去重键存在更高 revision 的记录",
                    "dedup_keys": list(dedup_keys),
                }
            )

    # 第三遍：资格判定与维度归桶。
    observations: list[PersonObservation] = []
    included_record_ids: set[str] = set()
    for record in winners.values():
        record_id = str(record.get("record_id", ""))
        eligible = _as_bool(record.get("eligible"), "eligible")
        screened = _as_bool(record.get("screened"), "screened")
        if not eligible:
            dispositions.append(
                {
                    "record_id": record_id,
                    "disposition": DISPOSITION_INELIGIBLE,
                    "reason": "eligible=false，不进入分母与分子",
                }
            )
            continue
        key = tuple(record.get(field_name) for field_name in dedup_keys)
        observation = PersonObservation(
            person_key=str(record.get("person_id", "")),
            period=str(record.get("period", "")).strip(),
            town=_dimension_value(record, "town"),
            age_band=_dimension_value(record, "age_band"),
            channel=_dimension_value(record, "channel"),
            eligible=True,
            screened=screened,
            source_record_ids=tuple(sorted(members[key])),
            revision=int(record.get("revision", 0)),
        )
        observations.append(observation)
        included_record_ids.add(record_id)
        dispositions.append(
            {
                "record_id": record_id,
                "disposition": DISPOSITION_INCLUDED,
                "reason": "纳入口径内（人, 期间）观察",
                "person_id": observation.person_key,
                "period": observation.period,
                "screened": screened,
            }
        )

    counts: dict[str, int] = {DISPOSITION_INCLUDED: 0}
    for item in dispositions:
        counts[item["disposition"]] = counts.get(item["disposition"], 0) + 1

    result = RebuildResult(
        observations=observations,
        dispositions=sorted(dispositions, key=lambda item: item["record_id"]),
        included_record_ids=included_record_ids,
        indicator_version=version,
        indicator_effective_at=str(indicator.get("effective_at")),
        dedup_keys=dedup_keys,
        counts=counts,
        input_fingerprint=fingerprint(
            {
                "as_of": request.get("as_of"),
                "indicator": dict(indicator),
                "record_count": len(raw_records),
                "minimum_cell_count": minimum_cell_count,
            }
        ),
    )
    return result
