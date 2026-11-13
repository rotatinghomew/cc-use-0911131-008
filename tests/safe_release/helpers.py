"""测试用请求构造器：生成确定的合成个体记录。"""
from __future__ import annotations


def _records(town_sizes: dict[str, int], *, two_views: bool = False, screened_all: bool = False):
    records = []
    record_id = 0
    for town, size in town_sizes.items():
        for age_band in ("young", "old"):
            for channel in (("clinic", "mobile") if two_views else ("clinic",)):
                # 简化：把人数均匀放到该 (镇, 年龄, 渠道) 组合。
                per_cell = max(1, size // 4)
                for _ in range(per_cell):
                    records.append(
                        {
                            "record_id": f"r{record_id}",
                            "person_id": f"p{record_id}",
                            "period": "2026-Q2",
                            "town": town,
                            "age_band": age_band,
                            "channel": channel,
                            "eligible": True,
                            "screened": screened_all or (record_id % 3 == 0),
                            "effective_at": "2026-06-01",
                            "known_at": "2026-06-20",
                            "revision": 1,
                        }
                    )
                    record_id += 1
    return records


def _views(two_views: bool):
    views = [{"view_id": "town-age", "dimensions": ["town", "age_band"], "margins": True}]
    if two_views:
        views.append(
            {"view_id": "town-channel", "dimensions": ["town", "channel"], "margins": True}
        )
    return views


def build_request(town_sizes: dict[str, int], k: int = 5) -> dict:
    return {
        "as_of": "2026-07-01",
        "records": _records(town_sizes),
        "indicator": {
            "version": "v1",
            "effective_at": "2026-01-01",
            "dedup_keys": ["person_id", "period"],
        },
        "minimum_cell_count": k,
        "views": _views(False),
        "historical_cells": [],
        "required_totals": ["all"],
    }


def two_view_request(k: int = 5) -> dict:
    # small 镇刻意保持很小，其余镇较大，复现乡镇单元差分场景。
    town_sizes = {"small": 2, "east": 24, "west": 24}
    request = build_request(town_sizes, k)
    request["records"] = _records(town_sizes, two_views=True)
    request["views"] = _views(True)
    return request
