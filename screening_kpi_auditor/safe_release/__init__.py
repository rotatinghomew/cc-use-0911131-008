"""安全发布规划（safe release planning）。

在既有指标口径与审计底稿之上，提供同一套业务指标的多维聚合与可发布性
推理：主抑制（最低单元人数）、互补抑制（线性/差分攻击防护）、历史发布
差分审计与可验证的发布证书。本包不做权限管理，也不生成报表页面。
"""
from __future__ import annotations

from screening_kpi_auditor.safe_release.service import (
    SafeReleasePlanner,
    plan_safe_release,
)

__all__ = ["SafeReleasePlanner", "plan_safe_release"]
