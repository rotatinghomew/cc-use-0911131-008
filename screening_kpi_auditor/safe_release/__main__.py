"""命令行入口：

    python3 -m screening_kpi_auditor.safe_release \
        --input <request.json> --database <audit.sqlite3> --output <release.json>

输出 JSON 只含白名单对外字段；内部真值与披露区间仅写入审计数据库。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from screening_kpi_auditor.runtime import DomainError
from screening_kpi_auditor.safe_release.service import SafeReleasePlanner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="screening_kpi_auditor.safe_release",
        description="筛查指标多维发布的安全发布规划（互补抑制 + 精确 LP 审计）",
    )
    parser.add_argument("--input", required=True, help="发布请求 JSON 路径")
    parser.add_argument("--database", required=True, help="审计台账 SQLite 路径")
    parser.add_argument("--output", required=True, help="对外发布结果 JSON 输出路径")
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    request = json.loads(input_path.read_text(encoding="utf-8"))
    try:
        result = SafeReleasePlanner(args.database).plan(request)
    except DomainError as exc:
        # 请求本身不合法：不产生发布，错误以非零码返回。
        print(f"safe_release 请求被拒绝: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False, indent=2),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
