"""安全发布证据的持久化。

与既有审计台账（:class:`screening_kpi_auditor.runtime.SQLiteLedger` 的
runs/events/evidence 表）共用同一个 SQLite 数据库，并新增只增不改的发
布证据表：

* ``safe_releases``：每次发布请求一行，含状态、证书指纹与输入指纹；
* ``safe_release_cells``：单元级工作底稿，真值只存内部库，外部文件永不
  带出；
* ``safe_release_links``：发布证据与既有审计 run/evidence 的关联；
* ``safe_release_record_dispositions``：逐条个体记录的口径处置留痕。

``safe_release_cells`` 上的触发器禁止 UPDATE/DELETE——已经发布的内容不
能事后「撤掉」来证明新版本安全；新版本只能把历史发布当作固定约束重新
推理。
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from screening_kpi_auditor.runtime import (
    ProcessingContext,
    SQLiteLedger,
    fingerprint,
    stable_json,
    utc_now,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS safe_releases(
  release_id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('published','rejected')),
  as_of TEXT NOT NULL,
  indicator_version TEXT NOT NULL,
  minimum_cell_count INTEGER NOT NULL,
  input_fingerprint TEXT NOT NULL,
  request_json TEXT NOT NULL,
  certificate_json TEXT NOT NULL,
  rejection_reasons_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS safe_release_cells(
  release_id TEXT NOT NULL,
  cell_id TEXT NOT NULL,
  view_id TEXT NOT NULL,
  level TEXT NOT NULL,
  is_total INTEGER NOT NULL,
  members_json TEXT NOT NULL,
  visibility TEXT NOT NULL CHECK(visibility IN ('published','suppressed')),
  suppression_reason TEXT,
  true_numerator INTEGER NOT NULL,
  true_denominator INTEGER NOT NULL,
  disclosed_numerator INTEGER,
  disclosed_denominator INTEGER,
  disclosure_interval_json TEXT,
  created_at TEXT NOT NULL,
  PRIMARY KEY(release_id, cell_id),
  FOREIGN KEY(release_id) REFERENCES safe_releases(release_id)
);
CREATE TABLE IF NOT EXISTS safe_release_links(
  release_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  evidence_stage TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(release_id, run_id, evidence_stage),
  FOREIGN KEY(release_id) REFERENCES safe_releases(release_id),
  FOREIGN KEY(run_id) REFERENCES runs(run_id)
);
CREATE TABLE IF NOT EXISTS safe_release_record_dispositions(
  release_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  disposition TEXT NOT NULL,
  detail_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY(release_id, record_id),
  FOREIGN KEY(release_id) REFERENCES safe_releases(release_id)
);
CREATE TRIGGER IF NOT EXISTS safe_release_cells_no_update
BEFORE UPDATE ON safe_release_cells
BEGIN
  SELECT RAISE(ABORT, 'published release evidence is append-only');
END;
CREATE TRIGGER IF NOT EXISTS safe_release_cells_no_delete
BEFORE DELETE ON safe_release_cells
BEGIN
  SELECT RAISE(ABORT, 'published release evidence is append-only');
END;
CREATE TRIGGER IF NOT EXISTS safe_releases_no_update
BEFORE UPDATE ON safe_releases
BEGIN
  SELECT RAISE(ABORT, 'release records are append-only');
END;
CREATE TRIGGER IF NOT EXISTS safe_releases_no_delete
BEFORE DELETE ON safe_releases
BEGIN
  SELECT RAISE(ABORT, 'release records are append-only');
END;
"""


class SafeReleaseStore:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)
        self.ledger = SQLiteLedger(self.database)
        self.initialize()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=20, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=20000")
        try:
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(SCHEMA)

    def save(
        self,
        release_id: str,
        ctx: ProcessingContext,
        status: str,
        request: Mapping[str, Any],
        certificate: Mapping[str, Any],
        cell_rows: Sequence[Mapping[str, Any]],
        dispositions: Sequence[Mapping[str, Any]],
        rejection_reasons: Sequence[str],
    ) -> None:
        # 先保证审计台账里存在关联 run（既有底稿表）。
        self.ledger.save(ctx)
        now = utc_now()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    """INSERT INTO safe_releases VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        release_id,
                        ctx.run_id,
                        status,
                        str(request.get("as_of", "")),
                        str(request.get("indicator", {}).get("version", "")),
                        int(request.get("minimum_cell_count", 0)),
                        fingerprint(request),
                        stable_json(request),
                        stable_json(certificate),
                        stable_json(list(rejection_reasons)),
                        now,
                    ),
                )
                connection.executemany(
                    """INSERT INTO safe_release_cells VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            release_id,
                            row["cell_id"],
                            row["view_id"],
                            row["level"],
                            1 if row["is_total"] else 0,
                            stable_json(row["members"]),
                            row["visibility"],
                            row.get("suppression_reason"),
                            int(row["true_numerator"]),
                            int(row["true_denominator"]),
                            row.get("disclosed_numerator"),
                            row.get("disclosed_denominator"),
                            stable_json(row["disclosure_interval"])
                            if row.get("disclosure_interval") is not None
                            else None,
                            now,
                        )
                        for row in cell_rows
                    ],
                )
                connection.execute(
                    """INSERT OR REPLACE INTO safe_release_links VALUES(?,?,?,?,?)""",
                    (
                        release_id,
                        ctx.run_id,
                        "safe_release",
                        fingerprint([ctx.run_id, release_id, status]),
                        now,
                    ),
                )
                connection.executemany(
                    """INSERT INTO safe_release_record_dispositions VALUES(?,?,?,?,?)""",
                    [
                        (
                            release_id,
                            str(item["record_id"]),
                            str(item["disposition"]),
                            stable_json(item),
                            now,
                        )
                        for item in dispositions
                    ],
                )
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise

    def find_by_input_fingerprint(self, request: Mapping[str, Any]) -> dict[str, Any] | None:
        digest = fingerprint(request)
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM safe_releases WHERE input_fingerprint=? ORDER BY created_at DESC LIMIT 1",
                (digest,),
            ).fetchone()
            return dict(row) if row else None

    def load_release(self, release_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM safe_releases WHERE release_id=?", (release_id,)
            ).fetchone()
            if row is None:
                return None
            cells = connection.execute(
                "SELECT * FROM safe_release_cells WHERE release_id=?", (release_id,)
            ).fetchall()
            dispositions = connection.execute(
                "SELECT * FROM safe_release_record_dispositions WHERE release_id=?",
                (release_id,),
            ).fetchall()
            return {
                "release": dict(row),
                "cells": [dict(item) for item in cells],
                "dispositions": [dict(item) for item in dispositions],
            }
