"""Engagement database — the workbench's memory.

Tracks targets, every executed action, every attack attempt (success or
failure), findings, and OSINT items. Agents query this before planning so
they never repeat a failed approach blindly.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    status TEXT DEFAULT 'new',
    added_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    target_id INTEGER,
    agent TEXT,
    tool TEXT,
    command TEXT,
    exit_code INTEGER,
    duration_sec REAL,
    output_file TEXT,
    status TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    target_id INTEGER,
    technique TEXT,
    vector TEXT,
    payload TEXT,
    result TEXT,
    success INTEGER DEFAULT 0,
    evidence TEXT DEFAULT '',
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    target_id INTEGER,
    title TEXT,
    severity TEXT DEFAULT 'info',
    description TEXT DEFAULT '',
    evidence TEXT DEFAULT '',
    status TEXT DEFAULT 'open',
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS osint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    target_id INTEGER,
    source TEXT,
    kind TEXT,
    data TEXT,
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE TABLE IF NOT EXISTS loot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT DEFAULT (datetime('now')),
    target_id INTEGER,
    kind TEXT,            -- credential | hash | file | screenshot | note
    title TEXT,
    value TEXT DEFAULT '',         -- e.g. user:pass or hash string
    file_path TEXT DEFAULT '',     -- for captured files/screenshots
    source TEXT DEFAULT '',        -- which action/attempt produced it
    FOREIGN KEY (target_id) REFERENCES targets(id)
);
CREATE INDEX IF NOT EXISTS idx_actions_target ON actions(target_id);
CREATE INDEX IF NOT EXISTS idx_attempts_target ON attempts(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
CREATE INDEX IF NOT EXISTS idx_osint_target ON osint(target_id);
CREATE INDEX IF NOT EXISTS idx_loot_target ON loot(target_id);
"""

# Columns added after v0.1 — applied idempotently to existing databases.
MIGRATIONS = [
    ("findings", "cvss", "ALTER TABLE findings ADD COLUMN cvss TEXT DEFAULT ''"),
    ("findings", "remediation", "ALTER TABLE findings ADD COLUMN remediation TEXT DEFAULT ''"),
    ("findings", "attack_id", "ALTER TABLE findings ADD COLUMN attack_id TEXT DEFAULT ''"),
    ("attempts", "attack_id", "ALTER TABLE attempts ADD COLUMN attack_id TEXT DEFAULT ''"),
]


class EngagementDB:
    def __init__(self, path: str | Path):
        import threading
        # check_same_thread=False: the dashboard server and parallel agents
        # access the DB from their own threads; _lock serializes all writes.
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self._migrate()
        with self._lock:
            self.conn.commit()

    def _migrate(self) -> None:
        for table, column, ddl in MIGRATIONS:
            cols = {r["name"] for r in self.conn.execute(
                f"PRAGMA table_info({table})").fetchall()}
            if column not in cols:
                self.conn.execute(ddl)

    def _execute(self, *args, **kwargs):
        """Thread-serialized write path (parallel agents + dashboard)."""
        with self._lock:
            cur = self.conn.execute(*args, **kwargs)
            self.conn.commit()
            return cur

    # ---- targets -------------------------------------------------------
    def add_target(self, host: str, description: str = "") -> int:
        cur = self._execute(
            "INSERT OR IGNORE INTO targets(host, description) VALUES (?, ?)",
            (host, description),
        )
        if cur.lastrowid:
            return cur.lastrowid
        return self.conn.execute(
            "SELECT id FROM targets WHERE host = ?", (host,)
        ).fetchone()["id"]

    def get_target(self, host_or_id) -> sqlite3.Row | None:
        if isinstance(host_or_id, int) or str(host_or_id).isdigit():
            row = self.conn.execute(
                "SELECT * FROM targets WHERE id = ?", (int(host_or_id),)
            ).fetchone()
            if row:
                return row
        return self.conn.execute(
            "SELECT * FROM targets WHERE host = ?", (str(host_or_id),)
        ).fetchone()

    def list_targets(self) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM targets ORDER BY id").fetchall()

    def set_target_status(self, target_id: int, status: str) -> None:
        self._execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))

    # ---- actions -------------------------------------------------------
    def record_action(self, target_id, agent, tool, command, exit_code,
                      duration_sec, output_file, status) -> int:
        cur = self._execute(
            "INSERT INTO actions(target_id, agent, tool, command, exit_code,"
            " duration_sec, output_file, status) VALUES (?,?,?,?,?,?,?,?)",
            (target_id, agent, tool, command, exit_code, duration_sec,
             output_file, status),
        )
        with self._lock:
            self.conn.commit()
        return cur.lastrowid

    # ---- attempts ------------------------------------------------------
    def record_attempt(self, target_id, technique, vector, payload,
                       result, success, evidence="", attack_id="") -> int:
        cur = self._execute(
            "INSERT INTO attempts(target_id, technique, vector, payload, result,"
            " success, evidence, attack_id) VALUES (?,?,?,?,?,?,?,?)",
            (target_id, technique, vector, payload, result, int(bool(success)),
             evidence, attack_id),
        )
        with self._lock:
            self.conn.commit()
        return cur.lastrowid

    def attempts_for(self, target_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM attempts WHERE target_id = ? ORDER BY id", (target_id,)
        ).fetchall()

    def tried_techniques(self, target_id: int) -> list[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT technique FROM attempts WHERE target_id = ?", (target_id,)
        ).fetchall()
        return [r["technique"] for r in rows]

    # ---- findings ------------------------------------------------------
    def record_finding(self, target_id, title, severity="info",
                       description="", evidence="", cvss="",
                       remediation="", attack_id="") -> int:
        cur = self._execute(
            "INSERT INTO findings(target_id, title, severity, description, evidence,"
            " cvss, remediation, attack_id) VALUES (?,?,?,?,?,?,?,?)",
            (target_id, title, severity, description, evidence,
             cvss, remediation, attack_id),
        )
        with self._lock:
            self.conn.commit()
        return cur.lastrowid

    # ---- loot ------------------------------------------------------------
    def record_loot(self, target_id, kind, title, value="",
                    file_path="", source="") -> int:
        # encrypt sensitive values at rest when a cipher is configured
        cipher = getattr(self, "cipher", None)
        if cipher and cipher.active and kind in ("credential", "hash"):
            value = cipher.encrypt(value)
        cur = self._execute(
            "INSERT INTO loot(target_id, kind, title, value, file_path, source)"
            " VALUES (?,?,?,?,?,?)",
            (target_id, kind, title, value, file_path, source),
        )
        return cur.lastrowid

    def _decrypt_row(self, row):
        cipher = getattr(self, "cipher", None)
        if cipher and row["value"]:
            d = dict(row)
            d["value"] = cipher.decrypt(d["value"])
            return d
        return row

    def loot_for(self, target_id: int | None = None) -> list[sqlite3.Row]:
        if target_id is None:
            rows = self.conn.execute("SELECT * FROM loot ORDER BY id").fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM loot WHERE target_id = ? ORDER BY id", (target_id,)
            ).fetchall()
        return [self._decrypt_row(r) for r in rows]

    def credentials(self) -> list[sqlite3.Row]:
        rows = self.conn.execute(
            "SELECT * FROM loot WHERE kind IN ('credential','hash') ORDER BY id"
        ).fetchall()
        return [self._decrypt_row(r) for r in rows]

    def findings_for(self, target_id: int | None = None) -> list[sqlite3.Row]:
        if target_id is None:
            return self.conn.execute("SELECT * FROM findings ORDER BY id").fetchall()
        return self.conn.execute(
            "SELECT * FROM findings WHERE target_id = ? ORDER BY id", (target_id,)
        ).fetchall()

    # ---- osint ---------------------------------------------------------
    def record_osint(self, target_id, source, kind, data: dict | list | str) -> int:
        cur = self._execute(
            "INSERT INTO osint(target_id, source, kind, data) VALUES (?,?,?,?)",
            (target_id, source, kind, json.dumps(data, ensure_ascii=False)),
        )
        with self._lock:
            self.conn.commit()
        return cur.lastrowid

    def osint_for(self, target_id: int) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM osint WHERE target_id = ? ORDER BY id", (target_id,)
        ).fetchall()

    # ---- agent memory summary ------------------------------------------
    def memory_summary(self, target_id: int) -> str:
        """Compact text digest of everything known about a target — fed to the LLM."""
        lines: list[str] = []
        actions = self.conn.execute(
            "SELECT tool, command, exit_code, status FROM actions"
            " WHERE target_id = ? ORDER BY id DESC LIMIT 30", (target_id,)
        ).fetchall()
        if actions:
            lines.append("## Recent actions (newest first)")
            for a in actions:
                lines.append(f"- [{a['status']}] `{a['command']}` (exit {a['exit_code']})")
        attempts = self.attempts_for(target_id)
        if attempts:
            lines.append("## Attack attempts")
            for t in attempts:
                mark = "SUCCESS" if t["success"] else "failed"
                lines.append(f"- [{mark}] {t['technique']} via {t['vector']} "
                             f"(payload: {t['payload']}): {t['result']}")
        findings = self.findings_for(target_id)
        if findings:
            lines.append("## Findings")
            for f in findings:
                lines.append(f"- ({f['severity']}) {f['title']}: {f['description'][:200]}")
        osint = self.osint_for(target_id)
        if osint:
            lines.append("## OSINT")
            for o in osint[-20:]:
                lines.append(f"- [{o['source']}/{o['kind']}] {o['data'][:200]}")
        loot = self.loot_for(target_id)
        if loot:
            lines.append("## Loot")
            for l in loot:
                lines.append(f"- ({l['kind']}) {l['title']}: {l['value'][:120]}")
        return "\n".join(lines) if lines else "(nothing known yet about this target)"

    def close(self) -> None:
        self.conn.close()
