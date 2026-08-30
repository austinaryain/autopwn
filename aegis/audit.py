"""Tamper-evident, append-only audit log.

Every entry is a JSON line containing a SHA-256 hash of the previous entry,
forming a chain. Any edit or deletion of a past line breaks the chain and is
detectable with `AuditLog.verify()`.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, logs_dir: str | Path):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.logs_dir / f"audit-{time.strftime('%Y%m%d')}.jsonl"
        self._prev_hash = self._load_tail_hash()

    def _load_tail_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last is None:
            return GENESIS
        try:
            return json.loads(last)["hash"]
        except (json.JSONDecodeError, KeyError):
            return GENESIS

    @staticmethod
    def _hash(payload: dict) -> str:
        blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()
        return hashlib.sha256(blob).hexdigest()

    def log(self, actor: str, category: str, action: str, detail: dict | None = None) -> dict:
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "epoch": time.time(),
            "actor": actor,
            "category": category,
            "action": action,
            "detail": detail or {},
            "prev_hash": self._prev_hash,
        }
        entry["hash"] = self._hash(entry)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._prev_hash = entry["hash"]
        return entry

    @classmethod
    def verify(cls, path: str | Path) -> tuple[bool, str]:
        """Verify chain integrity of one audit file."""
        prev = GENESIS
        n = 0
        with Path(path).open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                n += 1
                entry = json.loads(line)
                if entry.get("prev_hash") != prev:
                    return False, f"chain break at line {lineno}: prev_hash mismatch"
                claimed = entry.pop("hash")
                if cls._hash(entry) != claimed:
                    return False, f"chain break at line {lineno}: content hash mismatch"
                prev = claimed
        return True, f"OK ({n} entries)"
