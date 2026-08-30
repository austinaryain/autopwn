"""Loot vault — credentials, hashes, captured files, screenshots.

All material gathered during an engagement is copied into `loot/<target>/`
and catalogued in the DB. Hashes can be exported straight into a
john/hashcat-ready file.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from .db import EngagementDB
from .runner import Runner, RunnerError


class LootVault:
    def __init__(self, db: EngagementDB, runner: Runner,
                 loot_dir: str | Path = "loot"):
        self.db = db
        self.runner = runner
        self.loot_dir = Path(loot_dir)
        self.loot_dir.mkdir(parents=True, exist_ok=True)

    def _target_dir(self, host: str) -> Path:
        safe = host.replace("/", "_").replace(":", "_")
        d = self.loot_dir / safe
        d.mkdir(parents=True, exist_ok=True)
        return d

    def add_credential(self, target_id: int, title: str, value: str,
                       source: str = "") -> int:
        return self.db.record_loot(target_id, "credential", title, value,
                                   source=source)

    def add_hash(self, target_id: int, title: str, hash_value: str,
                 source: str = "") -> int:
        return self.db.record_loot(target_id, "hash", title, hash_value,
                                   source=source)

    def add_note(self, target_id: int, title: str, value: str) -> int:
        return self.db.record_loot(target_id, "note", title, value)

    def capture_file(self, target_id: int, host: str, src_path: str | Path,
                     title: str = "", source: str = "") -> Path | None:
        """Copy a captured file into the vault and catalogue it."""
        src = Path(src_path)
        if not src.exists():
            return None
        dest = self._target_dir(host) / src.name
        shutil.copy2(src, dest)
        self.db.record_loot(target_id, "file", title or src.name,
                            file_path=str(dest), source=source)
        return dest

    def capture_screenshot(self, target_id: int, host: str, url: str) -> Path | None:
        """Screenshot a web service with eyewitness or cutycapt if installed."""
        out_dir = self._target_dir(host) / "screenshots"
        out_dir.mkdir(exist_ok=True)
        for tool, args in (
            ("cutycapt", ["--url=" + url,
                          "--out=" + str(out_dir / f"{url.split('//')[-1].replace('/', '_')}.png")]),
            ("eyewitness", ["--single", url, "-d", str(out_dir), "--no-prompt"]),
        ):
            if shutil.which(tool) is None:
                continue
            try:
                res = self.runner.run(tool, args, target_host=host,
                                      target_id=target_id, agent="loot", timeout=90)
            except RunnerError:
                continue
            pngs = sorted(out_dir.glob("*.png"))
            if res.exit_code == 0 and pngs:
                self.db.record_loot(target_id, "screenshot", url,
                                    file_path=str(pngs[-1]), source=tool)
                return pngs[-1]
        return None

    def export_hashes(self, path: str | Path) -> Path:
        """Write all captured hashes to a john/hashcat-ready file."""
        lines = [r["value"] for r in self.db.credentials() if r["kind"] == "hash"]
        out = Path(path)
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return out
