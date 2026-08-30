"""OPSEC profiles — control noise, timing, and transport anonymity.

Levels:
  normal   — no throttling, proxychains optional (config default)
  stealth  — jittered delays between commands, proxychains enforced
  paranoid — long randomized delays, proxychains enforced, slow tools only
"""

from __future__ import annotations

import random
import time


class OpsecError(Exception):
    pass


# Tools considered noisy even for stealth (flagged, not blocked)
NOISY_TOOLS = {"masscan", "hydra", "medusa", "ncrack", "sqlmap", "msfconsole"}

PROFILES = {
    "normal":   {"jitter": (0, 0),   "enforce_proxy": False},
    "stealth":  {"jitter": (2, 8),   "enforce_proxy": True},
    "paranoid": {"jitter": (15, 45), "enforce_proxy": True},
}


class OpsecProfile:
    def __init__(self, level: str = "normal"):
        if level not in PROFILES:
            level = "normal"
        self.level = level
        self._cfg = PROFILES[level]

    @property
    def enforce_proxy(self) -> bool:
        return self._cfg["enforce_proxy"]

    def pre_exec(self, tool: str, *, proxy_wrapped: bool) -> dict:
        """Called by the runner before every command. Returns notes; may raise."""
        notes: dict = {"level": self.level}
        if self.enforce_proxy and not proxy_wrapped:
            raise OpsecError(
                f"OPSEC level '{self.level}' requires proxychains, but the "
                f"command would not be wrapped. Enable use_proxychains or lower "
                f"the OPSEC level.")
        lo, hi = self._cfg["jitter"]
        if hi > 0:
            delay = random.uniform(lo, hi)
            notes["jitter_sec"] = round(delay, 1)
            time.sleep(delay)
        if tool in NOISY_TOOLS and self.level != "normal":
            notes["warning"] = f"'{tool}' is noisy for level '{self.level}'"
        return notes
