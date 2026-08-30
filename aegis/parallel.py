"""Parallel agent execution — scan one host while attacking another.

Each agent runs in its own thread against its own target; the DB is
per-target isolated and SQLite serializes writes. Step events are
prefixed with the target so interleaved console output stays readable.
"""

from __future__ import annotations

import threading

from .agent import Agent


class ParallelRunner:
    def __init__(self, agent: Agent):
        self.agent = agent

    def run(self, jobs: list[tuple[str, str]], on_step=None) -> dict:
        """jobs: list of (mode, host). Returns {host: result-or-error}."""
        results: dict[str, dict | str] = {}
        lock = threading.Lock()

        def worker(mode: str, host: str):
            def prefixed(event: dict):
                if on_step:
                    with lock:
                        on_step(host, event)
            try:
                res = self.agent.run(mode, host, on_step=prefixed)
                results[host] = res
            except Exception as exc:  # keep sibling agents alive
                results[host] = f"error: {exc}"

        threads = [threading.Thread(target=worker, args=(m, h), daemon=True)
                   for m, h in jobs]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return results
