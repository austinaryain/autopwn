"""Web vulnerability pipeline — auto-detect HTTP services, run nuclei,
parse results straight into findings with CVSS and remediation."""

from __future__ import annotations

import json
from pathlib import Path

from .db import EngagementDB
from .runner import Runner, RunnerError

COMMON_WEB_PORTS = [
    (80, "http"), (443, "https"), (8080, "http"), (8443, "https"),
    (8000, "http"), (8888, "http"), (3000, "http"), (5000, "http"),
]


class WebVulnPipeline:
    def __init__(self, runner: Runner, db: EngagementDB):
        self.runner = runner
        self.db = db

    def discover_web_services(self, host: str, target_id: int) -> list[str]:
        """Probe common web ports with curl; return list of live base URLs."""
        urls: list[str] = []
        for port, scheme in COMMON_WEB_PORTS:
            url = f"{scheme}://{host}:{port}"
            try:
                res = self.runner.run(
                    "curl", ["-sk", "-o", "/dev/null", "-w", "%{http_code}",
                             "--max-time", "8", url],
                    target_host=host, target_id=target_id,
                    agent="webvuln", timeout=20)
            except RunnerError:
                continue
            code = res.stdout_tail.strip().splitlines()[-1] if res.stdout_tail.strip() else ""
            if code.isdigit() and code != "000":
                urls.append(url)
        return urls

    def nuclei_scan(self, url: str, host: str, target_id: int,
                    severity: str = "medium,high,critical") -> int:
        """Run nuclei against a URL and convert JSONL results into findings."""
        out = Path(self.runner.output_dir) / f"nuclei-{target_id}-{abs(hash(url))}.jsonl"
        try:
            self.runner.run(
                "nuclei", ["-u", url, "-jsonl", "-severity", severity,
                           "-o", str(out), "-stats=false"],
                target_host=host, target_id=target_id,
                agent="webvuln", timeout=900)
        except RunnerError as exc:
            raise RunnerError(f"nuclei unavailable or failed: {exc}") from exc
        return self._parse_nuclei(out, target_id)

    def _parse_nuclei(self, path: Path, target_id: int) -> int:
        if not path.exists():
            return 0
        count = 0
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                hit = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = hit.get("info", {})
            classification = info.get("classification", {}) or {}
            self.db.record_finding(
                target_id,
                title=f"[{hit.get('template-id', 'nuclei')}] "
                      f"{info.get('name', 'unnamed')}",
                severity=info.get("severity", "info"),
                description=(info.get("description", "") or "")[:500] +
                            f"\nMatched at: {hit.get('matched-at', '')}",
                evidence=str(path),
                cvss=classification.get("cvss-metrics", "") or "",
                remediation=info.get("remediation", "") or "",
                attack_id="T1595.002",
            )
            count += 1
        return count

    def run(self, host: str, target_id: int) -> dict:
        """Full pipeline: discover web services, nuclei-scan each."""
        urls = self.discover_web_services(host, target_id)
        results = {"host": host, "web_services": urls, "findings": 0, "errors": []}
        for url in urls:
            try:
                results["findings"] += self.nuclei_scan(url, host, target_id)
            except RunnerError as exc:
                results["errors"].append(str(exc))
                break
        return results
