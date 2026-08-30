"""Engagement diffing — compare two engagement databases (e.g. this quarter
vs. last quarter against the same scope) and report what changed:

- new / resolved findings
- new / removed targets
- attempt-volume deltas per target
"""

from __future__ import annotations

import time
from pathlib import Path

from .db import EngagementDB


def _finding_keys(db: EngagementDB) -> dict[tuple, dict]:
    out = {}
    for f in db.findings_for():
        t = db.get_target(f["target_id"])
        out[(t["host"] if t else "?", f["title"])] = dict(f)
    return out


def diff_engagements(old_path: str | Path, new_db: EngagementDB,
                     new_label: str = "current") -> str:
    old = EngagementDB(old_path)
    try:
        old_findings = _finding_keys(old)
        new_findings = _finding_keys(new_db)
        old_targets = {t["host"] for t in old.list_targets()}
        new_targets = {t["host"] for t in new_db.list_targets()}

        new_only = [k for k in new_findings if k not in old_findings]
        resolved = [k for k in old_findings if k not in new_findings]
        persistent = [k for k in new_findings if k in old_findings]

        L = [f"# Engagement Diff — {Path(str(old_path)).stem} → {new_label}",
             f"\n_Generated {time.strftime('%Y-%m-%d %H:%M')}_\n",
             "## Summary\n",
             f"- New findings: **{len(new_only)}**",
             f"- Resolved findings: **{len(resolved)}**",
             f"- Persistent findings: **{len(persistent)}**",
             f"- New targets: **{len(new_targets - old_targets)}**",
             f"- Removed targets: **{len(old_targets - new_targets)}**\n",
             "## New findings\n"]
        L += [f"- ({new_findings[k]['severity']}) `{k[0]}` — {k[1]}"
              for k in new_only] or ["_None._"]
        L.append("\n## Resolved findings\n")
        L += [f"- ({old_findings[k]['severity']}) `{k[0]}` — {k[1]}"
              for k in resolved] or ["_None._"]
        L.append("\n## Persistent findings (still open)\n")
        L += [f"- ({new_findings[k]['severity']}) `{k[0]}` — {k[1]}"
              for k in persistent] or ["_None._"]
        L.append("\n## Target changes\n")
        for h in sorted(new_targets - old_targets):
            L.append(f"- ➕ {h}")
        for h in sorted(old_targets - new_targets):
            L.append(f"- ➖ {h}")
        return "\n".join(L) + "\n"
    finally:
        old.close()
