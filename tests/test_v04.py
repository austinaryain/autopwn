"""v0.4 tests: provenance, refuter, operators/coordinator, disclosure,
War Room mission API."""

import json

import pytest
import requests

from aegis.dashboard import DashboardServer
from aegis.db import EngagementDB
from aegis.disclosure import DisclosurePipeline
from aegis.llm import LLMClient
from aegis.provenance import Refuter


class StubLLM(LLMClient):
    """LLM stub with programmable refuter verdicts."""
    verdict = "confirmed"

    def __init__(self):
        pass

    def available(self):
        return True

    def chat(self, messages, *, json_mode=False):
        return json.dumps({"verdict": self.verdict, "reason": "stub review"})


@pytest.fixture()
def db(workspace):
    return EngagementDB("eng.db")


# ---- provenance -------------------------------------------------------------

def test_provenance_defaults(db):
    tid = db.add_target("10.10.10.5")
    fid_llm = db.record_finding(tid, "LLM claim", "high", "desc",
                                provenance="model-asserted")
    fid_tool = db.record_finding(tid, "Parser claim", "low", "desc",
                                 provenance="tool-proven", verified=1)
    assert db.get_finding(fid_llm)["provenance"] == "model-asserted"
    assert db.get_finding(fid_tool)["verified"] == 1


# ---- refuter -----------------------------------------------------------------

def test_refuter_confirms(db):
    tid = db.add_target("10.10.10.5")
    fid = db.record_finding(tid, "Claimed RCE", "high", "desc",
                            provenance="model-asserted")
    StubLLM.verdict = "confirmed"
    r = Refuter(StubLLM(), db)
    out = r.refute_finding(fid)
    assert out["verdict"] == "confirmed"
    assert db.get_finding(fid)["verified"] == 1


def test_refuter_rejects_and_marks(db):
    tid = db.add_target("10.10.10.5")
    fid = db.record_finding(tid, "Overclaimed XSS", "medium", "desc",
                            provenance="model-asserted")
    StubLLM.verdict = "rejected"
    r = Refuter(StubLLM(), db)
    out = r.refute_finding(fid)
    assert out["verdict"] == "rejected"
    assert db.get_finding(fid)["status"] == "rejected"


def test_refuter_exempts_tool_proven(db):
    tid = db.add_target("10.10.10.5")
    fid = db.record_finding(tid, "Nuclei hit", "high", "desc",
                            provenance="tool-proven", verified=1)
    r = Refuter(StubLLM(), db)
    assert r.refute_finding(fid)["verdict"] == "confirmed"


def test_review_target_skips_low_and_rejected(db):
    tid = db.add_target("10.10.10.5")
    db.record_finding(tid, "low thing", "low", "d", provenance="model-asserted")
    db.record_finding(tid, "med thing", "medium", "d",
                      provenance="model-asserted")
    StubLLM.verdict = "uncertain"
    results = Refuter(StubLLM(), db).review_target(tid)
    assert len(results) == 1 and results[0]["title"] == "med thing"


# ---- disclosure ---------------------------------------------------------------

def test_disclosure_draft(db, workspace):
    tid = db.add_target("10.10.10.5")
    fid = db.record_finding(tid, "Apache 2.4.49 Path Traversal CVE-2021-41773",
                            "high", "Path traversal in Apache",
                            cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                            remediation="Upgrade Apache",
                            provenance="tool-proven", verified=1)
    pipe = DisclosurePipeline(db, workspace / "disclosures")
    out = pipe.draft(fid)
    assert out and out.exists()
    text = out.read_text(encoding="utf-8")
    assert "CVE-2021-41773" in text
    assert "Steps to Reproduce" in text
    assert "Aegis never sends" in text or "submit manually" in text
    assert "Upgrade Apache" in text


# ---- War Room mission API ------------------------------------------------------

def test_mission_api(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8897)
    launched = []
    server.mission_handler = lambda host, mode, cancel: launched.append((host, mode))
    server.start()
    try:
        # unauthorized
        r = requests.post("http://127.0.0.1:8897/api/mission/start",
                          json={"host": "10.10.10.5", "mode": "scan"}, timeout=5)
        assert r.status_code == 403
        # authorized
        r = requests.post(
            f"http://127.0.0.1:8897/api/mission/start?token={server.token}",
            json={"host": "10.10.10.5", "mode": "scan"}, timeout=5)
        assert r.status_code == 200
        mid = r.json()["mission_id"]
        import time
        time.sleep(0.3)
        state = requests.get(
            f"http://127.0.0.1:8897/api/state?token={server.token}",
            timeout=5).json()
        assert state["missions"][str(mid)]["status"] in ("running", "complete")
        assert launched == [("10.10.10.5", "scan")]
    finally:
        server.stop()
