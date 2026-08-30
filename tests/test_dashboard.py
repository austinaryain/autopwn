import requests

from aegis.dashboard import DashboardServer
from aegis.db import EngagementDB


def test_dashboard_requires_token(workspace):
    db = EngagementDB("eng.db")
    server = DashboardServer(db, port=8899)
    url = server.start()
    try:
        # no token -> 403
        assert requests.get("http://127.0.0.1:8899/", timeout=5).status_code == 403
        assert requests.get("http://127.0.0.1:8899/api/state",
                            timeout=5).status_code == 403
        # with token -> 200
        assert requests.get(url, timeout=5).status_code == 200
        r = requests.get("http://127.0.0.1:8899/api/state",
                         headers={"Authorization": f"Bearer {server.token}"},
                         timeout=5)
        assert r.status_code == 200
        assert "targets" in r.json()
    finally:
        server.stop()


def test_dashboard_masks_credentials(workspace):
    db = EngagementDB("eng.db")
    tid = db.add_target("10.10.10.5")
    db.record_loot(tid, "credential", "ssh admin", "admin:S3cur3!")
    server = DashboardServer(db, port=8898)
    server.start()
    try:
        state = requests.get(
            f"http://127.0.0.1:8898/api/state?token={server.token}",
            timeout=5).json()
        values = [l["value"] for l in state["loot"]]
        assert all("S3cur3" not in v for v in values)
        assert any(v.startswith("••••") for v in values)
    finally:
        server.stop()
