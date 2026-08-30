import json
from pathlib import Path

import pytest

from aegis.scope import ScopeGate


AUTH = {
    "engagement": "pytest-eng",
    "valid_from": "2020-01-01",
    "valid_until": "2099-01-01",
    "scope": ["10.10.10.0/24", "*.example.com", "testlab.local"],
    "exclusions": ["10.10.10.1"],
    "prohibited_techniques": ["denial-of-service", "T1498"],
    "max_requests_per_second": 0,
    "testing_hours": "",
}


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "authorization.json").write_text(json.dumps(AUTH))
    return tmp_path


@pytest.fixture()
def scope(workspace):
    return ScopeGate("authorization.json")
