import json

import pytest

from aegis.scope import ScopeError, ScopeGate


def test_in_scope_ip(scope):
    assert scope.is_in_scope("10.10.10.5") is True


def test_exclusion_wins(scope):
    assert scope.is_in_scope("10.10.10.1") is False


def test_out_of_scope_ip(scope):
    assert scope.is_in_scope("8.8.8.8") is False


def test_wildcard_domain(scope):
    assert scope.is_in_scope("app.example.com") is True
    assert scope.is_in_scope("example.com") is True
    assert scope.is_in_scope("evil-example.com") is False


def test_check_raises(scope):
    with pytest.raises(ScopeError):
        scope.check("169.254.169.254")  # cloud metadata — never in scope


def test_expired_window_refuses(workspace):
    data = json.loads((workspace / "authorization.json").read_text())
    data["valid_until"] = "2020-12-31"
    (workspace / "authorization.json").write_text(json.dumps(data))
    with pytest.raises(ScopeError):
        ScopeGate("authorization.json")


def test_missing_authorization_refuses(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ScopeError):
        ScopeGate("authorization.json")


def test_roe_fields_loaded(scope):
    assert "denial-of-service" in scope.roe["prohibited_techniques"]
    assert scope.roe["max_requests_per_second"] == 0
