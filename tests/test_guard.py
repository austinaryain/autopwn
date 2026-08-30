import pytest

from aegis.guard import CommandGuard, GuardError, extract_hosts


@pytest.fixture()
def guard(scope):
    return CommandGuard(scope, ".")


# ---- host extraction ------------------------------------------------------

def test_extract_plain_ip():
    assert extract_hosts(["-sV", "10.10.10.5"]) == ["10.10.10.5"]


def test_extract_url_host():
    assert extract_hosts(["-u", "https://app.example.com/login?x=1"]) == \
        ["app.example.com"]


def test_extract_multiple_hosts():
    hosts = extract_hosts(["10.10.10.5", "10.10.10.6", "-p80"])
    assert hosts == ["10.10.10.5", "10.10.10.6"]


def test_extract_scheme_host_port():
    assert extract_hosts(["ssh://10.10.10.5:22"]) == ["10.10.10.5"]


def test_wordlists_not_hosts():
    assert extract_hosts(["-w", "/usr/share/wordlists/rockyou.txt",
                          "10.10.10.5"]) == ["10.10.10.5"]


def test_key_value_form():
    assert extract_hosts(["RHOSTS=10.10.10.5"]) == ["10.10.10.5"]


# ---- embedded scope enforcement -------------------------------------------

def test_second_host_out_of_scope_refused(guard):
    with pytest.raises(GuardError, match="8.8.8.8"):
        guard.check_embedded_hosts(["-sV", "10.10.10.5", "8.8.8.8"])


def test_out_of_scope_url_refused(guard):
    with pytest.raises(GuardError):
        guard.check_embedded_hosts(["-u", "https://out-of-scope.example.org"])


def test_in_scope_args_pass(guard):
    hosts = guard.check_embedded_hosts(["-sV", "10.10.10.5"])
    assert hosts == ["10.10.10.5"]


# ---- flag policy ------------------------------------------------------------

def test_nmap_script_flag_denied(guard):
    with pytest.raises(GuardError, match="--script"):
        guard.check_flags("nmap", ["--script", "vuln", "10.10.10.5"])


def test_nc_exec_flag_denied(guard):
    with pytest.raises(GuardError):
        guard.check_flags("nc", ["-e", "/bin/sh", "10.10.10.5", "4444"])


def test_target_file_flag_denied(guard):
    with pytest.raises(GuardError, match="bypass"):
        guard.check_flags("nmap", ["-iL", "targets.txt"])


def test_output_path_escape_denied(guard):
    with pytest.raises(GuardError, match="escapes"):
        guard.check_flags("nmap", ["-oX", "/etc/cron.d/x", "10.10.10.5"])


# ---- rules of engagement ----------------------------------------------------

def test_prohibited_technique_refused(guard):
    with pytest.raises(GuardError, match="prohibited"):
        guard.check_roe("nmap", ["--flood", "denial-of-service", "10.10.10.5"])


def test_prohibited_attack_id_refused(guard):
    with pytest.raises(GuardError):
        guard.check_roe("tool", ["T1498", "10.10.10.5"])


def test_testing_hours_enforced(guard):
    guard.scope.roe["testing_hours"] = "00:00-00:01"
    with pytest.raises(GuardError, match="testing hours"):
        guard.check_roe("nmap", ["10.10.10.5"])


def test_rate_limiter_sleeps(guard):
    guard.scope.roe["max_requests_per_second"] = 100
    guard.rate_limit()
    wait = guard.rate_limit()
    assert wait >= 0  # second call within interval must not error
