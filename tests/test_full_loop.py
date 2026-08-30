"""Full-loop regression: simulation-mode lab validation must always pass."""

import pytest

from aegis.guard import CommandGuard, GuardError
from validation.run_lab_validation import run_simulation


def test_full_loop_simulation():
    cl = run_simulation(verbose=False)
    failed = [name for ok, name in cl.results if not ok]
    assert cl.ok, f"failed checks: {failed}"


def test_hydra_login_flag_allowed(scope):
    """'-l' is hydra's login flag, not a target-file flag."""
    g = CommandGuard(scope, ".")
    g.check_flags("hydra", ["-l", "admin", "-P", "wl.txt", "ssh://10.10.10.5"])


def test_nuclei_list_flag_denied(scope):
    g = CommandGuard(scope, ".")
    with pytest.raises(GuardError):
        g.check_flags("nuclei", ["-l", "targets.txt"])


def test_nmap_il_flag_denied(scope):
    g = CommandGuard(scope, ".")
    with pytest.raises(GuardError):
        g.check_flags("nmap", ["-iL", "targets.txt"])
